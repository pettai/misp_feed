import asyncio
import copy
import datetime
import ipaddress
import json
import os
import time
from typing import Any, Dict, Optional, Union

import requests
from requests.exceptions import ConnectionError as requestsConnectionError

from . import generator, settings
from .redis_db import event_endpoint_data, manifest_endpoint_data, redis_save


async def add_context(c2_entry: Dict[str, Any]) -> str:
    """Add all c2 data except for unwanted keys"""

    context = copy.deepcopy(c2_entry)

    for unwanted_key in ["whois", "geodata"]:
        try:
            del context[unwanted_key]
        except KeyError:
            pass

    return json.dumps(context)


async def get_current_event_id() -> Optional[str]:
    manifest_data = await manifest_endpoint_data()
    if manifest_data is None:
        return None

    data = json.loads(manifest_data)
    now = datetime.datetime.now()
    for x in data:
        if data[x]["date"] == now.strftime("%Y-%m-%d") and isinstance(x, str):
            return x

    return None


async def get_current_event_hosts(event: Dict[str, Any]) -> Dict[str, int]:
    hosts: Dict[str, int] = {}
    for event_object in event["Event"]["Object"]:
        for attribute in event_object["Attribute"]:
            if attribute["type"] == "ip-dst|port" or attribute["type"] == "hostname|port":
                hosts[attribute["value"]] = 1

    return hosts


async def generate_feed_event(c2_data: Dict[str, Any]) -> None:
    """Generate a feed with an event with all c2 as event objects"""

    event_id = await get_current_event_id()
    if event_id is None:
        current_hosts: Dict[str, int] = {}
    else:
        event_data = await event_endpoint_data(event_id)
        if event_data is None:
            current_hosts = {}
        else:
            event = json.loads(event_data)
            current_hosts = await get_current_event_hosts(event)

    domain_count = 0
    ip_count = 0

    feed_generator = generator.FeedGenerator()

    for c2_entry in c2_data:
        object_data: Dict[str, str] = {}

        if " UTC" not in c2_data[c2_entry]["C2_last_confirmed"]:
            raise ValueError(f"Unknown datetime format for {c2_data}")

        last_seen = datetime.datetime.strptime(c2_data[c2_entry]["C2_last_confirmed"], "%Y-%m-%dT%H:%M:%S UTC")

        if last_seen < (datetime.datetime.now() - datetime.timedelta(days=1)):
            continue

        if "DNS" in c2_data[c2_entry] or "dns" in c2_data[c2_entry]:
            # object_data["url"] = f"dns://{c2_entry}:{c2_data[c2_entry]['port']}"
            object_data["scheme"] = "dns"
        elif "https://" in c2_data[c2_entry]["url"]:
            # object_data["url"] = c2_data[c2_entry]["url"]
            object_data["scheme"] = "https"
        elif "http://" in c2_data[c2_entry]["url"]:
            # object_data["url"] = c2_data[c2_entry]["url"]
            object_data["scheme"] = "http"
        else:
            raise ValueError(f"Unknown scheme for {c2_data}")

        object_data["port"] = c2_data[c2_entry]["port"]

        object_data["last-seen"] = c2_data[c2_entry]["C2_last_confirmed"].replace(" UTC", "")

        # Add IP or domain
        try:
            ipaddress.ip_address(c2_entry)
            object_data["ip-dst|port"] = c2_entry + "|" + c2_data[c2_entry]["port"]

            if object_data["ip-dst|port"] in current_hosts:
                continue

        except ValueError:
            object_data["domain"] = c2_entry
            object_data["hostname|port"] = c2_entry + "|" + c2_data[c2_entry]["port"]

            if object_data["hostname|port"] in current_hosts:
                continue

        # Add context in misp text attribute
        object_data["text"] = await add_context(c2_data[c2_entry])

        tags = {
            "text": [
                {"colour": "#609b4b", "name": "CobaltStrike"},
                {"colour": "#50b33d", "name": "Cobalt Strike"},
                {"colour": "#0eb100", "name": 'admiralty-scale:information-credibility="1"'},
                {"colour": "#054300", "name": 'admiralty-scale:source-reliability="a"'},
            ]
        }

        # comments = {
        #     "url": "Not to be used for detection. This is a generated checksum8 "
        #     + "URI that can be used for downloading the beacon and reproducing the result."
        # }
        comments: Dict[str, str] = {}

        to_ids = {}
        if "ip-dst|port" in object_data:
            to_ids["ip-dst|port"] = True
            ip_count += 1
            if ip_count > 2:
                continue

        elif "hostname|port" in object_data:
            to_ids["hostname|port"] = True
            to_ids["domain"] = False
            domain_count += 1
            if domain_count > 2:
                continue
        else:
            raise ValueError("Unknown to_ids attribute")

        # disable_correlations = {"text": True}
        disable_correlations: Dict[str, bool] = {}

        # Add a url object to the daily event
        feed_generator.add_object_to_event(
            "sunet-c2",
            tags,
            comments,
            to_ids,
            disable_correlations,
            **object_data,
        )

    # Immediately write the event to the disk (Bypassing the default flushing behavior)
    feed_generator.flush_event()
    await redis_save()


async def update_feed() -> None:
    """Update the event evert 60*60*2 seconds"""

    headers = {"API-KEY": os.environ["C2_API_KEY"]}

    # Run forever
    while True:
        try:
            req = requests.get(os.environ["C2_API_URL"], headers=headers, timeout=20)
        except requestsConnectionError:
            await asyncio.sleep(60 * 60 * 2)
            print("Failed to connect to C2 API server")
            continue

        if req.status_code != 200:
            await asyncio.sleep(60 * 60 * 2)
            continue

        data = json.loads(req.text)
        await generate_feed_event(data)

        await asyncio.sleep(60 * 60 * 2)