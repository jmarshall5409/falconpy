#!/usr/bin/env python3
"""Quick SIEM exploration."""

import json
import time
from falconpy import NGSIEM

CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

ngsiem = NGSIEM(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)

def run_query(query, desc, time_range="1h"):
    print(f"\n{'='*60}")
    print(f" {desc}")
    print(f"{'='*60}")
    resp = ngsiem.start_search(repository="search-all", query_string=query, is_live=False, start=time_range)
    if resp.get("status_code") != 200:
        print(f"Failed: {resp.get('status_code')}")
        return None
    search_id = resp.get("resources", {}).get("id")
    if not search_id:
        return None
    for i in range(30):
        time.sleep(2)
        status = ngsiem.get_search_status(repository="search-all", search_id=search_id)
        body = status.get("body", {})
        if body.get("done") or body.get("events"):
            events = body.get("events", [])
            meta = body.get("metaData", {})
            print(f"Scanned: {meta.get('processedEvents', 0):,} events")
            return events
    print("Timed out")
    return None

# Event Types
events = run_query("#event_simpleName=* | groupBy(#event_simpleName) | sort(_count, order=desc, limit=30)", "EVENT TYPES (24h)", "24h")
if events:
    for e in events[:25]:
        name = e.get("#event_simpleName", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {name}")

# Platforms
events = run_query("event_platform=* | groupBy(event_platform)", "PLATFORMS (24h)", "24h")
if events:
    for e in events:
        platform = e.get("event_platform", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {platform}")

# Host Count
events = run_query("ComputerName=* | groupBy(ComputerName) | count()", "HOST COUNT (24h)", "24h")
if events:
    count = int(events[0].get("_count", 0))
    print(f"  Unique Hosts: {count:,}")

# Top Hosts
events = run_query("ComputerName=* | groupBy(ComputerName) | sort(_count, order=desc, limit=15)", "TOP ACTIVE HOSTS (24h)", "24h")
if events:
    for e in events[:12]:
        host = e.get("ComputerName", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {host}")

# MITRE Tactics
events = run_query("Tactic=* | groupBy(Tactic) | sort(_count, order=desc)", "MITRE TACTICS (24h)", "24h")
if events:
    for e in events:
        tactic = e.get("Tactic", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {tactic}")

# Detection Events
events = run_query("#event_simpleName=/Detection/ | groupBy(#event_simpleName) | sort(_count, order=desc)", "DETECTION EVENTS (7d)", "7d")
if events:
    for e in events[:10]:
        name = e.get("#event_simpleName", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {name}")
else:
    print("  No detection events found")

# Vendors
events = run_query("#Vendor=* | groupBy(#Vendor) | sort(_count, order=desc)", "VENDORS (24h)", "24h")
if events:
    for e in events:
        vendor = e.get("#Vendor", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {vendor}")

# Network Events
events = run_query("#event_simpleName=/Network/ | groupBy(#event_simpleName) | sort(_count, order=desc, limit=10)", "NETWORK EVENTS (6h)", "6h")
if events:
    for e in events:
        name = e.get("#event_simpleName", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {name}")

# Process Events
events = run_query("#event_simpleName=/Process/ | groupBy(#event_simpleName) | sort(_count, order=desc, limit=10)", "PROCESS EVENTS (6h)", "6h")
if events:
    for e in events:
        name = e.get("#event_simpleName", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {name}")

# Authentication Events
events = run_query("#event_simpleName=/Auth/ OR #event_simpleName=/Logon/ | groupBy(#event_simpleName) | sort(_count, order=desc)", "AUTHENTICATION EVENTS (24h)", "24h")
if events:
    for e in events[:10]:
        name = e.get("#event_simpleName", "Unknown")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {name}")

# Third Party Data
events = run_query("#Vendor!=crowdstrike | groupBy(#Vendor, @type) | sort(_count, order=desc, limit=15)", "THIRD-PARTY DATA (24h)", "24h")
if events:
    for e in events[:10]:
        vendor = e.get("#Vendor", "Unknown")
        dtype = e.get("@type", "")
        count = int(e.get("_count", 0))
        print(f"  {count:>12,}  {vendor} / {dtype}")
else:
    print("  No third-party data sources found")

print("\n" + "="*60)
print(" EXPLORATION COMPLETE")
print("="*60)
