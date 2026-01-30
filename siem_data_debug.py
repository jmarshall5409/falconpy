#!/usr/bin/env python3
"""Debug why SIEM queries aren't returning data."""

import json
import time
from datetime import datetime
from falconpy import NGSIEM

CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def dump_response(name, resp):
    """Print full response structure."""
    print(f"\n--- {name} ---")
    print(f"Type: {type(resp)}")
    if isinstance(resp, dict):
        print(f"Keys: {list(resp.keys())}")
        for k, v in resp.items():
            if k == 'headers':
                print(f"  {k}: (headers dict, {len(v)} items)")
            else:
                v_str = json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v)
                print(f"  {k}: {v_str[:500]}")
    else:
        print(f"Value: {resp}")

def main():
    print_section("SIEM DATA DEBUG")
    print(f"Timestamp: {datetime.now().isoformat()}")

    ngsiem = NGSIEM(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        base_url=BASE_URL
    )

    # Test 1: Simple query with full response inspection
    print_section("TEST 1: Simple Query - Full Response")

    resp = ngsiem.start_search(
        repository="search-all",
        query_string="*",
        is_live=False,
        start="5m"
    )
    dump_response("start_search response", resp)

    if resp.get('status_code') == 200:
        resources = resp.get('resources', {})
        search_id = resources.get('id') if isinstance(resources, dict) else None

        if search_id:
            print(f"\nSearch ID: {search_id}")
            print("\nPolling for results...")

            for i in range(30):
                time.sleep(2)
                status_resp = ngsiem.get_search_status(
                    repository="search-all",
                    search_id=search_id
                )

                print(f"\n--- Poll {i+1} ---")
                print(f"Status code: {status_resp.get('status_code')}")

                # Print FULL resources
                resources = status_resp.get('resources')
                print(f"Resources type: {type(resources)}")
                print(f"Resources: {json.dumps(resources, default=str)[:2000]}")

                if isinstance(resources, dict):
                    # Check all possible result keys
                    for key in ['events', 'result', 'data', 'rows', 'messages', 'done', 'state',
                                'processedEvents', 'eventCount', 'matchedEvents', 'scannedEvents']:
                        val = resources.get(key)
                        if val is not None:
                            print(f"  {key}: {str(val)[:200]}")

                    # Check if done
                    done = resources.get('done', False)
                    events = resources.get('events', [])

                    if done or (events and len(events) > 0):
                        print(f"\n✓ Query complete!")
                        print(f"Events found: {len(events)}")
                        for e in events[:5]:
                            print(f"  Event: {json.dumps(e, default=str)[:200]}")
                        break

    # Test 2: Try different query syntaxes
    print_section("TEST 2: Different Query Syntaxes")

    queries = [
        ("Wildcard", "*"),
        ("Head 5", "* | head(5)"),
        ("Count", "* | count()"),
        ("Event simple name exists", "#event_simpleName=*"),
        ("Type exists", "@type=*"),
        ("True filter", "true"),
    ]

    for name, query in queries:
        print(f"\n--- {name}: {query} ---")
        resp = ngsiem.start_search(
            repository="search-all",
            query_string=query,
            is_live=False,
            start="1m"
        )
        print(f"Status: {resp.get('status_code')}")
        if resp.get('status_code') != 200:
            errors = resp.get('errors', [])
            print(f"Errors: {errors}")

    # Test 3: Try different time ranges
    print_section("TEST 3: Different Time Ranges")

    time_ranges = ["1m", "5m", "15m", "1h", "24h", "7d"]

    for tr in time_ranges:
        resp = ngsiem.start_search(
            repository="search-all",
            query_string="* | head(1)",
            is_live=False,
            start=tr
        )
        print(f"Time range {tr}: status={resp.get('status_code')}")

    # Test 4: Check what the raw API returns
    print_section("TEST 4: Raw HTTP Details")

    # Check if there's additional info in meta or body
    resp = ngsiem.start_search(
        repository="search-all",
        query_string="* | head(1)",
        is_live=False,
        start="1h"
    )

    print("Full response structure:")
    for k in resp.keys():
        print(f"  {k}: {type(resp[k])}")
        if k not in ['headers']:
            print(f"    Value: {json.dumps(resp[k], default=str)[:300]}")

    # Test 5: Try using the search dict parameter instead
    print_section("TEST 5: Using search dict parameter")

    search_params = {
        "queryString": "*",
        "start": "1h",
        "isLive": False
    }

    resp = ngsiem.start_search(
        repository="search-all",
        search=search_params
    )
    dump_response("search with dict", resp)

    # Test 6: Live search
    print_section("TEST 6: Live Search Test")

    resp = ngsiem.start_search(
        repository="search-all",
        query_string="*",
        is_live=True
    )
    dump_response("live search", resp)

    if resp.get('status_code') == 200:
        resources = resp.get('resources', {})
        search_id = resources.get('id') if isinstance(resources, dict) else None
        if search_id:
            # Poll live search
            for i in range(5):
                time.sleep(3)
                status_resp = ngsiem.get_search_status(
                    repository="search-all",
                    search_id=search_id
                )
                print(f"\nLive poll {i+1}:")
                res = status_resp.get('resources', {})
                if isinstance(res, dict):
                    events = res.get('events', [])
                    print(f"  Events: {len(events)}")
                    if events:
                        for e in events[:3]:
                            print(f"    {json.dumps(e, default=str)[:150]}")

            # Stop the live search
            ngsiem.stop_search(repository="search-all", search_id=search_id)

if __name__ == "__main__":
    main()
