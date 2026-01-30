#!/usr/bin/env python3
"""Test raw API responses to understand the actual data structure."""

import json
import time
import requests
from datetime import datetime
from falconpy import OAuth2, NGSIEM

CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def main():
    print_section("RAW API INVESTIGATION")
    print(f"Timestamp: {datetime.now().isoformat()}")

    # Get OAuth token
    print("\n[*] Getting OAuth token...")
    auth = OAuth2(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
    token_resp = auth.token()

    if token_resp.get('status_code') != 201:
        print(f"Failed to get token: {token_resp}")
        return

    token = token_resp.get('body', {}).get('access_token')
    print(f"Token acquired: {token[:20]}...")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Test 1: Start search via raw HTTP
    print_section("TEST 1: Raw HTTP Start Search")

    search_payload = {
        "repository": "search-all",
        "search": {
            "queryString": "* | head(10)",
            "start": "1h",
            "isLive": False
        }
    }

    resp = requests.post(
        f"{BASE_URL}/humio/api/v1/repositories/search-all/queryjobs",
        headers=headers,
        json=search_payload.get("search")
    )

    print(f"Status: {resp.status_code}")
    print(f"Headers: {dict(resp.headers)}")
    print(f"Body: {resp.text[:1000]}")

    try:
        body = resp.json()
        print(f"\nParsed JSON keys: {list(body.keys()) if isinstance(body, dict) else 'not a dict'}")
        search_id = body.get('id')
        print(f"Search ID: {search_id}")
    except:
        print("Failed to parse JSON")
        search_id = None

    # Test 2: Poll for results via raw HTTP
    if search_id:
        print_section("TEST 2: Raw HTTP Poll Results")

        for i in range(10):
            time.sleep(2)
            poll_resp = requests.get(
                f"{BASE_URL}/humio/api/v1/repositories/search-all/queryjobs/{search_id}",
                headers=headers
            )

            print(f"\n--- Poll {i+1} ---")
            print(f"Status: {poll_resp.status_code}")
            print(f"Body length: {len(poll_resp.text)}")
            print(f"Body preview: {poll_resp.text[:2000]}")

            try:
                poll_body = poll_resp.json()
                print(f"Keys: {list(poll_body.keys()) if isinstance(poll_body, dict) else poll_body}")

                if isinstance(poll_body, dict):
                    done = poll_body.get('done', False)
                    events = poll_body.get('events', [])
                    print(f"Done: {done}, Events: {len(events)}")

                    if done or events:
                        print(f"\n✓ Results received!")
                        for e in events[:5]:
                            print(f"  {json.dumps(e, default=str)[:200]}")
                        break
            except Exception as e:
                print(f"Parse error: {e}")

    # Test 3: Try the FalconPy internal method with expand_result
    print_section("TEST 3: FalconPy with expand_result")

    ngsiem = NGSIEM(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)

    # Start search
    start_resp = ngsiem.start_search(
        repository="search-all",
        query_string="* | head(5)",
        is_live=False,
        start="1h"
    )

    print(f"Start response: {json.dumps(start_resp, default=str)[:500]}")

    resources = start_resp.get('resources', {})
    search_id = resources.get('id') if isinstance(resources, dict) else None

    if search_id:
        print(f"\nSearch ID: {search_id}")

        # Try getting status with expand_result
        for i in range(5):
            time.sleep(3)

            # Direct call to underlying method
            status_resp = ngsiem.get_search_status(
                repository="search-all",
                search_id=search_id
            )

            print(f"\nPoll {i+1}:")
            print(f"Full response: {json.dumps(status_resp, default=str)[:1500]}")

    # Test 4: Check the body field
    print_section("TEST 4: Check 'body' field in responses")

    start_resp = ngsiem.start_search(
        repository="search-all",
        query_string="* | head(3)",
        is_live=False,
        start="30m"
    )

    print(f"Response keys: {list(start_resp.keys())}")
    if 'body' in start_resp:
        print(f"Body: {start_resp['body']}")

    resources = start_resp.get('resources', {})
    search_id = resources.get('id') if isinstance(resources, dict) else None

    if search_id:
        time.sleep(5)
        status_resp = ngsiem.get_search_status(
            repository="search-all",
            search_id=search_id
        )
        print(f"\nStatus response keys: {list(status_resp.keys())}")
        if 'body' in status_resp:
            print(f"Body: {status_resp['body'][:2000] if isinstance(status_resp['body'], str) else status_resp['body']}")

    # Test 5: Different endpoint format
    print_section("TEST 5: Alternative Endpoints")

    # Try the /queryjobs/{id}/events endpoint
    if search_id:
        events_resp = requests.get(
            f"{BASE_URL}/humio/api/v1/repositories/search-all/queryjobs/{search_id}/events",
            headers=headers
        )
        print(f"Events endpoint status: {events_resp.status_code}")
        print(f"Events body: {events_resp.text[:1000]}")

if __name__ == "__main__":
    main()
