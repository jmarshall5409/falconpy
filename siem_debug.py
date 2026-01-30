#!/usr/bin/env python3
"""Debug SIEM API access and understand available capabilities."""

import json
from datetime import datetime
from falconpy import (
    NGSIEM, FoundryLogScale, Hosts, Detects, Incidents,
    SensorDownload, DeviceControlPolicies, OAuth2
)

# Configuration
CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def test_api(name, func):
    """Test an API call and report results."""
    try:
        resp = func()
        status = resp.get('status_code', 0)
        errors = resp.get('errors', [])
        resources = resp.get('resources', [])

        if status in [200, 201]:
            count = len(resources) if isinstance(resources, list) else ('dict' if isinstance(resources, dict) else 'N/A')
            print(f"  ✓ {name}: status={status}, resources={count}")
            if resources and isinstance(resources, list) and len(resources) > 0:
                print(f"    Sample: {str(resources[0])[:100]}")
            elif resources and isinstance(resources, dict):
                print(f"    Keys: {list(resources.keys())[:10]}")
            return True, resources
        else:
            print(f"  ✗ {name}: status={status}")
            if errors:
                for e in errors[:2]:
                    print(f"    Error: {e}")
            return False, None
    except Exception as e:
        print(f"  ✗ {name}: EXCEPTION - {e}")
        return False, None

def main():
    print_section("API CAPABILITIES DISCOVERY")
    print(f"Timestamp: {datetime.now().isoformat()}")

    # Check OAuth token and scopes
    print_section("OAUTH TOKEN INFO")
    try:
        auth = OAuth2(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            base_url=BASE_URL
        )
        token_resp = auth.token()
        print(f"Token Status: {token_resp.get('status_code')}")
        if token_resp.get('status_code') == 201:
            body = token_resp.get('body', {})
            print(f"Token Type: {body.get('token_type')}")
            print(f"Expires In: {body.get('expires_in')} seconds")
            # Note: scopes aren't returned in token response but we can infer from API access
    except Exception as e:
        print(f"Token Error: {e}")

    # Test Core Falcon APIs
    print_section("CORE FALCON APIS")

    # Hosts API
    print("\n--- Hosts API ---")
    try:
        hosts = Hosts(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        test_api("query_devices", lambda: hosts.query_devices(limit=5))
        test_api("query_devices_by_filter", lambda: hosts.query_devices_by_filter(limit=5))
    except Exception as e:
        print(f"Hosts API Error: {e}")

    # Detects API
    print("\n--- Detects API ---")
    try:
        detects = Detects(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        test_api("query_detects", lambda: detects.query_detects(limit=5))
    except Exception as e:
        print(f"Detects API Error: {e}")

    # Incidents API
    print("\n--- Incidents API ---")
    try:
        incidents = Incidents(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        test_api("query_incidents", lambda: incidents.query_incidents(limit=5))
    except Exception as e:
        print(f"Incidents API Error: {e}")

    # Test NGSIEM APIs with full response inspection
    print_section("NGSIEM API DETAILED TEST")

    ngsiem = NGSIEM(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)

    # Test search with full response
    print("\n--- Raw Search Response ---")
    try:
        resp = ngsiem.start_search(
            repository="search-all",
            query_string="* | head(5)",
            is_live=False,
            start="10m"
        )
        print(f"Full Response Keys: {list(resp.keys())}")
        print(f"Status Code: {resp.get('status_code')}")
        print(f"Headers (sample): X-Cs-Region={resp.get('headers', {}).get('X-Cs-Region')}")

        resources = resp.get('resources', {})
        print(f"Resources Type: {type(resources)}")
        if isinstance(resources, dict):
            print(f"Resources Keys: {list(resources.keys())}")
            for k, v in resources.items():
                print(f"  {k}: {type(v).__name__} = {str(v)[:100]}")

        # If we got a search ID, fetch status with full detail
        if isinstance(resources, dict) and resources.get('id'):
            search_id = resources['id']
            print(f"\n--- Polling search {search_id} ---")

            import time
            for i in range(5):
                time.sleep(3)
                status_resp = ngsiem.get_search_status(repository="search-all", search_id=search_id)
                print(f"\nPoll {i+1}:")
                print(f"  Status Code: {status_resp.get('status_code')}")
                status_resources = status_resp.get('resources', {})
                if isinstance(status_resources, dict):
                    for k, v in status_resources.items():
                        val_str = str(v)[:150] if v else 'None'
                        print(f"  {k}: {val_str}")

    except Exception as e:
        print(f"Search Error: {e}")
        import traceback
        traceback.print_exc()

    # Test content management APIs with search_domain parameter
    print_section("CONTENT MANAGEMENT APIS")

    content_tests = [
        ("list_dashboards (falcon)", lambda: ngsiem.list_dashboards(search_domain="falcon")),
        ("list_dashboards (all)", lambda: ngsiem.list_dashboards(search_domain="all")),
        ("list_parsers", lambda: ngsiem.list_parsers(repository="parsers-repository")),
        ("list_saved_queries (all)", lambda: ngsiem.list_saved_queries(search_domain="all")),
        ("list_lookup_files (all)", lambda: ngsiem.list_lookup_files(search_domain="all")),
    ]

    for name, func in content_tests:
        success, resources = test_api(name, func)

    # Check FoundryLogScale
    print_section("FOUNDRY LOGSCALE APIS")

    foundry = FoundryLogScale(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)

    foundry_tests = [
        ("list_repos", lambda: foundry.list_repos()),
        ("list_views", lambda: foundry.list_views()),
    ]

    for name, func in foundry_tests:
        success, resources = test_api(name, func)

    # Summary of available capabilities
    print_section("SUMMARY")
    print("""
Based on API testing:

1. NGSIEM Search API: Can START searches (200), but results not returning
   - This may indicate: empty environment, permissions issue on results, or
     the search-all repository may not have data indexed yet

2. FoundryLogScale APIs: 403 Forbidden
   - API key does not have Foundry LogScale read/write permissions

3. Content Management APIs (dashboards, parsers, queries, lookups):
   - Likely 400 errors indicate missing required parameters or no content exists

4. Core Falcon APIs (Hosts, Detects, Incidents):
   - Testing these will show if this is an NG-SIEM only key or full platform key
""")

if __name__ == "__main__":
    main()
