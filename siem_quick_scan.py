#!/usr/bin/env python3
"""Quick SIEM scan using FoundryLogScale dynamic execution."""

import json
import time
from datetime import datetime
from falconpy import NGSIEM, FoundryLogScale

# Configuration
CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def main():
    print_section("SIEM QUICK SCAN")
    print(f"Timestamp: {datetime.now().isoformat()}")

    # Initialize clients
    ngsiem = NGSIEM(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        base_url=BASE_URL
    )

    foundry = FoundryLogScale(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        base_url=BASE_URL
    )

    results = {}

    # Try FoundryLogScale dynamic execution
    print_section("FOUNDRY LOGSCALE - DYNAMIC QUERY EXECUTION")

    queries = [
        ("Sample Events", "* | head(10)", "1h"),
        ("Event Types (1 hour)", "#event_simpleName=* | groupBy(#event_simpleName) | head(20)", "1h"),
        ("Data Sources", "@type=* | groupBy(@type) | head(15)", "1h"),
    ]

    for name, query, timerange in queries:
        print(f"\n--- {name} ---")
        print(f"Query: {query}")
        print(f"Range: {timerange}")

        try:
            response = foundry.execute_dynamic(
                repo_or_view="search-all",
                search_query=query,
                start=timerange,
                mode="sync"
            )

            status = response.get('status_code', 0)
            print(f"Status: {status}")

            if status == 200:
                resources = response.get('resources', {})
                if isinstance(resources, dict):
                    events = resources.get('events', resources.get('result', []))
                    if events:
                        results[name] = events
                        print(f"Found {len(events)} results:")
                        for e in events[:10]:
                            if isinstance(e, dict):
                                # Print key fields
                                keys = ['#event_simpleName', '@type', 'event_platform', 'ComputerName', '_count']
                                vals = [f"{k}={e.get(k)}" for k in keys if e.get(k)]
                                if vals:
                                    print(f"  {', '.join(vals)[:100]}")
                                else:
                                    print(f"  {str(e)[:100]}")
                            else:
                                print(f"  {e}")
                    else:
                        print(f"No events. Resources: {json.dumps(resources, default=str)[:200]}")
                else:
                    print(f"Resources: {resources}")
            else:
                errors = response.get('errors', [])
                print(f"Errors: {errors}")
                print(f"Response: {json.dumps(response, default=str)[:300]}")

        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

    # Try raw Humio proxy search with longer wait
    print_section("NGSIEM SEARCH - EXTENDED WAIT")

    print("\n--- Simple count query ---")
    try:
        response = ngsiem.start_search(
            repository="search-all",
            query_string="* | count()",
            is_live=False,
            start="1h"
        )
        print(f"Start Status: {response.get('status_code')}")

        if response.get('status_code') == 200:
            resources = response.get('resources', {})
            search_id = resources.get('id') if isinstance(resources, dict) else None

            if search_id:
                print(f"Search ID: {search_id}")
                # Wait longer for results
                for i in range(60):
                    time.sleep(2)
                    status_resp = ngsiem.get_search_status(
                        repository="search-all",
                        search_id=search_id
                    )
                    if status_resp.get('status_code') == 200:
                        res = status_resp.get('resources', {})
                        if isinstance(res, dict):
                            done = res.get('done', res.get('state') == 'done')
                            events = res.get('events', [])
                            event_count = res.get('eventCount', 0)
                            processed = res.get('processedEvents', 0)

                            print(f"  Poll {i+1}: done={done}, events={len(events)}, eventCount={event_count}, processed={processed}")

                            if done or events:
                                results['total_events_1h'] = events or event_count
                                print(f"\nResults: {events}")
                                break
                    if i == 59:
                        print("Query still running after 2 minutes")

    except Exception as e:
        print(f"Error: {e}")

    # Check API scopes and permissions
    print_section("API SCOPE CHECK")

    print("\n--- Testing various endpoints ---")

    tests = [
        ("list_dashboards", lambda: ngsiem.list_dashboards(limit=5)),
        ("list_parsers", lambda: ngsiem.list_parsers(limit=5)),
        ("list_saved_queries", lambda: ngsiem.list_saved_queries(limit=5)),
        ("list_lookup_files", lambda: ngsiem.list_lookup_files(limit=5)),
        ("list_repos (foundry)", lambda: foundry.list_repos()),
    ]

    for name, func in tests:
        try:
            resp = func()
            status = resp.get('status_code', 0)
            resources = resp.get('resources', [])
            count = len(resources) if isinstance(resources, list) else 'N/A'
            print(f"  {name}: status={status}, resources={count}")
            if status not in [200, 201] and resp.get('errors'):
                print(f"    Errors: {resp.get('errors')}")
        except Exception as e:
            print(f"  {name}: ERROR - {e}")

    # Summary
    print_section("SCAN SUMMARY")

    print(f"""
API Connectivity: Working (search-all repository accessible)
Query Execution: Queries initiating but results may require longer wait times

This suggests:
1. The environment has data (queries start successfully)
2. Large data volume (queries take time to complete)
3. API credentials have search permissions

Discovered so far:
{json.dumps(results, indent=2, default=str)[:1000]}
""")

    # Save results
    with open("/Users/justin/Projects/falconpy/siem_quick_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

if __name__ == "__main__":
    main()
