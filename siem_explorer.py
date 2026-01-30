#!/usr/bin/env python3
"""SIEM Explorer - Deep dive into CrowdStrike NG-SIEM data sources and content."""

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

def print_subsection(title):
    print(f"\n--- {title} ---")

def run_query_and_wait(ngsiem, repo, query, description, timeout=30):
    """Run a CQL query and wait for results."""
    print_subsection(description)
    print(f"Repository: {repo}")
    print(f"Query: {query[:100]}{'...' if len(query) > 100 else ''}")

    try:
        # Start the search
        response = ngsiem.start_search(
            repository=repo,
            query_string=query,
            is_live=False,
            start="7d"
        )

        status_code = response.get('status_code', 0)
        print(f"Start Response: {status_code}")

        if status_code not in [200, 201]:
            errors = response.get('errors', [])
            if errors:
                print(f"Errors: {errors}")
            return None

        # Extract search ID
        resources = response.get('resources', {})
        if isinstance(resources, dict):
            search_id = resources.get('id')
        else:
            search_id = None

        if not search_id:
            print(f"No search ID returned. Response: {json.dumps(response, default=str)[:300]}")
            return None

        print(f"Search ID: {search_id}")

        # Poll for results
        start_time = time.time()
        while time.time() - start_time < timeout:
            status_response = ngsiem.get_search_status(
                repository=repo,
                search_id=search_id
            )

            if status_response.get('status_code') != 200:
                print(f"Status check failed: {status_response.get('status_code')}")
                time.sleep(1)
                continue

            resources = status_response.get('resources', {})
            if isinstance(resources, dict):
                state = resources.get('state', resources.get('done', False))
                events = resources.get('events', [])
                metadata = resources.get('metaData', {})

                if state == 'done' or state is True or events:
                    print(f"Query complete. Found {len(events)} results.")

                    # Print event count from metadata if available
                    if metadata:
                        print(f"Metadata: {json.dumps(metadata, default=str)[:200]}")

                    return events

                print(f"  Waiting... state={state}")

            time.sleep(1)

        print(f"Query timed out after {timeout}s")
        # Try to get final results anyway
        final_response = ngsiem.get_search_status(repository=repo, search_id=search_id)
        return final_response.get('resources', {}).get('events', [])

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    print_section("SIEM DEEP EXPLORATION")
    print(f"Timestamp: {datetime.now().isoformat()}")

    # Initialize
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

    results = {
        "timestamp": datetime.now().isoformat(),
        "event_types": [],
        "data_sources": [],
        "parsers_in_use": [],
        "field_analysis": [],
        "dashboards": [],
        "parsers": [],
        "saved_queries": [],
        "lookup_files": []
    }

    # Test repositories that might work
    repos_to_try = ["search-all", "search-falcon", "search-third-party", "falcon"]
    working_repo = None

    print_section("REPOSITORY DISCOVERY")
    for repo in repos_to_try:
        print(f"\nTrying repository: {repo}")
        try:
            test = ngsiem.start_search(
                repository=repo,
                query_string="* | head(1)",
                is_live=False,
                start="1h"
            )
            if test.get('status_code') in [200, 201]:
                print(f"  ✓ Repository '{repo}' is accessible")
                working_repo = repo
            else:
                print(f"  ✗ Status: {test.get('status_code')}")
        except Exception as e:
            print(f"  ✗ Error: {e}")

    if not working_repo:
        working_repo = "search-all"
        print(f"\nUsing default repository: {working_repo}")

    # Discovery Queries
    print_section("DATA SOURCE ANALYSIS")

    queries = [
        # Falcon-specific event types
        ("Falcon Event Types (Top 30)",
         "#event_simpleName=* | groupBy(#event_simpleName) | sort(_count, order=desc, limit=30)"),

        # Event platforms
        ("Event Platforms",
         "* | groupBy(event_platform) | sort(_count, order=desc, limit=20)"),

        # Parser/source types
        ("Parsers In Use",
         "* | groupBy(@type) | sort(_count, order=desc, limit=30)"),

        # Check for third-party data
        ("Third Party Sources",
         "* | @type!=crowdstrike* | groupBy(@type) | sort(_count, order=desc, limit=20)"),

        # Timestamps and ingestion
        ("Data Ingestion Timeline (hourly)",
         "* | timechart(span=1h, function=count())"),

        # Host/device count
        ("Unique Hosts/Devices",
         "ComputerName=* | groupBy(ComputerName) | count()"),

        # User activity
        ("Active Users (by UserName field)",
         "UserName=* | groupBy(UserName) | sort(_count, order=desc, limit=20)"),

        # Network data sources
        ("Network Events",
         "#event_simpleName=/Network/ OR #event_simpleName=/Dns/ OR #event_simpleName=/Http/ | groupBy(#event_simpleName) | sort(_count, order=desc, limit=20)"),

        # Process events
        ("Process Events",
         "#event_simpleName=/Process/ | groupBy(#event_simpleName) | sort(_count, order=desc, limit=20)"),

        # Detection events
        ("Detection Events",
         "#event_simpleName=/Detection/ OR #event_simpleName=/Alert/ | groupBy(#event_simpleName) | sort(_count, order=desc, limit=20)"),

        # Authentication events
        ("Authentication Events",
         "#event_simpleName=/Auth/ OR #event_simpleName=/Login/ OR #event_simpleName=/Logon/ | groupBy(#event_simpleName) | sort(_count, order=desc, limit=20)"),

        # File events
        ("File System Events",
         "#event_simpleName=/File/ OR #event_simpleName=/Document/ | groupBy(#event_simpleName) | sort(_count, order=desc, limit=20)"),

        # Registry events (Windows)
        ("Registry Events",
         "#event_simpleName=/Registry/ | groupBy(#event_simpleName) | sort(_count, order=desc)"),

        # Volume of data by day
        ("Daily Data Volume",
         "* | timechart(span=1d, function=count())"),
    ]

    for desc, query in queries:
        events = run_query_and_wait(ngsiem, working_repo, query, desc, timeout=20)
        if events:
            results["data_sources"].append({
                "description": desc,
                "query": query,
                "results": events[:50]  # Limit stored results
            })
            # Print results
            for event in events[:15]:
                if isinstance(event, dict):
                    # Format output nicely
                    items = [f"{k}={v}" for k, v in event.items() if v and k != '_count']
                    count = event.get('_count', '')
                    print(f"  {count:>10}  {', '.join(items)[:60]}")
                else:
                    print(f"  {event}")
            if len(events) > 15:
                print(f"  ... and {len(events) - 15} more rows")

    # List NGSIEM Content
    print_section("NGSIEM CONTENT INVENTORY")

    # Dashboards
    print_subsection("Custom Dashboards")
    try:
        for domain in ["all", "third-party"]:
            resp = ngsiem.list_dashboards(limit=100, search_domain=domain)
            if resp.get('status_code') == 200:
                dashboards = resp.get('resources', [])
                if dashboards:
                    print(f"Domain '{domain}': {len(dashboards)} dashboards")
                    results["dashboards"].extend(dashboards)
                    for d in dashboards:
                        if isinstance(d, dict):
                            print(f"  - {d.get('name', 'Unknown')} (id: {d.get('id', 'N/A')[:20]}...)")
    except Exception as e:
        print(f"Error listing dashboards: {e}")

    # Parsers
    print_subsection("Custom Parsers")
    try:
        resp = ngsiem.list_parsers(limit=100, repository="parsers-repository")
        if resp.get('status_code') == 200:
            parsers = resp.get('resources', [])
            results["parsers"] = parsers
            if parsers:
                print(f"Found {len(parsers)} parsers")
                for p in parsers:
                    if isinstance(p, dict):
                        print(f"  - {p.get('name', 'Unknown')}")
            else:
                print("No custom parsers found")
    except Exception as e:
        print(f"Error listing parsers: {e}")

    # Saved Queries
    print_subsection("Saved Queries")
    try:
        for domain in ["all", "third-party"]:
            resp = ngsiem.list_saved_queries(limit=100, search_domain=domain)
            if resp.get('status_code') == 200:
                queries_list = resp.get('resources', [])
                if queries_list:
                    print(f"Domain '{domain}': {len(queries_list)} saved queries")
                    results["saved_queries"].extend(queries_list)
                    for q in queries_list:
                        if isinstance(q, dict):
                            print(f"  - {q.get('name', 'Unknown')}")
    except Exception as e:
        print(f"Error listing saved queries: {e}")

    # Lookup Files
    print_subsection("Lookup Files")
    try:
        for domain in ["all", "third-party"]:
            resp = ngsiem.list_lookup_files(limit=100, search_domain=domain)
            if resp.get('status_code') == 200:
                lookups = resp.get('resources', [])
                if lookups:
                    print(f"Domain '{domain}': {len(lookups)} lookup files")
                    results["lookup_files"].extend(lookups)
                    for lf in lookups:
                        if isinstance(lf, dict):
                            print(f"  - {lf.get('filename', lf.get('name', 'Unknown'))}")
    except Exception as e:
        print(f"Error listing lookup files: {e}")

    # Additional Falcon-Specific Queries
    print_section("FALCON SENSOR DATA ANALYSIS")

    falcon_queries = [
        ("Sensor Versions",
         "ConfigBuild=* | groupBy(ConfigBuild) | sort(_count, order=desc, limit=10)"),

        ("Operating Systems",
         "OS=* | groupBy(OS) | sort(_count, order=desc, limit=10)"),

        ("Agent IDs (Sample)",
         "aid=* | groupBy(aid) | count() | head(1)"),
    ]

    for desc, query in falcon_queries:
        events = run_query_and_wait(ngsiem, working_repo, query, desc, timeout=15)
        if events:
            for event in events[:10]:
                if isinstance(event, dict):
                    items = [f"{k}={v}" for k, v in event.items()]
                    print(f"  {', '.join(items)[:80]}")

    # Summary
    print_section("ENVIRONMENT SUMMARY")

    print(f"""
Based on the discovery:

Content Inventory:
  - Dashboards: {len(results['dashboards'])}
  - Parsers: {len(results['parsers'])}
  - Saved Queries: {len(results['saved_queries'])}
  - Lookup Files: {len(results['lookup_files'])}

Data Sources Analyzed: {len(results['data_sources'])} queries executed
""")

    # Save full results
    output_file = "/Users/justin/Projects/falconpy/siem_exploration_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[*] Full results saved to: {output_file}")

if __name__ == "__main__":
    main()
