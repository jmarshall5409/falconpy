#!/usr/bin/env python3
"""SIEM Environment Discovery Tool - Explore CrowdStrike NG-SIEM/LogScale environment."""

import json
from datetime import datetime
from falconpy import NGSIEM, FoundryLogScale

# Configuration
CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

def print_section(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")

def print_subsection(title):
    print(f"\n--- {title} ---")

def safe_get(response, key="resources", default=None):
    """Safely extract data from API response."""
    if default is None:
        default = []
    if isinstance(response, dict):
        return response.get(key, default)
    return default

def main():
    print_section("SIEM ENVIRONMENT DISCOVERY")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Region: us-1")

    # Initialize clients
    print("\n[*] Initializing API clients...")

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
        "repositories": [],
        "dashboards": [],
        "parsers": [],
        "saved_queries": [],
        "lookup_files": []
    }

    # 1. List Repositories/Views
    print_section("REPOSITORIES & VIEWS")
    try:
        repos_response = foundry.list_repos()
        print(f"API Response Status: {repos_response.get('status_code', 'N/A')}")
        repos = safe_get(repos_response)
        results["repositories"] = repos
        if repos:
            for repo in repos:
                if isinstance(repo, dict):
                    print(f"  - {repo.get('name', 'Unknown')} (type: {repo.get('type', 'N/A')})")
                else:
                    print(f"  - {repo}")
        else:
            print("  No repositories found or access denied")
            print(f"  Response: {json.dumps(repos_response, indent=2, default=str)[:500]}")
    except Exception as e:
        print(f"  Error: {e}")

    # 2. List Views
    print_subsection("Views")
    try:
        views_response = foundry.list_views()
        print(f"API Response Status: {views_response.get('status_code', 'N/A')}")
        views = safe_get(views_response)
        if views:
            for view in views:
                if isinstance(view, dict):
                    print(f"  - {view.get('name', 'Unknown')}")
                else:
                    print(f"  - {view}")
        else:
            print("  No views found")
    except Exception as e:
        print(f"  Error: {e}")

    # 3. List Dashboards
    print_section("DASHBOARDS")
    for search_domain in ["all", "falcon", "third-party"]:
        print_subsection(f"Domain: {search_domain}")
        try:
            dash_response = ngsiem.list_dashboards(limit=100, search_domain=search_domain)
            print(f"API Response Status: {dash_response.get('status_code', 'N/A')}")
            dashboards = safe_get(dash_response)
            if dashboards:
                results["dashboards"].extend(dashboards)
                for dash in dashboards[:20]:  # Limit output
                    if isinstance(dash, dict):
                        print(f"  - {dash.get('name', 'Unknown')} (id: {dash.get('id', 'N/A')[:16]}...)")
                    else:
                        print(f"  - {dash}")
                if len(dashboards) > 20:
                    print(f"  ... and {len(dashboards) - 20} more")
            else:
                print("  No dashboards found in this domain")
        except Exception as e:
            print(f"  Error: {e}")

    # 4. List Parsers
    print_section("PARSERS")
    try:
        parser_response = ngsiem.list_parsers(limit=100, repository="parsers-repository")
        print(f"API Response Status: {parser_response.get('status_code', 'N/A')}")
        parsers = safe_get(parser_response)
        results["parsers"] = parsers
        if parsers:
            for parser in parsers[:30]:
                if isinstance(parser, dict):
                    print(f"  - {parser.get('name', 'Unknown')}")
                else:
                    print(f"  - {parser}")
            if len(parsers) > 30:
                print(f"  ... and {len(parsers) - 30} more")
        else:
            print("  No parsers found")
            print(f"  Response: {json.dumps(parser_response, indent=2, default=str)[:500]}")
    except Exception as e:
        print(f"  Error: {e}")

    # 5. List Saved Queries
    print_section("SAVED QUERIES")
    for search_domain in ["all", "falcon", "third-party"]:
        print_subsection(f"Domain: {search_domain}")
        try:
            query_response = ngsiem.list_saved_queries(limit=100, search_domain=search_domain)
            print(f"API Response Status: {query_response.get('status_code', 'N/A')}")
            queries = safe_get(query_response)
            if queries:
                results["saved_queries"].extend(queries)
                for query in queries[:15]:
                    if isinstance(query, dict):
                        print(f"  - {query.get('name', 'Unknown')}")
                    else:
                        print(f"  - {query}")
                if len(queries) > 15:
                    print(f"  ... and {len(queries) - 15} more")
            else:
                print("  No saved queries found in this domain")
        except Exception as e:
            print(f"  Error: {e}")

    # 6. List Lookup Files
    print_section("LOOKUP FILES")
    for search_domain in ["all", "falcon", "third-party"]:
        print_subsection(f"Domain: {search_domain}")
        try:
            lookup_response = ngsiem.list_lookup_files(limit=100, search_domain=search_domain)
            print(f"API Response Status: {lookup_response.get('status_code', 'N/A')}")
            lookups = safe_get(lookup_response)
            if lookups:
                results["lookup_files"].extend(lookups)
                for lookup in lookups[:15]:
                    if isinstance(lookup, dict):
                        print(f"  - {lookup.get('name', lookup.get('filename', 'Unknown'))}")
                    else:
                        print(f"  - {lookup}")
                if len(lookups) > 15:
                    print(f"  ... and {len(lookups) - 15} more")
            else:
                print("  No lookup files found in this domain")
        except Exception as e:
            print(f"  Error: {e}")

    # 7. Run Discovery Queries
    print_section("DATA SOURCE DISCOVERY")

    discovery_queries = [
        ("Event Types", "#event_simpleName=* | groupBy(#event_simpleName) | sort(_count, order=desc) | head(25)"),
        ("Data Sources", "* | groupBy(@rawstring.source, function=count()) | sort(_count, order=desc) | head(20)"),
        ("Log Sources by Vendor", "* | groupBy(@vendor) | sort(_count, order=desc) | head(20)"),
    ]

    for query_name, cql_query in discovery_queries:
        print_subsection(f"Query: {query_name}")
        print(f"CQL: {cql_query[:80]}...")
        try:
            search_response = ngsiem.start_search(
                repository="search-all",
                query_string=cql_query,
                is_live=False,
                start="7d"
            )
            print(f"API Response Status: {search_response.get('status_code', 'N/A')}")
            if search_response.get('status_code') in [200, 201]:
                search_id = safe_get(search_response).get('id') if isinstance(safe_get(search_response), dict) else None
                if search_id:
                    print(f"  Search initiated: {search_id}")
                    # Get results
                    status_response = ngsiem.get_search_status(repository="search-all", search_id=search_id)
                    print(f"  Status: {status_response.get('status_code', 'N/A')}")
                    if status_response.get('status_code') == 200:
                        res = safe_get(status_response)
                        if isinstance(res, dict):
                            events = res.get('events', [])
                            if events:
                                print(f"  Results ({len(events)} rows):")
                                for event in events[:10]:
                                    print(f"    {event}")
            else:
                print(f"  Response: {json.dumps(search_response, indent=2, default=str)[:300]}")
        except Exception as e:
            print(f"  Error: {e}")

    # Summary
    print_section("DISCOVERY SUMMARY")
    print(f"  Repositories/Views: {len(results['repositories'])}")
    print(f"  Dashboards: {len(results['dashboards'])}")
    print(f"  Parsers: {len(results['parsers'])}")
    print(f"  Saved Queries: {len(results['saved_queries'])}")
    print(f"  Lookup Files: {len(results['lookup_files'])}")

    # Save results to JSON
    output_file = "/Users/justin/Projects/falconpy/siem_discovery_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[*] Full results saved to: {output_file}")

if __name__ == "__main__":
    main()
