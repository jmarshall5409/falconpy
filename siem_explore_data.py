#!/usr/bin/env python3
"""Explore SIEM data - now that we know the correct response structure."""

import json
import time
from datetime import datetime
from collections import Counter
from falconpy import NGSIEM

CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def run_query(ngsiem, query, description, time_range="1h", max_wait=60):
    """Run a query and properly extract results from body field."""
    print(f"\n--- {description} ---")
    print(f"Query: {query[:80]}{'...' if len(query) > 80 else ''}")

    resp = ngsiem.start_search(
        repository="search-all",
        query_string=query,
        is_live=False,
        start=time_range
    )

    if resp.get('status_code') != 200:
        print(f"Start failed: {resp.get('status_code')}")
        return None

    resources = resp.get('resources', {})
    search_id = resources.get('id') if isinstance(resources, dict) else None

    if not search_id:
        print("No search ID")
        return None

    # Poll for results - check BODY field
    for i in range(max_wait // 2):
        time.sleep(2)
        status_resp = ngsiem.get_search_status(
            repository="search-all",
            search_id=search_id
        )

        # Results are in BODY, not resources!
        body = status_resp.get('body', {})
        if not body:
            continue

        done = body.get('done', False)
        events = body.get('events', [])
        metadata = body.get('metaData', {})

        if done or events:
            processed = metadata.get('processedEvents', 0)
            print(f"✓ Complete: {len(events)} results (scanned {processed:,} events)")
            return events

    print("Query timed out")
    return None

def main():
    print_section("SIEM DATA EXPLORATION")
    print(f"Timestamp: {datetime.now().isoformat()}")

    ngsiem = NGSIEM(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        base_url=BASE_URL
    )

    results = {}

    # 1. Event Types Distribution
    print_section("EVENT TYPE DISTRIBUTION")

    events = run_query(
        ngsiem,
        "#event_simpleName=* | groupBy(#event_simpleName) | sort(_count, order=desc, limit=50)",
        "Top 50 Event Types",
        time_range="24h"
    )

    if events:
        results['event_types'] = events
        print("\nTop Event Types:")
        for e in events[:25]:
            name = e.get('#event_simpleName', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {name}")

    # 2. Data Sources
    print_section("DATA SOURCES")

    events = run_query(
        ngsiem,
        "* | groupBy(@type) | sort(_count, order=desc, limit=30)",
        "Data Source Types",
        time_range="24h"
    )

    if events:
        results['data_sources'] = events
        print("\nData Sources:")
        for e in events[:20]:
            dtype = e.get('@type', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {dtype}")

    # 3. Platforms
    print_section("PLATFORMS")

    events = run_query(
        ngsiem,
        "event_platform=* | groupBy(event_platform) | sort(_count, order=desc)",
        "Event Platforms",
        time_range="24h"
    )

    if events:
        results['platforms'] = events
        print("\nPlatforms:")
        for e in events:
            platform = e.get('event_platform', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {platform}")

    # 4. Hosts/Endpoints
    print_section("HOSTS & ENDPOINTS")

    events = run_query(
        ngsiem,
        "ComputerName=* | groupBy(ComputerName) | count()",
        "Unique Host Count",
        time_range="24h"
    )

    if events:
        # Get host count from aggregation
        total_hosts = events[0].get('_count', 0) if events else 0
        results['total_hosts'] = total_hosts
        print(f"\nTotal Unique Hosts: {total_hosts:,}")

    # Sample hosts
    events = run_query(
        ngsiem,
        "ComputerName=* | groupBy(ComputerName) | sort(_count, order=desc, limit=20)",
        "Most Active Hosts",
        time_range="24h"
    )

    if events:
        results['top_hosts'] = events
        print("\nMost Active Hosts:")
        for e in events[:15]:
            host = e.get('ComputerName', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {host}")

    # 5. Network Events
    print_section("NETWORK ACTIVITY")

    events = run_query(
        ngsiem,
        "#event_simpleName=/Network/ | groupBy(#event_simpleName) | sort(_count, order=desc)",
        "Network Event Types",
        time_range="6h"
    )

    if events:
        results['network_events'] = events
        print("\nNetwork Events:")
        for e in events[:10]:
            name = e.get('#event_simpleName', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {name}")

    # 6. Process Events
    print_section("PROCESS ACTIVITY")

    events = run_query(
        ngsiem,
        "#event_simpleName=/Process/ | groupBy(#event_simpleName) | sort(_count, order=desc)",
        "Process Event Types",
        time_range="6h"
    )

    if events:
        results['process_events'] = events
        print("\nProcess Events:")
        for e in events[:10]:
            name = e.get('#event_simpleName', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {name}")

    # 7. Detection/Alert Events
    print_section("DETECTIONS & ALERTS")

    events = run_query(
        ngsiem,
        "#event_simpleName=/Detection/ OR #event_simpleName=/Alert/ | groupBy(#event_simpleName) | sort(_count, order=desc)",
        "Detection Event Types",
        time_range="7d"
    )

    if events:
        results['detection_events'] = events
        print("\nDetection Events:")
        for e in events[:10]:
            name = e.get('#event_simpleName', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {name}")

    # 8. MITRE ATT&CK Coverage
    print_section("MITRE ATT&CK COVERAGE")

    events = run_query(
        ngsiem,
        "Tactic=* | groupBy(Tactic) | sort(_count, order=desc)",
        "Tactics Observed",
        time_range="24h"
    )

    if events:
        results['mitre_tactics'] = events
        print("\nMITRE Tactics:")
        for e in events:
            tactic = e.get('Tactic', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {tactic}")

    events = run_query(
        ngsiem,
        "TechniqueId=* | groupBy(TechniqueId, function=[collect(Technique)]) | sort(_count, order=desc, limit=20)",
        "Top Techniques",
        time_range="24h"
    )

    if events:
        results['mitre_techniques'] = events
        print("\nTop MITRE Techniques:")
        for e in events[:15]:
            tech_id = e.get('TechniqueId', 'Unknown')
            tech_name = e.get('Technique', ['Unknown'])[0] if isinstance(e.get('Technique'), list) else e.get('Technique', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {tech_id} - {tech_name}")

    # 9. Third-Party Sources
    print_section("THIRD-PARTY DATA SOURCES")

    events = run_query(
        ngsiem,
        "@type!=falcon* AND @type!=crowdstrike* | groupBy(@type) | sort(_count, order=desc, limit=20)",
        "Non-CrowdStrike Sources",
        time_range="24h"
    )

    if events:
        results['third_party'] = events
        print("\nThird-Party Sources:")
        for e in events[:15]:
            dtype = e.get('@type', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {dtype}")

    # 10. Vendors
    print_section("VENDORS")

    events = run_query(
        ngsiem,
        "#Vendor=* | groupBy(#Vendor) | sort(_count, order=desc)",
        "Data by Vendor",
        time_range="24h"
    )

    if events:
        results['vendors'] = events
        print("\nVendors:")
        for e in events:
            vendor = e.get('#Vendor', 'Unknown')
            count = e.get('_count', 0)
            print(f"  {count:>12,}  {vendor}")

    # 11. Data Volume
    print_section("DATA VOLUME")

    events = run_query(
        ngsiem,
        "* | timechart(span=1h, function=count())",
        "Hourly Event Volume (24h)",
        time_range="24h"
    )

    if events:
        results['hourly_volume'] = events
        total_24h = sum(e.get('_count', 0) for e in events)
        avg_hourly = total_24h // len(events) if events else 0
        print(f"\nTotal events (24h): {total_24h:,}")
        print(f"Average per hour: {avg_hourly:,}")

    # Summary
    print_section("ENVIRONMENT SUMMARY")

    print(f"""
┌─────────────────────────────────────────────────────────────────────┐
│                    SIEM ENVIRONMENT OVERVIEW                         │
├─────────────────────────────────────────────────────────────────────┤
│  Total Unique Hosts:      {results.get('total_hosts', 'N/A'):>10}                          │
│  Event Types:             {len(results.get('event_types', [])):>10}                          │
│  Data Sources:            {len(results.get('data_sources', [])):>10}                          │
│  Platforms:               {len(results.get('platforms', [])):>10}                          │
│  MITRE Tactics:           {len(results.get('mitre_tactics', [])):>10}                          │
│  MITRE Techniques:        {len(results.get('mitre_techniques', [])):>10}                          │
└─────────────────────────────────────────────────────────────────────┘
""")

    # Save results
    output_file = "/Users/justin/Projects/falconpy/siem_data_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[*] Full results saved to: {output_file}")

if __name__ == "__main__":
    main()
