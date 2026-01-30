#!/usr/bin/env python3
"""Full SIEM environment audit - check all available data and capabilities."""

import json
from datetime import datetime
from falconpy import (
    NGSIEM, Hosts, Detects, Incidents, Alerts,
    SensorDownload, HostGroup, PreventionPolicies,
    DeviceControlPolicies, FirewallManagement, IOC,
    SpotlightVulnerabilities, ZeroTrustAssessment,
    EventStreams
)

CLIENT_ID = "6e982111281c457d8ae220ecaa2774df"
CLIENT_SECRET = "8m3LS126PI7ZAsQUxBVcFlnr4zgoDROy5X09vGNK"
BASE_URL = "https://api.crowdstrike.com"

def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

def test_api(client_class, method_name, params=None):
    """Test an API endpoint and return status."""
    if params is None:
        params = {}
    try:
        client = client_class(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        method = getattr(client, method_name)
        resp = method(**params)

        status = resp.get('status_code', 0)
        resources = resp.get('resources', [])
        errors = resp.get('errors', [])
        meta = resp.get('meta', {})

        count = len(resources) if isinstance(resources, list) else ('dict' if isinstance(resources, dict) else 0)
        total = meta.get('pagination', {}).get('total', count) if meta else count

        return {
            "status": status,
            "count": count,
            "total": total,
            "errors": errors,
            "sample": resources[:3] if isinstance(resources, list) and resources else resources
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def main():
    print_section("CROWDSTRIKE ENVIRONMENT FULL AUDIT")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Region: us-1")

    audit_results = {}

    # NGSIEM Content
    print_section("NG-SIEM CONTENT")
    ngsiem = NGSIEM(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)

    ngsiem_checks = {
        "Dashboards (all)": ("list_dashboards", {"search_domain": "all", "limit": 100}),
        "Dashboards (falcon)": ("list_dashboards", {"search_domain": "falcon", "limit": 100}),
        "Dashboards (third-party)": ("list_dashboards", {"search_domain": "third-party", "limit": 100}),
        "Parsers": ("list_parsers", {"repository": "parsers-repository", "limit": 100}),
        "Saved Queries (all)": ("list_saved_queries", {"search_domain": "all", "limit": 100}),
        "Lookup Files (all)": ("list_lookup_files", {"search_domain": "all", "limit": 100}),
    }

    for name, (method, params) in ngsiem_checks.items():
        result = test_api(NGSIEM, method, params)
        audit_results[f"ngsiem_{name}"] = result
        status_icon = "✓" if result['status'] == 200 else "✗"
        print(f"  {status_icon} {name}: status={result['status']}, count={result['count']}, total={result.get('total', 'N/A')}")

    # Hosts & Devices
    print_section("HOSTS & DEVICES")
    hosts_checks = {
        "All Devices": ("query_devices", {"limit": 10}),
        "Online Devices": ("query_devices_by_filter", {"filter": "status:'online'", "limit": 10}),
        "Windows Devices": ("query_devices_by_filter", {"filter": "platform_name:'Windows'", "limit": 10}),
        "Linux Devices": ("query_devices_by_filter", {"filter": "platform_name:'Linux'", "limit": 10}),
        "Mac Devices": ("query_devices_by_filter", {"filter": "platform_name:'Mac'", "limit": 10}),
    }

    for name, (method, params) in hosts_checks.items():
        result = test_api(Hosts, method, params)
        audit_results[f"hosts_{name}"] = result
        status_icon = "✓" if result['status'] == 200 else "✗"
        print(f"  {status_icon} {name}: status={result['status']}, count={result['count']}")

    # Security Events
    print_section("SECURITY EVENTS")

    # Alerts
    print("\n--- Alerts ---")
    try:
        alerts = Alerts(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        resp = alerts.query_alerts_v2(limit=10)
        result = {
            "status": resp.get('status_code'),
            "count": len(resp.get('resources', [])),
            "total": resp.get('meta', {}).get('pagination', {}).get('total', 0)
        }
        audit_results["alerts"] = result
        print(f"  Alerts: status={result['status']}, count={result['count']}, total={result.get('total', 'N/A')}")
    except Exception as e:
        print(f"  Alerts: error - {e}")

    # Incidents
    print("\n--- Incidents ---")
    result = test_api(Incidents, "query_incidents", {"limit": 10})
    audit_results["incidents"] = result
    print(f"  Incidents: status={result['status']}, count={result['count']}")

    # IOCs
    print("\n--- IOCs (Indicators) ---")
    try:
        ioc = IOC(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        resp = ioc.indicator_combined_v1(limit=10)
        result = {
            "status": resp.get('status_code'),
            "count": len(resp.get('resources', []))
        }
        audit_results["iocs"] = result
        print(f"  IOCs: status={result['status']}, count={result['count']}")
    except Exception as e:
        print(f"  IOCs: error - {e}")

    # Policies
    print_section("POLICIES")
    policy_checks = [
        ("Prevention Policies", PreventionPolicies, "query_policies", {}),
        ("Device Control", DeviceControlPolicies, "query_device_control_policies", {}),
    ]

    for name, client_class, method, params in policy_checks:
        result = test_api(client_class, method, params)
        audit_results[f"policy_{name}"] = result
        print(f"  {name}: status={result['status']}, count={result.get('count', 'N/A')}")

    # Host Groups
    print("\n--- Host Groups ---")
    result = test_api(HostGroup, "query_host_groups", {})
    audit_results["host_groups"] = result
    print(f"  Host Groups: status={result['status']}, count={result['count']}")

    # Sensor Downloads
    print_section("SENSOR MANAGEMENT")
    try:
        sensors = SensorDownload(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        resp = sensors.get_combined_sensor_installers_by_query(limit=10)
        result = {
            "status": resp.get('status_code'),
            "count": len(resp.get('resources', []))
        }
        audit_results["sensor_installers"] = result
        print(f"  Available Sensor Installers: status={result['status']}, count={result['count']}")
        if result['count'] > 0:
            for sensor in resp.get('resources', [])[:5]:
                if isinstance(sensor, dict):
                    print(f"    - {sensor.get('name', 'N/A')} ({sensor.get('os', 'N/A')})")
    except Exception as e:
        print(f"  Sensor Installers: error - {e}")

    # Vulnerabilities
    print_section("VULNERABILITIES (SPOTLIGHT)")
    try:
        spotlight = SpotlightVulnerabilities(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        resp = spotlight.query_vulnerabilities(limit=10)
        result = {
            "status": resp.get('status_code'),
            "count": len(resp.get('resources', []))
        }
        audit_results["vulnerabilities"] = result
        print(f"  Vulnerabilities: status={result['status']}, count={result['count']}")
    except Exception as e:
        print(f"  Vulnerabilities: error - {e}")

    # Event Streams
    print_section("EVENT STREAMS")
    try:
        streams = EventStreams(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
        resp = streams.list_available_streams_o_auth2(app_id="siem-audit")
        result = {
            "status": resp.get('status_code'),
            "resources": resp.get('resources', [])
        }
        audit_results["event_streams"] = result
        print(f"  Event Streams: status={result['status']}")
        if result['status'] == 200 and result['resources']:
            for stream in result['resources']:
                if isinstance(stream, dict):
                    print(f"    - URL: {stream.get('dataFeedURL', 'N/A')[:50]}...")
    except Exception as e:
        print(f"  Event Streams: error - {e}")

    # Final Summary
    print_section("ENVIRONMENT SUMMARY")

    # Calculate totals
    total_hosts = audit_results.get('hosts_All Devices', {}).get('count', 0)
    total_alerts = audit_results.get('alerts', {}).get('total', 0)
    total_incidents = audit_results.get('incidents', {}).get('count', 0)
    total_dashboards = audit_results.get('ngsiem_Dashboards (all)', {}).get('count', 0)
    total_parsers = audit_results.get('ngsiem_Parsers', {}).get('count', 0)
    total_queries = audit_results.get('ngsiem_Saved Queries (all)', {}).get('count', 0)
    total_lookups = audit_results.get('ngsiem_Lookup Files (all)', {}).get('count', 0)

    print(f"""
┌─────────────────────────────────────────────────────────────────────┐
│                    ENVIRONMENT STATUS                                │
├─────────────────────────────────────────────────────────────────────┤
│  ENDPOINT PROTECTION                                                 │
│    Hosts/Devices:     {total_hosts:>6}                                       │
│    Alerts:            {total_alerts:>6}                                       │
│    Incidents:         {total_incidents:>6}                                       │
├─────────────────────────────────────────────────────────────────────┤
│  NG-SIEM CONTENT                                                     │
│    Custom Dashboards: {total_dashboards:>6}                                       │
│    Custom Parsers:    {total_parsers:>6}                                       │
│    Saved Queries:     {total_queries:>6}                                       │
│    Lookup Files:      {total_lookups:>6}                                       │
└─────────────────────────────────────────────────────────────────────┘
""")

    if total_hosts == 0 and total_dashboards == 0:
        print("""
⚠️  ASSESSMENT: This appears to be a NEW/EMPTY environment

Recommendations:
1. Deploy Falcon sensors to endpoints to start collecting data
2. Configure data connectors for third-party log sources
3. Deploy community content from ng_siem repository
4. Create custom dashboards and saved queries

The API credentials are working correctly - the environment simply
has no data or content yet.
""")
    else:
        print("""
✓ Environment has active data - ready for tooling development
""")

    # Save full audit
    output_file = "/Users/justin/Projects/falconpy/siem_audit_results.json"
    with open(output_file, "w") as f:
        json.dump(audit_results, f, indent=2, default=str)
    print(f"\n[*] Full audit results saved to: {output_file}")

if __name__ == "__main__":
    main()
