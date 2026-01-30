#!/usr/bin/env python3
"""
Parser Auditor Tool for CrowdStrike NG-SIEM / LogScale

Audits parsers for:
1. ECS (Elastic Common Schema) compliance
2. CPS (CrowdStrike Parsing Standard) compliance
3. Case Management field mappings
4. Best practices (structure, comments, naming)
5. Field uniformity and naming conventions
6. Array handling patterns

Usage:
    python parser_auditor.py <parser_file.yaml>           # Audit local file
    python parser_auditor.py <directory> --recursive      # Audit directory
    python parser_auditor.py --deployed                   # Audit deployed parsers via API
    python parser_auditor.py --deployed --export ./out    # Export and audit deployed parsers
"""

import argparse
import json
import os
import re
import sys
import time
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum

# ============================================================================
# AUDIT STANDARDS & RULES
# ============================================================================

class Severity(Enum):
    ERROR = "ERROR"      # Must fix - breaks functionality or compliance
    WARNING = "WARNING"  # Should fix - best practice violation
    INFO = "INFO"        # Suggestion for improvement


# ============================================================================
# CPS 1.0 REQUIREMENTS (from official CrowdStrike documentation)
# Reference: https://library.humio.com/logscale-parsing-standard/pasta.html
# ============================================================================

# Required Tagged Fields (must appear in tagFields for case management)
# These are the 5 core CPS tag fields required for correlation and analysis
CPS_REQUIRED_TAG_FIELDS = [
    "Cps.version",      # CPS version (e.g., "1.0.0")
    "Vendor",           # Lowercase vendor name (e.g., "microsoft")
    "ecs.version",      # ECS version (e.g., "8.11.0")
    "event.kind",       # event, alert, metric, state, pipeline_error, signal
    "event.module",     # Product/module identifier (e.g., "azure", "defender")
]

# ECS Required Fields (Elastic Common Schema 8.11.0)
ECS_REQUIRED_FIELDS = {
    "ecs.version": "ECS version must be declared (e.g., '8.11.0')",
    "event.kind": "Event kind must be set (event, alert, metric, etc.)",
    "event.module": "Event module identifies the data source/product",
}

ECS_RECOMMENDED_FIELDS = {
    "event.category": "Event category for classification (network, authentication, etc.)",
    "event.type": "Event type provides additional classification (start, end, info, etc.)",
    "event.action": "Event action describes what happened",
    "event.outcome": "Event outcome (success/failure/unknown)",
    "event.dataset": "Dataset identifier (vendor.product - only if different from event.module)",
}

# CPS Required Script Fields (must be set in parser script)
CPS_REQUIRED_FIELDS = {
    "Cps.version": "CPS version must be declared (e.g., '1.0.0')",
    "Vendor": "Vendor identifier must be set (lowercase)",
}

CPS_RECOMMENDED_FIELDS = {
    "Parser.version": "Parser version for tracking changes",
    "Parser_version": "Alternative parser version field",
}

# Alert-specific requirements (when event.kind := "alert")
ALERT_REQUIRED_FIELDS = [
    "event.category",   # Required for alerts
    "event.type",       # Required for alerts
    "event.severity",   # Required for alerts (maps vendor severity to numeric 1-100)
]

# Event.kind allowed values (from ECS)
EVENT_KIND_VALUES = ["alert", "event", "metric", "state", "pipeline_error", "signal"]

# Event.category allowed values (from ECS 8.11)
EVENT_CATEGORY_VALUES = [
    "authentication", "configuration", "database", "driver", "email", "file",
    "host", "iam", "intrusion_detection", "library", "malware", "network",
    "package", "process", "registry", "session", "threat", "vulnerability", "web"
]

# Event.type allowed values (from ECS 8.11)
EVENT_TYPE_VALUES = [
    "access", "admin", "allowed", "change", "connection", "creation", "deletion",
    "denied", "end", "error", "group", "indicator", "info", "installation",
    "protocol", "start", "user"
]

# Event.outcome allowed values
EVENT_OUTCOME_VALUES = ["success", "failure", "unknown"]

# Case Management Required Tag Fields (for Case Management Workbench)
CASE_MANAGEMENT_TAG_FIELDS = {
    "required": CPS_REQUIRED_TAG_FIELDS,
    "recommended": [
        "event.dataset",
        "event.category",
        "event.type",
        "event.action",
        "event.outcome",
        "observer.type",
    ]
}

# ECS Field Naming Patterns
ECS_FIELD_HIERARCHIES = {
    "source": ["ip", "port", "address", "mac", "bytes", "packets", "geo.*"],
    "destination": ["ip", "port", "address", "mac", "bytes", "packets", "geo.*"],
    "network": ["iana_number", "application", "bytes", "packets", "community_id", "direction", "transport"],
    "host": ["ip", "name", "id", "hostname", "mac", "os.*"],
    "user": ["name", "email", "full_name", "id", "domain", "roles"],
    "event": ["kind", "category", "type", "action", "outcome", "module", "dataset", "id", "code", "severity"],
    "client": ["ip", "port", "address", "geo.*"],
    "server": ["ip", "port", "address", "geo.*"],
    "http": ["request.*", "response.*"],
    "url": ["domain", "scheme", "original", "path", "query"],
    "file": ["name", "path", "size", "hash.*", "extension"],
    "process": ["name", "pid", "executable", "command_line", "args"],
    "threat": ["framework", "tactic.*", "technique.*"],
    "rule": ["name", "id", "uuid", "version", "description"],
    "observer": ["type", "vendor", "product", "version"],
    "email": ["from.*", "to.*", "subject", "message_id", "attachments"],
}

# Best Practice Patterns
BEST_PRACTICE_PATTERNS = {
    "region_comments": r"//\s*#region\s+\w+",
    "metadata_section": r"(METADATA|Static Metadata)",
    "normalization_section": r"(NORMALIZATION|Normalize)",
    "timestamp_parsing": r"parseTimestamp|findTimestamp",
    "json_parsing": r"parseJson",
    "vendor_prefix": r'prefix\s*=\s*"Vendor\."',
}


# ============================================================================
# AUDIT RESULT CLASSES
# ============================================================================

@dataclass
class AuditFinding:
    """Single audit finding."""
    severity: Severity
    category: str
    message: str
    line_number: Optional[int] = None
    suggestion: Optional[str] = None

@dataclass
class ParserAuditResult:
    """Complete audit result for a parser."""
    parser_name: str
    parser_file: str
    findings: List[AuditFinding] = field(default_factory=list)
    ecs_score: int = 0
    cps_score: int = 0
    best_practices_score: int = 0
    overall_score: int = 0

    # Extracted metadata
    ecs_version: Optional[str] = None
    cps_version: Optional[str] = None
    vendor: Optional[str] = None
    declared_fields: List[str] = field(default_factory=list)
    tag_fields: List[str] = field(default_factory=list)

    # Source info
    source: str = "file"  # "file" or "api"
    parser_id: Optional[str] = None

    def add_finding(self, severity: Severity, category: str, message: str,
                    line_number: int = None, suggestion: str = None):
        self.findings.append(AuditFinding(
            severity=severity,
            category=category,
            message=message,
            line_number=line_number,
            suggestion=suggestion
        ))

    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.ERROR)

    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)


# ============================================================================
# API CLIENT FOR DEPLOYED PARSERS
# ============================================================================

class DeployedParserClient:
    """Client for fetching deployed parsers from NG-SIEM API."""

    def __init__(self, client_id: str = None, client_secret: str = None,
                 base_url: str = "https://api.crowdstrike.com"):
        self.client_id = client_id or os.environ.get("FALCON_CLIENT_ID")
        self.client_secret = client_secret or os.environ.get("FALCON_CLIENT_SECRET")
        self.base_url = base_url
        self.ngsiem = None

    def connect(self):
        """Initialize connection to NG-SIEM API."""
        try:
            from falconpy import NGSIEM
            self.ngsiem = NGSIEM(
                client_id=self.client_id,
                client_secret=self.client_secret,
                base_url=self.base_url
            )
            return True
        except ImportError:
            print("Error: falconpy library not installed. Run: pip install crowdstrike-falconpy")
            return False
        except Exception as e:
            print(f"Error connecting to API: {e}")
            return False

    def list_parsers(self, limit: int = 500) -> List[Dict]:
        """List all deployed custom parsers via API."""
        if not self.ngsiem:
            if not self.connect():
                return []

        parsers = []
        offset = 0

        while True:
            response = self.ngsiem.list_parsers(
                repository="parsers-repository",
                limit=min(100, limit - len(parsers)),
                offset=offset
            )

            if response.get("status_code") != 200:
                print(f"API Error: {response.get('status_code')} - {response.get('errors', [])}")
                break

            resources = response.get("resources", [])
            if not resources:
                break

            parsers.extend(resources)

            if len(parsers) >= limit or len(resources) < 100:
                break

            offset += len(resources)

        return parsers

    def discover_parsers_in_use(self, time_range: str = "7d") -> List[Dict]:
        """Discover parsers by querying SIEM for #type field values.

        This finds parsers that have actually processed data, including
        built-in and marketplace parsers not accessible via list_parsers API.
        """
        if not self.ngsiem:
            if not self.connect():
                return []

        import time as _time

        query = '#type=* | groupBy(#type) | sort(_count, order=desc, limit=200)'
        resp = self.ngsiem.start_search(
            repository="search-all",
            query_string=query,
            is_live=False,
            start=time_range
        )

        if resp.get("status_code") != 200:
            print(f"Query failed: {resp.get('status_code')}")
            return []

        search_id = resp.get("resources", {}).get("id")
        if not search_id:
            return []

        # Poll for results
        for i in range(30):
            _time.sleep(2)
            status = self.ngsiem.get_search_status(
                repository="search-all",
                search_id=search_id
            )
            body = status.get("body", {})
            if body.get("done") or body.get("events"):
                events = body.get("events", [])
                return [
                    {
                        "name": e.get("#type", "Unknown"),
                        "event_count": int(e.get("_count", 0)),
                        "source": "siem_discovery"
                    }
                    for e in events
                ]

        return []

    def get_parser_template(self, parser_id: str) -> Optional[str]:
        """Get parser YAML template by ID."""
        if not self.ngsiem:
            if not self.connect():
                return None

        response = self.ngsiem.get_parser_template(
            ids=parser_id,
            repository="parsers-repository"
        )

        if response.get("status_code") != 200:
            return None

        resources = response.get("resources", [])
        if resources and isinstance(resources, list) and len(resources) > 0:
            return resources[0].get("yaml_template") or resources[0].get("template")

        return None

    def get_parser_details(self, parser_id: str) -> Optional[Dict]:
        """Get parser details by ID."""
        if not self.ngsiem:
            if not self.connect():
                return None

        response = self.ngsiem.get_parser(
            ids=parser_id,
            repository="parsers-repository"
        )

        if response.get("status_code") != 200:
            return None

        resources = response.get("resources", [])
        if resources and isinstance(resources, list) and len(resources) > 0:
            return resources[0]

        return None


# ============================================================================
# PARSER AUDITOR CLASS
# ============================================================================

class ParserAuditor:
    """Audits LogScale/NG-SIEM parsers for compliance and best practices."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def audit_file(self, file_path: str) -> ParserAuditResult:
        """Audit a single parser YAML file."""
        path = Path(file_path)

        if not path.exists():
            result = ParserAuditResult(
                parser_name="Unknown",
                parser_file=file_path
            )
            result.add_finding(Severity.ERROR, "File", f"File not found: {file_path}")
            return result

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            parser_data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            result = ParserAuditResult(
                parser_name="Unknown",
                parser_file=file_path
            )
            result.add_finding(Severity.ERROR, "YAML", f"Invalid YAML: {e}")
            return result
        except Exception as e:
            result = ParserAuditResult(
                parser_name="Unknown",
                parser_file=file_path
            )
            result.add_finding(Severity.ERROR, "File", f"Error reading file: {e}")
            return result

        return self.audit_parser(parser_data, file_path, content)

    def audit_deployed_parser(self, parser_info: Dict, client: DeployedParserClient) -> ParserAuditResult:
        """Audit a deployed parser from the API."""
        parser_name = parser_info.get("name", "Unknown")
        parser_id = parser_info.get("id", "")

        result = ParserAuditResult(
            parser_name=parser_name,
            parser_file=f"[deployed] {parser_name}",
            source="api",
            parser_id=parser_id
        )

        # Get parser script from details
        script = parser_info.get("script", "")
        tag_fields = parser_info.get("fieldsToTag", []) or parser_info.get("fields_to_tag", []) or []

        if not script:
            # Try to get template
            template = client.get_parser_template(parser_id)
            if template:
                try:
                    parser_data = yaml.safe_load(template)
                    script = parser_data.get("script", "")
                    tag_fields = parser_data.get("tagFields", []) or tag_fields
                except:
                    pass

        if not script:
            # Try to get details
            details = client.get_parser_details(parser_id)
            if details:
                script = details.get("script", "")
                tag_fields = details.get("fieldsToTag", []) or details.get("fields_to_tag", []) or tag_fields

        if not script:
            result.add_finding(
                Severity.WARNING, "API",
                "Could not retrieve parser script",
                suggestion="Parser may require additional API permissions"
            )
            return result

        result.tag_fields = tag_fields if isinstance(tag_fields, list) else tag_fields.split(",") if tag_fields else []

        # Run audits
        self._audit_ecs_compliance(script, result)
        self._audit_cps_compliance(script, result)
        self._audit_case_management_fields(result.tag_fields, script, result)
        self._audit_best_practices(script, script, result)
        self._audit_field_uniformity(script, result)
        self._audit_array_handling(script, result)

        # Calculate scores
        self._calculate_scores(result)

        return result

    def audit_parser(self, parser_data: Dict, file_path: str, raw_content: str) -> ParserAuditResult:
        """Audit a parsed parser dictionary."""
        parser_name = parser_data.get('name', 'Unknown')
        result = ParserAuditResult(
            parser_name=parser_name,
            parser_file=file_path
        )

        script = parser_data.get('script', '')
        tag_fields = parser_data.get('tagFields', [])
        result.tag_fields = tag_fields

        # Run all audits
        self._audit_structure(parser_data, result)
        self._audit_ecs_compliance(script, result)
        self._audit_cps_compliance(script, result)
        self._audit_case_management_fields(tag_fields, script, result)
        self._audit_best_practices(script, raw_content, result)
        self._audit_field_uniformity(script, result)
        self._audit_array_handling(script, result)
        self._audit_test_cases(parser_data, result)

        # Calculate scores
        self._calculate_scores(result)

        return result

    def _audit_structure(self, parser_data: Dict, result: ParserAuditResult):
        """Audit basic parser structure."""
        if 'name' not in parser_data:
            result.add_finding(
                Severity.ERROR, "Structure",
                "Parser missing 'name' field",
                suggestion="Add 'name: ParserName' at the top of the file"
            )

        if 'script' not in parser_data:
            result.add_finding(
                Severity.ERROR, "Structure",
                "Parser missing 'script' field",
                suggestion="Add 'script: |-' with parsing logic"
            )
        elif not parser_data.get('script', '').strip():
            result.add_finding(
                Severity.ERROR, "Structure",
                "Parser script is empty",
                suggestion="Add parsing logic to the script section"
            )

        if 'tagFields' not in parser_data:
            result.add_finding(
                Severity.WARNING, "Structure",
                "Parser missing 'tagFields' section",
                suggestion="Add tagFields for case management and performance"
            )
        elif not parser_data.get('tagFields'):
            result.add_finding(
                Severity.WARNING, "Structure",
                "tagFields section is empty",
                suggestion="Add fields to tag for indexing and case management"
            )

        schema = parser_data.get('$schema', '')
        if not schema:
            result.add_finding(
                Severity.INFO, "Structure",
                "No $schema defined",
                suggestion="Add '$schema: https://schemas.humio.com/parser/v0.3.0'"
            )
        elif 'v0.2.0' in schema:
            result.add_finding(
                Severity.INFO, "Structure",
                "Using older schema v0.2.0",
                suggestion="Consider upgrading to v0.3.0 for testCases support"
            )

    def _audit_ecs_compliance(self, script: str, result: ParserAuditResult):
        """Audit ECS (Elastic Common Schema) compliance."""
        # Check required ECS fields
        for field, description in ECS_REQUIRED_FIELDS.items():
            pattern = rf'{re.escape(field)}\s*:='
            if not re.search(pattern, script):
                result.add_finding(
                    Severity.ERROR, "ECS",
                    f"Missing required ECS field: {field}",
                    suggestion=f"{description}. Add: {field} := \"value\""
                )
            else:
                result.declared_fields.append(field)
                # Extract ecs.version value
                if field == 'ecs.version':
                    match = re.search(rf'{re.escape(field)}\s*:=\s*"([^"]+)"', script)
                    if match:
                        result.ecs_version = match.group(1)
                        # Validate ECS version
                        if not match.group(1).startswith("8."):
                            result.add_finding(
                                Severity.WARNING, "ECS",
                                f"ECS version '{match.group(1)}' may be outdated",
                                suggestion="Current CPS standard uses ECS 8.11.0"
                            )
                # Validate event.kind value
                elif field == 'event.kind':
                    match = re.search(rf'{re.escape(field)}\s*:=\s*"([^"]+)"', script)
                    if match:
                        kind_value = match.group(1)
                        if kind_value not in EVENT_KIND_VALUES:
                            result.add_finding(
                                Severity.ERROR, "ECS",
                                f"Invalid event.kind value: '{kind_value}'",
                                suggestion=f"Allowed values: {', '.join(EVENT_KIND_VALUES)}"
                            )
                        # Check alert requirements
                        if kind_value == "alert":
                            for alert_field in ALERT_REQUIRED_FIELDS:
                                alert_pattern = rf'{re.escape(alert_field)}\s*:='
                                if not re.search(alert_pattern, script):
                                    result.add_finding(
                                        Severity.ERROR, "ECS",
                                        f"Alert requires '{alert_field}' field",
                                        suggestion="When event.kind := 'alert', event.category, event.type, and event.severity are required"
                                    )

        # Check recommended ECS fields
        for field, description in ECS_RECOMMENDED_FIELDS.items():
            pattern = rf'{re.escape(field)}\s*:='
            if not re.search(pattern, script):
                result.add_finding(
                    Severity.WARNING, "ECS",
                    f"Missing recommended ECS field: {field}",
                    suggestion=description
                )
            else:
                result.declared_fields.append(field)
                # Validate event.category value
                if field == 'event.category':
                    match = re.search(rf'{re.escape(field)}\s*:=\s*"([^"]+)"', script)
                    if match and match.group(1) not in EVENT_CATEGORY_VALUES:
                        result.add_finding(
                            Severity.WARNING, "ECS",
                            f"Non-standard event.category value: '{match.group(1)}'",
                            suggestion=f"Standard values include: {', '.join(EVENT_CATEGORY_VALUES[:8])}..."
                        )
                # Validate event.outcome value
                elif field == 'event.outcome':
                    match = re.search(rf'{re.escape(field)}\s*:=\s*"([^"]+)"', script)
                    if match and match.group(1) not in EVENT_OUTCOME_VALUES:
                        result.add_finding(
                            Severity.WARNING, "ECS",
                            f"Non-standard event.outcome value: '{match.group(1)}'",
                            suggestion=f"Allowed values: {', '.join(EVENT_OUTCOME_VALUES)}"
                        )

        # Check for deprecated/non-ECS field names
        deprecated_patterns = [
            (r'host\.hostname\s*:=', "host.hostname", "Use host.name instead"),
            (r'user_name\s*:=', "user_name", "Use user.name instead"),
            (r'src_ip\s*:=', "src_ip", "Use source.ip instead"),
            (r'dst_ip\s*:=', "dst_ip", "Use destination.ip instead"),
            (r'source_ip\s*:=', "source_ip", "Use source.ip instead"),
            (r'dest_ip\s*:=', "dest_ip", "Use destination.ip instead"),
            (r'source_port\s*:=', "source_port", "Use source.port instead"),
            (r'dest_port\s*:=', "dest_port", "Use destination.port instead"),
        ]

        for pattern, field_name, suggestion in deprecated_patterns:
            if re.search(pattern, script):
                result.add_finding(
                    Severity.WARNING, "ECS",
                    f"Using non-ECS field name: {field_name}",
                    suggestion=suggestion
                )

    def _audit_cps_compliance(self, script: str, result: ParserAuditResult):
        """Audit CPS (CrowdStrike Parsing Standard) 1.0 compliance."""
        # Check required CPS script fields
        for field, description in CPS_REQUIRED_FIELDS.items():
            pattern = rf'{re.escape(field)}\s*:='
            if not re.search(pattern, script):
                result.add_finding(
                    Severity.ERROR, "CPS",
                    f"Missing required CPS field: {field}",
                    suggestion=description
                )
            else:
                result.declared_fields.append(field)
                # Extract Cps.version
                if field == 'Cps.version':
                    match = re.search(rf'{re.escape(field)}\s*:=\s*"([^"]+)"', script)
                    if match:
                        result.cps_version = match.group(1)
                        # Validate CPS version format
                        if not re.match(r'^\d+\.\d+(\.\d+)?$', match.group(1)):
                            result.add_finding(
                                Severity.WARNING, "CPS",
                                f"CPS version format unusual: '{match.group(1)}'",
                                suggestion="Use semantic versioning (e.g., '1.0.0')"
                            )
                # Extract and validate Vendor
                elif field == 'Vendor':
                    match = re.search(rf'{re.escape(field)}\s*:=\s*"([^"]+)"', script)
                    if match:
                        result.vendor = match.group(1)
                        vendor_val = match.group(1)
                        # Vendor must be lowercase (per CPS guidelines)
                        if not vendor_val.islower():
                            result.add_finding(
                                Severity.ERROR, "CPS",
                                f"Vendor name MUST be lowercase: '{vendor_val}'",
                                suggestion=f"Use: Vendor := \"{vendor_val.lower()}\""
                            )
                        # Vendor should not contain spaces
                        if ' ' in vendor_val:
                            result.add_finding(
                                Severity.ERROR, "CPS",
                                f"Vendor name contains spaces: '{vendor_val}'",
                                suggestion=f"Use: Vendor := \"{vendor_val.replace(' ', '_').lower()}\""
                            )
                        # Warn about empty vendor
                        if not vendor_val.strip():
                            result.add_finding(
                                Severity.ERROR, "CPS",
                                "Vendor name is empty",
                                suggestion="Set Vendor to the lowercase vendor name (e.g., 'microsoft', 'paloalto')"
                            )

        # Check for Parser version (recommended)
        has_parser_version = False
        for field in CPS_RECOMMENDED_FIELDS.keys():
            pattern = rf'{re.escape(field)}\s*:='
            if re.search(pattern, script):
                has_parser_version = True
                result.declared_fields.append(field)
                break

        if not has_parser_version:
            result.add_finding(
                Severity.WARNING, "CPS",
                "Missing parser version field",
                suggestion="Add Parser.version := \"1.0.0\" or Parser_version := \"1.0.0\""
            )

        # Check for Vendor. prefix usage for non-ECS fields
        vendor_prefix_pattern = r'Vendor\.\w+\s*:='
        if not re.search(vendor_prefix_pattern, script):
            # Check if there are non-ECS fields that should use Vendor. prefix
            custom_field_pattern = r'(?<!source\.)(?<!destination\.)(?<!network\.)(?<!event\.)(?<!host\.)(?<!user\.)(?<!process\.)(?<!file\.)(\w{3,})\s*:='
            custom_fields = re.findall(custom_field_pattern, script)
            standard_fields = {'ecs', 'Cps', 'Vendor', 'Parser', 'Parser_version', 'true', 'false', 'null'}
            non_standard = [f for f in custom_fields if f.split('.')[0] not in standard_fields and not f.startswith('_')]
            if non_standard:
                result.add_finding(
                    Severity.INFO, "CPS",
                    "Consider using Vendor. prefix for non-ECS fields",
                    suggestion=f"Fields like '{non_standard[0]}' should be prefixed with 'Vendor.' for namespace clarity"
                )

    def _audit_case_management_fields(self, tag_fields: List[str], script: str,
                                       result: ParserAuditResult):
        """Audit fields required for case management workbench.

        Per CPS 1.0 documentation, these 5 fields MUST be tagged for correlation:
        - Cps.version
        - Vendor
        - ecs.version
        - event.kind
        - event.module
        """
        # Check required CPS tag fields (critical for case management)
        missing_required = []
        for field in CASE_MANAGEMENT_TAG_FIELDS["required"]:
            if field not in tag_fields:
                pattern = rf'{re.escape(field)}\s*:='
                if re.search(pattern, script):
                    result.add_finding(
                        Severity.ERROR, "Case Management",
                        f"Field '{field}' is SET but NOT in tagFields",
                        suggestion=f"Add '{field}' to tagFields section (required for case management)"
                    )
                else:
                    result.add_finding(
                        Severity.ERROR, "Case Management",
                        f"Missing required tag field: {field}",
                        suggestion=f"Set '{field}' in script AND add to tagFields"
                    )
                missing_required.append(field)

        # Summary of missing required fields
        if missing_required:
            result.add_finding(
                Severity.ERROR, "Case Management",
                f"Missing {len(missing_required)} of 5 required CPS tag fields",
                suggestion=f"Required tags: {', '.join(CPS_REQUIRED_TAG_FIELDS)}"
            )

        # Check recommended tag fields
        for field in CASE_MANAGEMENT_TAG_FIELDS["recommended"]:
            if field not in tag_fields:
                pattern = rf'{re.escape(field)}\s*:='
                if re.search(pattern, script):
                    result.add_finding(
                        Severity.INFO, "Case Management",
                        f"Field '{field}' could be tagged for enriched correlation",
                        suggestion=f"Consider adding '{field}' to tagFields"
                    )

        # Check for high-cardinality fields that should NOT be tagged
        high_cardinality_patterns = [
            "source.ip", "destination.ip", "client.ip", "server.ip",
            "user.name", "user.email", "user.id", "user.full_name",
            "host.ip", "host.name", "host.hostname", "host.id",
            "event.id", "url.original", "url.full",
            "process.pid", "process.name", "process.command_line",
            "file.name", "file.path", "file.hash.*",
            "message", "@rawstring"
        ]

        for field in tag_fields:
            if field in high_cardinality_patterns or field.startswith("Vendor."):
                result.add_finding(
                    Severity.WARNING, "Case Management",
                    f"High-cardinality field '{field}' in tagFields",
                    suggestion="Tagging high-cardinality fields impacts query performance. Only tag classification fields."
                )

        # Check if tagFields section exists and is properly populated
        if not tag_fields:
            result.add_finding(
                Severity.ERROR, "Case Management",
                "tagFields section is empty or missing",
                suggestion="Add the 5 required CPS tag fields: Cps.version, Vendor, ecs.version, event.kind, event.module"
            )

    def _audit_best_practices(self, script: str, raw_content: str, result: ParserAuditResult):
        """Audit parser best practices."""
        if not re.search(BEST_PRACTICE_PATTERNS["region_comments"], script):
            result.add_finding(
                Severity.INFO, "Best Practices",
                "No #region comments for code organization",
                suggestion="Add // #region METADATA, // #region NORMALIZATION sections"
            )

        if not re.search(BEST_PRACTICE_PATTERNS["metadata_section"], script, re.IGNORECASE):
            result.add_finding(
                Severity.INFO, "Best Practices",
                "No clear METADATA section",
                suggestion="Add a METADATA section with static field definitions"
            )

        if not re.search(BEST_PRACTICE_PATTERNS["timestamp_parsing"], script):
            result.add_finding(
                Severity.WARNING, "Best Practices",
                "No timestamp parsing detected",
                suggestion="Add parseTimestamp() or findTimestamp() for proper time handling"
            )

        if re.search(r'parseJson', script):
            if not re.search(BEST_PRACTICE_PATTERNS["vendor_prefix"], script):
                result.add_finding(
                    Severity.INFO, "Best Practices",
                    "JSON parsing without Vendor prefix",
                    suggestion="Consider using prefix=\"Vendor.\" to namespace vendor fields"
                )

        temp_field_pattern = r'_\w+\s*:='
        if re.search(temp_field_pattern, script):
            if not re.search(r'drop\s*\(\s*\[', script):
                result.add_finding(
                    Severity.INFO, "Best Practices",
                    "Temporary fields created but no drop() statement found",
                    suggestion="Use drop([_tempField]) to clean up temporary fields"
                )

        script_lines = len(script.split('\n'))
        if script_lines > 200:
            result.add_finding(
                Severity.INFO, "Best Practices",
                f"Parser script is {script_lines} lines - consider breaking into transforms",
                suggestion="Large parsers can be split into reusable transform files"
            )

        commented_code = re.findall(r'//\s*(parseJson|case\s*\{|\w+\s*:=)', script)
        if len(commented_code) > 3:
            result.add_finding(
                Severity.INFO, "Best Practices",
                "Multiple commented-out code blocks detected",
                suggestion="Remove unused code or move to documentation"
            )

    def _audit_field_uniformity(self, script: str, result: ParserAuditResult):
        """Audit field naming uniformity."""
        field_pattern = r'(\w+(?:\.\w+)*)\s*:='
        fields = re.findall(field_pattern, script)

        for field in fields:
            if ' ' in field or '-' in field:
                result.add_finding(
                    Severity.ERROR, "Field Uniformity",
                    f"Invalid characters in field name: '{field}'",
                    suggestion="Use dots for hierarchy, underscores within segments"
                )

            parts = field.split('.')
            for part in parts:
                if part in ['Vendor', 'Cps', 'Parser', 'Parser_version']:
                    continue
                if part != part.lower() and not part.startswith('_'):
                    result.add_finding(
                        Severity.WARNING, "Field Uniformity",
                        f"Field '{field}' contains uppercase - ECS uses lowercase",
                        suggestion=f"Consider: {field.lower()}"
                    )
                    break

            top_level = parts[0].lower()
            if top_level in ECS_FIELD_HIERARCHIES and len(parts) > 1:
                expected_children = ECS_FIELD_HIERARCHIES[top_level]
                child = parts[1]
                if not any(child.startswith(ec.rstrip('*').rstrip('.')) for ec in expected_children):
                    result.add_finding(
                        Severity.INFO, "Field Uniformity",
                        f"Non-standard ECS field: {field}",
                        suggestion=f"Standard {top_level}.* fields: {', '.join(expected_children[:5])}"
                    )

    def _audit_array_handling(self, script: str, result: ParserAuditResult):
        """Audit array handling patterns."""
        array_access = re.findall(r'(\w+(?:\.\w+)*)\[(\d+)\]', script)

        for field, index in array_access:
            if int(index) > 0:
                result.add_finding(
                    Severity.INFO, "Array Handling",
                    f"Accessing array index [{index}] on {field}",
                    suggestion="Ensure array element exists before access"
                )

        if re.search(r'splitString\s*\(', script):
            result.declared_fields.append("_uses_splitString")

        if re.search(r'concatArray\s*\(', script):
            result.declared_fields.append("_uses_concatArray")

        if re.search(r'\[\d+\]', script) and not re.search(r'(concatArray|splitString)', script):
            result.add_finding(
                Severity.INFO, "Array Handling",
                "Array access without concatArray/splitString",
                suggestion="Consider using concatArray() and splitString() for array normalization"
            )

    def _audit_test_cases(self, parser_data: Dict, result: ParserAuditResult):
        """Audit test case coverage."""
        tests = parser_data.get('tests', [])
        test_cases = parser_data.get('testCases', [])

        total_tests = len(tests) + len(test_cases)

        if total_tests == 0:
            result.add_finding(
                Severity.WARNING, "Testing",
                "No test cases defined",
                suggestion="Add 'tests:' or 'testCases:' with sample log entries"
            )
        elif total_tests < 3:
            result.add_finding(
                Severity.INFO, "Testing",
                f"Only {total_tests} test case(s) defined",
                suggestion="Add more test cases for edge cases and different log formats"
            )

    def _calculate_scores(self, result: ParserAuditResult):
        """Calculate compliance scores based on CPS 1.0 requirements."""
        # ECS Score: Based on required + recommended fields
        ecs_required = len(ECS_REQUIRED_FIELDS)
        ecs_recommended = len(ECS_RECOMMENDED_FIELDS)
        ecs_required_found = sum(1 for f in ECS_REQUIRED_FIELDS if f in result.declared_fields)
        ecs_recommended_found = sum(1 for f in ECS_RECOMMENDED_FIELDS if f in result.declared_fields)
        ecs_errors = sum(1 for f in result.findings if f.category == "ECS" and f.severity == Severity.ERROR)
        # Required fields are 70% of score, recommended are 30%
        ecs_base = (ecs_required_found / ecs_required * 70) + (ecs_recommended_found / ecs_recommended * 30)
        result.ecs_score = max(0, int(ecs_base - (ecs_errors * 10)))

        # CPS Score: Based on required fields + tag fields
        cps_required = len(CPS_REQUIRED_FIELDS)
        cps_found = sum(1 for f in CPS_REQUIRED_FIELDS if f in result.declared_fields)
        # Check how many required tag fields are present
        tag_fields_required = len(CPS_REQUIRED_TAG_FIELDS)
        tag_fields_found = sum(1 for f in CPS_REQUIRED_TAG_FIELDS if f in result.tag_fields)
        cps_errors = sum(1 for f in result.findings if f.category == "CPS" and f.severity == Severity.ERROR)
        cm_errors = sum(1 for f in result.findings if f.category == "Case Management" and f.severity == Severity.ERROR)
        # Script fields are 40%, tag fields are 60%
        cps_base = (cps_found / cps_required * 40) + (tag_fields_found / tag_fields_required * 60)
        result.cps_score = max(0, int(cps_base - (cps_errors * 10) - (cm_errors * 5)))

        # Best Practices Score
        bp_findings = [f for f in result.findings if f.category == "Best Practices"]
        bp_errors = sum(1 for f in bp_findings if f.severity == Severity.ERROR)
        bp_warnings = sum(1 for f in bp_findings if f.severity == Severity.WARNING)
        bp_info = sum(1 for f in bp_findings if f.severity == Severity.INFO)
        result.best_practices_score = max(0, 100 - (bp_errors * 20) - (bp_warnings * 10) - (bp_info * 3))

        # Overall Score: Weighted average
        # CPS compliance is most critical (40%), then ECS (35%), then best practices (25%)
        result.overall_score = int(
            (result.cps_score * 0.40) +
            (result.ecs_score * 0.35) +
            (result.best_practices_score * 0.25)
        )


# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_report(result: ParserAuditResult, format: str = "text") -> str:
    """Generate audit report in specified format."""
    if format == "json":
        return generate_json_report(result)
    else:
        return generate_text_report(result)


def generate_text_report(result: ParserAuditResult) -> str:
    """Generate human-readable text report."""
    lines = []

    lines.append("=" * 70)
    lines.append(f" PARSER AUDIT REPORT: {result.parser_name}")
    lines.append("=" * 70)
    lines.append(f"Source: {result.source.upper()}")
    lines.append(f"File/ID: {result.parser_file}")
    if result.parser_id:
        lines.append(f"Parser ID: {result.parser_id}")
    lines.append("")

    lines.append("COMPLIANCE SCORES")
    lines.append("-" * 40)
    lines.append(f"  ECS Compliance:      {result.ecs_score:3d}/100 {_score_bar(result.ecs_score)}")
    lines.append(f"  CPS Compliance:      {result.cps_score:3d}/100 {_score_bar(result.cps_score)}")
    lines.append(f"  Best Practices:      {result.best_practices_score:3d}/100 {_score_bar(result.best_practices_score)}")
    lines.append(f"  Overall Score:       {result.overall_score:3d}/100 {_score_bar(result.overall_score)}")
    lines.append("")

    lines.append("PARSER METADATA")
    lines.append("-" * 40)
    lines.append(f"  ECS Version: {result.ecs_version or 'Not set'}")
    lines.append(f"  CPS Version: {result.cps_version or 'Not set'}")
    lines.append(f"  Vendor:      {result.vendor or 'Not set'}")
    lines.append(f"  Tag Fields:  {len(result.tag_fields)}")
    lines.append("")

    lines.append("FINDINGS SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Errors:   {result.error_count():3d}")
    lines.append(f"  Warnings: {result.warning_count():3d}")
    lines.append(f"  Info:     {result.info_count():3d}")
    lines.append("")

    categories = {}
    for finding in result.findings:
        if finding.category not in categories:
            categories[finding.category] = []
        categories[finding.category].append(finding)

    for category, findings in sorted(categories.items()):
        lines.append(f"{category.upper()} FINDINGS")
        lines.append("-" * 40)
        for f in findings:
            icon = "❌" if f.severity == Severity.ERROR else "⚠️" if f.severity == Severity.WARNING else "ℹ️"
            lines.append(f"  {icon} [{f.severity.value}] {f.message}")
            if f.suggestion:
                lines.append(f"      → {f.suggestion}")
        lines.append("")

    if result.tag_fields:
        lines.append("TAG FIELDS")
        lines.append("-" * 40)
        for tf in result.tag_fields:
            lines.append(f"  • {tf}")
        lines.append("")

    return "\n".join(lines)


def _score_bar(score: int, width: int = 20) -> str:
    """Generate ASCII score bar."""
    filled = int(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    color = "🟢" if score >= 80 else "🟡" if score >= 60 else "🔴"
    return f"{color} [{bar}]"


def generate_json_report(result: ParserAuditResult) -> str:
    """Generate JSON report."""
    return json.dumps({
        "parser_name": result.parser_name,
        "parser_file": result.parser_file,
        "source": result.source,
        "parser_id": result.parser_id,
        "scores": {
            "ecs": result.ecs_score,
            "cps": result.cps_score,
            "best_practices": result.best_practices_score,
            "overall": result.overall_score
        },
        "metadata": {
            "ecs_version": result.ecs_version,
            "cps_version": result.cps_version,
            "vendor": result.vendor,
            "tag_fields": result.tag_fields
        },
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "message": f.message,
                "line_number": f.line_number,
                "suggestion": f.suggestion
            }
            for f in result.findings
        ],
        "summary": {
            "errors": result.error_count(),
            "warnings": result.warning_count(),
            "info": result.info_count()
        }
    }, indent=2)


def generate_summary_report(results: List[ParserAuditResult]) -> str:
    """Generate summary report for multiple parsers."""
    lines = []
    lines.append("=" * 80)
    lines.append(" PARSER AUDIT SUMMARY")
    lines.append("=" * 80)
    lines.append(f"Total Parsers Audited: {len(results)}")
    lines.append("")

    # Score distribution
    excellent = sum(1 for r in results if r.overall_score >= 80)
    good = sum(1 for r in results if 60 <= r.overall_score < 80)
    needs_work = sum(1 for r in results if r.overall_score < 60)

    lines.append("SCORE DISTRIBUTION")
    lines.append("-" * 40)
    lines.append(f"  🟢 Excellent (80+):  {excellent:3d} ({100*excellent//len(results) if results else 0}%)")
    lines.append(f"  🟡 Good (60-79):     {good:3d} ({100*good//len(results) if results else 0}%)")
    lines.append(f"  🔴 Needs Work (<60): {needs_work:3d} ({100*needs_work//len(results) if results else 0}%)")
    lines.append("")

    # Average scores
    avg_ecs = sum(r.ecs_score for r in results) // len(results) if results else 0
    avg_cps = sum(r.cps_score for r in results) // len(results) if results else 0
    avg_bp = sum(r.best_practices_score for r in results) // len(results) if results else 0
    avg_overall = sum(r.overall_score for r in results) // len(results) if results else 0

    lines.append("AVERAGE SCORES")
    lines.append("-" * 40)
    lines.append(f"  ECS Compliance:    {avg_ecs:3d}/100")
    lines.append(f"  CPS Compliance:    {avg_cps:3d}/100")
    lines.append(f"  Best Practices:    {avg_bp:3d}/100")
    lines.append(f"  Overall:           {avg_overall:3d}/100")
    lines.append("")

    # Total findings
    total_errors = sum(r.error_count() for r in results)
    total_warnings = sum(r.warning_count() for r in results)
    total_info = sum(r.info_count() for r in results)

    lines.append("TOTAL FINDINGS")
    lines.append("-" * 40)
    lines.append(f"  Errors:   {total_errors:4d}")
    lines.append(f"  Warnings: {total_warnings:4d}")
    lines.append(f"  Info:     {total_info:4d}")
    lines.append("")

    # Bottom parsers
    sorted_results = sorted(results, key=lambda r: r.overall_score)
    lines.append("PARSERS NEEDING ATTENTION (Lowest Scores)")
    lines.append("-" * 40)
    for r in sorted_results[:10]:
        lines.append(f"  {r.overall_score:3d}/100  {r.parser_name[:40]}")
    lines.append("")

    return "\n".join(lines)


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Audit LogScale/NG-SIEM parsers for ECS, CPS, and best practices compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s parser.yaml                    # Audit single parser file
  %(prog)s ./parsers/ --recursive         # Audit directory
  %(prog)s --deployed                     # Audit all deployed parsers
  %(prog)s --deployed --export ./out      # Export deployed parsers and audit
  %(prog)s --deployed --summary           # Show summary only

Environment Variables:
  FALCON_CLIENT_ID     - CrowdStrike API Client ID
  FALCON_CLIENT_SECRET - CrowdStrike API Client Secret
        """
    )

    parser.add_argument("path", nargs="?", help="Parser file or directory to audit")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Recursively audit directory")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--min-score", type=int, default=0,
                        help="Only show parsers below this score")
    parser.add_argument("--summary", action="store_true",
                        help="Show summary report only")

    # API options
    parser.add_argument("--deployed", action="store_true",
                        help="Audit deployed custom parsers from NG-SIEM API")
    parser.add_argument("--discover", action="store_true",
                        help="Discover all parsers in use by querying SIEM data")
    parser.add_argument("--client-id", help="CrowdStrike API Client ID")
    parser.add_argument("--client-secret", help="CrowdStrike API Client Secret")
    parser.add_argument("--export", metavar="DIR",
                        help="Export deployed parsers to directory")
    parser.add_argument("--time-range", default="7d",
                        help="Time range for parser discovery (default: 7d)")

    args = parser.parse_args()

    if not args.path and not args.deployed and not args.discover:
        parser.print_help()
        sys.exit(1)

    # Handle discovery mode
    if args.discover:
        # Use provided credentials or environment variables
        client_id = args.client_id or os.environ.get("FALCON_CLIENT_ID")
        client_secret = args.client_secret or os.environ.get("FALCON_CLIENT_SECRET")

        if not client_id or not client_secret:
            print("Error: API credentials required for discovery", file=sys.stderr)
            print("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables", file=sys.stderr)
            print("Or use --client-id and --client-secret arguments", file=sys.stderr)
            sys.exit(1)

        client = DeployedParserClient(
            client_id=client_id,
            client_secret=client_secret
        )
        if not client.connect():
            print("Failed to connect to NG-SIEM API", file=sys.stderr)
            sys.exit(1)

        print(f"Discovering parsers in use ({args.time_range})...", file=sys.stderr)
        parsers = client.discover_parsers_in_use(args.time_range)

        print(f"\n{'='*70}")
        print(f" PARSER DISCOVERY REPORT")
        print(f"{'='*70}")
        print(f"Time Range: {args.time_range}")
        print(f"Parsers Found: {len(parsers)}")
        print()

        # Categorize parsers
        custom = [p for p in parsers if 'crawco' in p['name'].lower() or 'custom' in p['name'].lower() or 'crawford' in p['name'].lower()]
        crowdstrike = [p for p in parsers if 'falcon' in p['name'].lower() or 'crowdstrike' in p['name'].lower()]
        third_party = [p for p in parsers if p not in custom and p not in crowdstrike]

        print("CUSTOM PARSERS (likely editable)")
        print("-" * 40)
        if custom:
            for p in sorted(custom, key=lambda x: -x['event_count']):
                print(f"  {p['event_count']:>12,}  {p['name']}")
        else:
            print("  No custom parsers detected")
        print()

        print("CROWDSTRIKE PARSERS")
        print("-" * 40)
        for p in sorted(crowdstrike, key=lambda x: -x['event_count']):
            print(f"  {p['event_count']:>12,}  {p['name']}")
        print()

        print("THIRD-PARTY / CONNECTOR PARSERS")
        print("-" * 40)
        for p in sorted(third_party, key=lambda x: -x['event_count'])[:20]:
            print(f"  {p['event_count']:>12,}  {p['name']}")
        if len(third_party) > 20:
            print(f"  ... and {len(third_party) - 20} more")
        print()

        print("HOW TO EXPORT PARSERS FOR AUDITING")
        print("-" * 40)
        print("""
  The API only exposes custom parsers created via API.
  To audit your deployed parsers:

  1. Go to Falcon Console > Next-Gen SIEM > Settings > Parsers
  2. Click on each parser you want to audit
  3. Click 'Export' or copy the YAML content
  4. Save to a .yaml file
  5. Run: python parser_auditor.py /path/to/parsers/

  For custom parsers (crawco-*, custom-*), export is especially
  important to ensure CPS compliance for case management.
""")
        sys.exit(0)

    auditor = ParserAuditor(verbose=args.verbose)
    results = []

    if args.deployed:
        # Audit deployed parsers via API
        client = DeployedParserClient(
            client_id=args.client_id,
            client_secret=args.client_secret
        )

        if not client.connect():
            print("Failed to connect to NG-SIEM API", file=sys.stderr)
            print("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables", file=sys.stderr)
            sys.exit(1)

        print("Fetching deployed parsers...", file=sys.stderr)
        parsers = client.list_parsers()
        print(f"Found {len(parsers)} deployed parsers", file=sys.stderr)

        if args.export:
            export_dir = Path(args.export)
            export_dir.mkdir(parents=True, exist_ok=True)
            print(f"Exporting parsers to {export_dir}", file=sys.stderr)

        for i, parser_info in enumerate(parsers):
            parser_name = parser_info.get("name", "Unknown")
            if args.verbose:
                print(f"Auditing [{i+1}/{len(parsers)}]: {parser_name}", file=sys.stderr)

            result = auditor.audit_deployed_parser(parser_info, client)
            results.append(result)

            # Export if requested
            if args.export:
                template = client.get_parser_template(parser_info.get("id", ""))
                if template:
                    safe_name = re.sub(r'[^\w\-]', '_', parser_name)
                    export_path = export_dir / f"{safe_name}.yaml"
                    with open(export_path, 'w') as f:
                        f.write(template)

        if args.export:
            print(f"Exported {len(results)} parsers to {args.export}", file=sys.stderr)

    elif args.path:
        path = Path(args.path)

        if path.is_file():
            results.append(auditor.audit_file(str(path)))
        elif path.is_dir():
            pattern = "**/*.yaml" if args.recursive else "*.yaml"
            yaml_files = list(path.glob(pattern))
            for i, yaml_file in enumerate(yaml_files):
                if args.verbose:
                    print(f"Auditing [{i+1}/{len(yaml_files)}]: {yaml_file}", file=sys.stderr)
                results.append(auditor.audit_file(str(yaml_file)))
        else:
            print(f"Error: Path not found: {args.path}", file=sys.stderr)
            sys.exit(1)

    # Filter by min score
    if args.min_score > 0:
        results = [r for r in results if r.overall_score < args.min_score]

    # Generate output
    if args.summary:
        output = generate_summary_report(results)
    else:
        output_lines = []
        for result in results:
            output_lines.append(generate_report(result, args.format))
        output = "\n\n".join(output_lines)

        # Add summary at the end if multiple results
        if len(results) > 1 and args.format == "text":
            output += "\n\n" + generate_summary_report(results)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Report written to: {args.output}")
    else:
        print(output)

    # Exit with error code if any errors found
    total_errors = sum(r.error_count() for r in results)
    sys.exit(1 if total_errors > 0 else 0)


if __name__ == "__main__":
    main()
