import copy
import json
import os
from typing import Dict

from ..core.models import VendorType


class ConfigurationManager:
    """Manages all system configurations from JSON files"""

    DEFAULT_FIELD_MAPPING_SCHEMA = {
        "version": "1.0",
        "description": "Field mapping configuration for firewall rule normalization",
        "vendors": {
            "palo_alto": {
                "required_fields": ["Name", "Source Zone", "Destination Zone", "Source Address",
                                  "Destination Address", "Service", "Application", "Action"],
                "optional_fields": ["Rule Usage", "Modified", "Source User", "Disabled"],
                "field_mappings": {
                    "rule_id": "Column1",
                    "name": "Name",
                    "source_zones": "Source Zone",
                    "dest_zones": "Destination Zone",
                    "source_addresses": "Source Address",
                    "dest_addresses": "Destination Address",
                    "source_users": "Source User",
                    "services": "Service",
                    "applications": "Application",
                    "action": "Action",
                    "disabled": "Disabled",
                    "rule_usage": "Rule Usage",
                    "modified": "Modified"
                }
            },
            "cisco_asa": {
                "required_fields": ["access-list", "action", "protocol", "source", "destination"],
                "optional_fields": ["hitcnt", "line", "inactive"],
                "field_mappings": {
                    "rule_id": "line",
                    "name": "access-list",
                    "source_addresses": "source",
                    "dest_addresses": "destination",
                    "services": "protocol",
                    "action": "action",
                    "disabled": "inactive",
                    "rule_usage": "hitcnt"
                }
            },
            "fortinet": {
                "required_fields": ["policyid", "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "action"],
                "optional_fields": ["status", "schedule", "logtraffic", "comments"],
                "field_mappings": {
                    "rule_id": "policyid",
                    "source_zones": "srcintf",
                    "dest_zones": "dstintf",
                    "source_addresses": "srcaddr",
                    "dest_addresses": "dstaddr",
                    "services": "service",
                    "action": "action",
                    "disabled": "status",
                    "name": "comments"
                }
            },
            "checkpoint": {
                "required_fields": ["rule-number", "name", "source", "destination", "service", "action"],
                "optional_fields": ["enabled", "install-on", "time", "track"],
                "field_mappings": {
                    "rule_id": "rule-number",
                    "name": "name",
                    "source_addresses": "source",
                    "dest_addresses": "destination",
                    "services": "service",
                    "action": "action",
                    "disabled": "enabled"
                }
            },
            "juniper_srx": {
                "required_fields": ["name", "from-zone", "to-zone", "source-address", "destination-address", "application", "then"],
                "optional_fields": ["description", "permit", "deny"],
                "field_mappings": {
                    "rule_id": "name",
                    "name": "name",
                    "source_zones": "from-zone",
                    "dest_zones": "to-zone",
                    "source_addresses": "source-address",
                    "dest_addresses": "destination-address",
                    "applications": "application",
                    "action": "then"
                }
            },
            "generic": {
                "required_fields": ["name", "source_addresses", "dest_addresses", "services", "action"],
                "optional_fields": ["source_zones", "dest_zones", "applications", "disabled", "rule_usage"],
                "field_mappings": {
                    "rule_id": "id",
                    "name": "name",
                    "source_zones": "source_zones",
                    "dest_zones": "dest_zones",
                    "source_addresses": "source_addresses",
                    "dest_addresses": "dest_addresses",
                    "source_users": "source_users",
                    "services": "services",
                    "applications": "applications",
                    "action": "action",
                    "disabled": "disabled",
                    "rule_usage": "rule_usage",
                    "modified": "modified"
                }
            }
        }
    }

    DEFAULT_ZONE_CONFIG = {
        "version": "1.0",
        "description": "Network zone configuration for traffic analysis",
        "zones": {
            "office": {
                "name": "Office Network",
                "description": "Internal office network",
                "subnets": ["192.168.1.0/24", "192.168.2.0/24"],
                "zone_type": "internal",
                "priority": 1,
                "criticality": "low",
                "data_classification": "general"
            },
            "dmz": {
                "name": "DMZ",
                "description": "Demilitarized zone with public-facing services",
                "subnets": ["10.0.1.0/24"],
                "zone_type": "perimeter",
                "priority": 2,
                "criticality": "high",
                "data_classification": "public"
            },
            "ot": {
                "name": "Operational Technology",
                "description": "Industrial control systems network",
                "subnets": ["172.16.0.0/16"],
                "zone_type": "critical",
                "priority": 3,
                "criticality": "critical",
                "data_classification": "confidential"
            },
            "external": {
                "name": "External/Internet",
                "description": "External networks and internet",
                "subnets": ["0.0.0.0/0"],
                "zone_type": "external",
                "priority": 0,
                "criticality": "unknown",
                "data_classification": "untrusted"
            }
        }
    }

    DEFAULT_ANALYSIS_CONFIG = {
        "risk_scoring": {
            "high_risk_threshold": 70,
            "medium_risk_threshold": 40,
            "risk_weights": {
                "zone_risk": 0.3,
                "port_risk": 0.25,
                "protocol_risk": 0.2,
                "application_risk": 0.25
            }
        },
        "application_risk_levels": {},
        "application_risk_scoring": {
            "enabled": False
        }
    }

    def __init__(self, config_dir: str = "."):
        self.config_dir = config_dir
        self.field_mapping_config = None
        self.zone_config = None
        self.analysis_config = None

    def load_field_mapping_config(self, config_file: str = None) -> Dict:
        """Load field mapping configuration from JSON file or use default"""
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.field_mapping_config = json.load(f)
                    return self.field_mapping_config
            except Exception as e:
                print(f"Warning: Error loading field mapping config: {e}")
                print("Using default configuration...")
                self.field_mapping_config = self.DEFAULT_FIELD_MAPPING_SCHEMA
                return self.field_mapping_config
        else:
            self.field_mapping_config = self.DEFAULT_FIELD_MAPPING_SCHEMA
            return self.field_mapping_config

    def load_zone_config(self, config_file: str = None) -> Dict:
        """Load zone configuration from JSON file or use default"""
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.zone_config = json.load(f)
                    return self.zone_config
            except Exception as e:
                print(f"Warning: Error loading zone config: {e}")
                print("Using default configuration...")
                self.zone_config = self.DEFAULT_ZONE_CONFIG
                return self.zone_config
        else:
            self.zone_config = self.DEFAULT_ZONE_CONFIG
            return self.zone_config

    def save_default_configs(self, output_dir: str = "."):
        """Save default configuration templates to JSON files"""
        os.makedirs(output_dir, exist_ok=True)

        field_mapping_file = os.path.join(output_dir, "field_mapping_schema.json")
        zone_config_file = os.path.join(output_dir, "zone_config.json")
        analysis_config_file = os.path.join(output_dir, "analysis_config.json")

        try:
            with open(field_mapping_file, 'w', encoding='utf-8') as f:
                json.dump(self.DEFAULT_FIELD_MAPPING_SCHEMA, f, indent=2)
            print(f"✓ Field mapping schema template saved: {field_mapping_file}")
        except Exception as e:
            print(f"Error saving field mapping schema: {e}")

        try:
            with open(zone_config_file, 'w', encoding='utf-8') as f:
                json.dump(self.DEFAULT_ZONE_CONFIG, f, indent=2)
            print(f"✓ Zone configuration template saved: {zone_config_file}")
        except Exception as e:
            print(f"Error saving zone config: {e}")

        try:
            with open(analysis_config_file, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_config or self._default_analysis_config(), f, indent=2)
            print(f"✓ Analysis configuration template saved: {analysis_config_file}")
        except Exception as e:
            print(f"Error saving analysis config: {e}")

    def get_vendor_schema(self, vendor_type: VendorType) -> Dict:
        """Get vendor-specific schema from configuration"""
        if not self.field_mapping_config:
            self.load_field_mapping_config()

        vendor_value = vendor_type.value
        if vendor_value in self.field_mapping_config.get('vendors', {}):
            return self.field_mapping_config['vendors'][vendor_value]

        return self.field_mapping_config['vendors'].get('generic', {})

    def get_zones(self) -> Dict:
        """Get all configured zones"""
        if not self.zone_config:
            self.load_zone_config()

        return self.zone_config.get('zones', {})

    def load_analysis_config(self, config_file: str = None) -> Dict:
        """Load analysis configuration or fall back to defaults"""
        if self.analysis_config and not config_file:
            return self.analysis_config

        candidate_paths = []
        if config_file:
            candidate_paths.append(config_file)
        if self.config_dir:
            candidate_paths.append(os.path.join(self.config_dir, "analysis_config.json"))
        module_default = os.path.join(os.path.dirname(__file__), "analysis_config.json")
        if module_default not in candidate_paths:
            candidate_paths.append(module_default)

        for path in candidate_paths:
            if not path:
                continue
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        self.analysis_config = json.load(f)
                        return self.analysis_config
                except Exception as e:
                    print(f"Warning: Error loading analysis config from {path}: {e}")

        print("Warning: Analysis configuration not found - using defaults")
        self.analysis_config = self._default_analysis_config()
        return self.analysis_config

    def _default_analysis_config(self) -> Dict:
        """Return a deep copy of the default analysis configuration"""
        return copy.deepcopy(self.DEFAULT_ANALYSIS_CONFIG)