import csv
import hashlib
from typing import List, Dict, Any, Optional

from ..config.manager import ConfigurationManager
from ..core.models import VendorType, FirewallRule
from .appid_handler import PaloAltoAppIDHandler


class SchemaNormalizer:
    """Normalize firewall rule data from different vendor formats to a common schema"""

    def __init__(self, vendor_type: VendorType = VendorType.GENERIC,
                 config_manager: ConfigurationManager = None,
                 app_id_handler: PaloAltoAppIDHandler = None):
        self.vendor_type = vendor_type
        self.config_manager = config_manager or ConfigurationManager()
        self.app_id_handler = app_id_handler
        self.schema = self.config_manager.get_vendor_schema(vendor_type)
        self.field_mappings = self.schema['field_mappings']

    def detect_vendor(self, fieldnames: List[str]) -> VendorType:
        """Auto-detect vendor type based on field names"""
        fieldnames_lower = [f.lower().replace(' ', '_').replace('-', '_') for f in fieldnames]

        palo_alto_indicators = ['column1', 'source_zone', 'destination_zone', 'source_address']
        if all(indicator in fieldnames_lower for indicator in palo_alto_indicators[:3]):
            return VendorType.PALO_ALTO

        cisco_indicators = ['access_list', 'source', 'destination', 'protocol']
        if any(indicator in fieldnames_lower for indicator in cisco_indicators):
            return VendorType.CISCO_ASA

        fortinet_indicators = ['policyid', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr']
        if all(indicator in fieldnames_lower for indicator in fortinet_indicators):
            return VendorType.FORTINET

        checkpoint_indicators = ['rule_number', 'source', 'destination', 'service']
        if all(indicator in fieldnames_lower for indicator in checkpoint_indicators):
            return VendorType.CHECKPOINT

        juniper_indicators = ['from_zone', 'to_zone', 'source_address', 'destination_address']
        if all(indicator in fieldnames_lower for indicator in juniper_indicators):
            return VendorType.JUNIPER_SRX

        return VendorType.GENERIC

    def normalize_row(self, row: Dict[str, str]) -> Dict[str, Any]:
        """Normalize a single row of firewall rule data"""
        normalized = {}

        for normalized_field, vendor_field in self.field_mappings.items():
            vendor_field_lower = vendor_field.lower().replace(' ', '_').replace('-', '_')
            value = None

            if vendor_field in row:
                value = row[vendor_field]
            else:
                for field_name, field_value in row.items():
                    field_name_normalized = field_name.lower().replace(' ', '_').replace('-', '_')
                    if field_name_normalized == vendor_field_lower:
                        value = field_value
                        break

            normalized[normalized_field] = value if value is not None else ''

        normalized = self._apply_vendor_transformations(normalized, row)
        return normalized

    def _apply_vendor_transformations(self, normalized: Dict[str, Any],
                                     original_row: Dict[str, str]) -> Dict[str, Any]:
        """Apply vendor-specific data transformations"""
        if self.vendor_type == VendorType.PALO_ALTO or (self.app_id_handler and self.vendor_type == VendorType.GENERIC):
            # Handle Palo Alto specific transformations

            if 'disabled' in normalized and normalized['disabled']:
                # Check for [Disabled] marker in the rule name or disabled field
                normalized['disabled'] = '[Disabled]' in normalized['disabled'] or \
                                        normalized['disabled'].lower() == 'yes'
            else:
                normalized['disabled'] = False

            for field in ['source_zones', 'dest_zones', 'source_addresses', 'dest_addresses',
                         'source_users', 'services', 'applications']:
                if normalized.get(field):
                    normalized[field] = self._parse_multiple_values(normalized[field])
                else:
                    normalized[field] = ['any']

            # Convert service names to ports using AppID database
            if self.app_id_handler and normalized.get('services'):
                normalized['services'] = self.app_id_handler.resolve_services_to_ports(normalized['services'])

        elif self.vendor_type == VendorType.CISCO_ASA:
            if 'disabled' in normalized and normalized['disabled']:
                normalized['disabled'] = normalized['disabled'].lower() == 'inactive'
            else:
                normalized['disabled'] = False

            for field in ['source_addresses', 'dest_addresses']:
                if normalized.get(field):
                    normalized[field] = self._parse_multiple_values(normalized[field])
                else:
                    normalized[field] = ['any']

            if normalized.get('services'):
                normalized['services'] = self._parse_multiple_values(normalized['services'])
            else:
                normalized['services'] = ['any']

        elif self.vendor_type == VendorType.FORTINET:
            if 'disabled' in normalized and normalized['disabled']:
                normalized['disabled'] = normalized['disabled'].lower() != 'enable'
            else:
                normalized['disabled'] = True

            for field in ['source_zones', 'dest_zones', 'source_addresses', 'dest_addresses', 'services']:
                if normalized.get(field):
                    normalized[field] = self._parse_multiple_values(normalized[field])
                else:
                    normalized[field] = ['any']

        elif self.vendor_type == VendorType.CHECKPOINT:
            if 'disabled' in normalized and normalized['disabled']:
                normalized['disabled'] = normalized['disabled'].lower() != 'true'
            else:
                normalized['disabled'] = False

            for field in ['source_addresses', 'dest_addresses', 'services']:
                if normalized.get(field):
                    normalized[field] = self._parse_multiple_values(normalized[field])
                else:
                    normalized[field] = ['any']

        elif self.vendor_type == VendorType.JUNIPER_SRX:
            for field in ['source_zones', 'dest_zones', 'source_addresses', 'dest_addresses', 'applications']:
                if normalized.get(field):
                    normalized[field] = self._parse_multiple_values(normalized[field])
                else:
                    normalized[field] = ['any']

        else:
            for field in ['source_zones', 'dest_zones', 'source_addresses', 'dest_addresses',
                         'source_users', 'services', 'applications']:
                if normalized.get(field):
                    normalized[field] = self._parse_multiple_values(normalized[field])
                else:
                    normalized[field] = ['any']

            if 'disabled' in normalized:
                normalized['disabled'] = str(normalized['disabled']).lower() in \
                                        ['true', 'yes', '1', 'enabled'] or \
                                        '[Disabled]' in str(normalized['disabled'])
            else:
                normalized['disabled'] = False

        for field in ['source_zones', 'dest_zones', 'source_addresses', 'dest_addresses',
                     'source_users', 'services', 'applications', 'action']:
            if field not in normalized or not normalized[field]:
                if field in ['source_zones', 'dest_zones', 'source_addresses',
                            'dest_addresses', 'source_users', 'services', 'applications']:
                    normalized[field] = ['any']
                else:
                    normalized[field] = 'allow'

        if 'rule_id' not in normalized or not normalized['rule_id']:
            normalized['rule_id'] = hashlib.md5(str(original_row).encode()).hexdigest()[:8]

        if 'name' not in normalized or not normalized['name']:
            normalized['name'] = f"Rule_{normalized['rule_id']}"

        return normalized

    def _parse_multiple_values(self, value_string: str) -> List[str]:
        """Parse values that may contain multiple items separated by common delimiters"""
        if not value_string or value_string.lower() in ['any', 'all']:
            return ['any']

        delimiters = [';', ',', '|', '\n']
        values = [value_string]

        for delimiter in delimiters:
            new_values = []
            for value in values:
                new_values.extend(value.split(delimiter))
            values = new_values

        cleaned_values = []
        for item in values:
            item = item.strip()
            if item and item.lower() not in ['', 'none', 'null']:
                cleaned_values.append(item)

        return cleaned_values if cleaned_values else ['any']


class MultiVendorCSVParser:
    """Parse CSV files from different firewall vendors into normalized FirewallRule objects"""

    def __init__(self, vendor_type: VendorType = None, config_manager: ConfigurationManager = None,
                 use_hashed=True, debug=False, app_id_handler: PaloAltoAppIDHandler = None):
        self.vendor_type = vendor_type
        self.config_manager = config_manager or ConfigurationManager()
        self.app_id_handler = app_id_handler
        self.use_hashed = use_hashed
        self.debug = debug
        self.schema_normalizer = None
        self.hashed_columns = {}

    def parse_csv(self, csv_file_path: str) -> List[FirewallRule]:
        """Parse CSV file into normalized FirewallRule objects"""
        rules = []

        with open(csv_file_path, 'r', encoding='utf-8') as csvfile:
            first_line = csvfile.readline()
            if not first_line.startswith('Column1'):
                csvfile.seek(0)

            reader = csv.DictReader(csvfile)

            if self.vendor_type is None:
                self.vendor_type = self._detect_vendor_from_headers(reader.fieldnames)
                if self.debug:
                    print(f"Auto-detected vendor: {self.vendor_type.value}")

            self.schema_normalizer = SchemaNormalizer(self.vendor_type, self.config_manager, self.app_id_handler)
            self.hashed_columns = self._detect_hashed_columns(reader.fieldnames)

            for row in reader:
                normalized_data = self.schema_normalizer.normalize_row(row)

                rule = FirewallRule(
                    id=normalized_data['rule_id'],
                    name=normalized_data['name'],
                    source_zones=normalized_data['source_zones'],
                    dest_zones=normalized_data['dest_zones'],
                    source_addresses=normalized_data['source_addresses'],
                    dest_addresses=normalized_data['dest_addresses'],
                    source_users=normalized_data.get('source_users', ['any']),
                    services=normalized_data['services'],
                    applications=normalized_data.get('applications', ['any']),
                    action=normalized_data['action'],
                    disabled=normalized_data.get('disabled', False),
                    rule_usage=normalized_data.get('rule_usage', ''),
                    modified=normalized_data.get('modified', ''),
                    raw_data=row,
                    vendor_type=self.vendor_type
                )
                rules.append(rule)

        return rules

    def _detect_vendor_from_headers(self, fieldnames: List[str]) -> VendorType:
        """Detect vendor type from CSV headers"""
        return self.schema_normalizer.detect_vendor(fieldnames) if self.schema_normalizer \
               else SchemaNormalizer().detect_vendor(fieldnames)

    def _detect_hashed_columns(self, fieldnames):
        """Detect columns that have hashed counterparts"""
        hashed_mapping = {}
        regular_columns = []
        hashed_columns_list = []

        for field in fieldnames:
            if 'hashed' in field.lower() or '_hash' in field.lower():
                hashed_columns_list.append(field)
            else:
                regular_columns.append(field)

        for regular in regular_columns:
            for hashed in hashed_columns_list:
                regular_clean = regular.lower().replace(' ', '_').replace('-', '_')
                hashed_clean = hashed.lower().replace(' ', '_').replace('-', '_')

                if regular_clean in hashed_clean:
                    hashed_mapping[regular] = hashed
                    if self.debug:
                        print(f"Mapped '{regular}' to hashed column '{hashed}'")

        return hashed_mapping