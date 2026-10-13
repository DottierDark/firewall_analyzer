import json
import re
from typing import List, Dict


class PaloAltoAppIDHandler:
    """Loads and manages Palo Alto AppID database for service-to-port mapping"""

    def __init__(self, app_id_file: str = "palo_alto_applipedia.json"):
        self.app_id_database = {}
        self.app_name_to_ports = {}
        self.app_metadata_by_name = {}
        self.load_app_id_database(app_id_file)

    def load_app_id_database(self, app_id_file: str):
        """Load Palo Alto AppID database from JSON file"""
        try:
            with open(app_id_file, 'r', encoding='utf-8') as f:
                apps = json.load(f)

            if not isinstance(apps, list):
                apps = [apps]

            for app in apps:
                app_id = app.get('id')
                ports = self._extract_ports_from_app(app)
                metadata = self._build_metadata(app, ports)

                # Index by ID
                if app_id:
                    self.app_id_database[str(app_id)] = metadata

                # Index by every alias (name, appName_js, sanitized variants)
                for alias in metadata['aliases']:
                    self.app_name_to_ports[alias] = ports
                    self.app_metadata_by_name[alias] = metadata

            print(f"✓ Loaded {len(self.app_id_database)} applications from Palo Alto AppID database")

        except FileNotFoundError:
            print(f"⚠ Warning: Palo Alto AppID database file '{app_id_file}' not found")
            print("  Service names will not be converted to ports")
        except json.JSONDecodeError as e:
            print(f"⚠ Warning: Error parsing AppID database: {e}")

    def _extract_ports_from_app(self, app: Dict) -> List[str]:
        """Extract port information from app definition"""
        ports = []

        # Check standard_ports in characteristics
        if 'characteristics' in app:
            characteristics = app['characteristics']
            if isinstance(characteristics, dict):
                standard_ports_str = characteristics.get('standard_ports', '')
            else:
                standard_ports_str = str(characteristics)

            # Parse port information like "tcp/3468,6346,11300" or "tcp/80,443"
            if standard_ports_str:
                # Extract just the port part
                port_match = re.search(r'(tcp|udp)/([\d,\-/]+)', standard_ports_str, re.IGNORECASE)
                if port_match:
                    protocol = port_match.group(1).lower()
                    port_spec = port_match.group(2)

                    # Parse individual ports and ranges
                    port_items = port_spec.split(',')
                    for item in port_items:
                        item = item.strip()
                        if '-' in item:
                            # Port range like 1560-1591
                            try:
                                start, end = item.split('-')
                                ports.append(f"{protocol}/{item}")
                            except ValueError:
                                ports.append(f"{protocol}/{item}")
                        else:
                            # Single port
                            ports.append(f"{protocol}/{item}")

        return ports if ports else ['any']

    def _build_metadata(self, app: Dict, ports: List[str]) -> Dict:
        """Create normalized metadata entry for an application"""
        characteristics = app.get('characteristics', {}) or {}
        risk_value = self._parse_risk_value(app.get('risk') or characteristics.get('risk'))

        display_name = (app.get('name') or '').strip()
        app_js = (app.get('appName_js') or '').strip()

        metadata = {
            'id': app.get('id'),
            'display_name': display_name or app_js,
            'app_name_js': app_js,
            'ports': ports,
            'category': app.get('category') or characteristics.get('category', ''),
            'subcategory': app.get('subcategory') or characteristics.get('subcategory', ''),
            'technology': app.get('technology') or characteristics.get('technology', ''),
            'risk': risk_value,
            'description': app.get('description', ''),
            'references': app.get('references', []),
            'raw': app,
            'aliases': self._generate_aliases(display_name, app_js)
        }

        return metadata

    def _generate_aliases(self, *names: str) -> List[str]:
        """Generate a list of normalized aliases for lookup"""
        aliases = set()

        for name in names:
            if not name:
                continue
            lowered = name.strip().lower()
            if not lowered:
                continue
            aliases.add(self._normalize_key(lowered))

            # Add variants
            variants = {
                lowered.replace(' ', ''),
                lowered.replace(' ', '-'),
                lowered.replace(' ', '_'),
                lowered.replace('-', ''),
                lowered.replace('_', ''),
                lowered.replace('-', '_'),
                lowered.replace('_', '-')
            }

            aliases.update(self._normalize_key(variant) for variant in variants if variant)

        return list(aliases)

    @staticmethod
    def _normalize_key(value: str) -> str:
        """Normalize lookup keys for consistent matching"""
        return value.strip().lower()

    @staticmethod
    def _parse_risk_value(value) -> int:
        """Normalize risk value to int between 0-5"""
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            digits = ''.join(ch for ch in value if ch.isdigit())
            if digits:
                try:
                    return int(digits)
                except ValueError:
                    return 0
        return 0

    def get_ports_for_service(self, service_name: str) -> List[str]:
        """Get ports for a given service name"""
        normalized = self._normalize_key(service_name)

        # Direct alias lookup
        if normalized in self.app_name_to_ports:
            return self.app_name_to_ports[normalized]

        # Partial / contains matching
        for alias, ports in self.app_name_to_ports.items():
            if alias in normalized or normalized in alias:
                return ports

        metadata = self.get_application_metadata(service_name)
        if metadata:
            return metadata.get('ports', ['any'])

        # Not found in database
        return [service_name]

    def resolve_services_to_ports(self, services: List[str]) -> List[str]:
        """Convert service names to ports (annotated with original service)"""
        resolved_ports = []

        for service in services:
            service_normalized = service.strip()
            if not service_normalized:
                continue

            if service_normalized.lower() == 'any':
                resolved_ports.append('any')
                continue

            ports = self.get_ports_for_service(service_normalized)
            metadata = self.get_application_metadata(service_normalized)
            display_label = service_normalized
            if metadata:
                display_label = metadata.get('display_name') or metadata.get('app_name_js') or service_normalized

            # If AppID lookup failed, keep the original value
            if len(ports) == 1 and ports[0] == service_normalized:
                resolved_ports.append(display_label)
                continue

            for port in ports:
                resolved_ports.append(f"{display_label} ({port})")

        # Remove duplicates while maintaining order
        seen = set()
        unique_ports = []
        for port in resolved_ports:
            if port not in seen:
                seen.add(port)
                unique_ports.append(port)

        return unique_ports if unique_ports else ['any']

    def get_application_metadata(self, application_name: str) -> Dict:
        """Return metadata for an application name if available"""
        if not application_name:
            return {}

        normalized = self._normalize_key(application_name)

        if normalized in self.app_metadata_by_name:
            return self.app_metadata_by_name[normalized]

        for alias, metadata in self.app_metadata_by_name.items():
            if alias in normalized or normalized in alias:
                return metadata

        return {}

    def get_application_risk(self, application_name: str) -> int:
        """Get Palo Alto risk rating (0-5) for an application"""
        metadata = self.get_application_metadata(application_name)
        return metadata.get('risk', 0) if metadata else 0