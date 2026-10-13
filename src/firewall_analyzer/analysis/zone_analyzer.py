from typing import List, Dict, Any, Optional

from ..core.models import FirewallRule
from ..utils.ip_utils import IPAddressUtils


class ZoneBasedAnalyzer:
    """Analyzes firewall rules by network zones"""

    def __init__(self, zone_config: Dict):
        self.zones = zone_config.get('zones', {})
        self._build_subnet_to_zone_mapping()

    def _build_subnet_to_zone_mapping(self):
        """Build mapping of subnets to zones for fast lookup"""
        self.subnet_to_zone = {}
        self.all_subnets = []

        for zone_id, zone_data in self.zones.items():
            for subnet in zone_data.get('subnets', []):
                self.subnet_to_zone[subnet] = zone_id
                self.all_subnets.append(subnet)

    def identify_zone_for_address(self, address: str) -> Optional[str]:
        """Identify which zone an IP address belongs to"""
        if address.lower() in ['any', 'all', '*', '0.0.0.0']:
            return 'external'

        for subnet in self.all_subnets:
            if IPAddressUtils.ip_in_subnet(address, subnet):
                return self.subnet_to_zone[subnet]

        return None

    def identify_zone_for_subnet(self, subnet: str) -> Optional[str]:
        """Identify which zone a subnet belongs to"""
        if subnet.lower() in ['any', 'all', '*', '0.0.0.0']:
            return 'external'

        if subnet in self.subnet_to_zone:
            return self.subnet_to_zone[subnet]

        for zone_subnet in self.all_subnets:
            overlap = IPAddressUtils.subnet_overlap_check(subnet, zone_subnet)
            if overlap['overlaps']:
                return self.subnet_to_zone[zone_subnet]

        return None

    def get_rules_for_zone_pair(self, rules: List[FirewallRule],
                               source_zone: str, dest_zone: str) -> List[FirewallRule]:
        """Get all rules for specific source → destination zone pair"""
        matching_rules = []

        for rule in rules:
            rule_source_zones = set()
            rule_dest_zones = set()

            for addr in rule.source_addresses:
                zone = self.identify_zone_for_address(addr) or self.identify_zone_for_subnet(addr)
                if zone:
                    rule_source_zones.add(zone)

            for addr in rule.dest_addresses:
                zone = self.identify_zone_for_address(addr) or self.identify_zone_for_subnet(addr)
                if zone:
                    rule_dest_zones.add(zone)

            if (source_zone in rule_source_zones or source_zone == 'any') and \
               (dest_zone in rule_dest_zones or dest_zone == 'any'):
                matching_rules.append(rule)

        return matching_rules

    def get_rules_for_ip(self, rules: List[FirewallRule], ip_address: str) -> List[FirewallRule]:
        """Get all rules connected to specific IP address or subnet"""
        matching_rules = []

        for rule in rules:
            for addr in rule.source_addresses + rule.dest_addresses:
                if IPAddressUtils.ip_in_subnet(ip_address, addr):
                    matching_rules.append(rule)
                    break

        return matching_rules

    def get_zone_summary(self, rules: List[FirewallRule]) -> Dict[str, Any]:
        """Generate summary of rules by zone pair"""
        zone_summary = {}

        for rule in rules:
            source_zones = set()
            dest_zones = set()

            for addr in rule.source_addresses:
                zone = self.identify_zone_for_address(addr) or self.identify_zone_for_subnet(addr)
                if zone:
                    source_zones.add(zone)

            for addr in rule.dest_addresses:
                zone = self.identify_zone_for_address(addr) or self.identify_zone_for_subnet(addr)
                if zone:
                    dest_zones.add(zone)

            for src_zone in source_zones:
                for dst_zone in dest_zones:
                    pair = f"{src_zone} → {dst_zone}"
                    if pair not in zone_summary:
                        zone_summary[pair] = {
                            'allow_rules': 0,
                            'deny_rules': 0,
                            'total_rules': 0,
                            'rules': []
                        }

                    if rule.action.lower() == 'allow':
                        zone_summary[pair]['allow_rules'] += 1
                    else:
                        zone_summary[pair]['deny_rules'] += 1

                    zone_summary[pair]['total_rules'] += 1
                    zone_summary[pair]['rules'].append(rule.id)

        return zone_summary