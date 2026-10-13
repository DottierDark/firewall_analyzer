import ipaddress
from typing import Tuple, Any, Dict


class IPAddressUtils:
    """Utilities for IP address and subnet operations"""

    @staticmethod
    def parse_ip_or_subnet(address: str) -> Tuple[bool, Any]:
        """
        Parse IP address or subnet notation
        Returns (is_valid, ipaddress_object or None)
        """
        address = address.strip().lower()

        if address in ['any', 'all', '*', '0.0.0.0']:
            return True, None

        try:
            if '/' in address:
                network = ipaddress.ip_network(address, strict=False)
                return True, network
            else:
                ip = ipaddress.ip_address(address)
                return True, ip
        except ValueError:
            return False, None

    @staticmethod
    def subnet_overlap_check(subnet1: str, subnet2: str) -> Dict[str, Any]:
        """
        Check if two subnets overlap
        Returns: {overlaps: bool, overlap_type: str, details: dict}
        """
        valid1, obj1 = IPAddressUtils.parse_ip_or_subnet(subnet1)
        valid2, obj2 = IPAddressUtils.parse_ip_or_subnet(subnet2)

        if not valid1 or not valid2 or obj1 is None or obj2 is None:
            return {'overlaps': False, 'overlap_type': 'invalid', 'details': {}}

        try:
            if isinstance(obj1, ipaddress.IPv4Address):
                net1 = ipaddress.ip_network(obj1, strict=False)
            else:
                net1 = obj1

            if isinstance(obj2, ipaddress.IPv4Address):
                net2 = ipaddress.ip_network(obj2, strict=False)
            else:
                net2 = obj2

            if net1 == net2:
                return {
                    'overlaps': True,
                    'overlap_type': 'identical',
                    'details': {'subnet1': str(net1), 'subnet2': str(net2)}
                }

            if net1.subnet_of(net2):
                return {
                    'overlaps': True,
                    'overlap_type': 'contained_in',
                    'details': {
                        'subnet1': str(net1),
                        'subnet2': str(net2),
                        'relationship': f"{net1} is contained in {net2}"
                    }
                }

            if net2.subnet_of(net1):
                return {
                    'overlaps': True,
                    'overlap_type': 'contains',
                    'details': {
                        'subnet1': str(net1),
                        'subnet2': str(net2),
                        'relationship': f"{net2} is contained in {net1}"
                    }
                }

            if net1.overlaps(net2):
                return {
                    'overlaps': True,
                    'overlap_type': 'partial_overlap',
                    'details': {'subnet1': str(net1), 'subnet2': str(net2)}
                }

            return {'overlaps': False, 'overlap_type': 'no_overlap', 'details': {}}

        except Exception as e:
            return {'overlaps': False, 'overlap_type': 'error', 'details': {'error': str(e)}}

    @staticmethod
    def ip_in_subnet(ip_address: str, subnet: str) -> bool:
        """Check if IP address is within subnet"""
        valid_ip, obj_ip = IPAddressUtils.parse_ip_or_subnet(ip_address)
        valid_subnet, obj_subnet = IPAddressUtils.parse_ip_or_subnet(subnet)

        if not valid_ip or not valid_subnet or obj_ip is None or obj_subnet is None:
            return False

        try:
            if isinstance(obj_ip, ipaddress.IPv4Network):
                obj_ip = obj_ip.network_address

            if isinstance(obj_subnet, ipaddress.IPv4Address):
                obj_subnet = ipaddress.ip_network(obj_subnet, strict=False)

            return obj_ip in obj_subnet
        except Exception:
            return False

    @staticmethod
    def get_subnet_size(subnet: str) -> int:
        """Get number of hosts in subnet"""
        valid, obj = IPAddressUtils.parse_ip_or_subnet(subnet)

        if not valid or obj is None:
            return 0

        try:
            if isinstance(obj, ipaddress.IPv4Address):
                return 1
            else:
                return obj.num_addresses
        except Exception:
            return 0