from typing import List, Dict
from ..core.models import FirewallRule


class ExternalCommunicationsAnalyzer:

    def analyze_rules(
        self,
        rules: List[FirewallRule],
        external_zones: List[str]
    ) -> Dict:

        external_zones = {
            zone.strip().lower()
            for zone in external_zones
        }

        external_rules = []
        potential_external_rules = []

        for rule in rules:

            if rule.disabled:
                continue

            if rule.action.lower() != "allow":
                continue

            source_zones = [
                z.lower()
                for z in rule.source_zones
            ]

            destination_zones = [
                z.lower()
                for z in rule.dest_zones
            ]

            matched = False

            # Source zone matches external zone
            if any(
                zone in external_zones
                for zone in source_zones
            ):
                matched = True

            # Destination zone matches external zone
            if any(
                zone in external_zones
                for zone in destination_zones
            ):
                matched = True

            # any = potential external
            if (
                "any" in source_zones
                or "any" in destination_zones
            ):
                potential_external_rules.append(rule)
                matched = True

            if matched:
                external_rules.append(rule)

        return {
            "external_rules": external_rules,
            "potential_external_rules": potential_external_rules,
            "total_external_rules": len(external_rules),
            "total_potential_external": len(
                potential_external_rules
            )
        }