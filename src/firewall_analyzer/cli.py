import argparse
import json
import sys
from datetime import datetime

from .config.manager import ConfigurationManager
from .core.models import VendorType
from .data.appid_handler import PaloAltoAppIDHandler
from .data.parser import MultiVendorCSVParser
from .orchestrator import EnhancedFirewallRuleAnalyzer
from .reporting.html_generator import EnhancedHTMLReportGenerator


def main():
    """Enhanced main function with configuration management"""
    parser = argparse.ArgumentParser(
        description='Complete Enhanced Multi-Vendor Firewall Rules Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.csv report.html
  %(prog)s --vendor palo_alto input.csv report.html
  %(prog)s --field-mapping field_mapping.json input.csv report.html
  %(prog)s --zone-config zone_config.json input.csv report.html
  %(prog)s --export-configs . input.csv report.html
  %(prog)s --export-json analysis.json input.csv report.html
  %(prog)s --group-findings input.csv report.html

Features:
  - Configuration-driven field mapping for all vendor formats
  - Palo Alto AppID database integration for service-to-port conversion
  - Zone-based traffic analysis with complete zone matrix
  - Full rule visibility with expandable rule details
  - Subnet overlap detection and hidden access pattern analysis
  - Intelligent filtering (disabled and catch-all DENY exclusion)
  - Advanced HTML reporting with interactive filtering
  - Excel-like search and sort capabilities
  - Rule grouping by name with consolidated analysis
  - Comprehensive risk scoring with detailed calculations
        """
    )

    parser.add_argument('input_csv', help='Path to input CSV file')
    parser.add_argument('output_report', help='Path to output HTML report file')
    parser.add_argument('--vendor', choices=[vt.value for vt in VendorType],
                       help='Specify firewall vendor type')
    parser.add_argument('--field-mapping', type=str,
                       help='Path to JSON field mapping configuration')
    parser.add_argument('--zone-config', type=str,
                       help='Path to JSON zone configuration')
    parser.add_argument('--analysis-config', type=str,
                       help='Path to JSON analysis scoring configuration')
    parser.add_argument('--appid-db', type=str, default='palo_alto_applipedia.json',
                       help='Path to Palo Alto AppID database JSON file (default: palo_alto_applipedia.json)')
    parser.add_argument('--export-json', type=str,
                       help='Export analysis results to JSON file')
    parser.add_argument('--export-configs', type=str,
                       help='Export default configuration templates')
    parser.add_argument('--group-findings', action='store_true',
                       help='Group findings by rule name in report')
    parser.add_argument('--high-risk-threshold', type=int, default=70,
                       help='Threshold score for high risk')
    parser.add_argument('--medium-risk-threshold', type=int, default=40,
                       help='Threshold score for medium risk')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()

    try:
        config_manager = ConfigurationManager()

        if args.export_configs:
            print(f"Exporting configuration templates to {args.export_configs}...")
            config_manager.save_default_configs(args.export_configs)
            print("\n✓ Configuration templates exported successfully!")
            return 0

        print("Loading configurations...")
        field_mapping_config = config_manager.load_field_mapping_config(args.field_mapping)
        zone_config = config_manager.load_zone_config(args.zone_config)
        analysis_config = config_manager.load_analysis_config(args.analysis_config)

        # Initialize Palo Alto AppID handler
        print("Loading Palo Alto AppID database...")
        app_id_handler = PaloAltoAppIDHandler(args.appid_db)
        print(app_id_handler)

        vendor_type = None
        if args.vendor:
            try:
                vendor_type = VendorType(args.vendor)
            except ValueError:
                print(f"Invalid vendor type: {args.vendor}")
                return 1

        print(f"\n{'='*70}")
        print(f"Processing firewall rules from {args.input_csv}")
        if vendor_type:
            print(f"Using vendor schema: {vendor_type.value}")
        else:
            print("Auto-detecting vendor schema...")

        csv_parser = MultiVendorCSVParser(
            vendor_type=vendor_type,
            config_manager=config_manager,
            use_hashed=False, # True
            debug=args.debug,
            app_id_handler=app_id_handler
        )
        rules = csv_parser.parse_csv(args.input_csv)
        print(f"✓ Parsed {len(rules)} rules from {rules[0].vendor_type.value if rules else 'unknown'} vendor")

        print("\nPerforming comprehensive security analysis...")
        analyzer = EnhancedFirewallRuleAnalyzer(
            high_risk_threshold=args.high_risk_threshold,
            medium_risk_threshold=args.medium_risk_threshold,
            zone_config=zone_config,
            config_manager=config_manager,
            analysis_config=analysis_config,
            app_id_handler=app_id_handler
        )
        analysis_results = analyzer.analyze_rules(rules)

        summary = analysis_results['summary']
        stats = analysis_results['statistics']

        print("\n" + "="*70)
        print("SECURITY ANALYSIS SUMMARY")
        print("="*70)
        print(f"\nOverall Security Health: {summary['overall_health']}")
        print(f"Total Issues Found: {summary['total_issues']}")
        print(f"  - Critical: {summary['critical_issues']}")
        print(f"  - High Risk: {summary['high_risk_issues']}")

        print(f"\nRule Analysis:")
        print(f"  Total Rules in File: {stats['all_rules_total']}")
        print(f"  Rules Analyzed: {stats['total_rules']}")
        print(f"  - Allow Rules: {stats['allow_rules']}")
        print(f"  - Disabled Rules (Excluded): {stats['disabled_rules_excluded']}")
        print(f"  - Deny Any/All Rules (Excluded): {stats['deny_any_rules_excluded']}")
        print(f"  - Unused Rules: {stats['unused_rules']}")

        print(f"\nNetwork Zone Analysis:")
        print(f"  Configured Zones: {len(zone_config.get('zones', {}))}")
        print(f"  Zone Traffic Pairs: {stats.get('zone_traffic_pairs', 0)}")

        if stats.get('zone_summary'):
            top_zones = sorted(stats['zone_summary'].items(),
                             key=lambda x: x[1]['total_rules'], reverse=True)[:5]
            print(f"\n  Top 5 Zone Pairs:")
            for pair, data in top_zones:
                print(f"    {pair}: {data['total_rules']} rules")

        print(f"\nVendor Distribution:")
        for vendor, count in stats.get('vendor_distribution', {}).items():
            print(f"  {vendor.replace('_', ' ').title()}: {count}")

        print("="*70)

        print(f"\nGenerating enhanced HTML report...")
        report_generator = EnhancedHTMLReportGenerator(
            detailed_mode=True,
            group_by_name=args.group_findings
        )
        report_generator.generate_report(analysis_results, args.output_report)

        if args.export_json:
            print(f"Exporting analysis results to {args.export_json}...")
            with open(args.export_json, 'w', encoding='utf-8') as f:
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'vendor_type': rules[0].vendor_type.value if rules else 'unknown',
                    'summary': analysis_results['summary'],
                    'statistics': {k: v for k, v in stats.items() if k not in ['zone_summary']},
                    'zone_summary': analysis_results.get('zone_summary', {}),
                    'findings': [],
                    'findings_by_rule': {}
                }

                for finding in analysis_results['findings']:
                    finding_data = {
                        'rule_id': finding.rule_id,
                        'rule_name': finding.rule_name,
                        'issue_type': finding.issue_type.value,
                        'risk_level': finding.risk_level.value,
                        'score': finding.score,
                        'description': finding.description,
                        'recommendation': finding.recommendation
                    }
                    export_data['findings'].append(finding_data)

                for rule_name, summary_data in analysis_results.get('findings_summary', {}).items():
                    export_data['findings_by_rule'][rule_name] = {
                        'total_findings': summary_data.get('total_findings', 0),
                        'total_score': summary_data.get('total_score', 0),
                        'risk_levels': dict(summary_data.get('risk_levels', {}))
                    }

                json.dump(export_data, f, indent=2)
                print(f"✓ Analysis results exported to {args.export_json}")

        if summary['critical_issues'] > 0:
            print("\n" + "!"*70)
            print("IMMEDIATE ACTION REQUIRED")
            print("!"*70)
            print(f"\n{summary['critical_issues']} CRITICAL security issues detected!")
            print("Review the detailed report for complete remediation guidance.")
            print("!"*70)

        print("\n✅ Analysis completed successfully!")
        print(f"📄 Report saved to: {args.output_report}")
        print(f"📊 Total findings: {stats['total_findings']}")
        if args.group_findings:
            print(f"📑 Findings grouped by rule name for consolidated analysis")

        return 0

    except FileNotFoundError as e:
        print(f"❌ Error: File not found - {e}")
        return 1
    except PermissionError as e:
        print(f"❌ Error: Permission denied - {e}")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())