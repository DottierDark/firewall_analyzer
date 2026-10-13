import json
from datetime import datetime
from typing import Dict, Any, List

from ..core.models import SecurityFinding, FirewallRule, RiskLevel


class EnhancedHTMLReportGenerator:
    """Extended report generator with zone-based filtering and full rule visibility"""

    def __init__(self, detailed_mode=False, group_by_name=False):
        self.detailed_mode = detailed_mode
        self.group_by_name = group_by_name
        self.colors = {
            'signature_orange': '#EB8C00',
            'black': '#000000',
            'dark_grey': '#2C2C2C',
            'medium_grey': '#5A5A5A',
            'light_grey': '#E8E8E8',
            'very_light_grey': '#F5F5F5',
            'risk_critical': '#B71C1C',
            'risk_high': '#E65100',
            'risk_medium': '#F9A825',
            'risk_low': '#2E7D32',
            'risk_info': '#0277BD',
            'white': '#FFFFFF',
            'success': '#4CAF50',
            'warning': '#FF9800',
            'danger': '#F44336',
            'info': '#2196F3'
        }

    def generate_report(self, analysis_results: Dict[str, Any], output_file: str):
        """Generate enhanced HTML report with all new features"""
        html_content = self._generate_enhanced_html(analysis_results)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"\n✓ Enhanced HTML report generated: {output_file}")

    def _generate_enhanced_html(self, results: Dict[str, Any]) -> str:
        """Generate the complete enhanced HTML report"""
        summary = results['summary']
        stats = results['statistics']
        zone_summary = results.get('zone_summary', {})
        disabled_rules = results.get('disabled_rules', [])
        deny_rules = results.get('deny_rules', [])
        grouped_findings = results.get('grouped_findings', {})
        findings_summary = results.get('findings_summary', {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Firewall Rules Security Analysis Report</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <style>
        {self._get_css_styles()}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Multi-Vendor Firewall Rules Security Analysis Report</h1>
            <div class="report-meta">
                <span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span>Total Rules Analyzed: {stats['total_rules']} (of {stats['all_rules_total']} total)</span>
                <span>Total Findings: {stats['total_findings']}</span>
            </div>
        </header>

        {self._generate_executive_summary(summary, stats)}
        {self._generate_filtered_rules_notice(stats)}
        {self._generate_zone_based_analysis(zone_summary, results)}
        {self._generate_risk_distribution_charts(stats)}
        {self._generate_critical_findings(results)}
        {self._generate_recommendations(summary['recommendations'])}
        {self._generate_detailed_statistics(stats)}
        {self._generate_scoring_methodology()}
        {self._generate_zone_traffic_matrix(zone_summary)}
        {self._generate_grouped_findings_by_rule(grouped_findings, findings_summary) if self.group_by_name else ''}
        {self._generate_high_risk_rules_table(results['high_risk_rules'])}
        {self._generate_complete_findings_table(results['findings'])}
        {self._generate_disabled_rules_table(disabled_rules)}
        {self._generate_deny_rules_table(deny_rules)}
        {self._generate_full_rule_details_section(results.get('rules', []))}
        {self._generate_footer()}
    </div>

    <script>
        {self._get_enhanced_javascript(stats, zone_summary)}
    </script>
</body>
</html>"""
        return html

    def _get_css_styles(self) -> str:
        """Get CSS styles with zone and detailed rule styling"""
        return f"""
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, {self.colors['very_light_grey']} 0%, {self.colors['light_grey']} 100%);
            min-height: 100vh;
            padding: 20px;
            color: {self.colors['dark_grey']};
            line-height: 1.6;
        }}

        .container {{
            max-width: 1900px;
            margin: 0 auto;
            background: {self.colors['white']};
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.15);
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, {self.colors['signature_orange']} 0%, #D57800 100%);
            color: {self.colors['white']};
            padding: 40px;
            text-align: center;
            position: relative;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}

        .report-meta {{
            display: flex;
            justify-content: center;
            gap: 30px;
            font-size: 1em;
            opacity: 0.95;
            font-weight: 500;
            flex-wrap: wrap;
        }}

        .section {{
            padding: 40px;
            border-bottom: 2px solid {self.colors['light_grey']};
        }}

        .section:last-child {{
            border-bottom: none;
        }}

        h2 {{
            color: {self.colors['dark_grey']};
            margin-bottom: 25px;
            font-size: 2em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 3px solid {self.colors['signature_orange']};
            padding-bottom: 12px;
        }}

        h3 {{
            color: {self.colors['dark_grey']};
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.4em;
            font-weight: 600;
        }}

        h4 {{
            color: {self.colors['medium_grey']};
            margin-top: 20px;
            margin-bottom: 12px;
            font-size: 1.1em;
            font-weight: 600;
        }}

        .health-badge {{
            display: inline-block;
            padding: 18px 35px;
            border-radius: 10px;
            font-weight: 700;
            color: {self.colors['white']};
            font-size: 1.4em;
            box-shadow: 0 6px 12px rgba(0,0,0,0.2);
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }}

        .health-critical {{
            background: linear-gradient(135deg, {self.colors['risk_critical']} 0%, #8B0000 100%);
        }}

        .health-poor {{
            background: linear-gradient(135deg, {self.colors['risk_high']} 0%, #BF3900 100%);
        }}

        .health-fair {{
            background: linear-gradient(135deg, {self.colors['risk_medium']} 0%, #C17E00 100%);
        }}

        .health-good {{
            background: linear-gradient(135deg, {self.colors['risk_low']} 0%, #1B5E20 100%);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 25px;
            margin-top: 35px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, {self.colors['white']} 0%, {self.colors['very_light_grey']} 100%);
            padding: 28px;
            border-radius: 12px;
            text-align: center;
            transition: all 0.3s ease;
            border: 2px solid {self.colors['light_grey']};
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: {self.colors['signature_orange']};
        }}

        .stat-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 12px 25px rgba(235, 140, 0, 0.25);
            border-color: {self.colors['signature_orange']};
        }}

        .stat-number {{
            font-size: 2.8em;
            font-weight: 700;
            color: {self.colors['signature_orange']};
            margin-bottom: 8px;
        }}

        .stat-label {{
            color: {self.colors['medium_grey']};
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            font-weight: 600;
        }}

        .chart-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 35px;
            margin-top: 35px;
        }}

        .chart-box {{
            background: {self.colors['white']};
            padding: 30px;
            border-radius: 12px;
            border: 2px solid {self.colors['light_grey']};
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }}

        .recommendations {{
            background: linear-gradient(135deg, {self.colors['very_light_grey']} 0%, {self.colors['white']} 100%);
            border-left: 5px solid {self.colors['signature_orange']};
            padding: 30px;
            margin: 25px 0;
            border-radius: 10px;
        }}

        .recommendation-item {{
            padding: 22px;
            margin: 18px 0;
            background: {self.colors['white']};
            border-radius: 10px;
            display: flex;
            align-items: start;
            gap: 18px;
            border: 2px solid {self.colors['light_grey']};
            transition: all 0.3s ease;
        }}

        .recommendation-item:hover {{
            box-shadow: 0 6px 18px rgba(235, 140, 0, 0.2);
            border-color: {self.colors['signature_orange']};
            transform: translateX(5px);
        }}

        .priority-badge {{
            background: {self.colors['signature_orange']};
            color: {self.colors['white']};
            padding: 10px;
            border-radius: 50%;
            font-weight: 700;
            min-width: 45px;
            height: 45px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 3px 6px rgba(0,0,0,0.2);
            font-size: 1.1em;
        }}

        .risk-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 5px;
            font-size: 0.8em;
            font-weight: 700;
            color: {self.colors['white']};
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }}

        .risk-critical {{
            background: {self.colors['risk_critical']};
            box-shadow: 0 2px 4px rgba(183, 28, 28, 0.3);
        }}

        .risk-high {{
            background: {self.colors['risk_high']};
            box-shadow: 0 2px 4px rgba(230, 81, 0, 0.3);
        }}

        .risk-medium {{
            background: {self.colors['risk_medium']};
            color: {self.colors['white']};
            box-shadow: 0 2px 4px rgba(249, 168, 37, 0.3);
        }}

        .risk-low {{
            background: {self.colors['risk_low']};
            box-shadow: 0 2px 4px rgba(46, 125, 50, 0.3);
        }}

        .risk-info {{
            background: {self.colors['risk_info']};
            box-shadow: 0 2px 4px rgba(2, 119, 189, 0.3);
        }}

        table {{
            width: 100%;
            margin-top: 25px;
            border-collapse: collapse;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border-radius: 10px;
        }}

        table thead {{
            background: {self.colors['dark_grey']};
            color: {self.colors['white']};
        }}

        table thead th {{
            padding: 16px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.8px;
            border: none;
        }}

        table tbody td {{
            padding: 14px 16px;
            border-bottom: 1px solid {self.colors['light_grey']};
            color: {self.colors['dark_grey']};
            font-size: 0.95em;
        }}

        table tbody tr:nth-child(even) {{
            background: {self.colors['very_light_grey']};
        }}

        table tbody tr:hover {{
            background: rgba(235, 140, 0, 0.08);
        }}

        .zone-pair-card {{
            background: linear-gradient(135deg, {self.colors['white']} 0%, {self.colors['very_light_grey']} 100%);
            padding: 20px;
            border-radius: 10px;
            border: 2px solid {self.colors['light_grey']};
            transition: all 0.3s ease;
        }}

        .zone-pair-card:hover {{
            box-shadow: 0 8px 20px rgba(235, 140, 0, 0.2);
            border-color: {self.colors['signature_orange']};
        }}

        .zone-pairs-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}

        .zone-stats {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .zone-stat-badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 5px;
            font-size: 0.85em;
            font-weight: 600;
            color: {self.colors['white']};
        }}

        .zone-stat-badge.allow {{
            background: {self.colors['risk_low']};
        }}

        .zone-stat-badge.deny {{
            background: {self.colors['risk_critical']};
        }}

        .zone-stat-badge.total {{
            background: {self.colors['medium_grey']};
        }}

        .zone-matrix {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border-radius: 10px;
        }}

        .zone-matrix th {{
            background: {self.colors['dark_grey']};
            color: {self.colors['white']};
            padding: 12px;
            text-align: center;
            font-weight: 600;
        }}

        .zone-matrix td {{
            padding: 12px;
            text-align: center;
            border: 1px solid {self.colors['light_grey']};
        }}

        .matrix-cell.high {{
            background: rgba(235, 140, 0, 0.3);
            font-weight: 600;
            color: {self.colors['signature_orange']};
        }}

        .matrix-cell.medium {{
            background: rgba(249, 168, 37, 0.2);
        }}

        .matrix-cell.low {{
            background: {self.colors['very_light_grey']};
        }}

        .action-badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 5px;
            font-weight: 600;
            color: {self.colors['white']};
            font-size: 0.85em;
        }}

        .action-badge.allow {{
            background: {self.colors['risk_low']};
        }}

        .action-badge.deny {{
            background: {self.colors['risk_critical']};
        }}

        .detail-button {{
            background: {self.colors['signature_orange']};
            color: {self.colors['white']};
            border: none;
            padding: 6px 12px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85em;
            transition: all 0.2s ease;
        }}

        .detail-button:hover {{
            background: #D57800;
            box-shadow: 0 3px 8px rgba(235, 140, 0, 0.3);
        }}

        .address-tag {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
            margin: 2px;
        }}

        .address-tag.any {{
            background: {self.colors['risk_high']};
            color: {self.colors['white']};
        }}

        .address-tag.subnet {{
            background: {self.colors['risk_medium']};
            color: {self.colors['white']};
        }}

        .address-tag.ip {{
            background: {self.colors['risk_low']};
            color: {self.colors['white']};
        }}

        .service-tag {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
            background: {self.colors['signature_orange']};
            color: {self.colors['white']};
            margin: 2px;
        }}

        .service-tag.any {{
            background: {self.colors['risk_high']};
        }}

        .search-box {{
            margin: 20px 0;
            padding: 15px;
            background: {self.colors['very_light_grey']};
            border-radius: 8px;
        }}

        .search-input {{
            width: 100%;
            padding: 12px 20px;
            font-size: 1em;
            border: 2px solid {self.colors['light_grey']};
            border-radius: 6px;
            outline: none;
            transition: all 0.3s ease;
        }}

        .search-input:focus {{
            border-color: {self.colors['signature_orange']};
            box-shadow: 0 0 0 3px rgba(235, 140, 0, 0.1);
        }}

        .formula {{
            background: {self.colors['dark_grey']};
            color: {self.colors['white']};
            padding: 18px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 18px 0;
            overflow-x: auto;
            font-size: 1em;
            line-height: 1.8;
        }}

        .methodology-box {{
            background: linear-gradient(135deg, {self.colors['very_light_grey']} 0%, {self.colors['white']} 100%);
            border: 2px solid {self.colors['light_grey']};
            border-radius: 12px;
            padding: 30px;
            margin: 25px 0;
        }}

        .score-component {{
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid {self.colors['light_grey']};
        }}

        .score-component:last-child {{
            border-bottom: none;
        }}

        .score-value {{
            color: {self.colors['signature_orange']};
            font-weight: 700;
            font-size: 1.05em;
        }}

        .critical-alert {{
            background: linear-gradient(135deg, #FFEBEE 0%, {self.colors['white']} 100%);
            border: 3px solid {self.colors['risk_critical']};
            border-radius: 12px;
            padding: 30px;
            margin: 30px 0;
            position: relative;
        }}

        .critical-alert h3 {{
            color: {self.colors['risk_critical']};
            margin-bottom: 12px;
            font-size: 1.5em;
        }}

        .grouped-findings-card {{
            background: linear-gradient(135deg, {self.colors['very_light_grey']} 0%, {self.colors['white']} 100%);
            border: 2px solid {self.colors['light_grey']};
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
            transition: all 0.3s ease;
        }}

        .grouped-findings-card:hover {{
            box-shadow: 0 6px 15px rgba(235, 140, 0, 0.15);
            border-color: {self.colors['signature_orange']};
        }}

        .grouped-findings-card.critical {{
            border-left: 5px solid {self.colors['risk_critical']};
        }}

        .grouped-findings-card.high {{
            border-left: 5px solid {self.colors['risk_high']};
        }}

        .grouped-findings-card.medium {{
            border-left: 5px solid {self.colors['risk_medium']};
        }}

        .grouped-findings-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid {self.colors['light_grey']};
        }}

        .grouped-findings-header h4 {{
            margin: 0;
            flex-grow: 1;
        }}

        .finding-summary-badge {{
            display: inline-block;
            padding: 8px 15px;
            border-radius: 20px;
            background: {self.colors['signature_orange']};
            color: {self.colors['white']};
            font-weight: 600;
            font-size: 0.9em;
            margin-left: 10px;
        }}

        .rule-detail-section {{
            background: {self.colors['very_light_grey']};
            border-radius: 12px;
            padding: 30px;
            margin-top: 20px;
        }}

        .rule-detail-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid {self.colors['light_grey']};
            cursor: pointer;
        }}

        .rule-detail-header:hover {{
            background: {self.colors['light_grey']};
            margin: -10px -10px 25px -10px;
            padding: 10px;
            border-radius: 8px;
        }}

        .rule-detail-body {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
        }}

        .detail-group {{
            background: {self.colors['white']};
            padding: 20px;
            border-radius: 10px;
            border: 1px solid {self.colors['light_grey']};
        }}

        .detail-group h5 {{
            color: {self.colors['dark_grey']};
            margin-bottom: 15px;
            font-weight: 600;
            border-bottom: 2px solid {self.colors['signature_orange']};
            padding-bottom: 8px;
        }}

        .detail-item {{
            padding: 8px 0;
            border-bottom: 1px solid {self.colors['light_grey']};
        }}

        .detail-item:last-child {{
            border-bottom: none;
        }}

        .detail-label {{
            font-weight: 600;
            color: {self.colors['dark_grey']};
            font-size: 0.9em;
        }}

        .detail-value {{
            color: {self.colors['medium_grey']};
            font-size: 0.95em;
            margin-top: 4px;
            word-break: break-all;
        }}

        .expanded {{
            display: block !important;
        }}

        .collapsed {{
            display: none !important;
        }}

        footer {{
            background: {self.colors['dark_grey']};
            color: {self.colors['white']};
            text-align: center;
            padding: 35px;
            font-size: 0.95em;
        }}

                .dataTables_wrapper {{
            margin-top: 20px;
            background: {self.colors['white']};
        }}

        .dataTables_length {{
            margin-bottom: 15px;
        }}

        .dataTables_filter {{
            margin-bottom: 15px;
        }}

        .dataTables_filter input {{
            border: 2px solid {self.colors['light_grey']};
            border-radius: 6px;
            padding: 8px 12px;
            width: 300px;
            font-size: 0.9em;
        }}

        .dataTables_filter label {{
            font-weight: 600;
            color: {self.colors['dark_grey']};
        }}

        .dataTables_info {{
            color: {self.colors['medium_grey']};
            font-size: 0.9em;
            margin-top: 10px;
        }}

        .dataTables_paginate {{
            margin-top: 15px;
            text-align: right;
        }}

        .dataTables_paginate .paginate_button {{
            padding: 5px 10px;
            margin: 0 3px;
            border-radius: 4px;
            background: {self.colors['light_grey']};
            color: {self.colors['dark_grey']};
            cursor: pointer;
            border: 1px solid {self.colors['light_grey']};
            font-weight: 600;
        }}

        .dataTables_paginate .paginate_button:hover {{
            background: {self.colors['signature_orange']};
            color: {self.colors['white']};
            border-color: {self.colors['signature_orange']};
        }}

        .dataTables_paginate .paginate_button.current {{
            background: {self.colors['signature_orange']};
            color: {self.colors['white']};
            border-color: {self.colors['signature_orange']};
        }}

        .dataTables_paginate .paginate_button.disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        .findings-datatable {{
            width: 100%;
            border-collapse: collapse;
        }}

        .findings-datatable thead th {{
            background: {self.colors['dark_grey']};
            color: {self.colors['white']};
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border: none;
        }}

        .findings-datatable tbody td {{
            padding: 12px;
            border-bottom: 1px solid {self.colors['light_grey']};
        }}

        .findings-datatable tbody tr {{
            transition: background-color 0.2s ease;
        }}

        .findings-datatable tbody tr:nth-child(even) {{
            background: {self.colors['very_light_grey']};
        }}

        .findings-datatable tbody tr:hover {{
            background: rgba(235, 140, 0, 0.08);
        }}

        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
            .chart-container {{ grid-template-columns: 1fr; }}
            .report-meta {{ flex-direction: column; gap: 10px; }}
            header h1 {{ font-size: 1.8em; }}
            .rule-detail-body {{ grid-template-columns: 1fr; }}
        }}
        """

    def _generate_executive_summary(self, summary: Dict, stats: Dict) -> str:
        """Generate executive summary section"""
        health_class = f"health-{summary['overall_health'].lower()}"

        return f"""
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div style="text-align: center; margin: 35px 0;">
                <div class="health-badge {health_class}">
                    Overall Security Health: {summary['overall_health']}
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['total_rules']}</div>
                    <div class="stat-label">Rules Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['total_issues']}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['critical_issues']}</div>
                    <div class="stat-label">Critical Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['high_risk_issues']}</div>
                    <div class="stat-label">High Risk Issues</div>
                </div>
            </div>

            {self._generate_critical_alert(summary) if summary['critical_issues'] > 0 else ''}
        </div>
        """

    def _generate_critical_alert(self, summary: Dict) -> str:
        """Generate critical issues alert"""
        return f"""
        <div class="critical-alert">
            <h3>⚠️ Critical Security Issues Detected</h3>
            <p style="font-size: 1.1em;"><strong>{summary['critical_issues']}</strong> critical security issues require immediate attention.</p>
            <p>These issues pose significant security risks and should be addressed as a priority.</p>
        </div>
        """

    def _generate_filtered_rules_notice(self, stats: Dict) -> str:
        """Generate notice about rules excluded from analysis"""
        excluded_count = stats.get('disabled_rules_excluded', 0) + stats.get('deny_any_rules_excluded', 0)

        if excluded_count == 0:
            return ""

        return f"""
        <div class="section" style="background: linear-gradient(135deg, #E3F2FD 0%, {self.colors['white']} 100%); border-left: 5px solid {self.colors['info']};">
            <h2>ℹ️ Analysis Scope Information</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['disabled_rules_excluded']}</div>
                    <div class="stat-label">Disabled Rules Excluded</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['deny_any_rules_excluded']}</div>
                    <div class="stat-label">Deny Any/All Rules Excluded</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['all_rules_total']}</div>
                    <div class="stat-label">Total Rules in File</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['total_rules']}</div>
                    <div class="stat-label">Rules Analyzed</div>
                </div>
            </div>
            <p style="margin-top: 20px; color: {self.colors['medium_grey']};">
                <strong>Note:</strong> Analysis focuses on active ALLOW rules and non-trivial DENY rules.
                Disabled rules and catch-all DENY rules are excluded from security analysis but listed separately.
            </p>
        </div>
        """

    def _generate_zone_based_analysis(self, zone_summary: Dict, results: Dict) -> str:
        """Generate zone-based traffic analysis section"""
        if not zone_summary:
            return ""

        zone_pairs_html = ""
        for pair, data in sorted(zone_summary.items(), key=lambda x: x[1]['total_rules'], reverse=True):
            zone_pairs_html += f"""
            <div class="zone-pair-card">
                <div style="font-weight: 600; font-size: 1.1em; margin-bottom: 10px;">{pair}</div>
                <div class="zone-stats">
                    <span class="zone-stat-badge allow">ALLOW: {data['allow_rules']}</span>
                    <span class="zone-stat-badge deny">DENY: {data['deny_rules']}</span>
                    <span class="zone-stat-badge total">TOTAL: {data['total_rules']}</span>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>🌐 Zone-Based Traffic Analysis</h2>
            <p style="margin-bottom: 20px;">Analysis of traffic flows between configured network zones:</p>
            <div class="zone-pairs-grid">
                {zone_pairs_html}
            </div>
        </div>
        """

    def _generate_zone_traffic_matrix(self, zone_summary: Dict) -> str:
        """Generate zone traffic matrix visualization"""
        if not zone_summary or len(zone_summary) < 2:
            return ""

        zones = set()
        for pair in zone_summary.keys():
            src, dst = pair.split(' → ')
            zones.add(src)
            zones.add(dst)

        zones = sorted(zones)

        matrix_data = {}
        for zone in zones:
            matrix_data[zone] = {}
            for zone2 in zones:
                pair = f"{zone} → {zone2}"
                if pair in zone_summary:
                    matrix_data[zone][zone2] = zone_summary[pair]['total_rules']
                else:
                    matrix_data[zone][zone2] = 0

        matrix_html = "<table class='zone-matrix'><thead><tr><th>From \ To</th>"
        for zone in zones:
            matrix_html += f"<th>{zone}</th>"
        matrix_html += "</tr></thead><tbody>"

        for src_zone in zones:
            matrix_html += f"<tr><th>{src_zone}</th>"
            for dst_zone in zones:
                count = matrix_data[src_zone][dst_zone]
                color_class = "high" if count > 10 else "medium" if count > 0 else "low"
                matrix_html += f"<td class='matrix-cell {color_class}'>{count}</td>"
            matrix_html += "</tr>"

        matrix_html += "</tbody></table>"

        return f"""
        <div class="section">
            <h2>📊 Zone Traffic Matrix</h2>
            <p style="margin-bottom: 20px;">Number of rules for each source → destination zone pair:</p>
            {matrix_html}
        </div>
        """

    def _generate_risk_distribution_charts(self, stats: Dict) -> str:
        """Generate risk distribution charts section"""
        return f"""
        <div class="section">
            <h2>📈 Risk Distribution Analysis</h2>
            <div class="chart-container">
                <div class="chart-box">
                    <h3>Findings by Risk Level</h3>
                    <canvas id="riskChart"></canvas>
                </div>
                <div class="chart-box">
                    <h3>Findings by Issue Type</h3>
                    <canvas id="typeChart"></canvas>
                </div>
            </div>
        </div>
        """

    def _generate_critical_findings(self, results: Dict) -> str:
        """Generate critical findings section"""
        critical_findings = [f for f in results['findings'] if f.risk_level == RiskLevel.CRITICAL]

        if not critical_findings:
            return ""

        findings_html = ""
        for finding in critical_findings[:10]:
            findings_html += f"""
            <div class="recommendation-item">
                <span class="risk-badge risk-critical">CRITICAL</span>
                <div style="flex-grow: 1;">
                    <strong style="font-size: 1.1em;">Rule: {finding.rule_name}</strong><br>
                    <span style="color: {self.colors['medium_grey']}; font-size: 1em;">{finding.description}</span><br>
                    <em style="color: {self.colors['signature_orange']}; font-size: 0.95em;">Recommendation: {finding.recommendation}</em>
                    <div class="formula" style="margin-top: 10px;">
                        <strong>Score Calculation:</strong> {finding.calculation_formula}
                    </div>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>🚨 Critical Security Findings</h2>
            {findings_html}
        </div>
        """

    def _generate_recommendations(self, recommendations: List[Dict]) -> str:
        """Generate recommendations section"""
        if not recommendations:
            return ""

        rec_html = ""
        for rec in recommendations:
            risk_class = f"risk-{rec['risk_level']}"
            rec_html += f"""
            <div class="recommendation-item">
                <span class="priority-badge">{rec['priority']}</span>
                <div style="flex-grow: 1;">
                    <span class="risk-badge {risk_class}">{rec['risk_level']}</span>
                    <span style="margin-left: 10px; font-weight: 600;">Impact Score: {rec['score']}</span><br>
                    <span style="margin-top: 10px; display: block; font-size: 1.05em;">{rec['recommendation']}</span>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>💡 Top Security Recommendations</h2>
            <div class="recommendations">
                {rec_html}
            </div>
        </div>
        """

    def _generate_detailed_statistics(self, stats: Dict) -> str:
        """Generate detailed statistics section"""
        protocols_html = ""
        if stats['insecure_protocols_found']:
            protocols = ", ".join([p.upper() for p in stats['insecure_protocols_found']])
            protocols_html = f"""
            <h3 style="margin-top: 35px;">Insecure Protocols Detected</h3>
            <div style="background: linear-gradient(135deg, #FFEBEE 0%, {self.colors['white']} 100%); padding: 25px; border-radius: 10px; margin-top: 15px; border-left: 5px solid {self.colors['risk_critical']};">
                <strong style="color: {self.colors['dark_grey']}; font-size: 1.1em;">Protocols:</strong>
                <span style="color: {self.colors['risk_critical']}; font-size: 1.1em; font-weight: 600;">{protocols}</span>
            </div>
            """

        return f"""
        <div class="section">
            <h2>📊 Detailed Statistics</h2>

            <h3>Overly Permissive Rules</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['source']}</div>
                    <div class="stat-label">Any Source</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['destination']}</div>
                    <div class="stat-label">Any Destination</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['service']}</div>
                    <div class="stat-label">Any Service</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['rules_with_any']['multiple_any']}</div>
                    <div class="stat-label">Multiple Any Fields</div>
                </div>
            </div>

            <h3 style="margin-top: 35px;">Other Metrics</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats.get('subnet_overlaps_found', 0)}</div>
                    <div class="stat-label">Subnet Overlaps Found</div>
                </div>
            </div>

            {protocols_html}
        </div>
        """

    def _generate_scoring_methodology(self) -> str:
        """Generate scoring methodology section"""
        return f"""
        <div class="section">
            <h2>📐 Scoring Methodology</h2>

            <div class="methodology-box">
                <h3>Risk Score Calculation</h3>
                <p style="font-size: 1.05em; margin-bottom: 20px;">Each security finding is assigned a risk score based on multiple factors.</p>

                <div class="formula">
                    Total Risk Score = Base Score + Σ(Factor Scores) + Σ(Modifiers)
                </div>

                <h4 style="margin-top: 25px;">Score Components:</h4>
                <ul style="margin-left: 25px; line-height: 2;">
                    <li><strong>Base Score:</strong> Initial score based on the security issue type</li>
                    <li><strong>Factor Scores:</strong> Additional points for specific risk factors</li>
                    <li><strong>Modifiers:</strong> Contextual adjustments to the score</li>
                </ul>

                <h4 style="margin-top: 25px;">Risk Level Thresholds:</h4>
                <div style="margin-top: 15px;">
                    <div class="score-component">
                        <span><span class="risk-badge risk-critical">CRITICAL</span></span>
                        <span class="score-value">≥ 90 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-high">HIGH</span></span>
                        <span class="score-value">70-89 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-medium">MEDIUM</span></span>
                        <span class="score-value">40-69 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-low">LOW</span></span>
                        <span class="score-value">20-39 points</span>
                    </div>
                    <div class="score-component">
                        <span><span class="risk-badge risk-info">INFO</span></span>
                        <span class="score-value">&lt; 20 points</span>
                    </div>
                </div>
            </div>
        </div>
        """

    def _generate_grouped_findings_by_rule(self, grouped_findings: Dict,
                                         findings_summary: Dict) -> str:
        """Generate findings grouped by rule name"""
        if not grouped_findings:
            return ""

        grouped_html = ""
        for rule_name, findings in sorted(grouped_findings.items(),
                                         key=lambda x: sum(f.score for f in x[1]), reverse=True):
            summary = findings_summary.get(rule_name, {})
            total_score = summary.get('total_score', 0)
            total_findings = summary.get('total_findings', 0)
            risk_levels = summary.get('risk_levels', {})

            # Determine risk class
            risk_class = 'low'
            if risk_levels.get('critical', 0) > 0:
                risk_class = 'critical'
            elif risk_levels.get('high', 0) > 0:
                risk_class = 'high'
            elif risk_levels.get('medium', 0) > 0:
                risk_class = 'medium'

            findings_detail_html = "<ul style='margin-left: 20px; margin-top: 10px;'>"
            for finding in findings[:5]:  # Show first 5 findings per rule
                findings_detail_html += f"<li><span class='risk-badge risk-{finding.risk_level.value}'>{finding.risk_level.value.upper()}</span> {finding.issue_type.value.replace('_', ' ').title()}: {finding.score} points</li>"

            if len(findings) > 5:
                findings_detail_html += f"<li>... and {len(findings) - 5} more findings</li>"

            findings_detail_html += "</ul>"

            grouped_html += f"""
            <div class="grouped-findings-card {risk_class}">
                <div class="grouped-findings-header">
                    <h4 style="margin: 0;">{rule_name}</h4>
                    <span class="finding-summary-badge">Score: {total_score}</span>
                    <span class="finding-summary-badge">Issues: {total_findings}</span>
                </div>
                <div style="margin-top: 10px;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px;">
                        <div><strong>Critical:</strong> {risk_levels.get('critical', 0)}</div>
                        <div><strong>High:</strong> {risk_levels.get('high', 0)}</div>
                        <div><strong>Medium:</strong> {risk_levels.get('medium', 0)}</div>
                        <div><strong>Low:</strong> {risk_levels.get('low', 0)}</div>
                    </div>
                </div>
                <div style="margin-top: 15px;">
                    <strong>Top Findings:</strong>
                    {findings_detail_html}
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>📑 Findings Grouped by Rule Name</h2>
            <p style="margin-bottom: 20px;">Security findings consolidated and aggregated by rule name for easier review:</p>
            {grouped_html}
        </div>
        """

    def _generate_high_risk_rules_table(self, high_risk_rules: List[FirewallRule]) -> str:
        """Generate high risk rules table"""
        if not high_risk_rules:
            return ""

        rows = ""
        for rule in sorted(high_risk_rules, key=lambda r: r.risk_score, reverse=True):
            rows += f"""
            <tr>
                <td>{rule.id}</td>
                <td>{rule.name}</td>
                <td>{rule.vendor_type.value.replace('_', ' ').title()}</td>
                <td><strong style="color: {self.colors['signature_orange']}; font-size: 1.1em;">{rule.risk_score}</strong></td>
                <td>{len(rule.findings)}</td>
                <td>{rule.action}</td>
                <td>{'Yes' if rule.disabled else 'No'}</td>
            </tr>
            """

        return f"""
        <div class="section">
            <h2>⚠️ High Risk Rules ({len(high_risk_rules)} Total)</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Vendor</th>
                        <th>Risk Score</th>
                        <th>Issues</th>
                        <th>Action</th>
                        <th>Disabled</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    def _generate_complete_findings_table(self, findings: List[SecurityFinding]) -> str:
        """Generate complete findings table with all findings"""
        if not findings:
            return ""

        findings_by_risk = {}
        for finding in findings:
            if finding.risk_level not in findings_by_risk:
                findings_by_risk[finding.risk_level] = []
            findings_by_risk[finding.risk_level].append(finding)

        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]

        html = f"""
        <div class="section">
            <h2>🔍 Complete Security Findings ({len(findings)} Total)</h2>
        """

        for risk_level in risk_order:
            if risk_level not in findings_by_risk:
                continue

            risk_findings = sorted(findings_by_risk[risk_level], key=lambda f: f.score, reverse=True)
            risk_class = f"risk-{risk_level.value}"

            table_id = f"findingsTable_{risk_level.value}"
            rows = ""

            for finding in risk_findings:
                rows += f"""
                <tr>
                    <td>{finding.rule_id}</td>
                    <td>{finding.rule_name}</td>
                    <td>{finding.issue_type.value.replace('_', ' ').title()}</td>
                    <td>{finding.description}</td>
                    <td><strong style="color: {self.colors['signature_orange']};">{finding.score}</strong></td>
                    <td>{finding.calculation_formula[:80]}...</td>
                </tr>
                """

            html += f"""
            <h3 style="margin-top: 30px;">
                <span class="risk-badge {risk_class}">{risk_level.value.upper()}</span>
                Risk Findings ({len(risk_findings)} items)
            </h3>
            <table id="{table_id}" class="findings-datatable">
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Rule Name</th>
                        <th>Issue Type</th>
                        <th>Description</th>
                        <th>Score</th>
                        <th>Formula</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
            """

        html += "</div>"
        return html

    def _get_enhanced_javascript(self, stats: Dict, zone_summary: Dict) -> str:
        """Get enhanced JavaScript with zone and detail filtering"""
        risk_data = stats.get('findings_by_risk', {})
        type_data = stats.get('findings_by_type', {})

        return f"""
        // Track all expanded/collapsed states
        var allRulesExpanded = false;

        function toggleRuleDetails(ruleIdx) {{
            var detailsDiv = document.getElementById('rule-details-' + ruleIdx);
            if (detailsDiv.classList.contains('collapsed')) {{
                detailsDiv.classList.remove('collapsed');
                detailsDiv.classList.add('expanded');
            }} else {{
                detailsDiv.classList.remove('expanded');
                detailsDiv.classList.add('collapsed');
            }}
        }}

        function toggleAllRules() {{
            // Find all rule detail sections
            var ruleSections = document.querySelectorAll('[id^="rule-details-"]');

            allRulesExpanded = !allRulesExpanded;

            ruleSections.forEach(function(section) {{
                if (allRulesExpanded) {{
                    section.classList.remove('collapsed');
                    section.classList.add('expanded');
                }} else {{
                    section.classList.remove('expanded');
                    section.classList.add('collapsed');
                }}
            }});
        }}

        // Initialize DataTables after DOM is ready
        $(document).ready(function() {{
            // Initialize all findings tables
            var tables = document.querySelectorAll('table.findings-datatable');

            tables.forEach(function(table) {{
                // Check if DataTable is not already initialized
                if (!$.fn.DataTable.isDataTable(table)) {{
                    $(table).DataTable({{
                        "paging": true,
                        "pageLength": 10,
                        "searching": true,
                        "ordering": true,
                        "info": true,
                        "autoWidth": false,
                        "lengthChange": true,
                        "lengthMenu": [[10, 25, 50, 100], [10, 25, 50, 100]],
                        "dom": '<"top"lf>rt<"bottom"ip>',
                        "language": {{
                            "search": "Filter findings:",
                            "lengthMenu": "Show _MENU_ entries",
                            "info": "Showing _START_ to _END_ of _TOTAL_ findings",
                            "paginate": {{
                                "previous": "Previous",
                                "next": "Next"
                            }}
                        }},
                        "columnDefs": [
                            {{ "width": "10%", "targets": 0 }},
                            {{ "width": "20%", "targets": 1 }},
                            {{ "width": "18%", "targets": 2 }},
                            {{ "width": "30%", "targets": 3 }},
                            {{ "width": "8%", "targets": 4 }},
                            {{ "width": "14%", "targets": 5 }}
                        ],
                        "order": [[4, 'desc']]  // Sort by Score column descending
                    }});
                }}
            }});
        }});

        // Risk Distribution Chart
        var riskCtx = document.getElementById('riskChart');
        if (riskCtx) {{
            new Chart(riskCtx.getContext('2d'), {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{{
                        data: [
                            {risk_data.get('critical', 0)},
                            {risk_data.get('high', 0)},
                            {risk_data.get('medium', 0)},
                            {risk_data.get('low', 0)},
                            {risk_data.get('info', 0)}
                        ],
                        backgroundColor: [
                            '{self.colors['risk_critical']}',
                            '{self.colors['risk_high']}',
                            '{self.colors['risk_medium']}',
                            '{self.colors['risk_low']}',
                            '{self.colors['risk_info']}'
                        ],
                        borderWidth: 3,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{ padding: 20, font: {{ size: 13, weight: '600' }} }}
                        }}
                    }}
                }}
            }});
        }}

        // Type Distribution Chart
        var typeCtx = document.getElementById('typeChart');
        if (typeCtx) {{
            var typeLabels = {json.dumps([k.replace('_', ' ').title() for k in type_data.keys()])};
            var typeValues = {json.dumps(list(type_data.values()))};

            new Chart(typeCtx.getContext('2d'), {{
                type: 'bar',
                data: {{
                    labels: typeLabels,
                    datasets: [{{
                        label: 'Number of Issues',
                        data: typeValues,
                        backgroundColor: '{self.colors['signature_orange']}',
                        borderColor: '{self.colors['dark_grey']}',
                        borderWidth: 2,
                        borderRadius: 5
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{ legend: {{ display: false }} }},
                    scales: {{
                        y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }},
                        x: {{ ticks: {{ maxRotation: 45, minRotation: 45 }} }}
                    }}
                }}
            }});
        }}
        """

    def _generate_disabled_rules_table(self, disabled_rules: List[FirewallRule]) -> str:
        """Generate table of disabled rules"""
        if not disabled_rules:
            return ""

        rows = ""
        for rule in sorted(disabled_rules, key=lambda r: r.name)[:100]:
            rows += f"""
            <tr>
                <td>{rule.id}</td>
                <td>{rule.name}</td>
                <td>{rule.vendor_type.value.replace('_', ' ').title()}</td>
                <td>{rule.action}</td>
                <td>{len(rule.source_addresses)} sources</td>
                <td>{len(rule.dest_addresses)} destinations</td>
            </tr>
            """

        return f"""
        <div class="section">
            <h2>⊘ Disabled Rules ({len(disabled_rules)} Total)</h2>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">
                These rules are disabled and not included in active security analysis.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Name</th>
                        <th>Vendor</th>
                        <th>Action</th>
                        <th>Sources</th>
                        <th>Destinations</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    def _generate_deny_rules_table(self, deny_rules: List[FirewallRule]) -> str:
        """Generate table of DENY rules"""
        if not deny_rules:
            return ""

        deny_rules_filtered = [r for r in deny_rules if not all(
            addr.lower() == 'any' for addr in r.source_addresses + r.dest_addresses
        )]

        if not deny_rules_filtered:
            return ""

        rows = ""
        for rule in sorted(deny_rules_filtered, key=lambda r: r.name)[:50]:
            src_display = ', '.join(rule.source_addresses[:2]) + ('...' if len(rule.source_addresses) > 2 else '')
            dst_display = ', '.join(rule.dest_addresses[:2]) + ('...' if len(rule.dest_addresses) > 2 else '')

            rows += f"""
            <tr>
                <td>{rule.id}</td>
                <td>{rule.name}</td>
                <td>{src_display}</td>
                <td>{dst_display}</td>
                <td>{', '.join(rule.services[:2]) + ('...' if len(rule.services) > 2 else '')}</td>
            </tr>
            """

        return f"""
        <div class="section">
            <h2>🚫 DENY Rules ({len(deny_rules_filtered)} Total)</h2>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">
                Non-trivial DENY rules shown for reference. Catch-all deny any rules are excluded.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Name</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Service</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        """

    def _generate_full_rule_details_section(self, rules: List[FirewallRule]) -> str:
        """Generate comprehensive section with expandable rule details"""
        if not rules:
            return ""

        # Sort rules by risk score (descending - highest risk first)
        sorted_rules = sorted(rules, key=lambda r: r.risk_score, reverse=True)

        rules_html = ""
        for rule_idx, rule in enumerate(sorted_rules):
            src_tags = self._format_address_list(rule.source_addresses)
            dst_tags = self._format_address_list(rule.dest_addresses)
            svc_tags = self._format_service_list(rule.services)

            action_class = 'allow' if rule.action.lower() == 'allow' else 'deny'

            # Generate findings for this rule
            findings_html = self._format_rule_findings(rule.findings)

            # Risk score color coding
            if rule.risk_score >= 90:
                risk_color = self.colors['risk_critical']
                risk_indicator = '🔴'
            elif rule.risk_score >= 70:
                risk_color = self.colors['risk_high']
                risk_indicator = '🟠'
            elif rule.risk_score >= 40:
                risk_color = self.colors['risk_medium']
                risk_indicator = '🟡'
            elif rule.risk_score >= 20:
                risk_color = self.colors['risk_low']
                risk_indicator = '🟢'
            else:
                risk_color = self.colors['risk_info']
                risk_indicator = '🔵'

            rules_html += f"""
            <div class="rule-detail-section" id="rule-{rule_idx}">
                <div class="rule-detail-header" onclick="toggleRuleDetails({rule_idx})">
                    <div>
                        <h4 style="margin: 0;">
                            <span style="font-size: 1.4em; margin-right: 8px;">{risk_indicator}</span>
                            Rule ID: {rule.id} - {rule.name}
                        </h4>
                        <span style="color: {self.colors['medium_grey']}; font-size: 0.9em;">Click to expand/collapse details</span>
                    </div>
                    <div style="text-align: right;">
                        <span class="action-badge {action_class}">{rule.action.upper()}</span>
                        <span style="margin-left: 10px; font-weight: 600; color: {risk_color}; font-size: 1.1em;">Risk Score: {rule.risk_score}</span>
                    </div>
                </div>

                <div id="rule-details-{rule_idx}" class="collapsed" style="margin-top: 20px;">
                    <div class="rule-detail-body">
                        <div class="detail-group">
                            <h5>Basic Information</h5>
                            <div class="detail-item">
                                <span class="detail-label">Rule ID:</span>
                                <span class="detail-value">{rule.id}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Rule Name:</span>
                                <span class="detail-value">{rule.name}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Vendor:</span>
                                <span class="detail-value">{rule.vendor_type.value.replace('_', ' ').title()}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Action:</span>
                                <span class="detail-value"><span class="action-badge {action_class}">{rule.action.upper()}</span></span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Disabled:</span>
                                <span class="detail-value">{'Yes' if rule.disabled else 'No'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Risk Score:</span>
                                <span class="detail-value" style="font-weight: 700; color: {risk_color}; font-size: 1.05em;">{rule.risk_score}</span>
                            </div>
                        </div>

                        <div class="detail-group">
                            <h5>Zone Configuration</h5>
                            <div class="detail-item">
                                <span class="detail-label">Source Zones:</span>
                                <span class="detail-value">{', '.join(rule.source_zones) if rule.source_zones else 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Destination Zones:</span>
                                <span class="detail-value">{', '.join(rule.dest_zones) if rule.dest_zones else 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Rule Usage:</span>
                                <span class="detail-value">{rule.rule_usage or 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Modified:</span>
                                <span class="detail-value">{rule.modified or 'N/A'}</span>
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Source Addresses ({len(rule.source_addresses)})</h5>
                            <div class="detail-value" style="margin-top: 8px;">
                                {src_tags}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Destination Addresses ({len(rule.dest_addresses)})</h5>
                            <div class="detail-value" style="margin-top: 8px;">
                                {dst_tags}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Services ({len(rule.services)})</h5>
                            <div class="detail-value" style="margin-top: 8px;">
                                {svc_tags}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Applications</h5>
                            <div class="detail-value">
                                {', '.join(rule.applications) if rule.applications else 'N/A'}
                            </div>
                        </div>

                        <div class="detail-group" style="grid-column: 1 / -1;">
                            <h5>Source Users</h5>
                            <div class="detail-value">
                                {', '.join(rule.source_users) if rule.source_users else 'N/A'}
                            </div>
                        </div>

                        {findings_html}
                    </div>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <h2>📋 Complete Rule Details (All {len(rules)} Active Rules - Sorted by Risk Score)</h2>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px;">
                <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🔴</span>
                        <span>Critical (≥90)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🟠</span>
                        <span>High (70-89)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🟡</span>
                        <span>Medium (40-69)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🟢</span>
                        <span>Low (20-39)</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 1.4em;">🔵</span>
                        <span>Info (<20)</span>
                    </div>
                </div>
                <div style="text-align: right;">
                    <button onclick="toggleAllRules()" style="padding: 10px 20px; background: {self.colors['signature_orange']}; color: {self.colors['white']}; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">
                        Expand/Collapse All
                    </button>
                </div>
            </div>
            <p style="margin-bottom: 20px; color: {self.colors['medium_grey']};">Click on any rule to expand and view all details. Rules are sorted by risk score (highest first)</p>
            {rules_html}
        </div>
        """

    def _format_address_list(self, addresses: List[str]) -> str:
        """Format address list with styling"""
        html = ""
        for addr in addresses:
            if addr.lower() == 'any':
                html += f"<span class='address-tag any'>ANY</span>"
            elif '/' in addr:
                html += f"<span class='address-tag subnet'>{addr}</span>"
            else:
                html += f"<span class='address-tag ip'>{addr}</span>"
        return html

    def _format_service_list(self, services: List[str]) -> str:
        """Format service list with styling"""
        html = ""
        for svc in services:
            if svc.lower() == 'any':
                html += f"<span class='service-tag any'>ANY</span>"
            else:
                html += f"<span class='service-tag'>{svc}</span>"
        return html

    def _format_rule_findings(self, findings: List[SecurityFinding]) -> str:
        """Format findings for rule detail view"""
        if not findings:
            return f"""
            <div class="detail-group" style="grid-column: 1 / -1; background: linear-gradient(135deg, #C8E6C9 0%, {self.colors['white']} 100%);">
                <h5>Security Findings</h5>
                <div style="color: {self.colors['risk_low']}; font-weight: 600;">✓ No security findings for this rule</div>
            </div>
            """

        html = f"""
        <div class="detail-group" style="grid-column: 1 / -1;">
            <h5>Security Findings ({len(findings)})</h5>
        """

        for finding in findings:
            html += f"""
            <div style="background: {self.colors['white']}; padding: 15px; border-radius: 8px; margin-top: 12px; border-left: 5px solid var(--risk-{finding.risk_level.value}, {self.colors['risk_' + finding.risk_level.value]});">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                    <span class="risk-badge risk-{finding.risk_level.value}">{finding.risk_level.value.upper()}</span>
                    <span style="font-weight: 600; color: {self.colors['signature_orange']};">Score: {finding.score}</span>
                </div>
                <div style="font-weight: 600; margin-bottom: 8px;">{finding.issue_type.value.replace('_', ' ').title()}</div>
                <div style="color: {self.colors['medium_grey']}; margin-bottom: 8px;">{finding.description}</div>
                <div style="background: {self.colors['very_light_grey']}; padding: 10px; border-radius: 6px; font-size: 0.95em;">
                    <strong>Recommendation:</strong> {finding.recommendation}
                </div>
                <div style="background: {self.colors['dark_grey']}; color: {self.colors['white']}; padding: 10px; border-radius: 6px; font-size: 0.85em; margin-top: 10px; font-family: monospace; overflow-x: auto;">
                    <strong>Calculation:</strong> {finding.calculation_formula}
                </div>
            </div>
            """

        html += "</div>"
        return html

    def _generate_footer(self) -> str:
        """Generate footer"""
        return f"""
        <footer>
            <p><strong>Multi-Vendor Firewall Security Analysis Report</strong></p>
            <p>Enhanced Security Analyzer - Full Implementation with All Features</p>
            <p style="margin-top: 12px; opacity: 0.9;">Zone-Based Analysis • Subnet Overlap Detection • Complete Rule Visibility • Comprehensive Risk Scoring</p>
            <p style="margin-top: 8px; opacity: 0.8;">Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </footer>
        """