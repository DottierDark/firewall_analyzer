# Firewall Rule Analyzer

A powerful tool for analyzing and optimizing firewall rules across multiple vendors. Identify security risks, misconfigurations, and optimization opportunities in your firewall rulebase.

## Features

- **Multi-Vendor Support**: Analyze rules from Palo Alto, Cisco ASA, Fortinet, and more
- **Security Analysis**: Detect insecure protocols, overly permissive rules, and security risks
- **Rule Optimization**: Identify redundant and shadowed rules
- **Comprehensive Reporting**: Generate detailed HTML, JSON, or CSV reports
- **Application Awareness**: Integrate with vendor application databases for enhanced analysis
- **Zone-Based Analysis**: Understand traffic flows between network security zones

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/firewall-analyzer.git
   cd firewall-analyzer
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   # Windows
   python -m venv .venv
   .venv\Scripts\activate
   
   # Unix/MacOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install the package:
   ```bash
   pip install -e .
   ```

## Usage

### Basic Analysis

Analyze a firewall ruleset and generate an HTML report:

```bash
firewall-analyzer --vendor palo_alto input_rules.csv report.html
```

### With Application ID Database

For enhanced analysis with application information:

```bash
firewall-analyzer --vendor palo_alto --appid-db palo_alto_applipedia.json input.csv report.html
```

### Command Line Options

```
usage: firewall-analyzer [-h] [--vendor {palo_alto,cisco_asa,fortinet,checkpoint,juniper}]
                        [--appid-db APPID_DB] [--format {html,json,csv}]
                        [--zone-filter ZONE_FILTER] [--config CONFIG] [-v] [--version]
                        input [output]

positional arguments:
  input                 Input CSV file containing firewall rules
  output                Output file path for the report (default: stdout)

options:
  -h, --help            show this help message and exit
  --vendor {palo_alto,cisco_asa,fortinet,checkpoint,juniper}
                        Firewall vendor type (default: palo_alto)
  --appid-db APPID_DB   Path to application ID database (JSON)
  --format {html,json,csv}
                        Output format (default: html)
  --zone-filter ZONE_FILTER
                        Filter rules by source->destination zones (e.g., "DMZ->Internal")
  --config CONFIG       Path to custom configuration file
  -v, --verbose         Enable verbose output
  --version             Show version and exit
```

## Example Reports

### HTML Report
![HTML Report Example](docs/images/html-report-screenshot.png)

### JSON Output
```json
{
  "summary": {
    "total_rules": 150,
    "issues_found": 27,
    "critical_issues": 5,
    "high_risk_issues": 12,
    "medium_risk_issues": 10
  },
  "findings": [
    {
      "rule_id": "RULE-001",
      "severity": "critical",
      "description": "Rule allows RDP from Internet",
      "recommendation": "Restrict source IP range and consider using VPN"
    }
  ]
}
```

## Input Format

The analyzer expects CSV input with columns specific to each vendor. Example for Palo Alto:

```csv
Rule Name,Source Zone,Source Address,Destination Zone,Destination Address,Application,Service,Action,Description,Disabled,Log Setting
Allow_Web,untrust,any,web,web_servers,web-browsing,http,allow,Allow web traffic,false,log-all
```

## Configuration

Customize the analyzer's behavior by creating a `config.json` file:

```json
{
  "vendor": "palo_alto",
  "risk_weights": {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1
  },
  "exclude_disabled_rules": true,
  "exclude_deny_rules": true
}
```

## Development

### Building Documentation

```bash
cd docs
make html
```
