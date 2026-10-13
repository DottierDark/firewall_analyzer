Usage
=====

Basic Usage
----------

The basic syntax for running the Firewall Analyzer is:

.. code-block:: bash

   firewall-analyzer [OPTIONS] INPUT_CSV [OUTPUT_REPORT]

Example:

.. code-block:: bash

   firewall-analyzer --vendor palo_alto --appid-db palo_alto_applipedia.csv input_rules.csv report.html

Command Line Options
-------------------

.. program-output:: python -m firewall_analyzer.cli --help
   :prompt:

Input Format
-----------

The Firewall Analyzer accepts CSV files containing firewall rules. The expected format depends on the vendor.

### Palo Alto Networks

For Palo Alto firewalls, the CSV should include these columns:
- Rule Name
- Source Zone
- Source Address
- Destination Zone
- Destination Address
- Application
- Service
- Action
- Description
- Disabled
- Log Setting

### Other Vendors

For other vendors (Cisco ASA, Fortinet, etc.), the tool will attempt to map the fields automatically based on the vendor schema.

Output Formats
-------------

The tool can generate reports in multiple formats:

1. **HTML Report** (default): Interactive web-based report with filtering and search capabilities.
   - Example: ``firewall-analyzer input.csv report.html``

2. **JSON Output**: Machine-readable JSON format for further processing.
   - Example: ``firewall-analyzer --format json input.csv report.json``

3. **CSV Output**: Tabular format that can be opened in spreadsheet software.
   - Example: ``firewall-analyzer --format csv input.csv report.csv``

Examples
--------

### Basic Analysis

Analyze a Palo Alto ruleset and generate an HTML report:

.. code-block:: bash

   firewall-analyzer --vendor palo_alto input_rules.csv analysis_report.html

### Using Application ID Database

Include application information using an AppID database:

.. code-block:: bash

   firewall-analyzer --vendor palo_alto --appid-db palo_alto_applipedia.json input.csv report.html

### Filtering by Zone

Analyze only rules affecting specific zones:

.. code-block:: bash

   firewall-analyzer --zone-filter "DMZ->Internal" input.csv report.html

### Custom Configuration

Use a custom configuration file:

.. code-block:: bash

   firewall-analyzer --config custom_config.json input.csv report.html

### Verbose Output

Enable verbose output for debugging:

.. code-block:: bash

   firewall-analyzer -v input.csv report.html

Troubleshooting
--------------

- **Missing Dependencies**: Ensure all required Python packages are installed
- **File Not Found**: Verify the input file path is correct
- **Permission Denied**: Make sure you have read access to input files and write access to the output directory
- **Unsupported Vendor**: Check that the vendor is supported (use ``--list-vendors`` to see available options)

For additional help, run:

.. code-block:: bash

   firewall-analyzer --help
