Installation
============

Prerequisites
-------------
- Python 3.8 or higher
- pip (Python package installer)

Installing from Source
----------------------

1. Clone the repository:

   .. code-block:: bash

      git clone https://github.com/yourusername/firewall-analyzer.git
      cd firewall-analyzer

2. Create and activate a virtual environment (recommended):

   .. code-block:: bash
      
      # On Windows
      python -m venv .venv
      .venv\Scripts\activate
      
      # On Unix or MacOS
      python3 -m venv .venv
      source .venv/bin/activate

3. Install the package in development mode:

   .. code-block:: bash

      pip install -e .

4. Install development dependencies (optional):

   .. code-block:: bash

      pip install -r requirements-dev.txt

Verifying the Installation
--------------------------

To verify that the installation was successful, run:

.. code-block:: bash

   firewall-analyzer --version

This should display the installed version of the Firewall Analyzer.

Upgrading
---------

To upgrade to the latest version:

.. code-block:: bash

   git pull origin main
   pip install -e . --upgrade

Troubleshooting
---------------

If you encounter any issues during installation, please check the following:

1. Ensure you have the correct Python version (3.8+)
2. Verify that pip is up to date: ``python -m pip install --upgrade pip``
3. Check for any error messages during installation
4. If you encounter permission errors, try using the ``--user`` flag with pip

For additional help, please open an issue on the project's GitHub repository.
