# Rogue MySQL Server (Python3 Version)

This repository contains a Python 3 rewritten version of the Rogue MySQL Server, which was initially implemented in Python 2.

## Changes from the original

- Updated all code for Python 3 compatibility, including:
  - Replacing `xrange` with `range`
  - Handling byte strings and Unicode explicitly
  - Using modern syntax and libraries compatible with Python 3
- Improved socket handling with Python 3’s `bytes` and `str` distinctions
- Maintained original functionality to simulate a rogue MySQL server for testing and security research

## Usage

Run the server with:

```bash
python3 rogue_mysql_server.py
