# Meris RouterOS Checker

This tool will check a list of ip addresses of RouterOS-based routers to validate if they were infected with Meris.

The tool will:
- Attempt to connect using credentials in credentials.txt file (1 pair of credentials per line, default provided)
- Attempt to exploit the router using CVE-2018-14847

The tool supports:
- RouterOS API
- SSH
- WinBox (tested for <= 6.42)

The tool uses:
- Modified version of https://github.com/tenable/routeros/tree/master/poc/bytheway (by tenable) for WinBox operations
- RouterOS API module (https://pypi.org/project/RouterOS-api/) for RouterOS API operations
- paramiko for ssh operations

The tool will output exploited.csv file with a table of results for each provided IP address.

**Note**: To build modified version of bytheway, use provided cpp files instead of original main.cpp when building. 
You need to name the binaries `btw` and `btw_stage2` respectively, and put them next to the tool

# Detection rules
The tool will attempt to list scheduler scripts, and attempt to check if it contains any IoCs listed in `indicators.txt`.
The tool will also attempt to match scheduler scripts contents to the regex 
`https?://[^/]+/poll/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, and flag the matches
as possible infections.

# Tool usage
The tool requires either an `--ip` or `--ipfile` option.

`--ip` option takes a single ip address as input, `--ipfile` takes a file with a list of ips, one ip per file, as input.

Optionally, `--threads` can be used to tune the number of threads, with default being 16.
