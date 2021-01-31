#!/usr/bin/env python3
# By Norrotor

import os
import argparse
from multiprocessing import Process
from typing import List

directory = "recon"
try:
    os.mkdir(directory)
except OSError:
    pass


def scan_message(timing: str, mode: str, protocol: str):
    """Print an appropriate message regarding the port scanning progress.

    Args:
        timing: scan stage (just started - 'starting', already done - 'skip' or completed - 'end').
        mode: type of scan (quick scan, service scan, vuln scan or directory scan).
        protocol: protocol of scan (TCP, UDP or HTTP)
    """

    timing = timing.lower()
    if timing not in ["start", "skip", "end"]:
        raise ValueError("Invalid time. Time should be 'start', 'skip' or 'end'.")

    mode = mode.lower()
    if mode not in ["quick", "service", "vuln"]:
        raise ValueError("Invalid mode. Mode should be 'quick', 'service' or 'vuln'.")

    protocol = protocol.upper()
    if protocol not in ["TCP", "UDP"]:
        raise ValueError("Invalid protocol. Protocol should be 'TCP' or 'UDP'.")

    line = None
    if timing == "start":
        if mode == "quick":
            line = f"Starting quick {protocol} scan."
        elif mode == "service":
            line = f"Starting {protocol} service scan."
        elif mode == "vuln":
            line = f"Starting {protocol} vulnerability scan."
    elif timing == "skip":
        if mode == "quick":
            line = f"Skipping quick {protocol} scan. File already exists."
        elif mode == "service":
            line = f"Skipping {protocol} service scan. File already exists."
        elif mode == "vuln":
            line = f"Skipping {protocol} vulnerability scan. File already exists."
        else:
            line = "Skipping directory scan. No open ports found."
    else:
        if mode == "quick":
            line = f"Quick {protocol} scan completed."
        elif mode == "service":
            line = f"{protocol} service scan completed."
        elif mode == "vuln":
            line = f"{protocol} vulnerability scan completed."

    separator_line = '#' * len(line)

    print()
    print(separator_line)
    print(line)
    print(separator_line)
    print()


def scan_ports(target: str, protocol: str, vuln: bool = False):
    """Perform a port scanning of the given target.

    Args:
        target: address to be scanned
        protocol: protocol of scan
        vuln: if set, also perform vulnerability scan on the target, using the 'nmap-vulners' script

    First, a 'quick' scan (checking open ports) will be performed, then a service scan (checking the services running
    on the open ports found) will be performed. If needed, there the 'vuln' scan will be performed after the service
    scan.
    """

    # Validates the protocol
    protocol = protocol.lower()
    if protocol not in ["tcp", "udp"]:
        raise ValueError("Invalid protocol.")

    global directory

    # File names of scans
    quick_file = f"{directory}/quick_{protocol}_scan"
    service_file = f"{directory}/service_{protocol}_scan"

    def quick_scan(_target: str, _protocol: str):
        """Scan the target for open ports. Doesn't provide any info besides whether the port is open or not.

        Args:
            _target: address to be scanned
            _protocol: protocol of scan
        """

        if os.path.isfile(quick_file + ".nmap"):  # If file exists skips scanning
            scan_message('skip', 'quick', protocol)
            return

        if _protocol == "tcp":
            command = "nmap -p- "  # Scan all TCP ports
        else:
            command = "nmap -sU "  # Scan common UDP ports, as scanning every port takes forever

        command += f"--min-rate 1000 -T5 {_target} -oA {quick_file}"  # Base scan command

        scan_message('start', 'quick', protocol)  # Prints starting scan message
        os.system(command)  # Scans the target
        scan_message('end', 'quick', protocol)  # Prints scan completed message

    # noinspection DuplicatedCode
    def service_scan(_target: str, _protocol: str):
        """Perform a service scan on the given target. Requires a quick scan file to be present.

        Args:
            _target: address to be scanned
            _protocol: protocol of scan
        """

        if os.path.isfile(service_file + ".nmap"):  # If file exists skip scanning
            scan_message('skip', 'service', protocol)
            return

        _quick_file = quick_file + ".nmap"
        if not os.path.isfile(_quick_file):
            message = f"Quick scan file '{_quick_file}' doesn't exist.\n" \
                      f"In order for the service scan to work, it needs a quick scan to be done beforehand."
            raise FileNotFoundError(message)

        # Get the ports from the quick scan file
        ports = os.popen(
            f"cat {_quick_file} | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//'").read()

        command = f"nmap --min-rate 1000 -T5 -p{ports} {_target} -sV -sC -oA {service_file}"  # Base scan command

        if _protocol == "udp":
            command += " -sU"  # Flag for UDP scan

        scan_message('start', 'service', protocol)  # Prints starting scan message
        os.system(command)  # Scans the target
        scan_message('end', 'service', protocol)  # Prints scan completed message

    # noinspection DuplicatedCode
    def vuln_scan(_target: str, _protocol: str):
        """Perform a vulnerability scan on the given target.

        Args:
            _target: address to be scanned
            _protocol: protocol of scan
        """

        _quick_file = quick_file + ".nmap"
        vuln_file = f"{directory}/vuln_{_protocol.lower()}_scan"

        if os.path.isfile(vuln_file + ".nmap"):  # If file exists skip scanning
            scan_message('skip', 'vuln', protocol)
            return

        if not os.path.isfile(_quick_file + ".nmap"):
            message = f"Quick scan file '{_quick_file}.nmap' doesn't exist.\n" \
                      f"In order for the service scan to work, it needs a quick scan to be done beforehand."
            raise FileNotFoundError(message)

        # Get the ports from the quick scan file
        ports = os.popen(
            f"cat {_quick_file} | grep ^[0-9] | grep open | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//'").read()

        command = f"nmap --script nmap-vulners -sV -p{ports} -T5 {_target} -oA {vuln_file}"  # Base scan command

        if _protocol == "udp":
            command += " -sU"  # Flag for UDP scan

        scan_message("start", "vuln", protocol)  # Prints starting scan message
        os.system(command)  # Scans the target
        scan_message("end", "vuln", protocol)  # Prints scan completed message

    quick_scan(target, protocol)
    service_scan(target, protocol)
    if vuln:
        vuln_scan(target, protocol)


def scan_dir(target: str, ports: List[int], wordlist: str, extensions: str,
             threads: int = 50,
             status_codes: str = "200,204,301,302,307,401,403"):
    """Perform a file and directory scan on the target.

    Args:
        target: address of target
        ports: list of ports with web servers listening
        wordlist: list of directories and files names to search for
        extensions: extensions of files
        threads: number of threads to use in scan
        status_codes: response status codes to show
    """

    def child_dir_scan(_target: str, _port: int, _wordlist: str,
                       _extensions: str = None,
                       _threads: int = 50,
                       _status_codes: str = "200,204,301,302,307,401,403"):
        """Scan the files and directories on the web server.

        Args:
            _target: address of target
            _port: the port the web server is listening on
            _wordlist: list of file names to search for
            _extensions: extensions to search for, along with directories
            _threads: number of threads to use in scan
            _status_codes: response status codes to show
        """

        # Ensures known wordlists contain full path
        if _wordlist in ["big.txt", "common.txt"]:
            _wordlist = "/usr/share/wordlists/dirb/" + _wordlist
        if _wordlist in ["directory-list-2.3-medium.txt", "directory-list-2.3-small.txt"]:
            _wordlist = "/usr/share/wordlists/dirbuster/" + _wordlist
        if _wordlist in ["medium", "small"]:
            _wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-" + _wordlist + ".txt"

        # Ensures target starts with 'http://'
        if not (_target.startswith('http://') or _target.startswith('https://')):
            _target = "http://" + _target

        # Removes trailing slash
        if _target.endswith('/'):
            _target = _target[:-1]

        path = _target.split('/')  # Path is ['http', '', target, <dir_tree>]
        dirs = path[3:]  # Only the directories of the path are needed

        if not dirs:
            out_file = f"{directory}/gobuster_{_port}.dir"
        else:
            dir_path = '_'.join(dirs)  # This is for the output file
            out_file = f"{directory}/gobuster_{_port}_{dir_path}.dir"

        dir_path = '/'.join(
            dirs)  # This is for the scan, because the port has to come between target and directories

        # Scan command
        command = (
            f"gobuster dir -u {_target}:{_port}/{dir_path} -w {_wordlist} "
            f" -t {_threads} -s {_status_codes} -o {out_file}")

        if _extensions is not None:
            command += f" -x {_extensions}"

        os.system(command)  # Runs scan

    if ports:
        for port in ports:
            p = Process(target=child_dir_scan, args=(
                target, port, wordlist, extensions, threads, status_codes))
            p.start()
            p.join()
            print()


def get_http_ports(file: str):
    """Get open http(s) ports from the given file.

    Args:
        file: file to search for ports in.

    Returns:
        list of open http(s) ports.

    Raises:
        FileNotFoundError if the file doesn't exist.
    """

    if not os.path.isfile(file):
        error_string = (f"File '{file}' not found."
                        "You can fix this performing a quick scan on the target (manually or using this script), "
                        "or you can specify the port the web server is listening on with the '-p' flag.")
        raise FileNotFoundError(error_string)
    else:
        _ports = os.popen(
            f"cat {file} | grep ^[0-9] | grep -v 'unrecognized despite returning data' | grep http | "
            f"cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//'").read()

        # Returns list of open ports
        if _ports:
            return _ports.split(',')

        # Returns empty list, because there are no open http ports
        else:
            return []


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="scan type", dest="scan_type", required=True)
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("target", help="address of target")

    parser_port = subparsers.add_parser("port", parents=[parent_parser], help="port scanning")
    parser_port.add_argument("-t", "--tcp", help="scan open TCP ports (default)",
                             action="store_true",
                             default=True)
    parser_port.add_argument("-u", "--udp", help="scan open UDP ports",
                             action="store_true",
                             default=False)
    parser_port.add_argument("-v", "--vuln",
                             help="perform vulnerability scanning, using nmap-vulners",
                             action="store_true",
                             default=False)

    parser_dir = subparsers.add_parser("dir", parents=[parent_parser], help="directory scanning")
    parser_dir.add_argument("--threads", help="number of threads", type=int,
                            default=50)
    parser_dir.add_argument("-w", "--wordlist", help="wordlist to be used",
                            default="big.txt")
    parser_dir.add_argument("-x", "--extensions",
                            help="comma separated list of extensions to search for")
    parser_dir.add_argument("-s", "--status-codes",
                            help="comma separated list of status codes to show",
                            default="200,204,301,302,307,401,403")
    port_group = parser_dir.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--port",
                            help="comma separated list of port(s) with web servers listening")
    port_group.add_argument("-f", "--file",
                            default=f"{directory}/service_tcp_scan.nmap",
                            help="file the http(s) port(s) will be taken from")

    args = None
    try:
        args = parser.parse_args()
    except TypeError:
        parser.print_help()
        exit(1)

    if args.scan_type == "port":
        if args.udp:
            protocol = "udp"
        else:
            protocol = "tcp"
        scan_ports(args.target, protocol, args.vuln)
    else:
        if not args.port:
            ports = get_http_ports(args.file)
        else:
            if "," in args.port:
                ports = args.port.split(",")
            else:
                ports = [args.port]
            try:
                ports = [int(port) for port in ports]
            except ValueError:
                raise ValueError("Invalid port(s). Ports should be an integer or a comma separated "
                                 "list of integers.")
        scan_dir(args.target, ports, args.wordlist, args.extensions, args.threads,
                 args.status_codes)


if __name__ == '__main__':
    main()
