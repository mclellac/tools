#!/usr/bin/env python
import argparse
import ipaddress
import logging
import socket
import concurrent.futures
import tqdm

logging.basicConfig(level=logging.WARN)

def scan_port(target_host, target_port):
    try:
        with socket.create_connection((target_host, target_port), timeout=1) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n")
            response = sock.recv(1024)
            return target_port
    except (socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
        logging.error(f"Error scanning port {target_port}: {e}")
        return None

def scan_ports(target_host, target_ports):
    open_ports = set()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_port, target_host, port) for port in target_ports]
        with tqdm.tqdm(total=len(target_ports)) as progress:
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.add(result)
                progress.update(1)
    return open_ports

def fingerprint_os(target_host):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(1)
            sock.connect((target_host, 80))
            sock.sendall(b"\x08\x00\x7d\x4b\x00\x00\x00\x00Ping")
            response = sock.recv(1024)
            if b"Windows" in response:
                return "Windows"
            elif b"Linux" in response:
                return "Linux"
            elif b"FreeBSD" in response:
                return "FreeBSD"
            else:
                return "Unknown"
    except Exception as e:
        logging.error(f"Error fingerprinting OS: {e}")
        return "Unknown"

def port_scanner(target_host, target_port_range):
    try:
        target_ip = ipaddress.ip_address(target_host)
    except ValueError:
        try:
            target_ip = socket.gethostbyname(target_host)
        except socket.gaierror as e:
            logging.error(f"Cannot resolve '{target_host}': {e}")
            return

    try:
        target_name = socket.gethostbyaddr(str(target_ip))[0]
        print(f"Scan results for: {target_name}")
    except socket.herror:
        print(f"Scan results for: {target_ip}")

    try:
        start_port, end_port = map(int, target_port_range.split("-"))
        if start_port < 0 or end_port > 65535:
            raise ValueError("Port range must be between 0 and 65535")
        target_ports = range(start_port, end_port + 1)
    except (ValueError, TypeError):
        logging.error(f"Invalid port range: {target_port_range}")
        return

    open_ports = scan_ports(target_host, target_ports)

    print("Open ports:")
    for port in sorted(open_ports):
        try:
            service_name = socket.getservbyport(port)
        except OSError:
            service_name = "unknown"
        print(f"{port}/tcp - {service_name}")

    os_name = fingerprint_os(target_host)
    print(f"OS fingerprint: {os_name}")

def main():
    parser = argparse.ArgumentParser(description='Port scanner')
    parser.add_argument('target_host', type=str, help='specify target host')
    parser.add_argument('target_port_range', type=str, help='specify target port range (e.g. 0-65535)')
    args = parser.parse_args()

    port_scanner(args.target_host, args.target_port_range)

if __name__ == "__main__":
    main()