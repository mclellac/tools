#!/usr/bin/env python
import optparse
import sys
from socket import *
from threading import *

screenLock = Semaphore(value=1)


def scan(target_host, target_port):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((target_host, target_port))
        sock.send("XXXX\r\n")
        results = sock.recv(100)
        screenLock.acquire()
        print("[+]%d/tcp open" % target_port)
        print("[+] " + str(results))
    except:
        screenLock.acquire()
        print("[-]%d/tcp closed" % target_port)
    finally:
        screenLock.release()
        sock.close()


def port_scanner(target_host, target_ports):
    try:
        target_ip = gethostbyname(target_host)
    except:
        print("[-] Cannot resolve '%s': Unknown host" % target_host)
        return

    try:
        targetName = gethostbyaddr(target_ip)
        print("\n[+] Scan Results for: " + targetName[0])
    except:
        print("\n[+] Scan Results for: " + target_ip)
        setdefaulttimeout(1)

    for target_port in target_ports:
        t = Thread(target=scan, args=(target_host, int(target_port)))
        t.start()


def main():
    parser = optparse.OptionParser(
        "usage%prog " + "-H <target host> -p <target port>"
    )
    parser.add_option(
        "-H", dest="target_host", type="string", help="specify target host"
    )
    parser.add_option(
        "-p",
        dest="target_port",
        type="string",
        help="specify target port[s] separated by comma",
    )
    (options, args) = parser.parse_args()

    target_host = options.target_host
    target_ports = str(options.target_port).split(", ")

    if (target_host == None) | (target_ports[0] == None):
        print(parser.usage)
        sys.exit(0)

    port_scanner(target_host, target_ports)


if __name__ == "__main__":
    main()
