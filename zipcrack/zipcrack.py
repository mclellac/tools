#!/usr/bin/env python
import zipfile
import argparse
import sys
from threading import Thread


def extractFile(zfile, password):
    try:
        zfile.extractall(pwd=password)
        print("[+] Found password " + password + "\n")
    except:
        pass


def main():
    parser = argparse.ArgumentParser(
        usage="Example use: " + sys.argv[0] + " -f <zipfile> -d <dictionaryfile>"
    )
    parser.add_argument("--filename", "-f", help="specify zip file", nargs="?")
    parser.add_argument("--dictionary", "-d", help="specify dictionary file", nargs="?")
    args = parser.parse_args()

    if args.filename == None or args.dictionary == None:
        print(parser.usage)
        sys.exit(0)
    else:
        zname = args.filename
        dname = args.dictionary

    zfile = zipfile.ZipFile(zname)
    passfile = open(dname)

    for line in passfile.readlines():
        password = line.strip("\n")
        t = Thread(target=extractFile, args=(zfile, password))
        t.start()


if __name__ == "__main__":
    main()
