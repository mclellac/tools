#!/usr/bin/env python
import zipfile
import optparse
import sys
from threading import Thread


def extractFile(zfile, password):
    try:
        zfile.extractall(pwd=password)
        print("[+] Found password " + password + "\n")
    except:
        pass


def main():
    parser = optparse.OptionParser("usage%prog -f <zipfile> -d <dictionary>")
    parser.add_option("-f", dest="zname", type="string", help="specify zip file")
    parser.add_option("-d", dest="dname", type="string", help="specify dictionary file")
    (options, args) = parser.parse_args()

    if (options.zname == None) | (options.dname == None):
        print(parser.usage)
        sys.exit(0)
    else:
        zname = options.zname

    dname = options.dname
    zfile = zipfile.ZipFile(zname)
    passfile = open(dname)

    for line in passfile.readlines():
        password = line.strip("\n")
        t = Thread(target=extractFile, args=(zfile, password))
        t.start()


if __name__ == "__main__":
    main()
