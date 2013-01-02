#!/usr/bin/env python
# encoding: utf-8

import argparse
import re

HASHES = {"MD5": re.compile(r"^[A-Fa-f0-9]{32}$"),
          "SHA1": re.compile(r"^[A-Fa-f0-9]{40}$"),
          "SHA224": re.compile(r"^[A-Fa-f0-9]{56}$"),
          "SHA256": re.compile(r"^[A-Fa-f0-9]{64}$"),
          "SHA384": re.compile(r"^[A-Fa-f0-9]{96}$"),
          "SHA512": re.compile(r"^[A-Fa-f0-9]{128}$"),
          "MySQL": re.compile(r"^[A-Fa-f0-9]{16}$"),
          "MD5-Crypt": re.compile(r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
          "SHA512-Crypt": re.compile(r"^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$")}


def main():

    parser = argparse.ArgumentParser(description='Identify a hash')
    parser.add_argument('hash', help='hash to identify')
    args = parser.parse_args()
    hashe = args.hash

    results = []

    for hashName, hashRegexp in HASHES.items():
        if hashRegexp.match(hashe):
            results.append(hashName)

    if len(results) == 0:
        print "[-] Unabble to identify the hash"
        return

    if len(results) == 1:
        print "[+] Result for '%s' :" % hashe
    else:
        print "[+] '%s' can be :" % hashe

    for result in results:
        print "\t - %s" % result

if __name__ == '__main__':
    main()
