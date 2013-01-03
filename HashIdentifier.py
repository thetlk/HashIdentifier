#!/usr/bin/env python
# encoding: utf-8

"""
    Copyright 2013 Jérémie BOUTOILLE

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

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
