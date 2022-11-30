#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################

# converts a CSV of peering testbed connections to a policies file

import sys
import csv

peeringCSV = open(sys.argv[1], newline='')

muxDict = {}
peersReader = csv.reader(peeringCSV, delimiter=',', quotechar='"')

for row in peersReader:
    if row[0][0] == "B":
        continue
    mux = row[0]
    asn = row[2]
    transit = True if row[-3] == "✔" else False
    # transit = True if row[-3] == "True" else False
    if mux not in muxDict:
        muxDict[mux] = [set(), set()]
    if asn not in muxDict[mux][1 if transit else 0]:
        muxDict[mux][1 if transit else 0].add(asn)
        print("{}:{}@{}".format(mux, "EXTRA_PROVIDER" if transit else "EXTRA_PEER", asn))
        # symmetric: add customer for provider too
        if transit:
            print("{}:{}@{}".format(asn, "EXTRA_CUSTOMER", mux))