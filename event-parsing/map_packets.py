#!/usr/bin/python

import packet_analyzer
import sys

filename = sys.argv[1]
f = open(filename)
pa = packet_analyzer.PacketAnalyzer("141.212.113.208")
for line in f:
	pa.add_line(line)
pa.printall()
pa.find_timings()
pa.output_timing_results()
