#!/usr/bin/python
#use to merge mobile ranges.
#usage: $0 sourceFile mergedFile

import sys
import re

linePattern = re.compile('(\\d+)-(\\d+)\\s+([\\dX]+)')

infile = open(str(sys.argv[1]))
outfile = open(str(sys.argv[2]),'w')

lastStart = -1
while 1 :
    line = infile.readline()
    if not line : break

    matcher = linePattern.match(line)
    if not matcher : print 'error on %s' % (line)

    start = long(matcher.group(1)); end = long(matcher.group(2)); city = matcher.group(3)
    #print '%s-%s %s' %(start, end, city)
    if lastStart < 0 :
        lastStart = start; lastEnd = end; lastCity = city; continue

    if city == lastCity and lastEnd + 1 == start : lastEnd = end; continue

    outfile.write('%ld-%ld %s;\n'%(lastStart, lastEnd, lastCity))
    lastStart = start; lastEnd = end; lastCity = city    

if not lastStart < 0:
    outfile.write('%ld-%ld %s;\n'%(lastStart, lastEnd, lastCity))
    

