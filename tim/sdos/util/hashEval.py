#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

from tim.sdos.core import KeyCascade
from tim.sdos.core.PartitionStore import PartitionStore

if __name__ == 'xx__main__':
	hvals = dict()
	for i in range(100000):
		s = str(i)
		h = KeyCascade.hashName(s)
		hvals[h] = 1 + hvals.get(h, 0)

	# print ("%s - %i" % (s, h))

	print("done, numvals: %i" % (len(hvals)))
# print(sorted(hvals.values(), reverse=True))

if __name__ == '__main__':
	ps = PartitionStore()

	for i in range(100):
		s = str(i)
		h = KeyCascade.getCascadePathIds(s)
		print("val: %s - %s" % (h[0], h[1]))
	# ps.readPartition(h[0][0])
	# ps.readPartition(h[1][0])
	# ps.readPartition(h[2][0])

	print("done")
# ps.printLen()
# print(sorted(hvals.values(), reverse=True))

if __name__ == 'mm__main__':
	p = KeyCascade.KeyPartition(0)
	p.print()
