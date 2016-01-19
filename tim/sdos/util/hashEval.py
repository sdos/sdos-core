#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on Apr 7, 2015

@author: tim
'''

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
		print ("val: %s - %s" % (h[0], h[1]))
		# ps.readPartition(h[0][0])
		# ps.readPartition(h[1][0])
		# ps.readPartition(h[2][0])
		
	print("done")
	# ps.printLen()
	# print(sorted(hvals.values(), reverse=True))
	
	
	
if __name__ == 'mm__main__':
	p = KeyCascade.KeyPartition(0)
	p.print()
