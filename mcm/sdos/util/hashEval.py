#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

from mcm.sdos.core import KeyCascade
from mcm.sdos.core.PartitionStore import PartitionStore

if __name__ == 'xx__main__':
    hvals = dict()
    for i in range(100000):
        s = str(i)
        #h = KeyCascade.hashName(s)
        hvals[h] = 1 + hvals.get(h, 0)

    # print ("%s - %i" % (s, h))

    print("done, numvals: %i" % (len(hvals)))
# print(sorted(hvals.values(), reverse=True))

if __name__ == '__main__':
    ps = PartitionStore()

    for i in range(100):
        s = str(i)
        #h = KeyCascade.getCascadePathIds(s)
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

"""
def insertNewObjectKey(ids, key, partitionStore):
	partitionIds = ids[0]
	slotIds = ids[1]
	#print(partitionIds) # ID order matters! root -> leaf

	partitions = partitionStore.readPartitions(partitionIds)
	#print(partitions)

	#insert actual key into last partition
	partitions[partitionIds[-1]].setKey(slotIds[-1], key)

def retrieveObjectKey(ids, partitionStore):
	partitionIds = ids[0]
	slotIds = ids[1]
	#print(partitionIds) # ID order matters! root -> leaf
	partitions = partitionStore.readPartitions(partitionIds)
	return partitions[partitionIds[-1]].getKey(slotIds[-1])
"""
###############################################################################
###############################################################################
###############################################################################
"""
def getCascadePathIds(name):
	partitionIds = [None] * (TREE_HEIGHT)
	slotIds = [None] * (TREE_HEIGHT)
	fullHash = hashName(name)
	# get byte array from hash values; 64 bits in size
	b = fullHash.to_bytes(length=8, byteorder='little', signed=False)
	for i in range(0, (TREE_HEIGHT)):
		partitionIds[i] = '%i_%i' % (i, int.from_bytes(b[:i], byteorder='little', signed=False))
		slotIds[i] = b[i]
	return partitionIds, slotIds

def hashName(name):
	return hash4(name)

def hash4(name):
	# "None" hash; only interpret name as integer
	return int(name)

def hash3(name):
	# Mersenne Twister pseudo random number generator based hash
	numberSlots = KeyPartition.NUMBER_SLOTS
	b = name.encode()
	i = int.from_bytes(b, byteorder='little', signed=False)

	r = random.Random()
	r.seed(i)
	h = r.randint(0, numberSlots)
	return h

def hash2(name):
	# prime modulo hash
	numberSlots = KeyPartition.NUMBER_SLOTS
	p = 52983525027941 #  large prime after 3^256

	b = name.encode()
	i = int.from_bytes(b, byteorder='little', signed=False)

	h = (i % p) % numberSlots
	#print("hash2: %s > %i - %i" % (name, i, h))
	return h

def hash1(name):
	# block shifting hash
	b = name.encode()
	# pad to 8 bytes
	b= b + '\0'.encode() * (32 - len(b))
	res = '\0'.encode()
	res = res[0] & b[0]
	res = res ^ b[1]
	res = res ^ b[2]
	res = res ^ b[3]
	return res
"""