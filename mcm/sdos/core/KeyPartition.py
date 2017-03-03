#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2017> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import io
import logging
import math

from sdos.crypto import CryptoLib


class KeyPartition(object):
    """
    An individual node (partition) form the tree
    """
    EMPTY_KEY = '\0'.encode() * 32

    def __init__(self, partitionId, cascadeProperties):
        """
        Constructor
        """
        self.log = logging.getLogger(__name__)
        self.cascadeProperties = cascadeProperties
        self.keys = [self.EMPTY_KEY] * self.cascadeProperties.PARTITION_SIZE
        self.partitionID = partitionId

    def print_partition(self):
        print()
        print('+' + '----' * 32 + '+')
        print('| SDOS key partition - PartitionID: %s' % (self.partitionID))
        print('+' + '----' * 32 + '+')
        for i in range(0, self.cascadeProperties.PARTITION_SIZE):
            # print ('| Key %i: \t %s' % (i, 'Empty' if self.keys[i] == self.EMPTY_KEY else self.keys[i]))
            print('| Key %i: \t %s' % (i, self.keys[i])) if self.keys[i] != self.EMPTY_KEY else None
        print('+' + '----' * 32 + '+')

    ###############################################################################
    # Key / slot operations
    ###############################################################################
    def setKey(self, slot, key):
        # yield from self.lock
        self.log.debug('partition {} setting slot {} to key {}'.format(self.partitionID, slot, key))
        self.keys[slot] = key

    def resetKey(self, slot):
        # self.lock.acquire()
        self.keys[slot] = self.EMPTY_KEY

    def getKey(self, slot):
        if (self.EMPTY_KEY == self.keys[slot]):
            return None
        return self.keys[slot]

    def generateKey(self, slot):
        if (self.EMPTY_KEY != self.keys[slot]):
            raise SystemError('requested generate key but slot is not empty')
        key = CryptoLib.generateRandomKey()
        self.setKey(slot, key)
        return key

    ###############################################################################
    # Navigate / traverse cascade structure
    ###############################################################################
    def getId(self):
        return self.partitionID

    def getParentId(self):
        return math.floor((self.partitionID - 1) / self.cascadeProperties.PARTITION_SIZE)

    def getSlotInParentForThisPartition(self):
        return ((self.partitionID - 1) % self.cascadeProperties.PARTITION_SIZE)

    def getChildIdAtSlot(self, slotId):
        return ((self.partitionID * self.cascadeProperties.PARTITION_SIZE) + 1 + slotId)

    ###############################################################################
    # Serialization
    ###############################################################################
    def serializeToBytesIO(self):
        by = io.BytesIO()
        by.write(self.partitionID.to_bytes(length=self.cascadeProperties.BYTES_FOR_PARTITION_IDs, byteorder='little',
                                           signed=False))
        for i in range(self.cascadeProperties.PARTITION_SIZE):
            by.write(self.keys[i])
        by.seek(0)
        return by

    def deserializeFromBytesIO(self, by):
        assert (len(by.getbuffer()) == (
            len(
                self.EMPTY_KEY) * self.cascadeProperties.PARTITION_SIZE) + self.cascadeProperties.BYTES_FOR_PARTITION_IDs)
        by.seek(0)
        self.partitionID = int.from_bytes(by.read(self.cascadeProperties.BYTES_FOR_PARTITION_IDs), byteorder='little',
                                          signed=False)
        for i in range(self.cascadeProperties.PARTITION_SIZE):
            self.keys[i] = by.read(len(self.EMPTY_KEY))
        by.__del__()