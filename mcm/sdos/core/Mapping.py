#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import logging
import io
import threading


###############################################################################
###############################################################################
###############################################################################
class KeySlotMapper(object):
    """
    here we store and manage the mapping between keys (identified by object IDs/object names)
    and slots in the object-key-partitions
    """

    def __init__(self, mappingStore, cascadeProperties):
        """
        the mapping dict stores all the used slots in the partitions
        the used/free lists are derived from this and don't get stored
        """
        logging.warning("Init new")
        self.log = logging.getLogger(__name__)
        self.is_mapping_clean = True
        self.mapping = dict()
        self.usedList = set()
        # self.freeList = dict() # no free list used ATM
        self.mappingStore = mappingStore
        self.cascadeProperties = cascadeProperties
        self.readMapping()
        self.__watch_and_store_mapping()


    def __populateUsedList(self):
        for t in self.mapping.values():
            self.usedList.add(t)

    def finish(self):
        self.storeMapping()

    def __watch_and_store_mapping(self):
        self.log.debug("checking mapping consistency...")
        if not self.is_mapping_clean:
            self.log.info("local mapping changed; flushing to store")
            self.storeMapping()
            self.is_mapping_clean = True
        threading.Timer(10, self.__watch_and_store_mapping).start()

    def getMappingDict(self):
        return self.mapping

    def getUsedList(self):
        return self.usedList

    ###############################################################################
    ###############################################################################
    def findFreeSlot(self):
        for slot in range(self.cascadeProperties.FIRST_OBJECT_KEY_SLOT, self.cascadeProperties.LAST_OBJCT_KEY_SLOT + 1):
            if slot not in self.usedList:
                return slot

        raise SystemError('no more free key slots available')

    def setMapping(self, name, slot):
        self.is_mapping_clean = False
        self.mapping[str(name)] = slot
        self.usedList.add(slot)
        self.log.debug('set mapping: {} {}, {} {}'.format(name, type(name), slot, type(slot)))

    def getOrCreateMapping(self, name):
        if name in self.mapping:
            slot = self.getMapping(name)
        else:
            slot = self.findFreeSlot()
            self.setMapping(name, slot)
        return slot

    def getMapping(self, name):
        return self.mapping[name]

    def resetMapping(self, name):
        self.is_mapping_clean = False
        slot = self.mapping.pop(name)
        self.usedList.remove(slot)
        return slot

    ###############################################################################
    ###############################################################################

    def serializeToBytesIO(self):
        # format: <len(ids)><len(name)><name><id>...<len(name)><name><id>...
        by = io.BytesIO()
        by.write(self.cascadeProperties.BYTES_FOR_SLOT_IDS.to_bytes(length=1, byteorder='little', signed=False))
        for k, v in self.mapping.items():
            by.write(
                len(k).to_bytes(length=self.cascadeProperties.BYTES_FOR_NAME_LENGTH, byteorder='little', signed=False))
            by.write(k.encode(encoding='utf_8', errors='strict'))
            by.write(v.to_bytes(length=self.cascadeProperties.BYTES_FOR_SLOT_IDS, byteorder='little', signed=False))
        by.seek(0)
        return by

    def deserializeFromBytesIO(self, by):
        by.seek(0)
        idLen = int.from_bytes(by.read(1), byteorder='little', signed=False)
        if (idLen != self.cascadeProperties.BYTES_FOR_SLOT_IDS):
            raise SystemError('error parsing mapping: ID byte length mismatch')
        while (True):
            keyLength = int.from_bytes(by.read(self.cascadeProperties.BYTES_FOR_NAME_LENGTH), byteorder='little',
                                       signed=False)
            if not keyLength:
                break
            key = by.read(keyLength).decode(encoding='utf_8', errors='strict')
            value = int.from_bytes(by.read(self.cascadeProperties.BYTES_FOR_SLOT_IDS), byteorder='little', signed=False)
            # self.log.debug('read mapping: {},{}'.format(key, value))
            self.setMapping(key, value)

        by.close()

    def storeMapping(self):
        self.log.info("flushing modified mapping from cache. Size: {}".format(len(self.mapping)))
        self.mappingStore.writeMapping(self.serializeToBytesIO())

    def readMapping(self):
        by = self.mappingStore.readMapping()
        if by:
            self.log.info("retrieved stored mapping")
            self.deserializeFromBytesIO(by)
            self.__populateUsedList()
            self.is_mapping_clean = True
        else:
            self.log.error('retrieved no stored mapping. starting empty...')
