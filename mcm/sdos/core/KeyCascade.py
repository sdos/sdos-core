#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import io
import logging
import math
from mcm.sdos.crypto.PartitionCrypt import PartitionCrypt
from mcm.sdos.crypto import CryptoLib
from sdos import configuration


class Cascade(object):
    """
    Key Cascade main object. One instance of this should exist for each key-cascade (for each container)
    """

    def __init__(self, partitionStore, keySlotMapper, cascadeProperties):
        self.log = logging.getLogger(__name__)
        self.partitionStore = partitionStore
        self.keySlotMapper = keySlotMapper
        self.cascadeProperties = cascadeProperties
        self.partitionCache = dict()
        self.log.info(
            "Initializing new Key Cascade: {} with partitionStore {}, keySlotMapper {}, cascadeProperties {}".format(
                self, self.partitionStore, self.keySlotMapper, self.cascadeProperties))

    ###############################################################################
    # Helpers for visualizing, debugging, statistics...
    ###############################################################################
    def get_used_partitions(self):
        def rekParts(listNow):
            if not listNow:
                return []
            n = set()
            for i in listNow:
                s = self.__getPartitionIdForSlot(i)
                n.add(s)
                if (i == 0): return n
            return n.union(rekParts(n))

        p = rekParts(self.keySlotMapper.getUsedList())
        return list(p)

    def get_reverse_object_key_partition_mapping(self):
        """
        produces a dict that maps obj key partitions to their object key content.
        example for partition 257:
        {"257": [{"objName": "WindowsInstaller.c", "slot": 157}, {"objName": "Inheritance.java", "slot": 23}
        :return:
        """
        result = dict()
        for objName, objKeySlot in self.keySlotMapper.getMappingDict().items():
            objKeyPartition = self.__getPartitionIdForSlot(objKeySlot)
            slotInPartition = self.__globalSlotToLocalSlot(objKeySlot)
            # print(objName, objKeySlot, objKeyPartition, slotInPartition)
            partition = result.get(objKeyPartition, [])
            partition.append({"slot": slotInPartition, "objName": objName})
            result[objKeyPartition] = partition
        return result

    ###############################################################################
    # Utility
    ###############################################################################
    def __getPartitionIdForSlot(self, slot):
        return max(0, math.floor((slot - 1) / self.cascadeProperties.PARTITION_SIZE))

    def __globalSlotToLocalSlot(self, slot):
        return (slot - 1) % self.cascadeProperties.PARTITION_SIZE

    def __is_object_key_slot(self, slot):
        """
        slot IDs are globally counted
        :param slot:
        :return:
        """
        return slot >= self.cascadeProperties.FIRST_OBJECT_KEY_SLOT

    def finish(self):
        # self.partitionStore.print()
        self.keySlotMapper.finish()

    ###############################################################################
    # Master Key
    ###############################################################################
    def __getCurrentMasterKey(self):
        return CryptoLib.digestKeyString('MASTERKEY')

    ###############################################################################
    # Partition load / store
    ###############################################################################
    def getPartition(self, partitionId, key):
        if partitionId in self.partitionCache:
            logging.info("getting cached partition: {}".format(partitionId))
            return self.partitionCache[partitionId]
        try:
            return self.__getOrGeneratePartition(partitionId, key, createIfNotExists=False)
        except SystemError:
            return None

    def generatePartition(self, partitionId, key):
        return self.__getOrGeneratePartition(partitionId, key, createIfNotExists=True)

    def __getOrGeneratePartition(self, partitionId, key, createIfNotExists=False):
        by = self.partitionStore.readPartition(partitionId)
        self.log.info('getting partition: {}, bytestream object is: {}, createIfNotExists={}'.format(partitionId, by,
                                                                                                     createIfNotExists))
        if not by and not createIfNotExists:
            raise SystemError('requested partition does not exist. Id: {}'.format(partitionId))

        partition = KeyPartition(partitionId=partitionId, cascadeProperties=self.cascadeProperties)
        if by:
            pc = PartitionCrypt(key)
            partition.deserializeFromBytesIO(pc.decryptBytesIO(by))
            by.close()
        self.partitionCache[partitionId] = partition
        return partition

    def __storePartition(self, partition, key):
        self.log.info('storing partition {}'.format(partition.getId()))
        if (configuration.log_level == logging.DEBUG):
            partition.print()
        pc = PartitionCrypt(key)
        by = pc.encryptBytesIO(partition.serializeToBytesIO())
        self.partitionStore.writePartition(partition.getId(), by)

    ###############################################################################
    # Get new key, get existing key
    ###############################################################################
    def getKeyForNewObject(self, name):
        slot = self.keySlotMapper.getOrCreateMapping(name)
        self.log.info('getting key for new object with name: {}'.format(name))
        return self._getKeyFromCascade(slot, createIfNotExists=True)

    def getKeyForStoredObject(self, name):
        slot = self.keySlotMapper.getMapping(name)
        return self._getKeyFromCascade(slot, createIfNotExists=False)

    def _getKeyFromCascade(self, slot, createIfNotExists=False):
        partitionId = self.__getPartitionIdForSlot(slot)
        if (0 == partitionId):
            partitionKey = self.__getCurrentMasterKey()
        else:
            partitionKey = self._getKeyFromCascade(partitionId, createIfNotExists)

        partition = self.getPartition(partitionId, partitionKey)
        if not partition and createIfNotExists:
            partition = self.generatePartition(partitionId, partitionKey)
        # the partition will be stored later since the key will be empty as well
        elif not partition and not createIfNotExists:
            raise SystemError('requested partition {} does not exist'.format(partitionId))

        localSlot = self.__globalSlotToLocalSlot(slot)
        key = partition.getKey(localSlot)
        if not key and createIfNotExists:
            key = partition.generateKey(localSlot)
            self.__storePartition(partition, partitionKey)
        elif not key and not createIfNotExists:
            raise SystemError('key slot {} in partition {} is empty'.format(localSlot, partitionId))

        self.log.debug(
            '_getKeyFromCascade for slot: {}, in partition: {}, is localSlot: {}'.format(slot, partitionId, localSlot))
        return key

    ###############################################################################
    # Delete: individual key
    ###############################################################################
    def deleteObjectKey(self, name):
        """
        This function just deletes a single key anywhere in the cascade.
        Not actually used in SDOS
        :param name:
        :return:
        """
        slot = self.keySlotMapper.resetMapping(name)
        self.log.info('deleting object key for object: {} in slot: {}'.format(name, slot))

        partitionId = self.__getPartitionIdForSlot(slot)
        partitionKey = self._getKeyFromCascade(partitionId)
        partition = self.getPartition(partitionId, partitionKey)

        partition.resetKey(self.__globalSlotToLocalSlot(slot))
        self.__storePartition(partition, partitionKey)

    ###############################################################################
    # Delete: secure delete
    ###############################################################################
    def secureDeleteObjectKey(self, name):
        # self.__secure_delete_bottom_up(name)
        self.__secure_delete_top_down(name)

    ###############################################################################
    # SECURE DELETE TOP DOWN
    def __secure_delete_top_down(self, name):
        # slot = self.keySlotMapper.getMapping(name)
        slot = self.keySlotMapper.resetMapping(name)
        self.log.warning('SECURE DELETE top down: deleting object key for object: {} in slot: {}'.format(name, slot))
        oldMasterKey = self.__getCurrentMasterKey()
        newMasterKey = self.__getCurrentMasterKey()
        self.__cascaded_rekey_top_down(oldMasterKey, newMasterKey, 0, [slot])

    def __cascaded_rekey_top_down(self, partitionKeyOld, partitionKeyNew, partitionId, objectKeySlots):
        """
        This is the main cascaded re-keying method; also batch-capable.
        recursively we modify the partitions top-down along all necessary paths to
        the object keys that should be cleared

        :param partitionKeyOld: the current key for the partition
        :param partitionKeyNew: the new key to use after modifying the partition
        :param partitionId: id of the partition to modify
        :param objectSlots: list of object-key slots to clear; these are the object that
        get securely deleted by this re-keying operation. The IDs are used to determine the paths.
        the slots here must be "globalslots" i.e. in the global slot range and not local to one partition
        :return:
        """
        # first we lod and decrypt the current partition
        thisPartition = self.getPartition(partitionId, partitionKeyOld)
        slotsToModify = self.__get_list_of_slots_to_branches(objectKeySlots, partitionId)
        self.log.info("cascaded re-keying on partition {}, targeting object Key IDs {}. following paths to: {}".format(
            partitionId, objectKeySlots, slotsToModify))
        for s in slotsToModify:
            localSlot = self.__globalSlotToLocalSlot(s)
            if self.__is_object_key_slot(s):
                self.log.info(
                    "cascaded re-keying on object key partition {}, clearing slot {}".format(
                        partitionId, s))
                thisPartition.resetKey(localSlot)
            else:
                self.log.info(
                    "cascaded re-keying on internal partition {}, replacing key in slot {}".format(
                        partitionId, s))
                ok = thisPartition.getKey(localSlot)
                nk = CryptoLib.generateRandomKey()
                self.__cascaded_rekey_top_down(ok, nk, s, objectKeySlots)
        self.__storePartition(thisPartition, partitionKeyNew)

    def __get_list_of_slots_to_branches(self, objectKeySlots, thisPartitionId):
        """
        here we determine a list of global slots (equiv. to partition IDs)
        that are children of this partition and are the next on a path to the
        object keys
        example: our cascade has 3 levels, partitions have 4 slots. object IDs 21..24 are in part. 5
        which is the child of 1, which is the child of 0. OKID 25 is in part. 6, child of 1, child of 0
        In [34]: __get_list_of_slots_to_branches(c, [21,22,23,25], 0)
        Out[34]: {1}

        In [35]: __get_list_of_slots_to_branches(c, [21,22,23,25], 1)
        Out[35]: {5, 6}

        In [36]: __get_list_of_slots_to_branches(c, [21,22,23,25], 5)
        Out[36]: {21, 22, 23}

        In [37]: __get_list_of_slots_to_branches(c, [21,22,23,25], 6)
        Out[37]: {25}

        :param objectKeySlots:
        :param thisPartitionId:
        :return:
        """
        slots = set()
        for oks in objectKeySlots:
            thisSlot = oks
            while thisSlot > thisPartitionId:
                parent = self.__getPartitionIdForSlot(thisSlot)
                if parent == thisPartitionId:
                    slots.add(thisSlot)
                thisSlot = parent
        l = list(slots)
        l.sort()
        return l

    ###############################################################################
    # SECURE DELETE BOTTOM-UP (legacy)
    def __secure_delete_bottom_up(self, name):
        slot = self.keySlotMapper.resetMapping(name)
        self.log.warning('SECURE DELETE bottom up:  deleting object key for object: {} in slot: {}'.format(name, slot))
        self._secureReplaceKey(slot, KeyPartition.EMPTY_KEY)

    def _secureReplaceKey(self, slot, newKey):
        """
        This is the main cascaded re-keying method. It eventually reaches partition 0 and
        replaces the master key. this method starts from bottom and goes up while processing nodes
        the disadvantage is that it reads the whole path to the top in every level in order to naively retrieve the
        partition key

        :param slot:
        :param newKey:
        :return:
        """
        partitionId = self.__getPartitionIdForSlot(slot)
        self.log.info('SECURE replacing key in slot: {} in partition: {}'.format(slot, partitionId))
        if (0 == partitionId):
            oldPartitionKey = self.__getCurrentMasterKey()
            newPartitionKey = self.__getCurrentMasterKey()
        else:
            oldPartitionKey = self._getKeyFromCascade(partitionId)
            newPartitionKey = CryptoLib.generateRandomKey()

        partition = self.getPartition(partitionId, oldPartitionKey)

        localSlot = self.__globalSlotToLocalSlot(slot)
        partition.setKey(localSlot, newKey)

        self.__storePartition(partition, newPartitionKey)

        if (0 == partitionId):
            # print('Replaced master key with: {}'.format(newPartitionKey))
            self.log.error("replacing master key {} with {}".format(oldPartitionKey, newPartitionKey))
            pass
        else:
            self._secureReplaceKey(partitionId, newPartitionKey)


###############################################################################
###############################################################################
###############################################################################
###############################################################################
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

    def print(self):
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
