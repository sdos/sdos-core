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
import math
from threading import Event, Lock, Condition

from sdos.crypto import CryptoLib
from sdos.crypto.PartitionCrypt import PartitionCrypt
from sdos import configuration
from sdos.core.KeyPartition import KeyPartition


class Cascade(object):
    """
    Key Cascade main object. One instance of this should exist for each key-cascade (for each container)

    self.num_cr_treads = 0

    The number of create and read threads.
    key reads and creates may run in parallel (creates wait on each other for writing individual partitions)
    but they all get blocked by a rekey operation which needs exclusive access.
     The rekey then has to wait until all c/r threads are done until it can start.
     This number is used by the rekey operation to wait for free access


    self.cascade_open_for_reading = Event()
    self.cascade_open_for_reading.set()

    readers don't wait on partition locks since they can run during creates.
    But they have to wait for rekey, so we have an event that the rekey op. sets to false to block all reads&creates
    when re-set, they start again.


    self.cascade_rekey_lock = Lock()

    This lock serializes the rekey/secure delete. --> synchronizes changing of the single master key
    """

    def __init__(self, partitionStore, keySlotMapper, masterKeySource, cascadeProperties):
        logging.warning("Init new")
        self.log = logging.getLogger(__name__)
        self.partitionStore = partitionStore
        self.keySlotMapper = keySlotMapper
        self.masterKeySource = masterKeySource
        self.cascadeProperties = cascadeProperties
        self.cascade_lock = Lock()
        self.log.info(
            "Initialized new Key Cascade: {} with partitionStore {}, keySlotMapper {}, cascadeProperties {}".format(
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
        # return CryptoLib.digestKeyString('MASTERKEY')
        return self.masterKeySource.get_current_key()

    def __getNewAndReplaceOldMasterKey(self):
        # return CryptoLib.digestKeyString('MASTERKEY')
        m = self.masterKeySource.get_new_key_and_replace_current()
        return m

    ###############################################################################
    # Partition load / store
    ###############################################################################
    def generatePartition(self, partitionId):
        # return self.__getOrGeneratePartition(partitionId, key, createIfNotExists=True, lockForWriting=True)
        return KeyPartition(partitionId=partitionId, cascadeProperties=self.cascadeProperties)

    def getPartition(self, partitionId, key, lockForWriting=False):
        self.log.info('getting partition: {}'.format(partitionId))
        by = self.partitionStore.readPartition(partitionId, lockForWriting=lockForWriting)
        if not by:
            self.log.info('requested partition does not exist. Id: {}'.format(partitionId))
            return None
        else:
            try:
                partition = KeyPartition(partitionId=partitionId, cascadeProperties=self.cascadeProperties)
                pc = PartitionCrypt(key)
                partition.deserializeFromBytesIO(pc.decryptBytesIO(by))
                by.close()
                return partition
            except TypeError as e:
                raise TypeError("error parsing partition {} - {}".format(partitionId, e))

    def __storePartition(self, partition, key):
        self.log.info('storing partition {}'.format(partition.getId()))
        if (configuration.log_level == logging.DEBUG):
            partition.print()
        pc = PartitionCrypt(key)
        by = pc.encryptBytesIO(partition.serializeToBytesIO())
        self.partitionStore.writePartition(partition.getId(), by)

    ###############################################################################
    # Insert new key, get existing key
    ###############################################################################
    def getKeyForNewObject(self, name):
        return self.__get_new_or_existing_key(name=name, createIfNotExists=True)

    def getKeyForStoredObject(self, name):
        return self.__get_new_or_existing_key(name=name, createIfNotExists=False)

    def __get_new_or_existing_key(self, name, createIfNotExists):
        self.cascade_lock.acquire()
        try:
            if createIfNotExists:
                slot = self.keySlotMapper.getOrCreateMapping(name)
            else:
                slot = self.keySlotMapper.getMapping(name)
            self.log.info(
                'getting key for (new?{}) object with name: {}, goes into slot: {}'.format(createIfNotExists, name,
                                                                                           slot))
            k = self._getKeyFromCascade(slot, createIfNotExists=createIfNotExists)
        finally:
            self.cascade_lock.release()
        return k

    def _getKeyFromCascade(self, slot, createIfNotExists=False):
        """
        TODO: separate reading/writing cases
        :param slot:
        :param createIfNotExists:
        :return:
        """
        partitionId = self.__getPartitionIdForSlot(slot)
        if (0 == partitionId):
            partitionKey = self.__getCurrentMasterKey()
            # print("got key")
            # print(partitionKey[:5])
        else:
            partitionKey = self._getKeyFromCascade(partitionId, createIfNotExists)

        # if create is allowed, we lock the partition a-priori. It could be that we add a new key...
        # this also means that we wait for release of the write lock on that partition.
        # in the other case, we don't wait for that lock and read immediately
        partition = self.getPartition(partitionId, partitionKey, lockForWriting=createIfNotExists)
        if not partition and createIfNotExists:
            partition = self.generatePartition(partitionId)
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
        #elif key and createIfNotExists:
            # If the partition did exist and also had the key, we need to manually release the a-priori lock.
            # In all other cases, the partition was saved above which unlocks implicitly
        #    self.partitionStore.unlockPartition(partitionId)
        self.log.debug(
            '_getKeyFromCascade for slot: {}, in partition: {}, is localSlot: {}'.format(slot, partitionId, localSlot))
        return key

    ###############################################################################
    # Delete: individual object key
    ###############################################################################
    def deleteObjectKey(self, name):
        """
        This function just deletes a single object key without path re-keying
        used to remove a falsely assigned/unused key
        :param name:
        :return:
        """
        slot = self.keySlotMapper.resetMapping(name)
        self.log.info('deleting object key for object: {} in slot: {}'.format(name, slot))

        partitionId = self.__getPartitionIdForSlot(slot)
        partitionKey = self._getKeyFromCascade(partitionId)
        partition = self.getPartition(partitionId, partitionKey, lockForWriting=True)

        partition.resetKey(self.__globalSlotToLocalSlot(slot))
        self.__storePartition(partition, partitionKey)

    ###############################################################################
    # Delete: secure delete
    ###############################################################################
    def secureDeleteObjectKey(self, name):
        if not name:
            raise ValueError("no obj name supplied")
        self.cascade_lock.acquire()
        try:
            self.__secure_delete_top_down(name)
        except Exception as e:
            raise Exception("Secure delete failed. {}".format(e))
        finally:
            self.cascade_lock.release()

    def secureDeleteObjectKeyBatch(self, names):
        if not names:
            raise ValueError("no obj name list supplied")
        self.cascade_lock.acquire()
        try:
            self.__secure_delete_top_down_batch(names)
        except Exception as e:
            raise Exception("Batched secure delete failed. {}".format(e))
        finally:
            self.cascade_lock.release()

    ###############################################################################
    # SECURE DELETE TOP DOWN
    def __secure_delete_top_down(self, name):
        slot = self.keySlotMapper.resetMapping(name)
        self.log.warning('Cascaded re-keying: deleting object key for object: {} in slot: {}'.format(name, slot))
        oldMasterKey = self.__getCurrentMasterKey()
        newMasterKey = self.__getNewAndReplaceOldMasterKey()
        self.__cascaded_rekey_top_down(oldMasterKey, newMasterKey, 0, [slot])

    def __secure_delete_top_down_batch(self, names):
        slots = [self.keySlotMapper.resetMapping(name) for name in names]

        self.log.warning('Cascaded batch re-keying starting. Batch length: {}'.format(len(slots)))
        self.log.debug('Cascaded batch re-keying deleting object keys for objects: {} in slots: {}'.format(names, slots))
        oldMasterKey = self.__getCurrentMasterKey()
        newMasterKey = self.__getNewAndReplaceOldMasterKey()
        self.__cascaded_rekey_top_down(oldMasterKey, newMasterKey, 0, slots)

    def __cascaded_rekey_top_down(self, partitionKeyOld, partitionKeyNew, partitionId, objectKeySlots):
        """
        This is the cascaded re-keying method
        here we delete keys in leave nodes (object-key partitions), and save these
        modified partitions encrypted with a new key (re-keyed). This new key replaces the old
        one in the parent node. This parent node (now modified) is also re-keyed and stored.
        Recursively, nodes are re-keyed (decrypted, modified, encrypted with new key) up to the root.

        This implementation accepts a list of keys to delete. It executes the re-keying (and then deleting in the leaves)
        depth-first, and so only visits each necessary node once.

        :param partitionKeyOld: the current key for the partition
        :param partitionKeyNew: the new key to use after modifying the partition
        :param partitionId: id of the partition to modify
        :param objectSlots: list of object-key slots to clear; these are the object that
        get securely deleted by this re-keying operation. The IDs are used to determine the paths.
        the slots here must be "globalslots" i.e. in the global slot range and not local to one partition
        :return:
        """
        thisPartition = self.getPartition(partitionId, partitionKeyOld, lockForWriting=True)
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
                thisPartition.setKey(localSlot, nk)
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


'''
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
'''
