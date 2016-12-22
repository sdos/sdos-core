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
from mcm.sdos.crypto.PartitionCrypt import PartitionCrypt
from mcm.sdos.crypto import CryptoLib
from mcm.sdos.configuration import *


###############################################################################
###############################################################################



###############################################################################
###############################################################################
###############################################################################
class Cascade(object):
	def __init__(self, partitionStore, keySlotMapper):
		self.log = logging.getLogger(__name__)
		self.log.info('partition bits: {}'.format(PARTITION_BITS))
		self.log.info('partitions have {} slots'.format(PARTITION_SIZE))
		self.log.info('cascade height without root: {}'.format(TREE_HEIGHT))
		self.log.info(
			'total number of partitions: {}, number of internal partitions {}'.format(TOTAL_NUMER_OF_PARTITIONS, NUMBER_OF_PARTITION_KEY_PARTITIONS))
		self.log.info('number of object key partitions (leaves) is {}, they have a total of {} key slots'.format(
			NUMBER_OF_OBJECT_KEY_PARTITIONS, NUMBER_OF_SLOTS_IN_OBJECT_KEY_PARTITIONS))
		self.log.info('object key IDs are in the range {}..{}'.format(FIRST_OBJECT_KEY_SLOT, LAST_OBJCT_KEY_SLOT))

		self.partitionStore = partitionStore
		self.keySlotMapper = keySlotMapper

	###############################################################################
	###############################################################################
	def _getPartitionIdForSlot(self, slot):
		return max(0, math.floor((slot - 1) / PARTITION_SIZE))

	def _slotToLocalSlot(self, slot):
		return (slot - 1) % PARTITION_SIZE

	def _getMasterKey(self):
		return CryptoLib.digestKeyString('MASTERKEY')

	def __is_object_key_slot(self, slot):
		"""
		slot IDs are globally counted
		:param slot:
		:return:
		"""
		return slot >= FIRST_OBJECT_KEY_SLOT

	def finish(self):
		# self.partitionStore.print()
		self.keySlotMapper.finish()

	###############################################################################
	###############################################################################

	def _getOrGeneratePartition(self, partitionId, key, createIfNotExists=False):
		by = self.partitionStore.readPartition(partitionId)
		self.log.info('getting partition: {}, bytestream object is: {}, createIfNotExists={}'.format(partitionId, by,createIfNotExists))

		if not by and not createIfNotExists:
			raise SystemError('requested partition does not exist. Id: {}'.format(partitionId))

		partition = KeyPartition(partitionId)
		if by:
			pc = PartitionCrypt(key)
			partition.deserializeFromBytesIO(pc.decryptBytesIO(by))
			by.close()

		return partition

	def getPartition(self, partitionId, key):
		try:
			return self._getOrGeneratePartition(partitionId, key, createIfNotExists=False)
		except SystemError:
			return None

	def generatePartition(self, partitionId, key):
		return self._getOrGeneratePartition(partitionId, key, createIfNotExists=True)

	def storePartition(self, partition, key):
		self.log.info('storing partition {}'.format(partition.getId()))
		if (30 > self.log.getEffectiveLevel()):
			partition.print()
		pc = PartitionCrypt(key)
		by = pc.encryptBytesIO(partition.serializeToBytesIO())
		self.partitionStore.writePartition(partition.getId(), by)

	###############################################################################
	###############################################################################
	def getKeyForNewObject(self, name):
		slot = self.keySlotMapper.getOrCreateMapping(name)
		self.log.info('getting key for new object with name: {}'.format(name))
		return self._getKeyFromCascade(slot, createIfNotExists=True)

	def getKeyForStoredObject(self, name):
		slot = self.keySlotMapper.getMapping(name)
		return self._getKeyFromCascade(slot, createIfNotExists=False)

	def _getKeyFromCascade(self, slot, createIfNotExists=False):
		partitionId = self._getPartitionIdForSlot(slot)
		if (0 == partitionId):
			partitionKey = self._getMasterKey()
		else:
			partitionKey = self._getKeyFromCascade(partitionId, createIfNotExists)

		partition = self.getPartition(partitionId, partitionKey)
		if not partition and createIfNotExists:
			partition = self.generatePartition(partitionId, partitionKey)
		# the partition will be stored later since the key will be empty as well
		elif not partition and not createIfNotExists:
			raise SystemError('requested partition {} does not exist'.format(partitionId))

		localSlot = self._slotToLocalSlot(slot)
		key = partition.getKey(localSlot)
		if not key and createIfNotExists:
			key = partition.generateKey(localSlot)
			self.storePartition(partition, partitionKey)
		elif not key and not createIfNotExists:
			raise SystemError('key slot {} in partition {} is empty'.format(localSlot, partitionId))

		self.log.debug(
			'_getKeyFromCascade for slot: {}, in partition: {}, is localSlot: {}'.format(slot, partitionId, localSlot))
		return key

	###############################################################################
	# INDIVIDUAL DELETE IN CASCADE
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

		partitionId = self._getPartitionIdForSlot(slot)
		partitionKey = self._getKeyFromCascade(partitionId)
		partition = self.getPartition(partitionId, partitionKey)

		partition.resetKey(self._slotToLocalSlot(slot))
		self.storePartition(partition, partitionKey)




	###############################################################################
	# SECURE DELETE
	###############################################################################
	def secureDeleteObjectKey(self, name):
		#self.__secure_delete_bottom_up(name)
		self.__secure_delete_top_down(name)


	###############################################################################
	# SECURE DELETE TOP DOWN
	###############################################################################
	def __secure_delete_top_down(self, name):
		slot = self.keySlotMapper.getMapping(name)
		#slot = self.keySlotMapper.resetMapping(name)
		self.log.warning('SECURE DELETE top down: deleting object key for object: {} in slot: {}'.format(name, slot))
		oldMasterKey = self._getMasterKey()
		newMasterKey = self._getMasterKey()
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
		self.log.info("cascaded re-keying on partition {}, targeting object Key IDs {}. following paths to: {}".format(partitionId, objectKeySlots, slotsToModify))
		for s in slotsToModify:
			localSlot = self._slotToLocalSlot(s)
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
		self.storePartition(thisPartition, partitionKeyNew)


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
				parent = self._getPartitionIdForSlot(thisSlot)
				if parent == thisPartitionId:
					slots.add(thisSlot)
				thisSlot = parent
		l = list(slots)
		l.sort()
		return l







	###############################################################################
	# SECURE DELETE BOTTOM-UP (legacy)
	###############################################################################
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
		partitionId = self._getPartitionIdForSlot(slot)
		self.log.info('SECURE replacing key in slot: {} in partition: {}'.format(slot, partitionId))
		if (0 == partitionId):
			oldPartitionKey = self._getMasterKey()
			newPartitionKey = self._getMasterKey()
		else:
			oldPartitionKey = self._getKeyFromCascade(partitionId)
			newPartitionKey = CryptoLib.generateRandomKey()

		partition = self.getPartition(partitionId, oldPartitionKey)

		localSlot = self._slotToLocalSlot(slot)
		partition.setKey(localSlot, newKey)

		self.storePartition(partition, newPartitionKey)

		if (0 == partitionId):
			# print('Replaced master key with: {}'.format(newPartitionKey))
			self.log.error("replacing master key {} with {}".format(oldPartitionKey, newPartitionKey))
			pass
		else:
			self._secureReplaceKey(partitionId, newPartitionKey)


		###############################################################################
		###############################################################################
		###############################################################################

	def get_used_partitions(self):
		def rekParts(listNow):
			if not listNow:
				return []
			n = set()
			for i in listNow:
				s = self._getPartitionIdForSlot(i)
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
			objKeyPartition = self._getPartitionIdForSlot(objKeySlot)
			slotInPartition = self._slotToLocalSlot(objKeySlot)
			# print(objName, objKeySlot, objKeyPartition, slotInPartition)
			partition = result.get(objKeyPartition, [])
			partition.append({"slot": slotInPartition, "objName": objName})
			result[objKeyPartition] = partition
		return result


###############################################################################
###############################################################################
###############################################################################
def getTreeLevel():
	# not sure how this can be calculated (without recursion/iteration)...
	# something like: math.log((i-math.floor((i-1)/n)), n)
	# but we currently don't need it anyway :D
	return None


class KeyPartition(object):
	"""
	classdocs
	"""
	EMPTY_KEY = '\0'.encode() * 32

	def __init__(self, partitionId):
		"""
		Constructor
		"""
		self.log = logging.getLogger(__name__)
		self.keys = [self.EMPTY_KEY] * PARTITION_SIZE
		self.partitionID = partitionId

	def print(self):
		print()
		print('+' + '----' * 32 + '+')
		print('| SDOS key partition - PartitionID: %s' % (self.partitionID))
		print('+' + '----' * 32 + '+')
		for i in range(0, PARTITION_SIZE):
			# print ('| Key %i: \t %s' % (i, 'Empty' if self.keys[i] == self.EMPTY_KEY else self.keys[i]))
			print('| Key %i: \t %s' % (i, self.keys[i])) if self.keys[i] != self.EMPTY_KEY else None
		print('+' + '----' * 32 + '+')

	def setKey(self, slot, key):
		self.log.debug('partition {} setting slot {} to key {}'.format(self.partitionID, slot, key))
		self.keys[slot] = key

	def resetKey(self, slot):
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

	def getId(self):
		return self.partitionID

	def getParentId(self):
		return math.floor((self.partitionID - 1) / PARTITION_SIZE)

	def getSlotInParentForThisPartition(self):
		return ((self.partitionID - 1) % PARTITION_SIZE)

	def getChildIdAtSlot(self, slotId):
		return ((self.partitionID * PARTITION_SIZE) + 1 + slotId)

	def serializeToBytesIO(self):
		by = io.BytesIO()
		by.write(self.partitionID.to_bytes(length=BYTES_FOR_PARTITION_IDs, byteorder='little', signed=False))
		for i in range(PARTITION_SIZE):
			by.write(self.keys[i])
		by.seek(0)
		return by

	def deserializeFromBytesIO(self, by):
		assert (len(by.getbuffer()) == (len(self.EMPTY_KEY) * PARTITION_SIZE) + BYTES_FOR_PARTITION_IDs)
		by.seek(0)
		self.partitionID = int.from_bytes(by.read(BYTES_FOR_PARTITION_IDs), byteorder='little', signed=False)
		for i in range(PARTITION_SIZE):
			self.keys[i] = by.read(len(self.EMPTY_KEY))
		by.__del__()


###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
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
###############################################################################
###############################################################################
###############################################################################
