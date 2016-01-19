#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on Apr 8, 2015

@author: tim
'''

import logging
import io
from tim.sdos.core import Configuration
from swiftclient import ClientException


class MemoryBackedPartitionStore(object):
	'''
	implements a partition store
	'''


	def __init__(self):
		'''
		Constructor
		'''
		self.log = logging.getLogger(__name__)
		self.partitions = dict()
		
	def writePartition(self, partitionId, by):
		self.partitions[partitionId] = by.getbuffer()
		
		
	def readPartition(self, partitionId):
		if (not self.partitions.__contains__(partitionId)):
			return None 
		return io.BytesIO(self.partitions[partitionId])
	
	# defunct
	def print(self):
		print('PartitionStore printing content...')
		print(self.partitions)
		for v in self.partitions:
			self.partitions[v].print()
		
	def printLen(self):
		print("Partition count: %i" % (len(self.partitions)))
	
###############################################################################
###############################################################################
###############################################################################

class LocalFilePartitionStore(object):
	'''
	implements a partition store backed by a local file
	'''


	def __init__(self):
		'''
		Constructor
		'''
		self.log = logging.getLogger(__name__)
		self.outerHeader = 'SDOS_PART_V1\0\0\0\0'.encode(encoding='utf_8', errors='strict')  # should be 16 bytes long
		# encrypted partitions already have a header from the CryptoLib. This header should be omitted in new implementations
		self.fileName = Configuration.CASCADE_FILE_PATH + '/partition_{}.sdos'
		
	def writePartition(self, partitionId, by):
		with open(self.fileName.format(partitionId), mode='wb') as f:
			f.write(self.outerHeader)
			f.write(by.getbuffer())
		f.close()
		
		
	def readPartition(self, partitionId):
		try:
			with open(self.fileName.format(partitionId), mode='rb') as f:
				mh = f.read(len(self.outerHeader))
				if not mh == self.outerHeader:
					raise TypeError('file header mismatch on partition id: {}'.format(partitionId))
				by = io.BytesIO(f.read())
			f.close()
			return by
		except FileNotFoundError:
			return None
		
		
	# defunct
	def print(self):
		print('PartitionStore iteration not possible')
		
	def printLen(self):
		print("Partition count: %i" % (len(self.partitions)))
###############################################################################
###############################################################################
###############################################################################	
		
class SwiftPartitionStore(object):
	'''
	implements a partition store backed by the swift object store
	'''


	def __init__(self, containerNameSdosMgmt, swiftBackend):
		'''
		Constructor
		'''
		self.log = logging.getLogger(__name__)
		self.outerHeader = 'SDOS_PART_V1\0\0\0\0'.encode(encoding='utf_8', errors='strict')  # should be 16 bytes long
		# encrypted partitions already have a header from the CryptoLib. This header should be omitted in new implementations
		self.objectName = 'partition_{}.sdos'
		self.containerNameSdosMgmt = containerNameSdosMgmt
		self.swiftBackend = swiftBackend
		
	def writePartition(self, partitionId, by):
		objName = self.objectName.format(partitionId)
		obj = self.outerHeader + by.getbuffer()
		self.swiftBackend.putObject(container=self.containerNameSdosMgmt, name=objName, dataObject=obj)
		self.log.debug('wrote partition {} to swift mgmt container {}'.format(objName, self.containerNameSdosMgmt))
		
	def readPartition(self, partitionId):
		objName = self.objectName.format(partitionId)
		try:
			obj = self.swiftBackend.getObject(container=self.containerNameSdosMgmt, name=objName)
		except ClientException:
			self.log.debug('partition {} was not found in swift'.format(partitionId))
			return None
		
		mh = obj.read(len(self.outerHeader))
		if not mh == self.outerHeader:
			raise TypeError('file header mismatch on partition id: {}'.format(partitionId))
		by = io.BytesIO(obj.read())
		obj.close()
		return by
		
		
		
	
	
	# defunct
	def print(self):
		print('PartitionStore iteration not possible')
		
	def printLen(self):
		print("Partition count unknown")
	
###############################################################################
###############################################################################
###############################################################################

