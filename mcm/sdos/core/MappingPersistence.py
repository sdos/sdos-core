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
from mcm.sdos.core import Configuration
from swiftclient import ClientException


###############################################################################
###############################################################################
###############################################################################

class LocalFileMappingStore(object):
	"""
	implements a mapping store backed by a local file
	"""

	def __init__(self):
		"""
		Constructor
		"""
		self.log = logging.getLogger(__name__)
		self.outerHeader = 'SDOS_MAPP_V1\0\0\0\0'.encode(encoding='utf_8', errors='strict')  # should be 16 bytes long
		self.fileName = Configuration.CASCADE_FILE_PATH + '/mapping.sdos'

	def writeMapping(self, by):
		with open(self.fileName, mode='wb') as f:
			f.write(self.outerHeader)
			f.write(by.getbuffer())
		f.close()

	def readMapping(self):
		try:
			with open(self.fileName, mode='rb') as f:
				mh = f.read(len(self.outerHeader))
				if not mh == self.outerHeader:
					raise SystemError('header mismatch on mapping file')
				by = io.BytesIO(f.read())
			f.close()
			return by
		except FileNotFoundError:
			return None


###############################################################################
###############################################################################
###############################################################################

class SwiftMappingStore(object):
	"""
	implements a mapping store backed by the swift object store
	"""

	def __init__(self, containerNameSdosMgmt, swiftBackend):
		"""
		Constructor
		"""
		self.log = logging.getLogger(__name__)
		self.outerHeader = 'SDOS_MAPP_V1\0\0\0\0'.encode(encoding='utf_8', errors='strict')  # should be 16 bytes long
		self.objName = 'mapping.sdos'

		self.containerNameSdosMgmt = containerNameSdosMgmt
		self.swiftBackend = swiftBackend

	def writeMapping(self, by):
		obj = self.outerHeader + by.getbuffer()
		self.swiftBackend.putObject(container=self.containerNameSdosMgmt, name=self.objName, dataObject=obj)
		self.log.debug('wrote mapping {} to swift mgmt container {}'.format(self.objName, self.containerNameSdosMgmt))

	def readMapping(self):
		try:
			obj = self.swiftBackend.getObject(container=self.containerNameSdosMgmt, name=self.objName)
		except ClientException:
			self.log.debug('mapping obj was not found in swift')
			return None

		mh = obj.read(len(self.outerHeader))
		if not mh == self.outerHeader:
			raise TypeError('file header mismatch on mapping obj')
		by = io.BytesIO(obj.read())
		obj.close()
		return by

###############################################################################
###############################################################################
###############################################################################
