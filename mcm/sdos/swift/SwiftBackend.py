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
import swiftclient
import io
from mcm.sdos import configuration


class SwiftBackend(object):
	"""
	classdocs
	"""

	def __init__(self):
		"""
		Constructor
		"""
		self.log = logging.getLogger(__name__)
		self.log.debug('initializing...')
		self.swiftC = None

	###############################################################################
	###############################################################################

	def set_existing_authentication(self, tenant, token):
		self.swiftC = swiftclient.client.Connection(preauthtoken=token,
		                                            preauthurl=configuration.swift_storage_url.format(tenant),
		                                            retries=1,
		                                            insecure='true')

	def authenticate(self, user, key):
		self.log.debug('establishing NEW connection')
		self.swiftC = swiftclient.client.Connection(authurl=configuration.swift_auth_url, user=user, key=key, retries=1,
		                                            insecure='true')

	def _assertConnection(self):
		if not self.swiftC: raise Exception(
			'no swift connection object present. Maybe the swift backend was not properly initialized.')

	###############################################################################
	###############################################################################

	def printStatus(self):
		self.log.info('status: ')

	def putObject(self, container, name, dataObject):
		self.log.debug('putting file to swift: {}'.format(name))
		self._assertConnection()
		rsp = dict()
		self.swiftC.put_object(container=container, obj=name, contents=dataObject, response_dict=rsp)

	def getObject(self, container, name):
		self.log.debug('getting file from swift: {}'.format(name))
		self._assertConnection()
		rsp = dict()
		t = self.swiftC.get_object(container=container, obj=name, resp_chunk_size=None, query_string=None,
		                           response_dict=rsp, headers=None)
		o = io.BytesIO(t[1])
		return o

	def deleteObject(self, container, name):
		self.log.debug('deleting file from swift: {}'.format(name))
		self._assertConnection()
		rsp = dict()
		self.swiftC.delete_object(container=container, obj=name, query_string=None, response_dict=rsp)
