#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on Mar 17, 2015

@author: tim
'''
import logging
import swiftclient
import io

class SwiftBackend(object):
	'''
	classdocs
	'''
	
	def __init__(self):
		'''
		Constructor
		'''
		self.log = logging.getLogger(__name__)
		self.log.debug('initializing...')
		self.authurl = 'http://192.168.209.204:8080/auth/v1.0'
		self.user = 'test:tester'
		self.key = 'testing'
		self.swiftC = None
		
		self._assertConnection()
###############################################################################
###############################################################################
		
	def _createConnection(self):
		self.log.debug('establishing NEW connection')
		self.swiftC = swiftclient.client.Connection(authurl=self.authurl, user=self.user, key=self.key, retries=1, insecure='true')
		
	def _verifyConnection(self):
		try:
			self.swiftC.get_auth()
		except:
			return False
		return True
		
	def _assertConnection(self):
		self.log.debug('asserting connection')

		if (not self._verifyConnection()):
			self._createConnection()
			if (not self._verifyConnection()):
				self.log.error('SWIFT connection could not be established')
				raise Exception('SWIFT connection could not be established')
		self.log.debug('connection OK')
			
			
###############################################################################
###############################################################################		  
			
	def printStatus(self):
		self.log.info('status: ') 
		
	def putObject(self, container, name, dataObject):
		self.log.debug('putting file to swift: {}'.format(name))
		self._assertConnection()
		rsp = dict()
		self.swiftC.put_object(container=container, obj=name, contents=dataObject, response_dict=rsp)
		# self.log.debug(rsp)
		
	def getObject(self, container, name):
		self.log.debug('getting file from swift: {}'.format(name))
		self._assertConnection()
		rsp = dict()
		t = self.swiftC.get_object(container=container, obj=name, resp_chunk_size=None, query_string=None, response_dict=rsp, headers=None)
		o = io.BytesIO(t[1])
		# self.log.debug(rsp)
		return o
	
	def deleteObject(self, container, name):
		self.log.debug('deleting file from swift: {}'.format(name))
		self._assertConnection()
		rsp = dict()
		self.swiftC.delete_object(container=container, obj=name, query_string=None, response_dict=rsp)
