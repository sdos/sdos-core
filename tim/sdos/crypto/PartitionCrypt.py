#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on Mar 18, 2015

@author: tim
'''
import logging
from tim.sdos.crypto.CryptoLib import CryptoLib

class PartitionCrypt(object):
	'''
	classdocs
	'''


	def __init__(self, key):
		'''
		Constructor
		'''
		self.log = logging.getLogger(__name__)
		self.log.debug('initializing')
		self.key = key
		self.cl = CryptoLib(key, 'SDOS_ENCPART_V1\0'.encode(encoding='utf_8', errors='strict'))
		
	
###############################################################################
###############################################################################



###############################################################################
###############################################################################
	def encryptBytesIO(self, plaintext):
		self.log.debug('encrypting partition with key: {}'.format(self.key))
		return self.cl.encryptBytesIO(plaintext)
		
		
	def decryptBytesIO(self, ciphertext):
		self.log.debug('decrypting partition with key: {}'.format(self.key))
		return self.cl.decryptBytesIO(ciphertext)  ####################################
