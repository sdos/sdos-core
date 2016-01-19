#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on Mar 18, 2015

@author: tim
'''

from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import logging
import io



def generateRandomKey():
	r = Random.new()
	return hashlib.sha256(r.read(64)).digest()  

def digestKeyString(keyString):
	return hashlib.sha256(keyString.encode()).digest()


class CryptoLib(object):
	'''
	classdocs
	'''

	def __init__(self, key, outerHeader):
		'''
		Constructor
		'''
		self.outerHeader = outerHeader
		self.innerHeader = outerHeader
		self.log = logging.getLogger(__name__)
		self.key = key
		self.blockSize = AES.block_size  # 16 bytes
		
		# self._padBytesIO = lambda s: s + (self.blockSize - len(s) % self.blockSize) * chr(self.blockSize - len(s) % self.blockSize)
		# self._unpadBytesIO = lambda s : s[:-ord(s[len(s)-1:])]
		
		
		
		
###############################################################################
###############################################################################
	
	def _padBytesIO(self, d):
		length = d.getbuffer().nbytes
		padSize = (self.blockSize - length % self.blockSize)
		d.seek(length)
		d.write(padSize * (padSize).to_bytes(1, byteorder='little'))
		d.seek(0)
		# return d
	
	def _unpadBytesIO(self, d):
		length = d.getbuffer().nbytes
		d.seek(length - 1)
		padSize = int.from_bytes(d.read(), byteorder='little')
		d.truncate(length - padSize)
		d.seek(0)
		# return d

###############################################################################
###############################################################################
	
	def setKeyString(self, keyString):
		self.key = hashlib.sha256(keyString.encode()).digest()
		
	def setkeyDigest(self, keyDigest):
		self.key = keyDigest
		
	def encryptBytesIO(self, plaintext):
		assert(self.key)
		self._padBytesIO(plaintext)
		iv = Random.new().read(self.blockSize)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		c = io.BytesIO(self.outerHeader + iv + cipher.encrypt(self.innerHeader + plaintext.getvalue()))
		plaintext.close()
		return c
		
	def decryptBytesIO(self, ciphertext):
		assert(self.key)
		ciphertext.seek(0)
		
		if not (ciphertext.read(len(self.outerHeader)) == self.outerHeader):
			raise TypeError('outer data header mismatch')
		
		iv = ciphertext.read(self.blockSize)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		plaintext = io.BytesIO(cipher.decrypt(ciphertext.read()))
		ciphertext.close()
		
		if not (plaintext.read(len(self.innerHeader)) == self.innerHeader):
			raise TypeError('inner data header mismatch')
		
		plaintextNoHeader = io.BytesIO(plaintext.getvalue()[len(self.innerHeader):])
		plaintext.close()
		self._unpadBytesIO(plaintextNoHeader)
		
		return plaintextNoHeader
		
		
