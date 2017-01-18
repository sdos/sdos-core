#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.


	@author: tim

"""
import logging
from mcm.sdos.core import Frontend
from mcm.sdos.parallelExecution import Borg
from mcm.sdos.swift import SwiftBackend
from sdos.core.CascadeProperties import CascadeProperties


class SwiftPool(Borg):
	"""
		A singleton that manages a pool of swift connections per tenant/user
		only one instance of this class exists at any time -> only one swift connection per user
	"""

	def __init__(self):
		Borg.__init__(self)

		try:
			self.__pool
		except:
			self.__pool = dict()

	def addConn(self, swiftTenant, swiftToken, conn):
		self.__pool[(swiftTenant, swiftToken)] = conn

	def getConn(self, swiftTenant, swiftToken):
		try:
			return self.__pool[(swiftTenant, swiftToken)]
		except:
			sb = SwiftBackend.SwiftBackend(tenant=swiftTenant, token=swiftToken)
			self.addConn(swiftTenant, swiftToken, sb)
			return sb

	def count(self):
		try:
			self.c += 1
		except:
			self.c = 0

		print(self.c)


class FEPool(Borg):
	"""
		A singleton that manages a pool of Frontends; i.e. key cascades with attached swift backends
		only one cascade exists per container/user combination
	"""

	def __init__(self):
		Borg.__init__(self)

		try:
			self.__pool
		except:
			self.__pool = dict()

	def addFE(self, container, swiftTenant, swiftToken, fe):
		#self.__pool[(container, swiftTenant, swiftToken)] = fe
		# TODO: multi-backend in the Key Cascade is necessary.
		# currently, we would re-use the first users token for all requests...
		self.__pool[(container, swiftTenant)] = fe

	def getFE(self, container, swiftTenant, swiftToken):
		logging.info("looking for Frontend for: container {}, swiftTenant {}, swiftToken {}".format(container, swiftTenant, swiftToken))
		try:
			return self.__pool[(container, swiftTenant)]
		except:
			sp = SwiftPool()
			sb = sp.getConn(swiftTenant, swiftToken)
			props = sb.get_sdos_properties(container)
			cascadeProperties = CascadeProperties(partition_bits=props[1], tree_height=props[2])
			fe = Frontend.SdosFrontend(container, swiftBackend=sb, cascadeProperties=cascadeProperties)
			self.addFE(container, swiftTenant, swiftToken, fe)
			return fe

	def count(self):
		try:
			self.c += 1
		except:
			self.c = 0

		print(self.c)
