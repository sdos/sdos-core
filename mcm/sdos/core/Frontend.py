#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2016> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.


	Created on Mar 19, 2015

	@author: tim

	This module contains SDOS-frontends, i.e. the classes that offer access to SDOS
	the frontends will then use methods from the SDOS core and finally use a backend to store/retrieve data
"""

import io
import logging
from mcm.sdos.swift import SwiftBackend
from mcm.sdos.crypto import DataCrypt
from mcm.sdos.crypto import CryptoLib
from mcm.sdos.core.KeyCascade import Cascade
from mcm.sdos.core import Mapping, CascadePersistence, MappingPersistence
from sdos.core.KeyPartitionCache import KeyPartitionCache


class DirectFrontend(object):
    """
    This frontend directly stores files in the backend without modification/additional stuff
    """

    def __init__(self, containerName, swiftTenant=None, swiftToken=None, swiftUser=None, swiftKey=None):
        """
        Constructor
        """
        self.si = SwiftBackend.SwiftBackend(tenant=swiftTenant, token=swiftToken, user=swiftUser, key=swiftKey)
        self.containerName = containerName

    def finish(self):
        pass

    def putObject(self, o, name):
        self.si.putObject(container=self.containerName, name=name, dataObject=o)

    def getObject(self, name):
        return self.si.getObject(container=self.containerName, name=name)

    def deleteObject(self, name):
        self.si.deleteObject(container=self.containerName, name=name)


###############################################################################
###############################################################################


class CryptoFrontend(object):
    """
    This frontend encrypts the objects with a predefined key before storing them.
    When retrieving objects, the same key is used to decrypt the data again.
    No key management/SDOS mgmt is performed
    """

    def __init__(self, containerName, swiftTenant=None, swiftToken=None, swiftUser=None, swiftKey=None):
        """
        Constructor
        """
        self.si = SwiftBackend.SwiftBackend(tenant=swiftTenant, token=swiftToken, user=swiftUser, key=swiftKey)
        self.containerName = containerName

    def finish(self):
        pass

    def putObject(self, o, name):
        key = CryptoLib.digestKeyString('keeey')
        c = DataCrypt.DataCrypt(key).encryptBytesIO(plaintext=o)
        self.si.putObject(self.containerName, name, c)

    def getObject(self, name):
        key = CryptoLib.digestKeyString('keeey')
        c = self.si.getObject(container=self.containerName, name=name)
        return DataCrypt.DataCrypt(key).decryptBytesIO(ciphertext=c)

    def deleteObject(self, name):
        self.si.deleteObject(container=self.containerName, name=name)


###############################################################################
###############################################################################


class SdosFrontend(object):
    """
    This frontend implements the SDOS functionality
    """

    def __init__(self, containerName, swiftBackend, cascadeProperties, useCache=False):
        """
        Constructor
        """
        logging.warning("initializing a new SDOS frontend: containerName={} useCache={}". format(containerName, useCache))
        self.containerName = containerName
        self.si = swiftBackend
        self.cascadeProperties = cascadeProperties

        containerNameSdosMgmt = '_mcm-internal_SDOS-partitions_{}'.format(containerName)

        # mappingStore = MappingPersistence.LocalFileMappingStore()
        mappingStore = MappingPersistence.SwiftMappingStore(containerNameSdosMgmt=containerNameSdosMgmt,
                                                            swiftBackend=self.si)
        keySlotMapper = Mapping.KeySlotMapper(mappingStore=mappingStore, cascadeProperties=self.cascadeProperties)

        # partitionStore = CascadePersistence.LocalFilePartitionStore()
        partitionStore = CascadePersistence.SwiftPartitionStore(containerNameSdosMgmt=containerNameSdosMgmt,
                                                                swiftBackend=self.si)
        if useCache:
            p = KeyPartitionCache(partitionStore=partitionStore)
        else:
            p = partitionStore

        self.cascade = Cascade(partitionStore=p, keySlotMapper=keySlotMapper,
                               cascadeProperties=self.cascadeProperties)

    def finish(self):
        self.cascade.finish()

    def encrypt_object(self, o, name):
        key = self.cascade.getKeyForNewObject(name)
        return DataCrypt.DataCrypt(key).encryptBytesIO(plaintext=o)

    def encrypt_bytes_object(self, o, name):
        return self.encrypt_object(o=io.BytesIO(o), name=name).read()

    def putObject(self, o, name):
        c = self.encrypt_object(o=o, name=name)
        self.si.putObject(self.containerName, name, c, headers={"X-Object-Meta-MCM-Content": DataCrypt.HEADER})

    def decrypt_object(self, c, name):
        key = self.cascade.getKeyForStoredObject(name)
        return DataCrypt.DataCrypt(key).decryptBytesIO(ciphertext=c)

    def decrypt_bytes_object(self, c, name):
        return self.decrypt_object(io.BytesIO(c), name).read()

    def getObject(self, name):
        c = self.si.getObject(container=self.containerName, name=name)
        return self.decrypt_object(c, name)

    def deleteObject(self, name, deleteDataObjectInSwift=True):
        self.cascade.secureDeleteObjectKey(name)
        if deleteDataObjectInSwift:
            self.si.deleteObject(container=self.containerName, name=name)

###############################################################################
###############################################################################
