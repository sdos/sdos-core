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
from sdos.core import MasterKeySource
from sdos.core.CascadeProperties import CascadeProperties
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
        logging.warning(
            "initializing a new SDOS frontend: containerName={} useCache={}".format(containerName, useCache))
        self.containerName = containerName
        self.swift_backend = swiftBackend
        self.cascadeProperties = cascadeProperties
        self.batch_delete_log = set()

        # mappingStore = MappingPersistence.LocalFileMappingStore()
        self.mappingStore = MappingPersistence.SwiftMappingStore(
            containerNameSdosMgmt=self.cascadeProperties.container_name_mgmt,
            swift_backend=self.swift_backend)

        self.keySlotMapper = Mapping.KeySlotMapper(mappingStore=self.mappingStore,
                                                   cascadeProperties=self.cascadeProperties)

        # partitionStore = CascadePersistence.LocalFilePartitionStore()
        self.partitionStore = CascadePersistence.SwiftPartitionStore(
            containerNameSdosMgmt=self.cascadeProperties.container_name_mgmt,
            swiftBackend=self.swift_backend)

        self.keySource = MasterKeySource.masterKeySourceFactory(
            swiftBackend=self.swift_backend,
            container_name_mgmt=self.cascadeProperties.container_name_mgmt,
            keysource_type=self.cascadeProperties.master_key_type,
            tpm_key_id=self.cascadeProperties.tpm_key_id)

        if useCache:
            p = KeyPartitionCache(partitionStore=self.partitionStore)
        else:
            p = self.partitionStore

        self.cascade = Cascade(partitionStore=p, keySlotMapper=self.keySlotMapper, masterKeySource=self.keySource,
                               cascadeProperties=self.cascadeProperties)

    def refresh_swift_backend(self, swift_backend_new):
        if self.swift_backend != swift_backend_new:
            logging.info(
                "container: {} - replacing old swift backend {} with {}".format(self.containerName, self.swift_backend,
                                                                                swift_backend_new))
            self.swift_backend = swift_backend_new
            self.mappingStore.swift_backend = swift_backend_new
            self.keySource.swiftBackend = swift_backend_new

    def finish(self):
        self.cascade.finish()

    def encrypt_object(self, o, name):
        key = self.cascade.getKeyForNewObject(name)
        return DataCrypt.DataCrypt(key).encryptBytesIO(plaintext=o)

    def encrypt_bytes_object(self, o, name):
        return self.encrypt_object(o=io.BytesIO(o), name=name).read()

    def putObject(self, o, name):
        c = self.encrypt_object(o=o, name=name)
        self.swift_backend.putObject(self.containerName, name, c,
                                     headers={"X-Object-Meta-MCM-Content": DataCrypt.HEADER})

    def decrypt_object(self, c, name):
        key = self.cascade.getKeyForStoredObject(name)
        return DataCrypt.DataCrypt(key).decryptBytesIO(ciphertext=c)

    def decrypt_bytes_object(self, c, name):
        return self.decrypt_object(io.BytesIO(c), name).read()

    def getObject(self, name):
        c = self.swift_backend.getObject(container=self.containerName, name=name)
        return self.decrypt_object(c, name)

    def deleteObject(self, name):
        """
        delete an individual object. this triggers the secure delete / re-keying on the cascade
        unless batch delete is activated, then the frontend will save deletions to a log and
        not call the cascade for re-keying
        :param name:
        :param deleteDataObjectInSwift:
        :return:
        """
        if self.cascadeProperties.use_batch_delete:
            self.batch_delete_log.add(name)
            logging.info("new batch delete log entry: {}".format(name))
        else:
            self.cascade.secureDeleteObjectKey(name)

    def batch_delete_start(self):
        """
        here we process the logged delete requests.
        The key cascade can process them all at once in a single re-key operation
        :return:
        """
        this_batch = self.batch_delete_log.copy()
        self.batch_delete_log.clear()
        logging.warning(
            "executing batch deletions on {}. Log has a length of {}".format(self.containerName, len(this_batch)))
        try:
            self.cascade.secureDeleteObjectKeyBatch(names=this_batch)
        except Exception as e:
            self.batch_delete_log.update(this_batch)
            raise SystemError("Batch log was restored. {}".format(e))


###############################################################################
###############################################################################



def frontendFactory(swift_backend, container_name):
    p = swift_backend.get_sdos_properties(container_name)
    # print(p)
    if p["sdos_type"] == "sdos":
        cascadeProperties = CascadeProperties(container_name=container_name,
                                              partition_bits=p["sdospartitionbits"],
                                              tree_height=p["sdosheight"],
                                              master_key_type=p["sdosmasterkey"],
                                              use_batch_delete=p["sdosbatchdelete"],
                                              tpm_key_id=p["sdostpmkeyid"])

        return SdosFrontend(container_name,
                            swiftBackend=swift_backend,
                            cascadeProperties=cascadeProperties,
                            useCache=True)
    else:
        return None
