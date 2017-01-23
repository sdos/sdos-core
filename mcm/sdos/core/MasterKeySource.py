#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2017> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import io
import logging
from swiftclient import ClientException
from sdos.crypto import CryptoLib
from sdos.crypto.DataCrypt import DataCrypt


class MasterKeyStatic(object):
    """
    a static, hard-coded master key for testing/development
    """

    STATIC_KEY = CryptoLib.digestKeyString('ANYTHING')
    my_key_type="static testing key"

    def __init__(self, cascadeProperties, swiftBackend):
        """

        """
        self.cascadeProperties = cascadeProperties
        self.containerNameSdosMgmt = self.cascadeProperties.container_name_mgmt
        self.swiftBackend = swiftBackend
        self.outerHeader = 'SDOS_MKEY_V1\0\0\0\0'.encode(encoding='utf_8', errors='strict')  # should be 16 bytes long
        self.keyObjName = 'masterkey.sdos'
        self.plainMasterKey = None
        try:
            self.unlock_key()
        except:
            logging.error("unlocking master key failed! Key source is not ready...")

    ###############################################################################
    # master key load/store
    ###############################################################################
    def __load_wrapped_key(self):
        logging.info("loading the wrapped master key from {}".format(self.containerNameSdosMgmt))
        try:
            obj = self.swiftBackend.getObject(container=self.containerNameSdosMgmt, name=self.keyObjName)
        except ClientException:
            logging.warning('master key obj was not found in swift')
            return None

        mkh = obj.read(len(self.outerHeader))
        if not mkh == self.outerHeader:
            raise TypeError('file header mismatch on master key obj')
        by = io.BytesIO(obj.read())
        obj.close()
        return by

    def __store_wrapped_key(self, wrapped_key):
        logging.info("writing the wrapped master key to {}".format(self.containerNameSdosMgmt))
        obj = self.outerHeader + wrapped_key.getbuffer()

        self.swiftBackend.putObject(container=self.containerNameSdosMgmt, name=self.keyObjName, dataObject=obj)
        logging.debug('wrote master key to swift mgmt container {}'.format(self.containerNameSdosMgmt))

    ###############################################################################
    # API for SDOS
    ###############################################################################
    def get_current_key(self):
        return self.plainMasterKey

    def get_new_key_and_replace_current(self):
        new_master = CryptoLib.generateRandomKey()
        self.plainMasterKey = new_master
        dc = DataCrypt(self.STATIC_KEY)
        wrapped_key = dc.encryptBytesIO(io.BytesIO(new_master))
        self.__store_wrapped_key(wrapped_key=wrapped_key)
        return self.plainMasterKey

    ###############################################################################
    # API for Swift/Bluebox
    ###############################################################################
    def get_status_json(self):
        return {
            'type': self.my_key_type,
            'is_unlocked': self.is_key_unlocked(),
            'key_id': CryptoLib.getKeyAsId(self.plainMasterKey),
            'is_next_wrapper_ready': self.is_next_wrapper_ready()
        }

    def is_key_unlocked(self):
        return bool(self.plainMasterKey)

    def is_next_wrapper_ready(self):
        return True

    def provide_next_wrapper(self, passphrase):
        return True

    def lock_key(self):
        self.plainMasterKey = None

    def unlock_key(self, passphrase = None):
        logging.info("unlocking the master key from {}".format(self.containerNameSdosMgmt))
        by = self.__load_wrapped_key()
        if not by:
            logging.error("no wrapped key found in {}. Assuming first run, creating default key".format(
                self.containerNameSdosMgmt))
            self.get_new_key_and_replace_current()
            return
        dc = DataCrypt(self.STATIC_KEY)
        plain = dc.decryptBytesIO(by)
        self.plainMasterKey = plain.read()



    ###############################################################################
    # Helpers
    ###############################################################################