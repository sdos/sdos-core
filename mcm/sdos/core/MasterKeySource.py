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

OUTERHEADER = 'SDOS_MKEY_V1\0\0\0\0'.encode(encoding='utf_8', errors='strict')  # should be 16 bytes long
KEYOBJNAME = 'masterkey.sdos'


###############################################################################
###############################################################################
# factory
###############################################################################
###############################################################################

def masterKeySourceFactory(swiftBackend, keysource_type, container_name_mgmt, tpm_key_id=None):
    """
    select and initialize on of the key sources
    :param swiftBackend:
    :param keysource_type:
    :param container_name_mgmt:
    :param tpm_key_id:
    :return:
    """

    if keysource_type == MasterKeyDummy.my_key_type:
        return MasterKeyDummy()
    elif keysource_type == MasterKeyStatic.my_key_type:
        return MasterKeyStatic(swiftBackend=swiftBackend, container_name_mgmt=container_name_mgmt)
    elif keysource_type == MasterKeyPassphrase.my_key_type:
        return MasterKeyPassphrase(swiftBackend=swiftBackend, container_name_mgmt=container_name_mgmt)
    elif keysource_type == MasterKeyTPM.my_key_type:
        return MasterKeyTPM(swiftBackend=swiftBackend, container_name_mgmt=container_name_mgmt, tpm_key_id=tpm_key_id)
    else:
        raise TypeError("could not create master key source. type missing or wrong: {}".format(keysource_type))


###############################################################################
###############################################################################
# master key load/store
###############################################################################
###############################################################################
def load_wrapped_key(containerNameSdosMgmt, swiftBackend):
    logging.info("loading the wrapped master key from {}".format(containerNameSdosMgmt))
    try:
        obj = swiftBackend.getObject(container=containerNameSdosMgmt, name=KEYOBJNAME)
    except ClientException:
        logging.warning('master key obj was not found in swift container {}'.format(containerNameSdosMgmt))
        return None

    mkh = obj.read(len(OUTERHEADER))
    if not mkh == OUTERHEADER:
        raise TypeError('file header mismatch on master key obj for container {}'.format(containerNameSdosMgmt))
    by = io.BytesIO(obj.read())
    obj.close()
    return by


def store_wrapped_key(containerNameSdosMgmt, swiftBackend, wrapped_key):
    logging.info("writing the wrapped master key to {}".format(containerNameSdosMgmt))
    obj = OUTERHEADER + wrapped_key.getbuffer()

    swiftBackend.putObject(container=containerNameSdosMgmt, name=KEYOBJNAME, dataObject=obj)
    logging.debug('wrote master key to swift mgmt container {}'.format(containerNameSdosMgmt))


###############################################################################
###############################################################################
# dummy key source
# a random key each time. no back end requests, key is only in memory during run
###############################################################################
###############################################################################
class MasterKeyDummy(object):
    my_key_type = "dummy"

    def __init__(self):
        self.swiftBackend=None
        self.get_new_key_and_replace_current()

    ###############################################################################
    # API for SDOS
    ###############################################################################
    def get_current_key(self):
        return self.plainMasterKey
        # return CryptoLib.digestKeyString("hallo")

    def get_new_key_and_replace_current(self):
        self.plainMasterKey = CryptoLib.generateRandomKey()
        self.plainMasterKeyBackup = self.plainMasterKey
        return self.plainMasterKey
        # return CryptoLib.digestKeyString("hallo")

    ###############################################################################
    # API for Swift/Bluebox
    ###############################################################################
    def get_status_json(self):
        return {
            'type': self.my_key_type,
            'is_unlocked': bool(self.plainMasterKey),
            'key_id': CryptoLib.getKeyAsId(self.plainMasterKey),
            'is_next_deletable_ready': True
        }

    def clear_next_deletable(self):
        pass

    def provide_next_deletable(self, passphrase):
        pass

    def lock_key(self):
        self.plainMasterKey = None

    def unlock_key(self, passphrase=None):
        self.plainMasterKey = self.plainMasterKeyBackup


###############################################################################
###############################################################################
# static key source
# a static, hard-coded master key for testing/development
###############################################################################
###############################################################################
class MasterKeyStatic(object):
    STATIC_KEY = CryptoLib.digestKeyString('ALWAYS_THE_SAME')
    my_key_type = "static"

    def __init__(self, swiftBackend, container_name_mgmt):
        self.containerNameSdosMgmt = container_name_mgmt
        self.swiftBackend = swiftBackend
        self.plainMasterKey = None
        try:
            self.unlock_key()
        except:
            logging.error("unlocking master key failed for {}! Key source is not ready...".format(
                self.containerNameSdosMgmt))

    ###############################################################################
    # API for SDOS
    ###############################################################################
    def get_current_key(self):
        if not self.plainMasterKey:
            raise KeyError("Master key is not available")
        return self.plainMasterKey

    def get_new_key_and_replace_current(self):
        new_master = CryptoLib.generateRandomKey()
        self.plainMasterKey = new_master
        dc = DataCrypt(self.STATIC_KEY)
        wrapped_key = dc.encryptBytesIO(io.BytesIO(new_master))
        store_wrapped_key(containerNameSdosMgmt=self.containerNameSdosMgmt, swiftBackend=self.swiftBackend,
                          wrapped_key=wrapped_key)
        return self.plainMasterKey

    ###############################################################################
    # API for Swift/Bluebox
    ###############################################################################
    def get_status_json(self):
        return {
            'type': self.my_key_type,
            'is_unlocked': bool(self.plainMasterKey),
            'key_id': CryptoLib.getKeyAsId(self.plainMasterKey),
            'is_next_deletable_ready': True
        }

    def clear_next_deletable(self):
        pass

    def provide_next_deletable(self, passphrase):
        pass

    def lock_key(self):
        self.plainMasterKey = None

    def unlock_key(self, passphrase=None):
        logging.info("unlocking the master key from {}".format(self.containerNameSdosMgmt))
        by = load_wrapped_key(containerNameSdosMgmt=self.containerNameSdosMgmt, swiftBackend=self.swiftBackend)
        if not by:
            logging.error("no wrapped key found in {}. Assuming first run, creating default key".format(
                self.containerNameSdosMgmt))
            self.get_new_key_and_replace_current()
            return
        try:
            dc = DataCrypt(self.STATIC_KEY)
            plain = dc.decryptBytesIO(by)
            self.plainMasterKey = plain.read()
        except:
            raise KeyError("Failed decrypting master key")


###############################################################################
###############################################################################
# passphrase key source
# use a pass phrase as deletable key. the master key will be encrypted with a different
# password each time.
###############################################################################
###############################################################################
class MasterKeyPassphrase(object):
    my_key_type = "passphrase"

    def __init__(self, swiftBackend, container_name_mgmt):
        self.containerNameSdosMgmt = container_name_mgmt
        self.swiftBackend = swiftBackend
        self.plainMasterKey = None
        self.next_deletable = None
        logging.error("Passphrase key source initialized for {}. ... set the passphrase to unlock".format(
            self.containerNameSdosMgmt))

    ###############################################################################
    # API for SDOS
    ###############################################################################
    def get_current_key(self):
        if not self.plainMasterKey:
            raise KeyError("Master key is not available")
        return self.plainMasterKey

    def get_new_key_and_replace_current(self, first_run=False):
        if not self.next_deletable:
            raise KeyError("can't replace current master key without new wrapping (deletable) key")
        if not first_run and not self.plainMasterKey:
            raise KeyError("not allowed while current master is locked")
        new_master = CryptoLib.generateRandomKey()
        self.plainMasterKey = new_master
        dc = DataCrypt(self.next_deletable)
        self.next_deletable = None
        wrapped_key = dc.encryptBytesIO(io.BytesIO(new_master))
        store_wrapped_key(containerNameSdosMgmt=self.containerNameSdosMgmt, swiftBackend=self.swiftBackend,
                          wrapped_key=wrapped_key)
        return self.plainMasterKey

    ###############################################################################
    # API for Swift/Bluebox
    ###############################################################################
    def get_status_json(self):
        return {
            'type': self.my_key_type,
            'is_unlocked': bool(self.plainMasterKey),
            'key_id': CryptoLib.getKeyAsId(self.plainMasterKey),
            'is_next_deletable_ready': bool(self.next_deletable)
        }

    def clear_next_deletable(self):
        self.next_deletable = None

    def provide_next_deletable(self, passphrase):
        nd = CryptoLib.digestKeyString(passphrase)
        if not nd:
            raise KeyError("could not digest the provided passphrase")
        self.next_deletable = nd

    def lock_key(self):
        self.plainMasterKey = None

    def unlock_key(self, passphrase):
        logging.info("unlocking the master key from {}".format(self.containerNameSdosMgmt))
        by = load_wrapped_key(containerNameSdosMgmt=self.containerNameSdosMgmt, swiftBackend=self.swiftBackend)
        if not by:
            logging.error("no wrapped key found in {}. Assuming first run, creating default key".format(
                self.containerNameSdosMgmt))
            self.provide_next_deletable(passphrase)
            self.get_new_key_and_replace_current(first_run=True)
            return
        try:
            dc = DataCrypt(CryptoLib.digestKeyString(passphrase))
            plain = dc.decryptBytesIO(by)
            self.plainMasterKey = plain.read()
        except:
            raise KeyError("wrong passphrase. Failed decrypting master key")


###############################################################################
###############################################################################
# tpm key source
# use a tpm key as deletable key. the master key will be encrypted with a different
# tpm-bound, non-migratable key inside the TPM
###############################################################################
###############################################################################
class MasterKeyTPM(object):
    my_key_type = "tpm"

    def __init__(self, swiftBackend, container_name_mgmt, tpm_key_id):
        self.containerNameSdosMgmt = container_name_mgmt
        self.swiftBackend = swiftBackend
        self.plainMasterKey = None
        self.keyId = tpm_key_id
        assert (self.keyId > 0)
        try:
            from sdos.util.tpmLib import TpmLib
            self.tpm = TpmLib()
        except ImportError:
            logging.exception("unable to import TPM lib, TPM functions will not be available")
            self.tpm = None
        try:
            self.unlock_key()
        except:
            logging.exception("unlocking master key failed for {}! Key source is not ready...".format(
                self.containerNameSdosMgmt))

    ###############################################################################
    # API for SDOS
    ###############################################################################
    def get_current_key(self):
        if not self.plainMasterKey:
            raise KeyError("Master key is not available")
        return self.plainMasterKey

    def get_new_key_and_replace_current(self, first_run=False):
        # if not self.next_deletable:
        # raise KeyError("can't replace current master key without new wrapping (deletable) key")
        if not first_run and not self.plainMasterKey:
            raise KeyError("not allowed while current master is locked")
        new_master = CryptoLib.generateRandomKey()
        next_deletable = self.tpm.get_new_key_and_replace_current(self.keyId, first_run=first_run)
        wrapped_key = io.BytesIO(next_deletable.bind(new_master))
        # TODO ADD key id to store_wrapped_key?

        store_wrapped_key(containerNameSdosMgmt=self.containerNameSdosMgmt, swiftBackend=self.swiftBackend,
                          wrapped_key=wrapped_key)
        self.plainMasterKey = new_master
        return self.plainMasterKey

    ###############################################################################
    # API for Swift/Bluebox
    ###############################################################################
    def get_status_json(self):
        return {
            'type': self.my_key_type,
            'is_unlocked': bool(self.plainMasterKey),
            'key_id': CryptoLib.getKeyAsId(self.plainMasterKey),
            'is_next_deletable_ready': True
        }

    def clear_next_deletable(self):
        pass

    def provide_next_deletable(self):
        pass

    def lock_key(self):
        self.plainMasterKey = None

    def unlock_key(self, passphrase=None):
        logging.info("unlocking the TPM backed master key from {}".format(self.containerNameSdosMgmt))
        by = load_wrapped_key(containerNameSdosMgmt=self.containerNameSdosMgmt, swiftBackend=self.swiftBackend)
        if not by:
            logging.error("no wrapped key found in {}. Assuming first run, creating default key".format(
                self.containerNameSdosMgmt))
            self.get_new_key_and_replace_current(first_run=True)
            return
        try:
            deletable = self.tpm.get_current_key(self.keyId)
            self.plainMasterKey = bytes(deletable.unbind(by.read()))
        except:
            raise KeyError("TPM Error. Failed decrypting master key")
