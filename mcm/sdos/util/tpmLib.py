#!/usr/bin/python
# coding=utf-8

"""
	Project MCM - Micro Content Management
	SDOS - Secure Delete Object Store


	Copyright (C) <2017> Tim Waizenegger, <University of Stuttgart>

	This software may be modified and distributed under the terms
	of the MIT license.  See the LICENSE file for details.
"""

import binascii
import logging
import subprocess

from mcm.sdos.crypto.CryptoLib import getSha1Bytes
from mcm.sdos.parallelExecution import Borg
from pytss import *
from pytss.tspi_defines import *


class TpmLib(Borg):
    srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
    keyFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE
    # srkSecret = getSha1Bytes("hallo".encode("UTF-8"))
    ownerSecret = getSha1Bytes("hi".encode("UTF-8"))

    def __init__(self):
        Borg.__init__(self)

        logging.info("TPMlib init")
        try:
            self.context
        except:
            self.lock()

    ###############################################################################
    ###############################################################################
    # lock / unlock
    ###############################################################################
    ###############################################################################

    def is_unlocked(self):
        return bool(self.context)

    def unlock(self, srk_password_string):
        logging.warning("unlocking TPM with SRK >{}<".format(srk_password_string))
        self.srkSecret = getSha1Bytes(str(srk_password_string).encode("UTF-8"))
        self.__create_context()
        try:
            self.probe_tpm_function()
        except pytss.tspi_exceptions.TPM_E_DEFEND_LOCK_RUNNING:
            raise SystemError("TPM is defending against dictionary attacks and is in some time-out period")

    def lock(self):
        self.context = None
        self.srk = None
        self.srkSecret = None

    def __create_context(self):
        if not self.srkSecret:
            raise KeyError("SRK not provided yet")
        self.context = TspiContext()
        self.context.connect()
        self.srk = self.context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, self.srk_uuid)
        srkpolicy = self.srk.get_policy_object(TSS_POLICY_USAGE)
        srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, self.srkSecret)

    def probe_tpm_function(self):
        self.__create_context()
        self.context.create_wrap_key(self.keyFlags, self.srk.get_handle())

    ###############################################################################
    ###############################################################################
    # get / create / replace key
    ###############################################################################
    ###############################################################################


    def __idxToUUID(self, idx):
        return uuid.UUID('{' + str(idx).zfill(8) + '-0000-0000-0000-000000000002}')

    def get_current_key(self, idx):
        key_uuid = self.__idxToUUID(idx)
        logging.warning("retrieving key {} from TPM".format(key_uuid))
        self.__create_context()
        k = self.context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM, key_uuid)
        return k

    def get_new_key_and_replace_current(self, key_id, first_run=False):
        if first_run:
            return self.__initialize_new_key(key_id=key_id)
        else:
            return self.__get_new_key_and_replace_current(key_id=key_id)

    def __get_new_key_and_replace_current(self, key_id):
        key_uuid = self.__idxToUUID(key_id)
        logging.warning("replacing current key {} in TPM.".format(key_uuid))
        self.__create_context()
        kOld = self.context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM, key_uuid)
        kNew = self.context.create_wrap_key(self.keyFlags, self.srk.get_handle())
        kOld.unregisterKey()
        kNew.registerKey(key_uuid, self.srk_uuid)
        kNew.load_key()
        return kNew


    def __initialize_new_key(self, key_id):
        key_uuid = self.__idxToUUID(key_id)
        logging.warning("creating initial key {} in TPM.".format(key_uuid))
        self.__create_context()
        try:
            k = self.context.create_wrap_key(self.keyFlags, self.srk.get_handle())
            k.load_key()
            k.registerKey(key_uuid, self.srk_uuid)
            return k
        except pytss.tspi_exceptions.TSS_E_KEY_ALREADY_REGISTERED:
            raise KeyError("Key slot is already in use")

    def get_registered_keys(self):
        keys = self.context.list_keys()
        keys.remove(str(self.srk_uuid))
        return [int(k.split("-")[0]) for k in keys]

    ###############################################################################
    ###############################################################################
    # management
    ###############################################################################
    ###############################################################################

    def clearKeys(self):
        self.__create_context()
        for k in self.context.list_keys():
            key = uuid.UUID(k)
            if key == self.srk_uuid:
                continue
            k1 = self.context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM, key)
            k1.unregisterKey()

    def set_new_srk(self):
        srkSecret = getSha1Bytes("hallo".encode("UTF-8"))
        context = TspiContext()
        context.connect()
        srk = context.create_rsa_key(TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION)
        srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
        srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)

    ###############################################################################
    ###############################################################################
    # Status and version info
    ###############################################################################
    ###############################################################################

    def __get_version(self):
        s = subprocess.run("tpm_version", stdout=subprocess.PIPE)
        return s.stdout.decode()

    def get_status(self):
        s = self.__get_version()
        s += "\n\n"
        try:
            self.probe_tpm_function()
            s += self.__get_status()
        except pytss.tspi_exceptions.TPM_E_DEFEND_LOCK_RUNNING:
            s += "TPM is defending against dictionary attacks and is in some time-out period"
        except KeyError:
            s += "TPM is locked, enter Storage Root Key (SRK)"
        except pytss.tspi_exceptions.TPM_E_AUTHFAIL:
            s += "TPM authentication failed. Possible wrong Storage Root Key (SRK)"

        return s

    def __get_status(self):
        tpm = self.context.get_tpm_object()
        tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
        tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, self.ownerSecret)

        statusStr = ""

        maxkeyslots = binascii.hexlify(
            tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_SLOTS)).decode("ascii")
        maxKeys = binascii.hexlify(
            tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_MAXKEYS)).decode(
            "ascii")
        maxSess = binascii.hexlify(
            tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_MAXSESSIONS)).decode("ascii")
        maxContexts = binascii.hexlify(
            tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_MAXCONTEXTS)).decode("ascii")
        maxInputBuffer = binascii.hexlify(
            tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_INPUTBUFFERSIZE)).decode("ascii")
        maxNVavail = binascii.hexlify(
            tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_MAXNVAVAILABLE)).decode("ascii")
        statusStr += (
            "KeySlots={}, \nMaxKeys={}, \nMaxSess={}, \nMaxContexts={}, \nInputBufferSize={}, \nMaxNVSpace={}".format(
                maxkeyslots,
                maxKeys,
                maxSess,
                maxContexts,
                maxInputBuffer,
                maxNVavail))

        # nvIndices=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_NV_LIST,0)).decode("ascii")
        algsrsa = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_RSA)).decode("ascii")
        algsdes = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_DES)).decode("ascii")
        algs3des = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_3DES)).decode("ascii")
        algssha = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_SHA)).decode("ascii")
        # algssha256=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_SHA256)).decode("ascii")
        algshmac = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_HMAC)).decode("ascii")
        algsaes128 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES128)).decode(
            "ascii")
        algsmgf1 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_MGF1)).decode("ascii")
        algsaes192 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES192)).decode(
            "ascii")
        algsaes256 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES256)).decode(
            "ascii")
        algsxor = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_XOR)).decode("ascii")
        algsaes = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES)).decode("ascii")
        statusStr += (
            ", \nRSA={}, \nDES={}, \n3DES={}, \nSHA-1={}, \nHMAC={}, \nAES128={}, \nMGF1={}, \nAES192={}, \nAES256={}, \nXOR={}, \nAES={}".format(
                algsrsa,
                algsdes,
                algs3des,
                algssha,
                algshmac,
                algsaes128,
                algsmgf1,
                algsaes192,
                algsaes256,
                algsxor,
                algsaes))
        flags = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_FLAG, 0)).decode("ascii")
        statusStr += (", \nFlags={}".format(flags))
        statusStr += ", \nRegisteredKeys={}".format(self.get_registered_keys())
        return statusStr
