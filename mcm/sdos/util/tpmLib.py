import binascii
import uuid
import subprocess

from mcm.sdos.crypto.CryptoLib import getSha1Bytes
from pytss import *
from pytss.tspi_defines import *
from mcm.sdos.parallelExecution import Borg

class TpmLib(Borg):
    srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
    keyFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE
    #srkSecret = getSha1Bytes("ot6do5dFj2anjVZKDtHsy4s".encode("UTF-8"))
    ownerSecret = getSha1Bytes("tYb6cBk7ytmzzGTo5ehxaih".encode("UTF-8"))

    def __init__(self):
        Borg.__init__(self)

        print("TPMlib init")
        try:
            self.context
        except:
            self.context = None
            self.srk = None
        #self.unlock("ot6do5dFj2anjVZKDtHsy4s")




    def is_unlocked(self):
        return bool(self.context)


    def unlock(self, srk_password_string):
        self.srkSecret = getSha1Bytes(str(srk_password_string).encode("UTF-8"))
        self.__create_context()
        try:
            self.probe_tpm_function()
        except pytss.tspi_exceptions.TPM_E_DEFEND_LOCK_RUNNING:
            raise SystemError("TPM is defending against dictionary attacks and is in some time-out period")



    def lock(self):
        self.context = None
        self.srk = None


    def __create_context(self):
        try:
            self.srkSecret
        except AttributeError:
            raise KeyError("SRK not provided yet")
        self.context = TspiContext()
        self.context.connect()
        self.srk = self.context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, self.srk_uuid)
        srkpolicy = self.srk.get_policy_object(TSS_POLICY_USAGE)
        srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, self.srkSecret)


    def __idxToUUID(self, idx):
        return uuid.UUID('{' + str(idx).zfill(8) + '-0000-0000-0000-000000000002}')



    def clearKeys(self):
        self.__create_context()
        for k in self.context.list_keys():
            key = uuid.UUID(k)
            if key == self.srk_uuid:
                continue
            k1 = self.context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM, key)
            k1.unregisterKey()


    def probe_tpm_function(self):
        self.__create_context()
        self.context.create_wrap_key(self.keyFlags, self.srk.get_handle())



    def get_current_key(self, idx):
        self.__create_context()
        k = self.context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM, self.__idxToUUID(idx))
        return k


    def get_new_key_and_replace_current(self, idx, first_run=False):
        self.__create_context()
        if first_run == True:
            k = self.context.create_wrap_key(self.keyFlags, self.srk.get_handle())
            k.load_key()
            k.registerKey(self.__idxToUUID(idx), self.srk_uuid)
            return k
        else:
            kOld = self.context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM, self.__idxToUUID(idx))
            kNew = self.context.create_wrap_key(self.keyFlags, self.srk.get_handle())
            kOld.unregisterKey()
            kNew.registerKey(self.__idxToUUID(idx), self.srk_uuid)
            kNew.load_key()
            return kNew


    def get_registered_keys(self):
        keys = self.context.list_keys()
        keys.remove(str(self.srk_uuid))
        indexes = []
        for k in keys:
            # cut away leading 0
            indexes.append(str(int(k.split("-")[0])))
        return indexes


    def is_key_registered_to_idx(self, idx):
        return str(idx) in self.get_registered_keys()


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
        s=subprocess.run("tpm_version", stdout=subprocess.PIPE)
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
        tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, self.srkSecret)

        statusStr = ""

        maxkeyslots = binascii.hexlify(
            tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_SLOTS)).decode("ascii")
        maxKeys = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY, tss_lib.TSS_TPMCAP_PROP_MAXKEYS)).decode(
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
            "KeySlots={}, \nMaxKeys={}, \nMaxSess={}, \nMaxContexts={}, \nInputBufferSize={}, \nMaxNVSpace={}".format(maxkeyslots,
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
        algsaes128 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES128)).decode("ascii")
        algsmgf1 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_MGF1)).decode("ascii")
        algsaes192 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES192)).decode("ascii")
        algsaes256 = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES256)).decode("ascii")
        algsxor = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_XOR)).decode("ascii")
        algsaes = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG, tss_lib.TSS_ALG_AES)).decode("ascii")
        statusStr += (
            ", \nRSA={}, \nDES={}, \n3DES={}, \nSHA-1={}, \nHMAC={}, \nAES128={}, \nMGF1={}, \nAES192={}, \nAES256={}, \nXOR={}, \nAES={}".format(algsrsa,
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
