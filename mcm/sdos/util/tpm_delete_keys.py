from pytss import *
import pytss.tspi_exceptions as tspi_exceptions
import uuid
from pytss.tspi_defines import *
import binascii


srk_uuid    = uuid.UUID('{00000000-0000-0000-0000-000000000001}')

keyFlags    =  TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE
srkSecret   = bytearray([0] * 20)
ownerSecret = bytearray([0] * 20)


def getSha1Bytes(d):
	h = hashlib.sha1()
	h.update(d)
	return h.digest()

srkSecret = getSha1Bytes(str("hallo").encode("UTF-8"))


def clearKeys():
    context = TspiContext()
    context.connect()
    srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)
    for k in context.list_keys():
        key = uuid.UUID(k)
        if key == srk_uuid:
            continue
        k1 = context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM, key)
        k1.unregisterKey()




if __name__ == "__main__":
    clearKeys()