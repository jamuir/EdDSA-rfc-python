'''
Use this script to exercise the test vectors listed in Section 7
against the library code given in Appendix A:

  $ python3 test-eddsa2.py < Section-7.input

This script is based on Appendix B.
'''

import sys
import binascii

from eddsa2 import eddsa_obj


def munge_string(s, pos, change):
    return (s[:pos] +
            int.to_bytes(s[pos] ^ change, 1, "little") +
            s[pos+1:])

testno = 0
bucket = None
state = None
algorithm_lines = []
secret_key_lines = []
public_key_lines = []
message_lines = []
context_lines = []
signature_lines = []

for line in sys.stdin:
    if "  ALGORITHM" in line:
        bucket = algorithm_lines
        continue
    if "  SECRET KEY" in line:
        bucket = secret_key_lines
        continue
    if "  PUBLIC KEY" in line:
        bucket = public_key_lines
        continue
    if "  MESSAGE" in line:
        bucket = message_lines
        continue
    if "  CONTEXT" in line:
        bucket = context_lines
        continue
    if "  SIGNATURE" in line:
        bucket = signature_lines
        state = "signature"
        continue

    # check if we are at the end of current test vector
    if state == "signature" and (line == "\n" or "  -----" in line):

        # exercise test vector data
        testno += 1
        print(testno)

        EdDSA = eddsa_obj("".join(algorithm_lines))
        secret = binascii.unhexlify("".join(secret_key_lines))
        public = binascii.unhexlify("".join(public_key_lines))
        msg = binascii.unhexlify("".join(message_lines))
        ctx = binascii.unhexlify("".join(context_lines))
        signature = binascii.unhexlify("".join(signature_lines))

        privkey,pubkey = EdDSA.keygen(secret)
        assert public == pubkey
        assert signature == EdDSA.sign(privkey, pubkey, msg, ctx)
        assert EdDSA.verify(public, msg, signature, ctx)
        if len(msg) == 0:
            bad_msg = b"x"
        else:
            bad_msg = munge_string(msg, len(msg) // 3, 4)
        assert not EdDSA.verify(public,bad_msg,signature, ctx)
        assert not EdDSA.verify(public, msg, munge_string(signature,20,8), ctx)
        assert not EdDSA.verify(public,msg,munge_string(signature,40,16), ctx)

        # reset
        bucket = None
        state = None
        algorithm_lines = []
        secret_key_lines = []
        public_key_lines = []
        message_lines = []
        context_lines = []
        signature_lines = []

        continue

    if bucket != None:
        bucket.append(line.strip())
