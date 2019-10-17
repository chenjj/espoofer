#!/usr/bin/python
# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2016 Google, Inc.
# Contact: Brandon Long <blong@google.com>
# Modified by Scott Kitterman <scott@kitterman.com>
# Copyright (c) 2017,2018 Scott Kitterman

"""Generates new domainkeys pairs.

"""


from __future__ import print_function
import os
import subprocess
import sys
import tempfile
import argparse
import hashlib
import base64

# how strong are our keys?
BITS_REQUIRED = 2048

# what openssl binary do we use to do key manipulation?
OPENSSL_BINARY = '/usr/bin/openssl'

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def GenRSAKeys(private_key_file):
  """ Generates a suitable private key.  Output is unprotected.
  You should encrypt your keys.
  """
  eprint('generating ' + private_key_file)
  subprocess.check_call([OPENSSL_BINARY, 'genrsa', '-out', private_key_file,
                         str(BITS_REQUIRED)])

def GenEd25519Keys(private_key_file):
    """Generates a base64 encoded private key for ed25519 DKIM signing.
    Output is unprotected.  You should protect your keys.
    """
    import nacl.signing # Yes, pep-8, but let's not make everyone install nacl
    import nacl.encoding
    import os
    skg = nacl.signing.SigningKey(seed=os.urandom(32))
    eprint('generating ' + private_key_file)
    priv_key = skg.generate()
    with open(private_key_file, 'w') as pkf:
        pkf.write(priv_key.encode(encoder=nacl.encoding.Base64Encoder).decode("utf-8"))
    return(priv_key)

def ExtractRSADnsPublicKey(private_key_file, dns_file):
  """ Given a key, extract the bit we should place in DNS.
  """
  eprint('extracting ' + private_key_file)
  working_file = tempfile.NamedTemporaryFile(delete=False).name
  subprocess.check_call([OPENSSL_BINARY, 'rsa', '-in', private_key_file,
                         '-out', working_file, '-pubout', '-outform', 'PEM'])
  try:
      with open(working_file) as wf:
          y = ''
          for line in wf.readlines():
              if not line.startswith('---'):
                  y+= line
          output = ''.join(y.split())
  finally:
      os.unlink(working_file)
  with open(dns_file, 'w') as dns_fp:
      eprint('writing ' + dns_file)
      dns_fp.write("v=DKIM1; k=rsa; h=sha256; p={0}".format(output))

def ExtractEd25519PublicKey(dns_file, priv_key):
    """ Given a ed25519 key, extract the bit we should place in DNS.
    """
    import nacl.encoding # Yes, pep-8, but let's not make everyone install nacl
    pubkey = priv_key.verify_key
    output = pubkey.encode(encoder=nacl.encoding.Base64Encoder).decode("utf-8")
    with open(dns_file, 'w') as dns_fp:
        eprint('writing ' + dns_file)
        dns_fp.write("v=DKIM1; k=ed25519; p={0}".format(output))

def main():
  parser = argparse.ArgumentParser(
    description='Produce DKIM keys.',)
  parser.add_argument('key_name', action="store")
  parser.add_argument('--ktype', choices=['rsa', 'ed25519'],
    default='rsa',
    help='DKIM key type: Default is rsa')
  args=parser.parse_args()

  key_name = args.key_name
  key_type = args.ktype
  private_key_file = key_name + '.key'
  dns_file = key_name + '.dns'

  if key_type == 'rsa':
      GenRSAKeys(private_key_file)
      ExtractRSADnsPublicKey(private_key_file, dns_file)
  elif key_type == 'ed25519':
      priv_key = GenEd25519Keys(private_key_file)
      ExtractEd25519PublicKey(dns_file, priv_key)
  else:
      eprint("Unknown key type - no key generated.")


if __name__ == '__main__':
  main()
