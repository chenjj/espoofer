#!/usr/bin/env python

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
# Copyright (c) 2008 Greg Hewgill http://hewgill.com
#
# This has been modified from the original software.
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>
# Copyright (c) 2017 Scott Kitterman <scott@kitterman.com>

from __future__ import print_function

import sys
import argparse

import dkim


def main():
    # Backward compatibility hack because argparse doesn't support optional
    # positional arguments
    arguments=['--'+arg if arg[:8] == 'identity' else arg for arg in sys.argv[1:]]
    parser = argparse.ArgumentParser(
        description='Produce DKIM signature for email messages.',
        epilog="message to be signed follows commands on stdin")
    parser.add_argument('selector', action="store")
    parser.add_argument('domain', action="store")
    parser.add_argument('privatekeyfile', action="store")
    parser.add_argument('--hcanon', choices=['simple', 'relaxed'],
        default='relaxed',
        help='Header canonicalization algorithm: default=relaxed')
    parser.add_argument('--bcanon', choices=['simple', 'relaxed'],
        default='simple',
        help='Body canonicalization algorithm: default=simple')
    parser.add_argument('--signalg', choices=['rsa-sha256', 'ed25519-sha256', 'rsa-sha1'],
        default='rsa-sha256',
        help='Signature algorithm: default=rsa-sha256')
    parser.add_argument('--identity', help='Optional value for i= tag.')
    args=parser.parse_args(arguments)
    include_headers = None
    length = None
    logger = None

    if sys.version_info[0] >= 3:
        args.selector = bytes(args.selector, encoding='UTF-8')
        args.domain = bytes(args.domain, encoding='UTF-8')
        if args.identity is not None:
            args.identity = bytes(args.identity, encoding='UTF-8')
        args.hcanon = bytes(args.hcanon, encoding='UTF-8')
        args.bcanon = bytes(args.bcanon, encoding='UTF-8')
        args.signalg = bytes(args.signalg, encoding='UTF-8')
        # Make sys.stdin and stdout binary streams.
        sys.stdin = sys.stdin.detach()
        sys.stdout = sys.stdout.detach()
    canonicalize = (args.hcanon, args.bcanon)

    message = sys.stdin.read()
    try:
        d = dkim.DKIM(message,logger=logger, signature_algorithm=args.signalg,
                      linesep=dkim.util.get_linesep(message))
        sig = d.sign(args.selector, args.domain, open(
                     args.privatekeyfile, "rb").read(), identity = args.identity,
                     canonicalize=canonicalize, include_headers=include_headers,
                     length=length)
        sys.stdout.write(sig)
        sys.stdout.write(message)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.stdout.write(message)


if __name__ == "__main__":
    main()
