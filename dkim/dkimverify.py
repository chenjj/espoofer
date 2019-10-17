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

from __future__ import print_function

import sys

import dkim


def main():
    if sys.version_info[0] >= 3:
        # Make sys.stdin a binary stream.
        sys.stdin = sys.stdin.detach()

    message = sys.stdin.read()
    verbose = '-v' in sys.argv
    if verbose:
        import logging
        d = dkim.DKIM(message, logger=logging)
        res = d.verify()
    else:
        res = dkim.verify(message)
    if not res:
        print("signature verification failed")
        sys.exit(1)
    print("signature ok")


if __name__ == "__main__":
    main()
