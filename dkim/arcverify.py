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
#
# This has been modified from the original software.
# Copyright (c) 2016 Google, Inc.
# Contact: Brandon Long <blong@google.com>

from __future__ import print_function

import logging
import sys

import dkim


def main():
    if sys.version_info[0] >= 3:
        # Make sys.stdin a binary stream.
        sys.stdin = sys.stdin.detach()

    message = sys.stdin.read()
    verbose = '-v' in sys.argv
    if verbose:
        logging.basicConfig(level=10)
        a = dkim.ARC(message)
        cv, results, comment = a.verify()
    else:
        cv, results, comment = dkim.arc_verify(message)

    print("arc verification: cv=%s %s" % (cv, comment))
    if verbose:
        print(repr(results))


if __name__ == "__main__":
    main()
