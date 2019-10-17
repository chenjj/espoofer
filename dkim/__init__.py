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
#
# This has been modified from the original software.
# Copyright (c) 2016, 2017, 2018, 2019 Scott Kitterman <scott@kitterman.com>
#
# This has been modified from the original software.
# Copyright (c) 2017 Valimail Inc
# Contact: Gene Shuman <gene@valimail.com>
#


import base64
import hashlib
import logging
import re
import time

# only needed for arc
try:
    from authres import AuthenticationResultsHeader
except ImportError:
    pass

# only needed for ed25519 signing/verification
try:
    import nacl.signing
    import nacl.encoding
except ImportError:
    pass

from dkim.canonicalization import (
    CanonicalizationPolicy,
    InvalidCanonicalizationPolicyError,
    )
from dkim.canonicalization import Relaxed as RelaxedCanonicalization

from dkim.crypto import (
    DigestTooLargeError,
    HASH_ALGORITHMS,
    ARC_HASH_ALGORITHMS,
    parse_pem_private_key,
    parse_public_key,
    RSASSA_PKCS1_v1_5_sign,
    RSASSA_PKCS1_v1_5_verify,
    UnparsableKeyError,
    )
try:
    from dkim.dnsplug import get_txt
except ImportError:
    def get_txt(s):
        raise RuntimeError("DKIM.verify requires DNS or dnspython module")
from dkim.util import (
    get_default_logger,
    InvalidTagValueList,
    parse_tag_value,
    )

__all__ = [
    "DKIMException",
    "InternalError",
    "KeyFormatError",
    "MessageFormatError",
    "ParameterError",
    "ValidationError",
    "AuthresNotFoundError",
    "NaClNotFoundError",
    "CV_Pass",
    "CV_Fail",
    "CV_None",
    "Relaxed",
    "Simple",
    "DKIM",
    "ARC",
    "sign",
    "verify",
    "dkim_sign",
    "dkim_verify",
    "arc_sign",
    "arc_verify",
]

Relaxed = b'relaxed'    # for clients passing dkim.Relaxed
Simple = b'simple'      # for clients passing dkim.Simple

# for ARC
CV_Pass = b'pass'
CV_Fail = b'fail'
CV_None = b'none'


class HashThrough(object):
  def __init__(self, hasher, debug=False):
    self.data = []
    self.hasher = hasher
    self.name = hasher.name
    self.debug = debug

  def update(self, data):
    if self.debug:
        self.data.append(data)
    return self.hasher.update(data)

  def digest(self):
    return self.hasher.digest()

  def hexdigest(self):
    return self.hasher.hexdigest()

  def hashed(self):
    return b''.join(self.data)


def bitsize(x):
    """Return size of long in bits."""
    return len(bin(x)) - 2


class DKIMException(Exception):
    """Base class for DKIM errors."""
    pass


class InternalError(DKIMException):
    """Internal error in dkim module. Should never happen."""
    pass


class KeyFormatError(DKIMException):
    """Key format error while parsing an RSA public or private key."""
    pass


class MessageFormatError(DKIMException):
    """RFC822 message format error."""
    pass


class ParameterError(DKIMException):
    """Input parameter error."""
    pass


class ValidationError(DKIMException):
    """Validation error."""
    pass


class AuthresNotFoundError(DKIMException):
    """ Authres Package not installed, needed for ARC """
    pass


class NaClNotFoundError(DKIMException):
    """ Nacl package not installed, needed for ed25119 signatures """
    pass


class UnknownKeyTypeError(DKIMException):
    """ Key type (k tag) is not known (rsa/ed25519) """


def select_headers(headers, include_headers):
    """Select message header fields to be signed/verified.

    >>> h = [('from','biz'),('foo','bar'),('from','baz'),('subject','boring')]
    >>> i = ['from','subject','to','from']
    >>> select_headers(h,i)
    [('from', 'baz'), ('subject', 'boring'), ('from', 'biz')]
    >>> h = [('From','biz'),('Foo','bar'),('Subject','Boring')]
    >>> i = ['from','subject','to','from']
    >>> select_headers(h,i)
    [('From', 'biz'), ('Subject', 'Boring')]
    """
    sign_headers = []
    lastindex = {}
    for h in include_headers:
        assert h == h.lower()
        i = lastindex.get(h, len(headers))
        while i > 0:
            i -= 1
            if h == headers[i][0].lower():
                sign_headers.append(headers[i])
                break
        lastindex[h] = i
    return sign_headers


# FWS  =  ([*WSP CRLF] 1*WSP) /  obs-FWS ; Folding white space  [RFC5322]
FWS = br'(?:(?:\s*\r?\n)?\s+)?'
RE_BTAG = re.compile(br'([;\s]b'+FWS+br'=)(?:'+FWS+br'[a-zA-Z0-9+/=])*(?:\r?\n\Z)?')


def hash_headers(hasher, canonicalize_headers, headers, include_headers,
                 sigheader, sig):
    """Update hash for signed message header fields."""
    sign_headers = select_headers(headers,include_headers)
    # The call to _remove() assumes that the signature b= only appears
    # once in the signature header
    cheaders = canonicalize_headers.canonicalize_headers(
        [(sigheader[0], RE_BTAG.sub(b'\\1',sigheader[1]))])
    # the dkim sig is hashed with no trailing crlf, even if the
    # canonicalization algorithm would add one.
    for x,y in sign_headers + [(x, y.rstrip()) for x,y in cheaders]:
        hasher.update(x)
        hasher.update(b":")
        hasher.update(y)
    return sign_headers


def hash_headers_ed25519(pk, canonicalize_headers, headers, include_headers,
                 sigheader, sig):
    """Update hash for signed message header fields."""
    hash_header = ''
    sign_headers = select_headers(headers,include_headers)
    # The call to _remove() assumes that the signature b= only appears
    # once in the signature header
    cheaders = canonicalize_headers.canonicalize_headers(
        [(sigheader[0], RE_BTAG.sub(b'\\1',sigheader[1]))])
    # the dkim sig is hashed with no trailing crlf, even if the
    # canonicalization algorithm would add one.
    for x,y in sign_headers + [(x, y.rstrip()) for x,y in cheaders]:
        hash_header += x + y
    return sign_headers, hash_header


def validate_signature_fields(sig, mandatory_fields=[b'v', b'a', b'b', b'bh', b'd', b'h', b's'], arc=False):
    """Validate DKIM or ARC Signature fields.
    Basic checks for presence and correct formatting of mandatory fields.
    Raises a ValidationError if checks fail, otherwise returns None.
    @param sig: A dict mapping field keys to values.
    @param mandatory_fields: A list of non-optional fields
    @param arc: flag to differentiate between dkim & arc
    """
    if arc:
        hashes = ARC_HASH_ALGORITHMS
    else:
        hashes = HASH_ALGORITHMS
    for field in mandatory_fields:
        if field not in sig:
            raise ValidationError("missing %s=" % field)

    if b'a' in sig and not sig[b'a'] in hashes:
        raise ValidationError("unknown signature algorithm: %s" % sig[b'a'])

    if b'b' in sig:
        if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'b']) is None:
            raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])
        if len(re.sub(br"\s+", b"", sig[b'b'])) % 4 != 0:
            raise ValidationError("b= value is not valid base64 (%s)" % sig[b'b'])

    if b'bh' in sig:
        if re.match(br"[\s0-9A-Za-z+/]+=*$", sig[b'bh']) is None:
            raise ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])
        if len(re.sub(br"\s+", b"", sig[b'bh'])) % 4 != 0:
            raise ValidationError("bh= value is not valid base64 (%s)" % sig[b'bh'])

    if b'cv' in sig and sig[b'cv'] not in (CV_Pass, CV_Fail, CV_None):
        raise ValidationError("cv= value is not valid (%s)" % sig[b'cv'])

    # Nasty hack to support both str and bytes... check for both the
    # character and integer values.
    if not arc and b'i' in sig and (
        not sig[b'i'].lower().endswith(sig[b'd'].lower()) or
        sig[b'i'][-len(sig[b'd'])-1] not in ('@', '.', 64, 46)):
        raise ValidationError(
            "i= domain is not a subdomain of d= (i=%s d=%s)" %
            (sig[b'i'], sig[b'd']))
    if b'l' in sig and re.match(br"\d{,76}$", sig[b'l']) is None:
        raise ValidationError(
            "l= value is not a decimal integer (%s)" % sig[b'l'])
    if b'q' in sig and sig[b'q'] != b"dns/txt":
        raise ValidationError("q= value is not dns/txt (%s)" % sig[b'q'])

    if b't' in sig:
        if re.match(br"\d+$", sig[b't']) is None:
            raise ValidationError(
                "t= value is not a decimal integer (%s)" % sig[b't'])
        now = int(time.time())
        slop = 36000 # 10H leeway for mailers with inaccurate clocks
        t_sign = int(sig[b't'])
        if t_sign > now + slop:
            raise ValidationError("t= value is in the future (%s)" % sig[b't'])

    if b'v' in sig and sig[b'v'] != b"1":
        raise ValidationError("v= value is not 1 (%s)" % sig[b'v'])

    if b'x' in sig:
        if re.match(br"\d+$", sig[b'x']) is None:
            raise ValidationError(
              "x= value is not a decimal integer (%s)" % sig[b'x'])
        x_sign = int(sig[b'x'])
        now = int(time.time())
        slop = 36000 # 10H leeway for mailers with inaccurate clocks
        if x_sign < now - slop:
            raise ValidationError(
                "x= value is past (%s)" % sig[b'x'])
            if x_sign < t_sign:
                raise ValidationError(
                    "x= value is less than t= value (x=%s t=%s)" %
                    (sig[b'x'], sig[b't']))


def rfc822_parse(message):
    """Parse a message in RFC822 format.

    @param message: The message in RFC822 format. Either CRLF or LF is an accepted line separator.
    @return: Returns a tuple of (headers, body) where headers is a list of (name, value) pairs.
    The body is a CRLF-separated string.
    """
    headers = []
    lines = re.split(b"\r?\n", message)
    i = 0
    while i < len(lines):
        if len(lines[i]) == 0:
            # End of headers, return what we have plus the body, excluding the blank line.
            i += 1
            break
        if lines[i][0] in ("\x09", "\x20", 0x09, 0x20):
            headers[-1][1] += lines[i]+b"\r\n"
        else:
            m = re.match(br"([\x21-\x7e]+?):", lines[i])
            if m is not None:
                headers.append([m.group(1), lines[i][m.end(0):]+b"\r\n"])
            elif lines[i].startswith(b"From "):
                pass
            else:
                raise MessageFormatError("Unexpected characters in RFC822 header: %s" % lines[i])
        i += 1
    return (headers, b"\r\n".join(lines[i:]))


def text(s):
    """Normalize bytes/str to str for python 2/3 compatible doctests.
    >>> text(b'foo')
    'foo'
    >>> text(u'foo')
    'foo'
    >>> text('foo')
    'foo'
    """
    if type(s) is str: return s
    s = s.decode('ascii')
    if type(s) is str: return s
    return s.encode('ascii')


def fold(header, namelen=0, linesep=b'\r\n'):
    """Fold a header line into multiple crlf-separated lines of text at column
     72.  The crlf does not count for line length.

    >>> text(fold(b'foo'))
    'foo'
    >>> text(fold(b'foo  '+b'foo'*24).splitlines()[0])
    'foo '
    >>> text(fold(b'foo'*25).splitlines()[-1])
    ' foo'
    >>> len(fold(b'foo'*25).splitlines()[0])
    72
    >>> text(fold(b'x'))
    'x'
    >>> text(fold(b'xyz'*24))
    'xyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyzxyz'
    >>> len(fold(b'xyz'*48))
    150
    """
    # 72 is the max line length we actually want, but the header field name
    # has to fit in the first line too (See Debian Bug #863690).
    maxleng = 72 - namelen
    if len(header) <= maxleng:
        return header
    if len(header) - header.rfind(b"\r\n") == 2 and len(header) <= maxleng +2:
        return header
    i = header.rfind(b"\r\n ")
    if i == -1:
        pre = b""
    else:
        i += 3
        pre = header[:i]
        header = header[i:]
    while len(header) > maxleng:
        i = header[:maxleng].rfind(b" ")
        if i == -1:
            j = maxleng
            pre += header[:j] + linesep + b" "
        else:
            j = i + 1
            pre += header[:i] + linesep + b" "
        header = header[j:]
        maxleng = 71
    if len(header) > 2:
        return pre + header
    else:
        if pre[0] == b' ':
            return pre[:-1]
        else:
            return pre + header


def load_pk_from_dns(name, dnsfunc=get_txt):
  s = dnsfunc(name)
  if not s:
      raise KeyFormatError("missing public key: %s"%name)
  try:
      if type(s) is str:
        s = s.encode('ascii')
      pub = parse_tag_value(s)
  except InvalidTagValueList as e:
      raise KeyFormatError(e)
  try:
      if pub[b'v'] != b'DKIM1':
          raise KeyFormatError("bad version")
  except KeyError as e:
      # Version not required in key record: RFC 6376 3.6.1
      pass
  try:
      if pub[b'k'] == b'ed25519':
          pk = nacl.signing.VerifyKey(pub[b'p'], encoder=nacl.encoding.Base64Encoder)
          keysize = 256
          ktag = b'ed25519'
  except KeyError:
      pub[b'k'] = b'rsa'
  if pub[b'k'] == b'rsa':
      try:
          pk = parse_public_key(base64.b64decode(pub[b'p']))
          keysize = bitsize(pk['modulus'])
      except KeyError:
          raise KeyFormatError("incomplete public key: %s" % s)
      except (TypeError,UnparsableKeyError) as e:
          raise KeyFormatError("could not parse public key (%s): %s" % (pub[b'p'],e))
      ktag = b'rsa'
  if pub[b'k'] != b'rsa' and pub[b'k'] != b'ed25519':
      raise KeyFormatError('unknown algorithm in k= tag: {0}'.format(pub[b'k']))
  return pk, keysize, ktag


#: Abstract base class for holding messages and options during DKIM/ARC signing and verification.
class DomainSigner(object):
  # NOTE - the first 2 indentation levels are 2 instead of 4
  # to minimize changed lines from the function only version.

  #: @param message: an RFC822 formatted message to be signed or verified
  #: (with either \\n or \\r\\n line endings)
  #: @param logger: a logger to which debug info will be written (default None)
  #: @param signature_algorithm: the signing algorithm to use when signing
  #: @param debug_content: log headers and body after canonicalization (default False)
  #: @param linesep: use this line seperator for folding the headers
  def __init__(self,message=None,logger=None,signature_algorithm=b'rsa-sha256',
        minkey=1024, linesep=b'\r\n', debug_content=False):
    self.set_message(message)
    if logger is None:
        logger = get_default_logger()
    self.logger = logger
    self.debug_content = debug_content and logger.isEnabledFor(logging.DEBUG)
    if signature_algorithm not in HASH_ALGORITHMS:
        raise ParameterError(
            "Unsupported signature algorithm: "+signature_algorithm)
    self.signature_algorithm = signature_algorithm
    #: Header fields which should be signed.  Default as suggested by RFC6376
    self.should_sign = set(DKIM.SHOULD)
    #: Header fields which should not be signed.  The default is from RFC6376.
    #: Attempting to sign these headers results in an exception.
    #: If it is necessary to sign one of these, it must be removed
    #: from this list first.
    self.should_not_sign = set(DKIM.SHOULD_NOT)
    #: Header fields to sign an extra time to prevent additions.
    self.frozen_sign = set(DKIM.FROZEN)
    #: Minimum public key size.  Shorter keys raise KeyFormatError. The
    #: default is 1024
    self.minkey = minkey
    # use this line seperator for output
    self.linesep = linesep


  #: Header fields to protect from additions by default.
  #:
  #: The short list below is the result more of instinct than logic.
  #: @since: 0.5
  FROZEN = (b'from',)

  #: The rfc6376 recommended header fields to sign
  #: @since: 0.5
  SHOULD = (
    b'from', b'sender', b'reply-to', b'subject', b'date', b'message-id', b'to', b'cc',
    b'mime-version', b'content-type', b'content-transfer-encoding',
    b'content-id', b'content-description', b'resent-date', b'resent-from',
    b'resent-sender', b'resent-to', b'resent-cc', b'resent-message-id',
    b'in-reply-to', b'references', b'list-id', b'list-help', b'list-unsubscribe',
    b'list-subscribe', b'list-post', b'list-owner', b'list-archive'
  )

  #: The rfc6376 recommended header fields not to sign.
  #: @since: 0.5
  SHOULD_NOT = (
    b'return-path',b'received',b'comments',b'keywords',b'bcc',b'resent-bcc',
    b'dkim-signature'
  )

  # Doesn't seem to be used (GS)
  #: The U{RFC5322<http://tools.ietf.org/html/rfc5322#section-3.6>}
  #: complete list of singleton headers (which should
  #: appear at most once).  This can be used for a "paranoid" or
  #: "strict" signing mode.
  #: Bcc in this list is in the SHOULD NOT sign list, the rest could
  #: be in the default FROZEN list, but that could also make signatures
  #: more fragile than necessary.
  #: @since: 0.5
  RFC5322_SINGLETON = (b'date',b'from',b'sender',b'reply-to',b'to',b'cc',b'bcc',
        b'message-id',b'in-reply-to',b'references')

  def add_frozen(self,s):
    """ Add headers not in should_not_sign to frozen_sign.
    @param s: list of headers to add to frozen_sign
    @since: 0.5

    >>> dkim = DKIM()
    >>> dkim.add_frozen(DKIM.RFC5322_SINGLETON)
    >>> [text(x) for x in sorted(dkim.frozen_sign)]
    ['cc', 'date', 'from', 'in-reply-to', 'message-id', 'references', 'reply-to', 'sender', 'to']
    >>> dkim2 = DKIM()
    >>> dkim2.add_frozen((b'date',b'subject'))
    >>> [text(x) for x in sorted(dkim2.frozen_sign)]
    ['date', 'from', 'subject']
    """
    self.frozen_sign.update(x.lower() for x in s
        if x.lower() not in self.should_not_sign)


  def add_should_not(self,s):
    """ Add headers not in should_not_sign to frozen_sign.
    @param s: list of headers to add to frozen_sign
    @since: 0.9

    >>> dkim = DKIM()
    >>> dkim.add_should_not(DKIM.RFC5322_SINGLETON)
    >>> [text(x) for x in sorted(dkim.should_not_sign)]
    ['bcc', 'cc', 'comments', 'date', 'dkim-signature', 'in-reply-to', 'keywords', 'message-id', 'received', 'references', 'reply-to', 'resent-bcc', 'return-path', 'sender', 'to']
    """
    self.should_not_sign.update(x.lower() for x in s
        if x.lower() not in self.frozen_sign)


  #: Load a new message to be signed or verified.
  #: @param message: an RFC822 formatted message to be signed or verified
  #: (with either \\n or \\r\\n line endings)
  #: @since: 0.5
  def set_message(self,message):
    if message:
      self.headers, self.body = rfc822_parse(message)
    else:
      self.headers, self.body = [],''
    #: The DKIM signing domain last signed or verified.
    self.domain = None
    #: The DKIM key selector last signed or verified.
    self.selector = 'default'
    #: Signature parameters of last sign or verify.  To parse
    #: a DKIM-Signature header field that you have in hand,
    #: use L{dkim.util.parse_tag_value}.
    self.signature_fields = {}
    #: The list of headers last signed or verified.  Each header
    #: is a name,value tuple.  FIXME: The headers are canonicalized.
    #: This could be more useful as original headers.
    self.signed_headers = []
    #: The public key size last verified.
    self.keysize = 0

  def default_sign_headers(self):
    """Return the default list of headers to sign: those in should_sign or
    frozen_sign, with those in frozen_sign signed an extra time to prevent
    additions.
    @since: 0.5"""
    hset = self.should_sign | self.frozen_sign
    include_headers = [ x for x,y in self.headers
        if x.lower() in hset ]
    return include_headers + [ x for x in include_headers
        if x.lower() in self.frozen_sign]

  def all_sign_headers(self):
    """Return header list of all existing headers not in should_not_sign.
    @since: 0.5"""
    return [x for x,y in self.headers if x.lower() not in self.should_not_sign]


  # Abstract helper method to generate a tag=value header from a list of fields
  #: @param fields: A list of key value tuples to be included in the header
  #: @param include_headers: A list message headers to include in the b= signature computation
  #: @param canon_policy: A canonicialization policy for b= & bh=
  #: @param header_name: The name of the generated header
  #: @param pk: The private key used for signature generation
  #: @param standardize:  Flag to enable 'standard' header syntax
  def gen_header(self, fields, include_headers, canon_policy, header_name, pk, standardize=False):
    if standardize:
        lower = [(x,y.lower().replace(b' ', b'')) for (x,y) in fields if x != b'bh']
        reg   = [(x,y.replace(b' ', b'')) for (x,y) in fields if x == b'bh']
        fields = lower + reg
        fields = sorted(fields, key=(lambda x: x[0]))

    header_value = b"; ".join(b"=".join(x) for x in fields)
    if not standardize:
      header_value = fold(header_value, namelen=len(header_name), linesep=b'\r\n')
    header_value = RE_BTAG.sub(b'\\1',header_value)
    header = (header_name, b' ' + header_value)
    h = HashThrough(self.hasher(), self.debug_content)
    sig = dict(fields)

    headers = canon_policy.canonicalize_headers(self.headers)
    self.signed_headers = hash_headers(
        h, canon_policy, headers, include_headers, header, sig)
    if self.debug_content:
        self.logger.debug("sign %s headers: %r" % (header_name, h.hashed()))

    if self.signature_algorithm == b'rsa-sha256' or self.signature_algorithm == b'rsa-sha1':
        try:
            sig2 = RSASSA_PKCS1_v1_5_sign(h, pk)
        except DigestTooLargeError:
            raise ParameterError("digest too large for modulus")
    elif self.signature_algorithm == b'ed25519-sha256':
        sigobj = pk.sign(h.digest())
        sig2 = sigobj.signature
    # Folding b= is explicity allowed, but yahoo and live.com are broken
    #header_value += base64.b64encode(bytes(sig2))
    # Instead of leaving unfolded (which lets an MTA fold it later and still
    # breaks yahoo and live.com), we change the default signing mode to
    # relaxed/simple (for broken receivers), and fold now.
    idx = [i for i in range(len(fields)) if fields[i][0] == b'b'][0]
    fields[idx] = (b'b', base64.b64encode(bytes(sig2)))
    header_value = b"; ".join(b"=".join(x) for x in fields) + self.linesep

    if not standardize:
      header_value = fold(header_value, namelen=len(header_name), linesep=self.linesep)

    return header_value

  # Abstract helper method to verify a signed header
  #: @param sig: List of (key, value) tuples containing tag=values of the header
  #: @param include_headers: headers to validate b= signature against
  #: @param sig_header: (header_name, header_value)
  #: @param dnsfunc: interface to dns
  def verify_sig(self, sig, include_headers, sig_header, dnsfunc):
    name = sig[b's'] + b"._domainkey." + sig[b'd'] + b"."
    try:
      pk, self.keysize, ktag = load_pk_from_dns(name, dnsfunc)
    except KeyFormatError as e:
      self.logger.error("%s" % e)
      return False

    try:
        canon_policy = CanonicalizationPolicy.from_c_value(sig.get(b'c', b'simple/simple'))
    except InvalidCanonicalizationPolicyError as e:
        raise MessageFormatError("invalid c= value: %s" % e.args[0])

    hasher = HASH_ALGORITHMS[sig[b'a']]

    # validate body if present
    if b'bh' in sig:
      h = HashThrough(hasher(), self.debug_content)

      body = canon_policy.canonicalize_body(self.body)
      if b'l' in sig:
        body = body[:int(sig[b'l'])]
      h.update(body)
      if self.debug_content:
          self.logger.debug("body hashed: %r" % h.hashed())
      bodyhash = h.digest()

      self.logger.debug("bh: %s" % base64.b64encode(bodyhash))
      try:
          bh = base64.b64decode(re.sub(br"\s+", b"", sig[b'bh']))
      except TypeError as e:
          raise MessageFormatError(str(e))
      if bodyhash != bh:
          raise ValidationError(
              "body hash mismatch (got %s, expected %s)" %
              (base64.b64encode(bodyhash), sig[b'bh']))

    # address bug#644046 by including any additional From header
    # fields when verifying.  Since there should be only one From header,
    # this shouldn't break any legitimate messages.  This could be
    # generalized to check for extras of other singleton headers.
    if b'from' in include_headers:
      include_headers.append(b'from')
    h = HashThrough(hasher(), self.debug_content)

    headers = canon_policy.canonicalize_headers(self.headers)
    self.signed_headers = hash_headers(
        h, canon_policy, headers, include_headers, sig_header, sig)
    if self.debug_content:
        self.logger.debug("signed for %s: %r" % (sig_header[0], h.hashed()))
    signature = base64.b64decode(re.sub(br"\s+", b"", sig[b'b']))
    if ktag == b'rsa':
        try:
            res = RSASSA_PKCS1_v1_5_verify(h, signature, pk)
            self.logger.debug("%s valid: %s" % (sig_header[0], res))
            if res and self.keysize < self.minkey:
                raise KeyFormatError("public key too small: %d" % self.keysize)
            return res
        except (TypeError,DigestTooLargeError) as e:
            raise KeyFormatError("digest too large for modulus: %s"%e)
    elif ktag == b'ed25519':
        try:
            pk.verify(h.digest(), signature)
            self.logger.debug("%s valid" % (sig_header[0]))
            return True
        except (nacl.exceptions.BadSignatureError) as e:
            return False
    else:
        raise UnknownKeyTypeError(ktag)


#: Hold messages and options during DKIM signing and verification.
class DKIM(DomainSigner):
  #: Sign an RFC822 message and return the DKIM-Signature header line.
  #:
  #: The include_headers option gives full control over which header fields
  #: are signed.  Note that signing a header field that doesn't exist prevents
  #: that field from being added without breaking the signature.  Repeated
  #: fields (such as Received) can be signed multiple times.  Instances
  #: of the field are signed from bottom to top.  Signing a header field more
  #: times than are currently present prevents additional instances
  #: from being added without breaking the signature.
  #:
  #: The length option allows the message body to be appended to by MTAs
  #: enroute (e.g. mailing lists that append unsubscribe information)
  #: without breaking the signature.
  #:
  #: The default include_headers for this method differs from the backward
  #: compatible sign function, which signs all headers not
  #: in should_not_sign.  The default list for this method can be modified
  #: by tweaking should_sign and frozen_sign (or even should_not_sign).
  #: It is only necessary to pass an include_headers list when precise control
  #: is needed.
  #:
  #: @param selector: the DKIM selector value for the signature
  #: @param domain: the DKIM domain value for the signature
  #: @param privkey: a PKCS#1 private key in base64-encoded text form
  #: @param identity: the DKIM identity value for the signature
  #: (default "@"+domain)
  #: @param canonicalize: the canonicalization algorithms to use
  #: (default (Simple, Simple))
  #: @param include_headers: a list of strings indicating which headers
  #: are to be signed (default rfc4871 recommended headers)
  #: @param length: true if the l= tag should be included to indicate
  #: body length signed (default False).
  #: @return: DKIM-Signature header field terminated by '\r\n'
  #: @raise DKIMException: when the message, include_headers, or key are badly
  #: formed.
  def sign(self, selector, domain, privkey, signature_algorithm=None, identity=None,
        canonicalize=(b'relaxed',b'simple'), include_headers=None, length=False):
    if signature_algorithm:
        self.signature_algorithm = signature_algorithm
    if self.signature_algorithm == b'rsa-sha256' or self.signature_algorithm == b'rsa-sha1':
        try:
            pk = parse_pem_private_key(privkey)
        except UnparsableKeyError as e:
            raise KeyFormatError(str(e))
    elif self.signature_algorithm == b'ed25519-sha256':
        pk = nacl.signing.SigningKey(privkey, encoder=nacl.encoding.Base64Encoder)

    if identity is not None and not identity.endswith(domain):
        raise ParameterError("identity must end with domain")

    canon_policy = CanonicalizationPolicy.from_c_value(b'/'.join(canonicalize))

    if include_headers is None:
        include_headers = self.default_sign_headers()
    try:
        include_headers = [bytes(x, 'utf-8') for x in include_headers]
    except TypeError:
        # TypeError means it's already bytes and we're good or we're in
        # Python 2 and we don't care.  See LP: #1776775.
        pass

    include_headers = tuple([x.lower() for x in include_headers])
    # record what verify should extract
    self.include_headers = include_headers

    # rfc4871 says FROM is required
    if b'from' not in include_headers:
        raise ParameterError("The From header field MUST be signed")

    # raise exception for any SHOULD_NOT headers, call can modify
    # SHOULD_NOT if really needed.
    for x in set(include_headers).intersection(self.should_not_sign):
      raise ParameterError("The %s header field SHOULD NOT be signed"%x)

    body = canon_policy.canonicalize_body(self.body)

    self.hasher = HASH_ALGORITHMS[self.signature_algorithm]
    h = self.hasher()
    h.update(body)
    bodyhash = base64.b64encode(h.digest())

    sigfields = [x for x in [
        (b'v', b"1"),
        (b'a', self.signature_algorithm),
        (b'c', canon_policy.to_c_value()),
        (b'd', domain),
        (b'i', identity or b"@"+domain),
        length and (b'l', str(len(body)).encode('ascii')),
        (b'q', b"dns/txt"),
        (b's', selector),
        (b't', str(int(time.time())).encode('ascii')),
        (b'h', b" : ".join(include_headers)),
        (b'bh', bodyhash),
        # Force b= to fold onto it's own line so that refolding after
        # adding sig doesn't change whitespace for previous tags.
        (b'b', b'0'*60),
    ] if x]

    res = self.gen_header(sigfields, include_headers, canon_policy,
                           b"DKIM-Signature", pk)

    self.domain = domain
    self.selector = selector
    self.signature_fields = dict(sigfields)
    return b'DKIM-Signature: ' + res

  #: Verify a DKIM signature.
  #: @type idx: int
  #: @param idx: which signature to verify.  The first (topmost) signature is 0.
  #: @type dnsfunc: callable
  #: @param dnsfunc: an option function to lookup TXT resource records
  #: for a DNS domain.  The default uses dnspython or pydns.
  #: @return: True if signature verifies or False otherwise
  #: @raise DKIMException: when the message, signature, or key are badly formed
  def verify(self,idx=0,dnsfunc=get_txt):
    sigheaders = [(x,y) for x,y in self.headers if x.lower() == b"dkim-signature"]
    if len(sigheaders) <= idx:
        return False

    # By default, we validate the first DKIM-Signature line found.
    try:
        sig = parse_tag_value(sigheaders[idx][1])
        self.signature_fields = sig
    except InvalidTagValueList as e:
        raise MessageFormatError(e)

    self.logger.debug("sig: %r" % sig)

    validate_signature_fields(sig)
    self.domain = sig[b'd']
    self.selector = sig[b's']

    include_headers = [x.lower() for x in re.split(br"\s*:\s*", sig[b'h'])]
    self.include_headers = tuple(include_headers)

    return self.verify_sig(sig, include_headers, sigheaders[idx], dnsfunc)


#: Hold messages and options during ARC signing and verification.
class ARC(DomainSigner):
  #: Header fields used by ARC
  ARC_HEADERS = (b'arc-seal', b'arc-message-signature', b'arc-authentication-results')

  #: Regex to extract i= value from ARC headers
  INSTANCE_RE = re.compile(br'[\s;]?i\s*=\s*(\d+)', re.MULTILINE | re.IGNORECASE)

  def sorted_arc_headers(self):
    headers = []
    # Use relaxed canonicalization to unfold and clean up headers
    relaxed_headers = RelaxedCanonicalization.canonicalize_headers(self.headers)
    for x,y in relaxed_headers:
      if x.lower() in ARC.ARC_HEADERS:
        m = ARC.INSTANCE_RE.search(y)
        if m is not None:
          try:
            i = int(m.group(1))
            headers.append((i, (x, y)))
          except ValueError:
            self.logger.debug("invalid instance number %s: '%s: %s'" % (m.group(1), x, y))
        else:
          self.logger.debug("not instance number: '%s: %s'" % (x, y))

    if len(headers) == 0:
      return 0, []

    def arc_header_key(a):
      return [a[0], a[1][0].lower(), a[1][1].lower()]

    headers = sorted(headers, key=arc_header_key)
    headers.reverse()
    return headers[0][0], headers

  #: Sign an RFC822 message and return the list of ARC set header lines
  #:
  #: The include_headers option gives full control over which header fields
  #: are signed for the ARC-Message-Signature.  Note that signing a header
  #: field that doesn't exist prevents
  #: that field from being added without breaking the signature.  Repeated
  #: fields (such as Received) can be signed multiple times.  Instances
  #: of the field are signed from bottom to top.  Signing a header field more
  #: times than are currently present prevents additional instances
  #: from being added without breaking the signature.
  #:
  #: The default include_headers for this method differs from the backward
  #: compatible sign function, which signs all headers not
  #: in should_not_sign.  The default list for this method can be modified
  #: by tweaking should_sign and frozen_sign (or even should_not_sign).
  #: It is only necessary to pass an include_headers list when precise control
  #: is needed.
  #:
  #: @param selector: the DKIM selector value for the signature
  #: @param domain: the DKIM domain value for the signature
  #: @param privkey: a PKCS#1 private key in base64-encoded text form
  #: @param srv_id: an srv_id for identitfying AR headers to sign & extract cv from
  #: @param include_headers: a list of strings indicating which headers
  #: are to be signed (default rfc4871 recommended headers)
  #: @return: list of ARC set header fields
  #: @raise DKIMException: when the message, include_headers, or key are badly
  #: formed.
  def sign(self, selector, domain, privkey, srv_id, include_headers=None,
           timestamp=None, standardize=False):

    INSTANCE_LIMIT = 50 # Maximum allowed i= value
    self.add_should_not(('Authentication-Results',))
    # check if authres has been imported
    try:
        AuthenticationResultsHeader
    except:
        self.logger.debug("authres package not installed")
        raise AuthresNotFoundError

    try:
        pk = parse_pem_private_key(privkey)
    except UnparsableKeyError as e:
        raise KeyFormatError(str(e))

    # extract, parse, filter & group AR headers
    ar_headers = [res.strip() for [ar, res] in self.headers if ar == b'Authentication-Results']
    grouped_headers = [(res, AuthenticationResultsHeader.parse('Authentication-Results: ' + res.decode('utf-8')))
                       for res in ar_headers]
    auth_headers = [res for res in grouped_headers if res[1].authserv_id == srv_id.decode('utf-8')]

    if len(auth_headers) == 0:
      self.logger.debug("no AR headers found, chain terminated")
      return []

    # consolidate headers
    results_lists = [raw.replace(srv_id + b';', b'').strip() for (raw, parsed) in auth_headers]
    results_lists = [tags.split(b';') for tags in results_lists]
    results = [tag.strip() for sublist in results_lists for tag in sublist]
    auth_results = srv_id + b'; ' + (b';' + self.linesep + b'  ').join(results)

    # extract cv
    parsed_auth_results = AuthenticationResultsHeader.parse('Authentication-Results: ' + auth_results.decode('utf-8'))
    arc_results = [res for res in parsed_auth_results.results if res.method == 'arc']
    if len(arc_results) == 0:
      chain_validation_status = CV_None
    elif len(arc_results) != 1:
      self.logger.debug("multiple AR arc stamps found, failing chain")
      chain_validation_status = CV_Fail
    else:
      chain_validation_status = arc_results[0].result.lower().encode('utf-8')

    # Setup headers
    if include_headers is None:
        include_headers = self.default_sign_headers()

    include_headers = tuple([x.lower() for x in include_headers])

    # record what verify should extract
    self.include_headers = include_headers

    # rfc4871 says FROM is required
    if b'from' not in include_headers:
        raise ParameterError("The From header field MUST be signed")

    # raise exception for any SHOULD_NOT headers, call can modify
    # SHOULD_NOT if really needed.
    for x in set(include_headers).intersection(self.should_not_sign):
        raise ParameterError("The %s header field SHOULD NOT be signed"%x)

    max_instance, arc_headers_w_instance = self.sorted_arc_headers()
    instance = 1
    if len(arc_headers_w_instance) != 0:
        instance = max_instance + 1
    if instance > INSTANCE_LIMIT:
        raise ParameterError("Maximum instance tag value exceeded")

    if instance == 1 and chain_validation_status != CV_None:
        raise ParameterError("No existing chain found on message, cv should be none")
    elif instance != 1 and chain_validation_status == CV_None:
      self.logger.debug("no previous AR arc results found and instance > 1, chain terminated")
      return []

    new_arc_set = []
    if chain_validation_status != CV_Fail:
      arc_headers = [y for x,y in arc_headers_w_instance]
    else: # don't include previous sets for a failed/invalid chain
      arc_headers = []

    # Compute ARC-Authentication-Results
    aar_value = ("i=%d; " % instance).encode('utf-8') + auth_results
    if aar_value[-1] != b'\n': aar_value += b'\r\n'

    new_arc_set.append(b"ARC-Authentication-Results: " + aar_value)
    self.headers.insert(0, (b"arc-authentication-results", aar_value))
    arc_headers.insert(0, (b"ARC-Authentication-Results", aar_value))

    # Compute bh=
    canon_policy = CanonicalizationPolicy.from_c_value(b'relaxed/relaxed')

    self.hasher = HASH_ALGORITHMS[self.signature_algorithm]
    h = HashThrough(self.hasher(), self.debug_content)
    h.update(canon_policy.canonicalize_body(self.body))
    if self.debug_content:
        self.logger.debug("sign ams body hashed: %r" % h.hashed())
    bodyhash = base64.b64encode(h.digest())

    # Compute ARC-Message-Signature
    timestamp = str(timestamp or int(time.time())).encode('ascii')
    ams_fields = [x for x in [
        (b'i', str(instance).encode('ascii')),
        (b'a', self.signature_algorithm),
        (b'c', b'relaxed/relaxed'),
        (b'd', domain),
        (b's', selector),
        (b't', timestamp),
        (b'h', b" : ".join(include_headers)),
        (b'bh', bodyhash),
        # Force b= to fold onto it's own line so that refolding after
        # adding sig doesn't change whitespace for previous tags.
        (b'b', b'0'*60),
    ] if x]

    res = self.gen_header(ams_fields, include_headers, canon_policy,
                          b"ARC-Message-Signature", pk, standardize)

    new_arc_set.append(b"ARC-Message-Signature: " + res)
    self.headers.insert(0, (b"ARC-Message-Signature", res))
    arc_headers.insert(0, (b"ARC-Message-Signature", res))

    # Compute ARC-Seal
    as_fields = [x for x in [
        (b'i', str(instance).encode('ascii')),
        (b'cv', chain_validation_status),
        (b'a', self.signature_algorithm),
        (b'd', domain),
        (b's', selector),
        (b't', timestamp),
        # Force b= to fold onto it's own line so that refolding after
        # adding sig doesn't change whitespace for previous tags.
        (b'b', b'0'*60),
    ] if x]

    as_include_headers = [x[0].lower() for x in arc_headers]
    as_include_headers.reverse()

    # if our chain is failing or invalid, we only grab the most recent set
    # reversing the order of the headers accomplishes this
    if chain_validation_status == CV_Fail:
      self.headers.reverse()
    if b'h' in as_fields:
        raise ValidationError("h= tag not permitted in ARC-Seal header field")    
    res = self.gen_header(as_fields, as_include_headers, canon_policy,
                           b"ARC-Seal", pk, standardize)

    new_arc_set.append(b"ARC-Seal: " + res)
    self.headers.insert(0, (b"ARC-Seal", res))
    arc_headers.insert(0, (b"ARC-Seal", res))

    new_arc_set.reverse()

    return new_arc_set

  #: Verify an ARC set.
  #: @type instance: int
  #: @param instance: which ARC set to verify, based on i= instance.
  #: @type dnsfunc: callable
  #: @param dnsfunc: an optional function to lookup TXT resource records
  #: for a DNS domain.  The default uses dnspython or pydns.
  #: @return: True if signature verifies or False otherwise
  #: @return: three-tuple of (CV Result (CV_Pass, CV_Fail, CV_None or None, for a chain that has ended), list of
  #: result dictionaries, result reason)
  #: @raise DKIMException: when the message, signature, or key are badly formed
  def verify(self,dnsfunc=get_txt):
    result_data = []
    max_instance, arc_headers_w_instance = self.sorted_arc_headers()
    if max_instance == 0:
        return CV_None, result_data, "Message is not ARC signed"
    for instance in range(max_instance, 0, -1):
        try:
            result = self.verify_instance(arc_headers_w_instance, instance, dnsfunc=dnsfunc)
            result_data.append(result)
        except DKIMException as e:
            self.logger.error("%s" % e)
            return CV_Fail, result_data, "%s" % e

    # Most recent instance must ams-validate
    if not result_data[0]['ams-valid']:
        return CV_Fail, result_data, "Most recent ARC-Message-Signature did not validate"
    for result in result_data:
      if result['cv'] == CV_Fail:
        return None, result_data, "ARC-Seal[%d] reported failure, the chain is terminated" % result['instance']
      elif not result['as-valid']:
        return CV_Fail, result_data, "ARC-Seal[%d] did not validate" % result['instance']
      elif (result['instance'] == 1) and (result['cv'] != CV_None):
        return CV_Fail, result_data, "ARC-Seal[%d] reported invalid status %s" % (result['instance'], result['cv'])
      elif (result['instance'] != 1) and (result['cv'] == CV_None):
        return CV_Fail, result_data, "ARC-Seal[%d] reported invalid status %s" % (result['instance'], result['cv'])
    return CV_Pass, result_data, "success"

  #: Verify an ARC set.
  #: @type arc_headers_w_instance: list
  #: @param arc_headers_w_instance: list of tuples, (instance, (name, value)) of
  #: ARC headers
  #: @type instance: int
  #: @param instance: which ARC set to verify, based on i= instance.
  #: @type dnsfunc: callable
  #: @param dnsfunc: an optional function to lookup TXT resource records
  #: for a DNS domain.  The default uses dnspython or pydns.
  #: @return: True if signature verifies or False otherwise
  #: @raise DKIMException: when the message, signature, or key are badly formed
  def verify_instance(self,arc_headers_w_instance,instance,dnsfunc=get_txt):
    if (instance == 0) or (len(arc_headers_w_instance) == 0):
        raise ParameterError("request to verify instance %d not present" % (instance))

    aar_value = None
    ams_value = None
    as_value = None
    arc_headers = []
    output = { 'instance': instance }

    for i, arc_header in arc_headers_w_instance:
      if i > instance: continue
      arc_headers.append(arc_header)
      if i == instance:
        if arc_header[0].lower() == b"arc-authentication-results":
          if aar_value is not None:
            raise MessageFormatError("Duplicate ARC-Authentication-Results for instance %d" % instance)
          aar_value = arc_header[1]
        elif arc_header[0].lower() == b"arc-message-signature":
          if ams_value is not None:
            raise MessageFormatError("Duplicate ARC-Message-Signature for instance %d" % instance)
          ams_value = arc_header[1]
        elif arc_header[0].lower() == b"arc-seal":
          if as_value is not None:
            raise MessageFormatError("Duplicate ARC-Seal for instance %d" % instance)
          as_value = arc_header[1]

    if (aar_value is None) or (ams_value is None) or (as_value is None):
        raise MessageFormatError("Incomplete ARC set for instance %d" % instance)

    output['aar-value'] = aar_value

    # Validate Arc-Message-Signature
    try:
        sig = parse_tag_value(ams_value)
    except InvalidTagValueList as e:
        raise MessageFormatError(e)

    self.logger.debug("ams sig[%d]: %r" % (instance, sig))

    validate_signature_fields(sig, [b'i', b'a', b'b', b'bh', b'd', b'h', b's'], True)
    output['ams-domain'] = sig[b'd']
    output['ams-selector'] = sig[b's']

    include_headers = [x.lower() for x in re.split(br"\s*:\s*", sig[b'h'])]
    if b'arc-seal' in include_headers:
        raise ParameterError("The Arc-Message-Signature MUST NOT sign ARC-Seal")

    ams_header = (b'ARC-Message-Signature', b' ' + ams_value)


    # we can't use the AMS provided above, as it's already been canonicalized relaxed
    # for use in validating the AS.  However the AMS is included in the AMS itself,
    # and this can use simple canonicalization
    raw_ams_header = [(x, y) for (x, y) in self.headers if x.lower() == b'arc-message-signature'][0]

    # Only relaxed canonicalization used by ARC
    if b'c' not in sig:
        sig[b'c'] = b'relaxed/relaxed'
    try:
      ams_valid = self.verify_sig(sig, include_headers, raw_ams_header, dnsfunc)
    except DKIMException as e:
      self.logger.error("%s" % e)
      ams_valid = False

    output['ams-valid'] = ams_valid
    self.logger.debug("ams valid: %r" % ams_valid)

    # Validate Arc-Seal
    try:
        sig = parse_tag_value(as_value)
    except InvalidTagValueList as e:
        raise MessageFormatError(e)

    self.logger.debug("as sig[%d]: %r" % (instance, sig))

    validate_signature_fields(sig, [b'i', b'a', b'b', b'cv', b'd', b's'], True)
    if b'h' in sig:
        raise ValidationError("h= tag not permitted in ARC-Seal header field")

    output['as-domain'] = sig[b'd']
    output['as-selector'] = sig[b's']
    output['cv'] = sig[b'cv']

    as_include_headers = [x[0].lower() for x in arc_headers]
    as_include_headers.reverse()
    as_header = (b'ARC-Seal', b' ' + as_value)
    # Only relaxed canonicalization used by ARC
    if b'c' not in sig:
        sig[b'c'] = b'relaxed/relaxed'
    try:
      as_valid = self.verify_sig(sig, as_include_headers[:-1], as_header, dnsfunc)
    except DKIMException as e:
      self.logger.error("%s" % e)
      as_valid = False

    output['as-valid'] = as_valid
    self.logger.debug("as valid: %r" % as_valid)
    return output


def sign(message, selector, domain, privkey, identity=None,
         canonicalize=(b'relaxed', b'simple'),
         signature_algorithm=b'rsa-sha256',
         include_headers=None, length=False, logger=None,
         linesep=b'\r\n'):
    # type: (bytes, bytes, bytes, bytes, bytes, tuple, bytes, list, bool, any) -> bytes
    """Sign an RFC822 message and return the DKIM-Signature header line.
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param identity: the DKIM identity value for the signature (default "@"+domain)
    @param canonicalize: the canonicalization algorithms to use (default (Simple, Simple))
    @param signature_algorithm: the signing algorithm to use when signing
    @param include_headers: a list of strings indicating which headers are to be signed (default all headers not listed as SHOULD NOT sign)
    @param length: true if the l= tag should be included to indicate body length (default False)
    @param logger: a logger to which debug info will be written (default None)
    @param linesep: use this line seperator for folding the headers
    @return: DKIM-Signature header field terminated by \\r\\n
    @raise DKIMException: when the message, include_headers, or key are badly formed.
    """

    d = DKIM(message,logger=logger,signature_algorithm=signature_algorithm,linesep=linesep)
    return d.sign(selector, domain, privkey, identity=identity, canonicalize=canonicalize, include_headers=include_headers, length=length)


def verify(message, logger=None, dnsfunc=get_txt, minkey=1024):
    """Verify the first (topmost) DKIM signature on an RFC822 formatted message.
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param logger: a logger to which debug info will be written (default None)
    @return: True if signature verifies or False otherwise
    """
    # type: (bytes, any, function, int) -> bool
    d = DKIM(message,logger=logger,minkey=minkey)
    try:
        return d.verify(dnsfunc=dnsfunc)
    except DKIMException as x:
        if logger is not None:
            logger.error("%s" % x)
        return False

# For consistency with ARC
dkim_sign = sign
dkim_verify = verify


def arc_sign(message, selector, domain, privkey,
             srv_id, signature_algorithm=b'rsa-sha256',
             include_headers=None, timestamp=None,
             logger=None, standardize=False, linesep=b'\r\n'):
    # type: (bytes, bytes, bytes, bytes, bytes, bytes, list, any, any, bool) -> list
    """Sign an RFC822 message and return the ARC set header lines for the next instance
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param srv_id: the authserv_id used to identify the ADMD's AR headers and to use for ARC authserv_id
    @param signature_algorithm: the signing algorithm to use when signing
    @param include_headers: a list of strings indicating which headers are to be signed (default all headers not listed as SHOULD NOT sign)
    @param timestamp: the time in integer seconds when the message is sealed (default is int(time.time) based on platform, can be string or int)
    @param logger: a logger to which debug info will be written (default None)
    @param linesep: use this line seperator for folding the headers
    @return: A list containing the ARC set of header fields for the next instance
    @raise DKIMException: when the message, include_headers, or key are badly formed.
    """

    a = ARC(message,logger=logger,signature_algorithm=b'rsa-sha256',linesep=linesep)
    if not include_headers:
        include_headers = a.default_sign_headers()
    return a.sign(selector, domain, privkey, srv_id, include_headers=include_headers,
                  timestamp=timestamp, standardize=standardize)


def arc_verify(message, logger=None, dnsfunc=get_txt, minkey=1024):
    # type: (bytes, any, function, int) -> tuple
    """Verify the ARC chain on an RFC822 formatted message.
    @param message: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param logger: a logger to which debug info will be written (default None)
    @param dnsfunc: an optional function to lookup TXT resource records
    @param minkey: the minimum key size to accept
    @return: three-tuple of (CV Result (CV_Pass, CV_Fail or CV_None), list of
    result dictionaries, result reason)
    """
    a = ARC(message,logger=logger,minkey=minkey)
    try:
        return a.verify(dnsfunc=dnsfunc)
    except DKIMException as x:
        if logger is not None:
            logger.error("%s" % x)
        return CV_Fail, [], "%s" % x
