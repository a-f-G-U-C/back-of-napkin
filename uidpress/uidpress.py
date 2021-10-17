#!/usr/bin/python3
"""
TAK UID COMPRESSION WORKBENCH
Copyright 2021 by https://github.com/a-f-G-U-C, MIT license

Adaptive compression for small (<80 chars) formatted strings using a
hard-coded pattern dictionary and several bit packing methods
"""

import re
import sys
from select import select
from binascii import hexlify, unhexlify
from struct import pack, unpack
from base64 import b64encode, b64decode
import uuid


# REGEX for UUID - intentionally lowercase-only
RXUUID = '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'

# REGEX for MAC addresses - (L)ower and (U)pper case
RXMACL = '([0-9a-f]{2}:){5}[0-9a-f]{2}'
RXMACU = '([0-9A-F]{2}:){5}[0-9A-F]{2}'

"""
PATTERNS - REGEX patterns for classifying UIDs, mostly empirically determined
Some rules for simplicity:
- these patterns must be ACTIONABLE from a compression perspective: we LOOK
  for them because we KNOW what we will DO to them when we find them
- order matters: list patterns specific before generic, optimistic before
  pessimistic etc, as they will be checked in the given order
- all copies of the software must run the same version of the dictionaries

Maximum 127 records in this category
"""
PATTERNS = [
    # 128-bit UUIDs - convert to bytes
    {'name': 'uuid128',     'regex': '^' + RXUUID + '$'},
    # a UUID with a 4-digit decimal number appended with an underscore
    {'name': 'uuid128d4',   'regex': '^' + RXUUID + '_[0-9]{4}$'},

    # strip ANDROID- part and compress the rest
    {'name': 'and-dec15',   'regex': '^ANDROID-[0-9]{15}$'},
    {'name': 'and-dec14',   'regex': '^ANDROID-[0-9]{14}$'},
    {'name': 'and-hex64',   'regex': '^ANDROID-[0-9a-f]{16}$'},
    {'name': 'and-R-b36',   'regex': '^ANDROID-R[0-9A-Z]{10}$'},
    {'name': 'and-mac_l',   'regex': '^ANDROID-' + RXMACL + '$'},
    {'name': 'and-mac_u',   'regex': '^ANDROID-' + RXMACU + '$'},
    {'name': 'and-uuid',    'regex': '^ANDROID-' + RXUUID + '$'},

    # a hex string of any length - compressible to bytes
    {'name': 'and-hex_l',   'regex': '^ANDROID-([0-9a-f]{2})+$'},
    {'name': 'and-hex_u',   'regex': '^ANDROID-([0-9A-F]{2})+$'},

    # TAK ICU is a remote video app that generates its own UIDs
    {'name': 'and-icu',     'regex': '^ANDROID-TAK-ICU-' + RXUUID + '$'},

    # attempt bit-packing compression on text (base36, base64)
    {'name': 'and-b36',     'regex': '^ANDROID-[A-Z1-9][A-Z0-9]+$'},
    {'name': 'and-b64',     'regex': '^ANDROID-[a-zA-Z0-9-][a-zA-Z0-9.-]{9,}$'},

    # worst case, strip ANDROID- prefix and pass-through the rest
    {'name': 'and-text',    'regex': '^ANDROID-[a-zA-Z0-9_.+-]+$'},

    {'name': 'wintak',      'regex': '^S-1-5-21(-[0-9]+){4}$'},

    {'name': 'mts-hex32',   'regex': '^MESHTASTIC-[0-9a-f]{8}$'},

    # Decimal number, not zero padded
    {'name': 'dec_unpad',   'regex': '^[1-9][0-9]+$'},

    # Hex string, any length
    {'name': 'hex_l',       'regex': '^([0-9a-f]{2})+$'},
    {'name': 'hex_u',       'regex': '^([0-9A-F]{2})+$'},

    # Uppercase and numeric, suitable for base36, no leading zero!
    {'name': 'base36',      'regex': '^[A-Z1-9][A-Z0-9]+$'},

    # Minimal alphanumeric charset, encodable in 6 bits
    {'name': 'base64',      'regex': '^[a-zA-Z0-9-][a-zA-Z0-9.-]{9,}$'},
]


"""
MODIFIERS - static prefixes and suffixes applied to entity UIDs in certain
scenarios to create derivative UIDs for related, but distinct events, such
as alerts, chat messages etc. They are a separate category to UID patterns,
and are uncorrelated - any modifier can apply to any primary UID irrespective
of the UID pattern.

Maximum 63 records in this category
"""
MODIFIERS = [
    {'name': 'chat-all',    'prefix': 'GeoChat.', 'suffix': '.All'},
    {'name': 'chat-srv',    'prefix': 'GeoChat.SERVER-UID.', 'suffix': ''},
    {'name': 'chat-pre',    'prefix': 'GeoChat.', 'suffix': ''},
    {'name': 'spi1',        'prefix': '', 'suffix': '.SPI1'},
    {'name': 'spi2',        'prefix': '', 'suffix': '.SPI2'},
    {'name': 'dash911',     'prefix': '', 'suffix': '-9-1-1'},
    {'name': 'ping',        'prefix': '', 'suffix': '-ping'},
    {'name': 'sig_chk',     'prefix': 'SigCheck.', 'suffix': ''},
]

count_p = {}    # pattern match counters
count_m = {}    # modifier match counters
count_l = 0     # literal (no match) counter


def base36(number, alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """
    Helper function to convert an integer to base36 (numbers and upper alpha)
    """

    if not isinstance(number, int):
        raise TypeError('number must be an integer')

    base36 = ''

    if 0 <= number < len(alphabet):
        return alphabet[number]

    while number != 0:
        number, i = divmod(number, len(alphabet))
        base36 = alphabet[i] + base36

    return base36


def b64pad(s, c='.'):
    """
    Custom padding of base64 strings at front rather than back, to
      protect the last digit
    This means we can only accept strings that don't start with the new
      padding character (dot), but "it's OK because most of them don't"
    """
    if len(s) % 4:
        s = (4 - (len(s) % 4)) * c + s

    return s


def modmatch(uid):
    """
    Search for the presence of modifiers in a UID
    """

    found = False

    # for modname in MODIFIERS:
    for mod_id in range(len(MODIFIERS)):
        m = MODIFIERS[mod_id]
        if (uid.startswith(m['prefix']) and uid.endswith(m['suffix'])):
            found = True
            break

    if not found:
        return False

    return (mod_id + 1)


def modstrip(uid, mod_id):
    """
    Strip a modifier (indicated by ID returned by modmatch()) from a UID
    """

    m = MODIFIERS[mod_id - 1]
    uid = uid[len(m['prefix']):]

    if len(m['suffix']):
        uid = uid[:-len(m['suffix'])]

    return uid


def modapply(uid, mod_id):
    """
    Apply a modifier (indicated by ID returned by modmatch()) to a UID
    """

    m = MODIFIERS[mod_id - 1]
    return (m['prefix'] + uid + m['suffix'])


def patmatch(uid):
    """
    Attempt to classify a UID based on our list of patterns
    """

    found = False

    for pat in range(len(PATTERNS)):
        p = PATTERNS[pat]['regex']
        if re.search(p, uid):
            found = True
            break

    if not found:
        return False

    return (pat + 1)


def uint_enc(x):
    """
    Encodes an unsigned int into bytes using minimum space
    WARNING: input may actually exceed 64 bits (in case of base36 etc)
    """
    return x.to_bytes(int((x.bit_length() + 7) / 8), 'big')


def uint_dec(x):
    """
    Expands an unsigned int from bytes
    """
    return int.from_bytes(x, 'big')


def uid_codec(uid, patname, encode=True):
    """
    The main encoder/decoder function
    """

    if (patname == 'uuid128'):
        if encode:
            return uuid.UUID(uid).bytes
        else:
            return str(uuid.UUID(bytes=uid))

    elif (patname == 'uuid128d4'):
        if encode:
            (uid0, tail) = uid.split('_')
            # Pack tail before head in case we can drop a leading zero byte
            return pack('>H', int(tail, 10)) + uuid.UUID(uid0).bytes
        else:
            if (len(uid) == 18):
                tail = unpack('>H', uid[:2])
            else:
                # shortened version (leading zero dropped)
                tail = unpack('B', uid[:1])
            return str(uuid.UUID(bytes=uid[-16:])) + ('_%04d' % tail)

    elif (patname == 'and-uuid'):
        if encode:
            return uuid.UUID(uid[8:]).bytes
        else:
            return 'ANDROID-' + str(uuid.UUID(bytes=uid))

    elif (patname == 'and-icu'):
        if encode:
            return uuid.UUID(uid[16:]).bytes
        else:
            return 'ANDROID-TAK-ICU-' + str(uuid.UUID(bytes=uid))

    elif (patname == 'wintak'):
        if encode:
            # reverse the list because the last term appears to be smaller
            # -> potential opportunity to strip some leading zeroes?
            return b''.join([pack('>L', int(x)) for x in reversed(uid[9:].split('-'))]).lstrip(b'\0')
        else:
            # Always 16 bytes, re-add zero padding if stripped previously
            uid = (16 - len(uid)) * b'\0' + uid
            return 'S-1-5-21-' + '-'.join(('%d' % x) for x in reversed(unpack('>LLLL', uid)))

    elif (patname == 'and-hex64'):
        if encode:
            return uint_enc(int(uid[8:], 16))
        else:
            return 'ANDROID-%016x' % uint_dec(uid)

    elif (patname == 'mts-hex32'):
        if encode:
            return uint_enc(int(uid[11:], 16))
        else:
            return 'MESHTASTIC-%08x' % uint_dec(uid)

    elif (patname == 'and-dec15') or (patname == 'and-dec14'):
        if encode:
            return uint_enc(int(uid[8:], 10))
        else:
            if (patname == 'and-dec15'):
                return 'ANDROID-%015d' % uint_dec(uid)
            else:
                return 'ANDROID-%014d' % uint_dec(uid)

    elif (patname == 'and-mac_l') or (patname == 'and-mac_u'):
        if encode:
            return uint_enc(int(uid[8:].replace(':', ''), 16))
        else:
            if (patname == 'and-mac_l'):
                mac = '%012x' % uint_dec(uid)
            else:
                mac = '%012X' % uint_dec(uid)
            return 'ANDROID-' + ':'.join([i + j for i, j in zip(mac[::2], mac[1::2])])

    elif (patname == 'and-R-b36'):
        if encode:
            return uint_enc(int(uid[9:], 36))
        else:
            return 'ANDROID-R' + base36(uint_dec(uid))

    elif (patname == 'base36'):
        if encode:
            return uint_enc(int(uid, 36))
        else:
            return base36(uint_dec(uid))

    elif (patname == 'and-b36'):
        if encode:
            return uint_enc(int(uid[8:], 36))
        else:
            return 'ANDROID-' + base36(uint_dec(uid))

    elif (patname == 'dec_unpad'):
        if encode:
            return uint_enc(int(uid, 10))
        else:
            return '%d' % uint_dec(uid)

    elif (patname == 'hex_l') or (patname == 'hex_u'):
        if encode:
            return unhexlify(uid)
        else:
            if (patname == 'hex_u'):
                return hexlify(uid).decode().upper()
            else:
                return hexlify(uid).decode()

    elif (patname == 'base64'):
        if encode:
            # Custom padding at the front to protect the last digit
            return b64decode(b64pad(uid, '.'), '.-')
        else:
            return b64encode(uid, b'.-').lstrip(b'.').decode()

    elif (patname == 'and-b64'):
        if encode:
            return b64decode(b64pad(uid[8:], '.'), '.-')
        else:
            return 'ANDROID-' + b64encode(uid, b'.-').lstrip(b'.').decode()

    elif (patname == 'and-text'):
        if encode:
            return uid[8:].encode()
        else:
            return 'ANDROID-' + uid.decode()

    # if no compression method was available, just pass through
    if encode:
        return uid.encode()
    else:
        return uid.decode()


def uid_encode(uid):
    """
    All-inclusive function for encoding a UID to compressed bytes
    """
    global count_l

    # First, check for modifiers
    mod_id = modmatch(uid)
    if mod_id:
        modname = MODIFIERS[mod_id-1]['name']
        uid = modstrip(uid, mod_id)
        try:
            count_m[modname] += 1
        except KeyError:
            count_m[modname] = 1

    # Then, check for patterns
    pat_id = patmatch(uid)
    if pat_id:
        patname = PATTERNS[pat_id-1]['name']
        try:
            count_p[patname] += 1
        except KeyError:
            count_p[patname] = 1
    else:
        patname = 'LITERAL'
        count_l += 1

    print('# ' + ('MOD=' + modname + ' ' if(mod_id) else '') +
          'PAT=' + ('%s ' % patname if(pat_id) else 'LITERAL'))

    # Perform pattern-based encoding
    e = uid_codec(uid, patname, True)

    # estimate compressed length - add 1 byte each for pat and mod
    newlen = 2 if mod_id else 1

    if type(e) == int:
        print("!! DEPRECATION ALERT !! INT64 OUTPUT !!")
        e = pack('>Q', e)

    newlen += len(e)

    """
    Encoding of pattern ID and (optional) modifier ID:
    - first byte:
      - bit 0-6: pattern ID 0-127 (0=literal)
      - bit 7(MSB), if set, means next byte (modifier ID) is present
    - second byte (see above):
      - bit 0-4: modifier ID 0-63 (0=reserved)
      - bit 5-7: RESERVED
    """
    if mod_id:
        e_how = pack('BB', pat_id | 0x80, mod_id & 0x3f)
    else:
        e_how = pack('B', pat_id & 0x7f)

    return (e_how + e)


def uid_decode(enc):
    """
    All-inclusive function for decoding a UID from compressed bytes
    """

    # First 1-2 bytes encode compression details (see above)
    (pat_id, mod_id) = unpack('BB', enc[:2])

    if (pat_id & 0x80):  # mod indicator bit
        pat_id &= 0x7f
        enc = enc[2:]
    else:
        mod_id = 0
        enc = enc[1:]

    if pat_id:
        patname = PATTERNS[pat_id - 1]['name']
    else:
        patname = 'LITERAL'

    # decode using provided pattern
    uid = uid_codec(enc, patname, False)

    # if modifier specified, apply it now
    if(mod_id):
        uid = modapply(uid, mod_id)

    return uid


if __name__ == '__main__':
    """
    Read UIDs on STDIN, one per line, and attempt to classify and
    compress them. Finish at End-of-File (or Ctrl-D)

    At the end, output:
    - a CSV list of item counters per pattern, for distribution stats, and
    - grand totals of bytes in/out to estimate the median compression ratio
    """

    # Some counters
    tot_len = 0
    tot_enc = 0

    while True:

        # read line in non-blocking mode
        if sys.stdin in select([sys.stdin], [], [], 0)[0]:

            l = sys.stdin.readline()
            if not l:
                break

            l = l.rstrip()
            print('UID=' + l)

            # Perform encoding using all-inclusive function
            enc = uid_encode(l)
            print('ENC=' + hexlify(enc).decode())

            # Verify conversion by decoding and comparing to original
            v = uid_decode(enc)

            if (v != l):
                print('ERR:' + v)
            else:
                print('SUCCESS %d->%d' % (len(l), len(enc)))

            print('')

            tot_len += len(l)
            tot_enc += len(enc)


    """
    Print pattern match counters
    """

    print ('MODIFIERS')
    for id in range(len(MODIFIERS)):
        modname = MODIFIERS[id]['name']
        if modname in count_m:
            print("%s,%d" % (modname, count_m[modname]))

    print ('PATTERNS')
    for id in range(len(PATTERNS)):
        patname = PATTERNS[id]['name']
        if patname in count_p:
            print("%s,%d" % (patname, count_p[patname]))

    print('LITERAL,%d' % count_l)

    print('TOTAL COMPRESSION: %d->%d' % (tot_len, tot_enc))
