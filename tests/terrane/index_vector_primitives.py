"""Assembles and examines deterministic CBOR primitives for index witnesses.

The byte tables deliberately bypass Terrane format encoders. Encoded map keys
sort lexicographically as TREE-25 requires. Registered identity preimages are
hashed only by the source-built raw BLAKE3 executable supplied by the caller.
"""

import re
import subprocess


def head(major, argument):
    """Builds the minimal definite CBOR head for an unsigned argument."""
    if type(argument) is not int or not 0 <= argument < 2**64:
        raise ValueError("unsigned CBOR argument outside uint64")
    if argument < 24:
        return bytes([(major << 5) | argument])
    for width, additional in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if argument < 2 ** (8 * width):
            return bytes([(major << 5) | additional]) + argument.to_bytes(width, "big")
    raise AssertionError("uint64 head width")


def cbor(value):
    """Assembles primitives without imposing an Entry, Node or carrier schema."""
    if value is None:
        return b"\xf6"
    if type(value) is bool:
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        # TREE-25 orders encoded key bytes, without a preceding length rank.
        fields = sorted(
            ((cbor(key), cbor(item)) for key, item in value.items()),
            key=lambda pair: pair[0],
        )
        return head(5, len(fields)) + b"".join(key + item for key, item in fields)
    raise TypeError(f"unsupported primitive: {type(value).__name__}")


def diagnostic(value):
    """Retains bytes, integers and text distinctly in the JSON field model."""
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, list):
        return [diagnostic(item) for item in value]
    if isinstance(value, dict):
        fields = sorted(value.items(), key=lambda pair: cbor(pair[0]))
        return {"map": [[diagnostic(key), diagnostic(item)] for key, item in fields]}
    return value


def raw_digest(binary, domain, data):
    """Hashes only the exact registered-domain preimage assembled here."""
    preimage = domain.encode("ascii") + b"\0" + data
    result = subprocess.run(
        [str(binary)], input=preimage, stdout=subprocess.PIPE, check=True,
    ).stdout.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", result):
        raise ValueError("raw helper did not return one lowercase 32-byte digest")
    return bytes.fromhex(result)


def leaf(entries, properties=None):
    """Prefix-compresses a manually supplied, sorted complete field table."""
    previous = b""
    items = []
    for key, entry in sorted(entries):
        shared = 0
        while shared < min(len(previous), len(key)) and previous[shared] == key[shared]:
            shared += 1
        items.append([key[shared:], shared, entry])
        previous = key
    result = {1: 0, 2: items}
    if properties is not None:
        result[3] = properties
    # Every leaf in this bounded corpus ends below the minimum node cut size.
    assert sum(len(cbor(item)) for item in items) < 4096
    return result


def expanded(model):
    """Reconstructs full keys independently from the retained leaf item table."""
    if set(model) - {1, 2, 3} or model.get(1) != 0 or not isinstance(model.get(2), list):
        raise ValueError("not a closed leaf node")
    result = []
    previous = b""
    for position, item in enumerate(model[2]):
        if not isinstance(item, list) or len(item) != 3:
            raise ValueError("leaf item shape")
        suffix, shared, entry = item
        if not isinstance(suffix, bytes) or type(shared) is not int:
            raise ValueError("leaf key types")
        if shared < 0 or shared > len(previous) or (position == 0 and shared != 0):
            raise ValueError("leaf prefix bounds")
        key = previous[:shared] + suffix
        if not key or len(key) > 4096 or (position and key <= previous):
            raise ValueError("leaf key length/order")
        common = 0
        while common < min(len(previous), len(key)) and previous[common] == key[common]:
            common += 1
        if shared != common:
            raise ValueError("nonmaximal leaf prefix")
        result.append((key, entry))
        previous = key
    return result


def key_canonical(value):
    """Checks canonical primitive structure iteratively, with input-sized bounds."""
    cursor = 0
    stack = [{'remaining': 1, 'map': False}]
    while stack:
        frame = stack[-1]
        if frame['remaining'] == 0:
            stack.pop()
            if frame.get('key_start') is not None:
                key = value[frame['key_start']:cursor]
                parent = stack[-1]
                if parent.get('last_key') is not None and key <= parent['last_key']:
                    raise ValueError('map encoded-key order or duplicate')
                parent['last_key'] = key
            continue
        start = cursor
        if cursor >= len(value):
            raise ValueError('truncated primitive')
        initial = value[cursor]
        cursor += 1
        major, extra = initial >> 5, initial & 31
        if major == 7:
            if extra not in (20, 21, 22):
                raise ValueError('excluded simple/float')
            argument = None
        else:
            if extra < 24:
                argument = extra
            elif extra in (24, 25, 26, 27):
                width = {24: 1, 25: 2, 26: 4, 27: 8}[extra]
                if cursor + width > len(value):
                    raise ValueError('truncated head')
                argument = int.from_bytes(value[cursor:cursor + width], 'big')
                cursor += width
                if argument < {24: 24, 25: 256, 26: 65536, 27: 4294967296}[extra]:
                    raise ValueError('nonminimal head')
            else:
                raise ValueError('indefinite/reserved head')
        is_key = frame['map'] and frame['remaining'] % 2 == 0
        frame['remaining'] -= 1
        if major in (0, 1, 7):
            pass
        elif major in (2, 3):
            if argument > len(value) - cursor:
                raise ValueError('size before allocation')
            if major == 3:
                value[cursor:cursor + argument].decode('utf8')
            cursor += argument
        elif major in (4, 5):
            count = argument * (2 if major == 5 else 1)
            if count > len(value) - cursor:
                raise ValueError('count before allocation')
            stack.append({'remaining': count, 'map': major == 5,
                          'key_start': start if is_key else None})
            continue
        else:
            raise ValueError('excluded tag')
        if is_key:
            key = value[start:cursor]
            if frame.get('last_key') is not None and key <= frame['last_key']:
                raise ValueError('map encoded-key order or duplicate')
            frame['last_key'] = key
    if cursor != len(value):
        raise ValueError('trailing primitive')
