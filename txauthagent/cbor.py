"""Minimal CBOR codec (RFC 8949 subset) used by the txAuthAgent wire format.

Self-contained, dependency-free. Supports the types needed by the WebAuthn
extension outputs: unsigned/negative integers, byte strings, text strings,
arrays, maps, booleans, and null.

Example:
    >>> from txauthagent import cbor
    >>> blob = cbor.dumps({"up": True, "sig": b"\\x01\\x02"})
    >>> cbor.loads(blob)
    {'up': True, 'sig': b'\\x01\\x02'}
"""

from __future__ import annotations

import struct

__all__ = ["dumps", "loads", "CBORError"]

CBORError = ValueError


class _Encoder:
    def __init__(self) -> None:
        self.out = bytearray()

    def _head(self, major: int, value: int) -> None:
        if value < 24:
            self.out.append((major << 5) | value)
        elif value < 0x100:
            self.out.append((major << 5) | 24)
            self.out.append(value)
        elif value < 0x10000:
            self.out.append((major << 5) | 25)
            self.out += struct.pack(">H", value)
        elif value < 0x100000000:
            self.out.append((major << 5) | 26)
            self.out += struct.pack(">I", value)
        elif value < 0x10000000000000000:
            self.out.append((major << 5) | 27)
            self.out += struct.pack(">Q", value)
        else:
            raise CBORError("integer too large for CBOR")

    def encode(self, obj) -> None:
        if obj is None:
            self.out.append(0xF6)
        elif obj is False:
            self.out.append(0xF4)
        elif obj is True:
            self.out.append(0xF5)
        elif isinstance(obj, int):
            if obj >= 0:
                self._head(0, obj)
            else:
                self._head(1, -1 - obj)
        elif isinstance(obj, bytes):
            self._head(2, len(obj))
            self.out += obj
        elif isinstance(obj, str):
            raw = obj.encode("utf-8")
            self._head(3, len(raw))
            self.out += raw
        elif isinstance(obj, (list, tuple)):
            self._head(4, len(obj))
            for item in obj:
                self.encode(item)
        elif isinstance(obj, dict):
            self._head(5, len(obj))
            for k, v in obj.items():
                if not isinstance(k, (str, int, bytes)):
                    raise CBORError(f"unsupported map key type: {type(k)!r}")
                self.encode(k)
                self.encode(v)
        else:
            raise CBORError(f"unsupported type: {type(obj)!r}")

    def dumps(self, obj) -> bytes:
        self.encode(obj)
        return bytes(self.out)


def dumps(obj) -> bytes:
    return _Encoder().dumps(obj)


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CBORError("truncated CBOR data")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def _arg(self, major: int, extra: int) -> int:
        if extra < 24:
            return extra
        if extra == 24:
            return self._take(1)[0]
        if extra == 25:
            return struct.unpack(">H", self._take(2))[0]
        if extra == 26:
            return struct.unpack(">I", self._take(4))[0]
        if extra == 27:
            return struct.unpack(">Q", self._take(8))[0]
        raise CBORError(f"invalid additional info: {extra}")

    def decode(self):
        if self.pos >= len(self.data):
            raise CBORError("empty CBOR data")
        initial = self._take(1)[0]
        major = initial >> 5
        extra = initial & 0x1F
        if major == 0:
            return self._arg(major, extra)
        if major == 1:
            return -1 - self._arg(major, extra)
        if major == 2:
            n = self._arg(major, extra)
            return self._take(n)
        if major == 3:
            n = self._arg(major, extra)
            return self._take(n).decode("utf-8")
        if major == 4:
            n = self._arg(major, extra)
            return [self.decode() for _ in range(n)]
        if major == 5:
            n = self._arg(major, extra)
            out = {}
            for _ in range(n):
                k = self.decode()
                if not isinstance(k, (str, int, bytes)):
                    raise CBORError(f"unsupported map key type: {type(k)!r}")
                out[k] = self.decode()
            return out
        if major == 7:
            if extra == 20:
                return False
            if extra == 21:
                return True
            if extra == 22:
                return None
            if extra == 23:
                return None  # undefined — map to None
            raise CBORError(f"unsupported simple value: {extra}")
        raise CBORError(f"unsupported major type: {major}")


def loads(data: bytes):
    if not isinstance(data, (bytes, bytearray)):
        raise CBORError("CBOR input must be bytes")
    dec = _Decoder(bytes(data))
    value = dec.decode()
    if dec.pos != len(dec.data):
        raise CBORError("trailing bytes after CBOR value")
    return value
