"""CBOR codec tests — RFC 8949 subset used by the txAuthAgent wire format."""

import pytest

from txauthagent import cbor


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        1,
        23,
        24,
        255,
        256,
        65535,
        65536,
        2**32,
        2**53,
        -1,
        -24,
        -25,
        -256,
        -1000,
        b"",
        b"\x00\x01\x02",
        "hello",
        "héllo wörld 🚀",
        [1, 2, 3],
        ["a", b"b", True, None],
        {"up": True, "uv": False, "sig": b"\x01"},
        {"nested": {"a": [1, {"b": 2}]}},
    ],
)
def test_roundtrip(value):
    assert cbor.loads(cbor.dumps(value)) == value


def test_deterministic_bytes():
    a = cbor.dumps({"up": True, "alg": -8})
    b = cbor.dumps({"up": True, "alg": -8})
    assert a == b


def test_deterministic_mode_sorts_map_keys():
    assert cbor.dumps({"b": 1, "a": 2}, deterministic=True) == b"\xa2\x61a\x02\x61b\x01"


def test_deterministic_mode_sorts_nested_maps():
    blob = cbor.dumps({"z": {"y": 1, "x": 2}, "a": 3}, deterministic=True)
    assert cbor.loads(blob) == {"z": {"y": 1, "x": 2}, "a": 3}
    # keys sorted: "a" then "z", and inside z: "x" then "y"
    assert blob == b"\xa2\x61a\x03\x61z\xa2\x61x\x02\x61y\x01"


def test_deterministic_mode_ignores_insertion_order():
    a = cbor.dumps({"b": 1, "a": 2}, deterministic=True)
    b = cbor.dumps({"a": 2, "b": 1}, deterministic=True)
    assert a == b


def test_deterministic_mode_sorts_by_full_encoding():
    # RFC 8949 §4.2.1: bytewise lexicographic order of the full deterministic
    # encodings — the length header byte participates, so "b" (0x6162) sorts
    # before "ab" (0x6261 0x61).
    blob = cbor.dumps({"ab": 1, "b": 2}, deterministic=True)
    assert blob == b"\xa2\x61b\x02\x62ab\x01"


def test_default_mode_preserves_insertion_order():
    assert cbor.dumps({"b": 1, "a": 2}) == b"\xa2\x61b\x01\x61a\x02"


def test_known_vector_unsigned():
    assert cbor.dumps(0) == b"\x00"
    assert cbor.dumps(1) == b"\x01"
    assert cbor.dumps(23) == b"\x17"
    assert cbor.dumps(24) == b"\x18\x18"
    assert cbor.dumps(255) == b"\x18\xff"


def test_known_vector_negative():
    assert cbor.dumps(-1) == b"\x20"
    assert cbor.dumps(-24) == b"\x37"
    assert cbor.dumps(-25) == b"\x38\x18"


def test_known_vector_text():
    assert cbor.dumps("IETF") == b"\x64IETF"
    assert cbor.dumps("") == b"\x60"


def test_known_vector_bytes():
    assert cbor.dumps(b"\x01\x02\x03\x04") == b"\x44\x01\x02\x03\x04"


def test_known_vector_array():
    assert cbor.dumps([1, 2, 3]) == b"\x83\x01\x02\x03"


def test_known_vector_map():
    assert cbor.dumps({"a": 1}) == b"\xa1\x61a\x01"


def test_loads_rejects_truncated():
    with pytest.raises(cbor.CBORError):
        cbor.loads(b"\x83\x01\x02")  # array says 3 items, only 2 present


def test_loads_rejects_trailing():
    with pytest.raises(cbor.CBORError):
        cbor.loads(b"\x01\x02")


def test_loads_rejects_empty():
    with pytest.raises(cbor.CBORError):
        cbor.loads(b"")


def test_unsupported_type_rejected():
    with pytest.raises(cbor.CBORError):
        cbor.dumps(object())


def test_float_rejected_by_design():
    # Spec subset is integer/bytes/text/array/map — floats intentionally unsupported
    with pytest.raises(cbor.CBORError):
        cbor.dumps(3.14)
