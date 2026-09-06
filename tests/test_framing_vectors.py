from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from mercury_relay_plugin.framing import (  # noqa: E402
    FRAME_HEADER_SIZE,
    MAX_LOGICAL_MESSAGE_BYTES,
    MAX_NOISE_PLAINTEXT_BYTES,
    MAX_PAYLOAD_BYTES,
    DecodeError,
    Reassembler,
    ReassemblyError,
    decode_record,
    encode_message,
)


def _payload(spec: dict) -> bytes:
    if spec["encoding"] == "hex":
        return bytes.fromhex(spec["hex"])
    if spec["encoding"] == "utf8":
        return spec["text"].encode()
    if spec["encoding"] == "repeat":
        return bytes.fromhex(spec["byte_hex"]) * spec["length"]
    raise AssertionError(spec)


def test_canonical_frame_corpus_matches_encoder_and_decoder() -> None:
    corpus = json.loads(
        (REPOSITORY_ROOT / "protocol/vectors/frames/corpus.json").read_text(encoding="utf-8")
    )
    for vector in corpus["vectors"]:
        payload = _payload(vector["payload"])
        records = encode_message(
            bytes.fromhex(vector["channel_id_hex"]),
            bytes.fromhex(vector["message_id_hex"]),
            payload,
        )
        assert len(records) == vector["fragment_count"]
        assert len(payload) == vector["logical_length"]
        assert hashlib.sha256(payload).hexdigest() == vector["payload_sha256"]
        for record, expected in zip(records, vector["records"], strict=True):
            assert len(record) == expected["length"]
            if "record_hex" in expected:
                assert record.hex() == expected["record_hex"]
            else:
                assert hashlib.sha256(record).hexdigest() == expected["sha256"]
            assert decode_record(record).payload == record[FRAME_HEADER_SIZE:]
        reassembler = Reassembler(channel_id=bytes.fromhex(vector["channel_id_hex"]))
        result = None
        for record in records:
            result = reassembler.push(record)
        assert result == payload


def test_exact_16mib_boundary_is_one_contract() -> None:
    """BR-01: schema, corpus, and runtime all agree on 16 MiB / 257 fragments."""

    from mercury_relay_plugin.framing import MAX_FRAGMENT_COUNT

    assert MAX_LOGICAL_MESSAGE_BYTES == 16 * 1024 * 1024
    assert MAX_FRAGMENT_COUNT == 257

    schema = json.loads(
        (REPOSITORY_ROOT / "protocol/schemas/framing-envelope-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["logical_message_max_bytes"] == MAX_LOGICAL_MESSAGE_BYTES
    assert schema["max_fragment_count"] == MAX_FRAGMENT_COUNT

    corpus = json.loads(
        (REPOSITORY_ROOT / "protocol/vectors/frames/corpus.json").read_text(encoding="utf-8")
    )
    assert corpus["protocol"]["max_logical_message_bytes"] == MAX_LOGICAL_MESSAGE_BYTES
    assert corpus["protocol"]["max_fragment_count"] == MAX_FRAGMENT_COUNT
    assert any(
        vector["logical_length"] == MAX_LOGICAL_MESSAGE_BYTES
        and vector["fragment_count"] == MAX_FRAGMENT_COUNT
        for vector in corpus["vectors"]
    )

    # Exact 16 MiB round trip: 257 records, byte-identical reassembly.
    channel = bytes.fromhex("aa" * 16)
    message = bytes.fromhex("bb" * 16)
    payload = b"\x5a" * MAX_LOGICAL_MESSAGE_BYTES
    records = encode_message(channel, message, payload)
    assert len(records) == MAX_FRAGMENT_COUNT
    assert all(len(record) == MAX_NOISE_PLAINTEXT_BYTES for record in records[:-1])
    reassembler = Reassembler(channel_id=channel)
    result = None
    for record in records:
        result = reassembler.push(record)
    assert result == payload

    # One byte over the limit fails on encode.
    with pytest.raises(ValueError, match="logical"):
        encode_message(channel, message, b"\x5a" * (MAX_LOGICAL_MESSAGE_BYTES + 1))


def test_frames_manifest_authenticates_the_corpus() -> None:
    corpus_path = REPOSITORY_ROOT / "protocol/vectors/frames/corpus.json"
    manifest = json.loads(
        (REPOSITORY_ROOT / "protocol/vectors/frames/manifest.json").read_text(encoding="utf-8")
    )
    data = corpus_path.read_bytes()
    recorded = manifest["artifacts"]["corpus.json"]
    assert recorded["bytes"] == len(data)
    assert recorded["sha256"] == hashlib.sha256(data).hexdigest()


def test_framing_boundaries_and_replay_fail_closed() -> None:
    channel = bytes.fromhex("00" * 16)
    message = bytes.fromhex("11" * 16)
    records = encode_message(channel, message, b"x" * (MAX_PAYLOAD_BYTES + 1))
    assert [len(record) for record in records] == [MAX_NOISE_PLAINTEXT_BYTES, 51]

    reassembler = Reassembler(channel_id=channel)
    assert reassembler.push(records[0]) is None
    with pytest.raises(ReassemblyError, match="order"):
        reassembler.push(records[0])
    assert not reassembler.in_progress

    malformed = bytearray(records[0])
    malformed[2] ^= 1
    with pytest.raises(DecodeError, match="version"):
        decode_record(malformed)

    with pytest.raises(ValueError, match="logical"):
        encode_message(channel, message, b"x" * (MAX_LOGICAL_MESSAGE_BYTES + 1))
