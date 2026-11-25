"""Public behavior checks for the password record helpers."""

import hashlib

from kdfrec.verify import (
    DEFAULT_SALT,
    format_record,
    kdf_batch,
    needs_rehash,
    parse_record,
    verify,
)

POLICY = {
    "min_iterations": 210_000,
    "min_salt_len": 16,
    "allowed_algs": {"pbkdf2_sha256"},
}

BATCH_POLICY = {
    "min_iterations": 100_000,
    "min_salt_len": 16,
    "allowed_algs": {"pbkdf2_sha256"},
}


def _digest(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


def _record(password: str, salt: bytes, iterations: int) -> dict:
    return {
        "alg": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": salt,
        "digest": _digest(password, salt, iterations),
    }


def test_record_parse_roundtrip():
    salt = b"public-salt-000001"
    digest = b"d" * 32
    text = format_record("pbkdf2_sha256", 210_000, salt, digest)
    record = parse_record(text)

    assert record["alg"] == "pbkdf2_sha256"
    assert record["iterations"] == 210_000
    assert record["salt"] == salt
    assert record["digest"] == digest


def test_verify_uses_record_parameters():
    password = "correct horse battery staple"
    salt = b"public-record-salt-02"
    record = _record(password, salt, 260_000)

    assert verify(password, record, POLICY) is True


def test_wrong_password_rejected():
    password = "right-password"
    salt = b"public-wrong-salt-03"
    record = _record(password, salt, 210_000)

    assert verify(password, record, POLICY) is True
    assert verify("wrong-password", record, POLICY) is False


def test_low_iterations_flagged_for_upgrade():
    password = "legacy-password"
    salt = b"public-upgrade-salt-04"
    record = _record(password, salt, 1_000)

    assert needs_rehash(record, POLICY) is True


def test_batch_keeps_records_independent():
    password = "batch-password"
    first = _record(password, DEFAULT_SALT, 120_000)
    second = _record(password, b"public-batch-salt-02", 120_000)
    second["digest"] = b"z" * 32

    batch = kdf_batch([(password, first), (password, second)], BATCH_POLICY)

    assert batch["results"] == [True, False]
    assert batch["accepted"] == 1
    assert batch["rejected"] == 1