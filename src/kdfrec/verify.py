"""Password record handling.

A record is stored as semicolon separated fields.  Salt and digest fields use
standard base64.  The canonical shape is:

    alg=pbkdf2_sha256;iter=210000;salt=<base64>;digest=<base64>

Every parameter needed to derive the digest is stored next to the digest
itself.  Verification therefore uses the parameters carried by the record,
never module level defaults; defaults only describe parameters for *new*
records.  This keeps old records verifiable after the global defaults or the
active policy have been strengthened.

The functions in this module are deliberately small so they can be used by a
migration script, an authentication path, and an offline audit job.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

DEFAULT_ALG = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 120_000
DEFAULT_SALT = b"kdfrec-default-salt-v1"
DEFAULT_MIN_ITERATIONS = 210_000
DEFAULT_MIN_SALT_LEN = 16
DIGEST_LEN = 32

_HASHES = {
    "pbkdf2_sha256": "sha256",
    "pbkdf2_sha512": "sha512",
}


def _b64decode(value: str | None) -> bytes | None:
    if not value:
        return None
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, binascii.Error):
        return None


def parse_record(text: str) -> dict:
    """Parse a serialized record into a dictionary.

    Missing or malformed optional fields are represented by None.  The
    algorithm field is treated as a name that identifies the derivation
    function and its hash.  A missing algorithm is preserved as None so that
    callers can reject the record; it is never silently replaced by a
    default.
    """
    fields: dict[str, str] = {}
    for chunk in (text or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        fields[key.strip().lower()] = value.strip()

    alg = fields.get("alg") or None

    iterations = None
    raw_iterations = fields.get("iter")
    if raw_iterations:
        try:
            iterations = int(raw_iterations)
        except ValueError:
            iterations = None

    salt = _b64decode(fields.get("salt"))
    digest = _b64decode(fields.get("digest"))

    return {
        "alg": alg,
        "iterations": iterations,
        "salt": salt,
        "digest": digest,
    }


def _valid_iterations(value) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 1
    )


def _salt_bytes(salt) -> bytes | None:
    if not isinstance(salt, (bytes, bytearray)) or not salt:
        return None
    return bytes(salt)


def _salt_is_unique(salt: bytes) -> bool:
    """A real salt must not be a single repeated byte."""
    return len(set(salt)) > 1


def check_params(record: dict, policy: dict) -> list[str]:
    """Return policy violations for the parameters in a record.

    The record's own parameters are judged against the active policy.  A
    record below the policy floor is rejected; ``needs_rehash`` reports that
    it has to be upgraded before it can be used again.
    """
    issues: list[str] = []

    alg = record.get("alg")
    allowed = policy.get("allowed_algs") or set(_HASHES)
    if not alg:
        issues.append("algorithm missing")
    elif alg not in allowed:
        issues.append("algorithm not allowed")

    minimum = policy.get("min_iterations")
    if minimum is None:
        minimum = DEFAULT_MIN_ITERATIONS
    iterations = record.get("iterations")
    if iterations is None:
        issues.append("iterations missing")
    elif not _valid_iterations(iterations):
        issues.append("iterations invalid")
    elif iterations < int(minimum):
        issues.append("iterations below minimum")

    min_salt_len = policy.get("min_salt_len")
    if min_salt_len is None:
        min_salt_len = DEFAULT_MIN_SALT_LEN
    min_salt_len = int(min_salt_len)
    salt = _salt_bytes(record.get("salt"))
    if salt is None:
        issues.append("salt missing")
    elif not _salt_is_unique(salt):
        issues.append("salt repeated")
    elif len(salt) < min_salt_len:
        issues.append("salt too short")

    return issues


def derive(password, record: dict) -> bytes:
    """Derive a digest using the algorithm, salt, and iteration count.

    All three values are read from the record so that a record always
    reproduces its own digest regardless of the current global defaults.
    """
    alg = record.get("alg")
    if not alg:
        raise ValueError("algorithm is required")
    hash_name = _HASHES.get(alg)
    if hash_name is None:
        raise ValueError("unsupported algorithm")

    iterations = record.get("iterations")
    if not _valid_iterations(iterations):
        raise ValueError("iterations must be a positive integer")

    salt = _salt_bytes(record.get("salt"))
    if salt is None:
        raise ValueError("salt is required")

    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = bytes(password)

    return hashlib.pbkdf2_hmac(
        hash_name,
        password_bytes,
        salt,
        iterations,
        dklen=DIGEST_LEN,
    )


def verify(password, record: dict, policy: dict) -> bool:
    """Check a password against a record and the active parameter policy."""
    issues = check_params(record, policy)
    if issues:
        return False

    expected = record.get("digest")
    if not isinstance(expected, (bytes, bytearray)) or not expected:
        return False

    try:
        derived = derive(password, record)
    except (TypeError, ValueError):
        return False

    # Constant-time comparison: the amount of work must not reveal how much
    # of the digest matched.
    return hmac.compare_digest(bytes(expected), derived)


def needs_rehash(record: dict, policy: dict) -> bool:
    """Report whether a record should be re-derived with stronger parameters.

    Any record that no longer satisfies the active policy is flagged, with
    an iteration count below the policy floor being the classic case.
    """
    return bool(check_params(record, policy)) or bool(validate_record(record))


def format_record(alg: str, iterations: int, salt: bytes, digest: bytes) -> str:
    """Serialize a record for storage.

    The derivation parameters travel with the digest.  Omitting them is what
    makes a record impossible to verify after the defaults change.
    """
    salt_b64 = base64.b64encode(bytes(salt)).decode("ascii")
    digest_b64 = base64.b64encode(bytes(digest)).decode("ascii")

    parts = [
        f"alg={alg}",
        f"iter={int(iterations)}",
        f"salt={salt_b64}",
        f"digest={digest_b64}",
    ]
    return ";".join(parts)


def validate_record(record: dict) -> list[str]:
    """Return structural problems found in a parsed record."""
    issues: list[str] = []

    alg = record.get("alg")
    if not alg:
        issues.append("algorithm missing")

    iterations = record.get("iterations")
    if iterations is None:
        issues.append("iterations missing")
    elif not _valid_iterations(iterations):
        issues.append("iterations invalid")

    salt = _salt_bytes(record.get("salt"))
    if salt is None:
        issues.append("salt missing")
    elif not _salt_is_unique(salt):
        issues.append("salt repeated")
    elif len(salt) < DEFAULT_MIN_SALT_LEN:
        issues.append("salt too short")

    digest = record.get("digest")
    if not isinstance(digest, (bytes, bytearray)) or not digest:
        issues.append("digest missing")

    return issues


def kdf_batch(attempts, policy: dict) -> dict:
    """Verify a sequence of password and record pairs.

    Each attempt is a tuple of the form (password, record).  The result
    contains a per-attempt boolean list plus accepted and rejected counts.
    Records are handled independently: no state is carried from one attempt
    to the next.
    """
    results: list[bool] = []

    for password, record in attempts:
        results.append(verify(password, record, policy))

    accepted = sum(1 for result in results if result)
    return {
        "results": results,
        "accepted": accepted,
        "rejected": len(results) - accepted,
    }
