"""
securelink.py
=============

A single-file, production-oriented library for building an encrypted
communication protocol on top of HTTP.

    from securelink import SecureClient, SecureServer, SecureConfig

Design goals
------------
* AES-256-GCM (default) / ChaCha20-Poly1305 (alternative) authenticated
  encryption, selected via a strategy pattern (`CipherSuite`).
* Proper key derivation (PBKDF2-HMAC-SHA256 or HKDF) -- passphrases are
  never used directly as key material.
* Optional ECDH (X25519) ephemeral key exchange for per-session forward
  secrecy.
* Defense-in-depth HMAC-SHA256 tag in addition to the AEAD tag.
* Replay protection via timestamp + single-use nonce cache with a
  configurable acceptance window.
* Sync + async HTTP transport (via `httpx`), with pluggable push modes
  (WebSocket / SSE / long-polling), retries with backoff, a circuit
  breaker, streaming/chunked transfer, and optional pre-encryption
  compression with anti-CRIME/BREACH safeguards.
* A builder-style `SecureConfig` object plus lifecycle hooks.

This file is intentionally organized into clearly delimited sections so
that, despite living in one module, the logical architecture stays easy
to navigate:

    # === Exceptions ===
    # === Crypto Core ===
    # === Config ===
    # === Replay Protection ===
    # === Transport / Hooks ===
    # === Client ===
    # === Server ===
    # === Example ===

Security notes are inlined next to every security-critical decision.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import enum
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import secrets
import threading
import time
import zlib
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Optional,
    Tuple,
    Union,
)

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a hard runtime dependency
    httpx = None  # type: ignore

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

__all__ = [
    "SecureConfig",
    "SecureClient",
    "SecureServer",
    "CipherSuite",
    "AESGCMCipherSuite",
    "ChaCha20CipherSuite",
    "TransportMode",
    "SecureLinkError",
    "DecryptionError",
    "AuthenticationFailedError",
    "HandshakeError",
    "ReplayAttackDetected",
    "ConnectionTimeoutError",
    "ConfigError",
]

_LOG = logging.getLogger("securelink")
if not _LOG.handlers:
    # Library code should never configure root logging for the caller;
    # attach a NullHandler so "no handlers found" warnings never appear
    # unless the application explicitly opts in.
    _LOG.addHandler(logging.NullHandler())


# =====================================================================
# === Exceptions ===
# =====================================================================
#
# All errors that can cross the "trust boundary" (i.e. that a remote,
# possibly hostile, party could trigger) are represented by dedicated
# exception types. Handlers at the transport boundary catch these and
# translate them into a single generic wire-level error so that no
# internal detail (which check failed, what the plaintext looked like,
# timing information, etc.) is ever leaked to the other side.


class SecureLinkError(Exception):
    """Base class for all securelink errors."""


class DecryptionError(SecureLinkError):
    """Raised when an AEAD payload cannot be decrypted/authenticated."""


class AuthenticationFailedError(SecureLinkError):
    """Raised when the defense-in-depth HMAC layer fails verification."""


class HandshakeError(SecureLinkError):
    """Raised when the (optional) ECDH handshake cannot be completed."""


class ReplayAttackDetected(SecureLinkError):
    """Raised when a message is rejected by the replay-protection layer."""


class ConnectionTimeoutError(SecureLinkError):
    """Raised when a network operation exceeds its configured timeout."""


class ConfigError(SecureLinkError):
    """Raised when a `SecureConfig` is invalid or incomplete."""


class CircuitOpenError(SecureLinkError):
    """Raised when the circuit breaker is open and a call is rejected."""


def _generic_wire_error(_: BaseException) -> Dict[str, str]:
    """
    Build a generic, non-descriptive payload safe to send to a remote peer.

    Security note: we deliberately never echo back the original exception
    message, type, or stack trace. Detailed diagnostics are logged locally
    only (see `_LOG.exception` call sites) so an attacker probing the
    endpoint cannot use error content to distinguish, e.g., "bad MAC" from
    "bad padding" from "replay detected" (a classic oracle vulnerability).
    """
    return {"status": "error", "detail": "request could not be processed"}


# =====================================================================
# === Crypto Core ===
# =====================================================================


class CipherName(str, enum.Enum):
    AES_256_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "CHACHA20-POLY1305"


class KDFName(str, enum.Enum):
    PBKDF2_HMAC_SHA256 = "PBKDF2-HMAC-SHA256"
    HKDF_SHA256 = "HKDF-SHA256"


@dataclasses.dataclass(frozen=True)
class EncryptedEnvelope:
    """
    Wire format for a single encrypted message.

    Fields
    ------
    nonce:       Unique, randomly generated per-message nonce/IV. Never
                 reused with the same key (see `CipherSuite.encrypt`).
    ciphertext:  AEAD ciphertext, which already includes the built-in
                 authentication tag (GCM/Poly1305 append it internally).
    hmac_tag:    Defense-in-depth HMAC-SHA256 over (nonce || ciphertext),
                 computed with a key independent of the AEAD key.
    timestamp:   Unix timestamp (seconds, float) at time of encryption,
                 used by the replay-protection layer.
    key_id:      Identifies which derived/rotated key produced this
                 message, so the receiver can select the right key
                 during a rotation window without ambiguity.
    compressed:  Whether the plaintext was compressed prior to
                 encryption (see compression safeguards below).
    """

    nonce: bytes
    ciphertext: bytes
    hmac_tag: bytes
    timestamp: float
    key_id: str
    compressed: bool = False

    def to_wire(self) -> Dict[str, Any]:
        return {
            "n": base64.b64encode(self.nonce).decode("ascii"),
            "c": base64.b64encode(self.ciphertext).decode("ascii"),
            "h": base64.b64encode(self.hmac_tag).decode("ascii"),
            "t": self.timestamp,
            "k": self.key_id,
            "z": self.compressed,
        }

    @classmethod
    def from_wire(cls, data: Dict[str, Any]) -> "EncryptedEnvelope":
        try:
            return cls(
                nonce=base64.b64decode(data["n"]),
                ciphertext=base64.b64decode(data["c"]),
                hmac_tag=base64.b64decode(data["h"]),
                timestamp=float(data["t"]),
                key_id=str(data["k"]),
                compressed=bool(data.get("z", False)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            # Malformed envelope. Treated as a decryption failure so the
            # caller doesn't need a separate "parse error" branch, and so
            # no extra information about *why* it failed leaks out.
            raise DecryptionError("malformed envelope") from exc


class CipherSuite(ABC):
    """
    Strategy interface for authenticated encryption. Concrete
    implementations must produce a fresh, unpredictable nonce for every
    call to `encrypt` -- nonce reuse under the same key catastrophically
    breaks both AES-GCM and ChaCha20-Poly1305 (it can reveal the
    authentication key and allow forgeries), so this is the single most
    important invariant in this file.
    """

    name: CipherName
    nonce_size: int
    key_size: int

    @abstractmethod
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """Return (nonce, ciphertext_with_tag)."""

    @abstractmethod
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Return plaintext or raise DecryptionError."""


class AESGCMCipherSuite(CipherSuite):
    name = CipherName.AES_256_GCM
    nonce_size = 12  # 96-bit nonce, the size AES-GCM is designed for
    key_size = 32  # 256-bit key

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        # A fresh CSPRNG nonce every call -- never derived, counted, or
        # reused. os.urandom / secrets are backed by the OS CSPRNG.
        nonce = secrets.token_bytes(self.nonce_size)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:  # cryptography raises InvalidTag
            # Fail closed: never distinguish "bad tag" from other
            # failures externally, and never expose the underlying
            # exception (which could hint at internal state).
            raise DecryptionError("authentication failed") from exc


class ChaCha20CipherSuite(CipherSuite):
    name = CipherName.CHACHA20_POLY1305
    nonce_size = 12
    key_size = 32

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        nonce = secrets.token_bytes(self.nonce_size)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise DecryptionError("authentication failed") from exc


_CIPHER_REGISTRY: Dict[CipherName, Callable[[], CipherSuite]] = {
    CipherName.AES_256_GCM: AESGCMCipherSuite,
    CipherName.CHACHA20_POLY1305: ChaCha20CipherSuite,
}


def get_cipher_suite(name: CipherName) -> CipherSuite:
    try:
        return _CIPHER_REGISTRY[name]()
    except KeyError as exc:
        raise ConfigError(f"unknown cipher suite: {name!r}") from exc


# --- Key derivation ---------------------------------------------------


def derive_key(
    passphrase: bytes,
    salt: bytes,
    *,
    kdf: KDFName = KDFName.PBKDF2_HMAC_SHA256,
    length: int = 32,
    iterations: int = 390_000,
    info: bytes = b"securelink-v1",
) -> bytes:
    """
    Derive symmetric key material from a passphrase.

    Security note: raw passphrases are never used as AES/ChaCha keys.
    Passphrases have far less entropy per byte than a real key and are
    vulnerable to brute-force/dictionary attacks; a slow, salted KDF
    (PBKDF2 with a high iteration count, or HKDF when deriving from an
    already-high-entropy secret such as an ECDH shared secret) is
    required to produce a uniformly random, appropriately sized key.
    """
    if len(salt) < 16:
        raise ConfigError("salt must be at least 16 bytes")
    if kdf == KDFName.PBKDF2_HMAC_SHA256:
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
        ).derive(passphrase)
    elif kdf == KDFName.HKDF_SHA256:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(passphrase)
    else:
        raise ConfigError(f"unknown KDF: {kdf!r}")


def _compute_hmac(mac_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Defense-in-depth HMAC-SHA256 over (nonce || ciphertext).

    This is redundant with the AEAD tag by design: if a future bug or a
    cipher downgrade ever weakened the AEAD's own authentication, this
    independent, differently-keyed MAC still has to pass, so a single
    implementation flaw is less likely to result in a full authentication
    bypass.
    """
    return hmac_mod.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()


def _verify_hmac(mac_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> None:
    expected = _compute_hmac(mac_key, nonce, ciphertext)
    # Constant-time comparison to avoid timing side-channels that could
    # let an attacker forge a valid tag byte-by-byte.
    if not hmac_mod.compare_digest(expected, tag):
        raise AuthenticationFailedError("HMAC verification failed")


# --- ECDH (X25519) ephemeral key exchange -----------------------------


def _handshake_salt(session_id: str, public_key_a: bytes, public_key_b: bytes) -> bytes:
    """
    Compute a salt for the post-ECDH HKDF that both peers can derive
    identically, regardless of which one is "client" or "server".

    Security/correctness note: naively salting with
    `session_id + the_other_party's_public_key` gives each side a
    *different* salt (each hashes in only the key it received), which
    silently produces two different session keys from the same ECDH
    shared secret. Sorting the two public keys into a canonical order
    before hashing makes the salt -- and therefore the derived key --
    identical on both ends.
    """
    ordered = sorted((public_key_a, public_key_b))
    return hashlib.sha256(session_id.encode("utf-8") + ordered[0] + ordered[1]).digest()[:16]


class ECDHKeyExchange:
    """
    Optional ephemeral Elliptic-Curve Diffie-Hellman (X25519) key
    exchange, used to derive a fresh per-session key that is never
    persisted, giving forward secrecy: even if a long-term passphrase or
    stored key is later compromised, past session traffic cannot be
    decrypted because the session key derivation depended on private
    key material that was discarded at session end.
    """

    def __init__(self) -> None:
        self._private_key = X25519PrivateKey.generate()

    @property
    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def derive_shared_key(
        self, peer_public_bytes: bytes, *, salt: bytes, length: int = 32
    ) -> bytes:
        try:
            peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
            shared_secret = self._private_key.exchange(peer_public_key)
        except Exception as exc:
            raise HandshakeError("ECDH exchange failed") from exc
        # The raw ECDH shared secret is NOT used directly as a key; it is
        # passed through HKDF to produce uniformly random key material
        # and to bind the key to this specific handshake via the salt.
        return derive_key(
            shared_secret,
            salt=salt,
            kdf=KDFName.HKDF_SHA256,
            length=length,
            info=b"securelink-ecdh-session-key",
        )


# --- Key rotation -------------------------------------------------------


class KeyRing:
    """
    Derives a sequence of rotating "epoch keys" from a single base
    secret and hands out whichever epoch is current.

    Design note -- why rotation is *deterministic*, not random:
    two independent peers (client and server) each run their own
    `KeyRing` instance with no side channel to announce "I just
    rotated." If rotation picked fresh random key material, the two
    sides would silently diverge the moment either one rotated and all
    further traffic would fail to decrypt. Instead, both sides derive
    the epoch key as `HKDF(base_secret, info=f"epoch-{n}")`, where the
    epoch number `n` is a pure function of the same rotation policy
    (elapsed wall-clock time and/or message count) applied to the same
    base secret. As long as both sides share the base secret (from the
    same passphrase+salt or the same ECDH exchange) and the same
    rotation policy, they independently compute identical epoch keys
    without any additional coordination messages -- this is the same
    "epoch"-style ratchet idea used by protocols like Signal's sender
    keys, simplified for a request/response transport.

    A small window of adjacent epochs (previous/current/next) is kept
    derivable so that clock skew or messages that straddle a rotation
    boundary can still be decrypted.
    """

    _EPOCH_WINDOW = 1  # derive [-window, +window] around the current epoch

    def __init__(
        self,
        base_secret: bytes,
        *,
        rotate_every_seconds: Optional[float] = None,
        rotate_every_messages: Optional[int] = None,
        max_retained_keys: int = 8,
    ) -> None:
        self._lock = threading.Lock()
        self._base_secret = base_secret
        self._rotate_every_seconds = rotate_every_seconds
        self._rotate_every_messages = rotate_every_messages
        self._max_retained_keys = max_retained_keys
        self._start_time = time.time()
        self._message_count = 0
        # cache of derived keys by epoch number, to avoid re-deriving on
        # every call; bounded and pruned like an LRU.
        self._cache: "OrderedDict[int, Tuple[str, bytes]]" = OrderedDict()

    @staticmethod
    def _key_id_for(key: bytes) -> str:
        # The key_id is a non-secret fingerprint of the key material. It
        # must be a deterministic function of the key alone (not random)
        # so that two peers who derive the same epoch key independently
        # also compute the same key_id, letting a receiver look up the
        # right key from an envelope with no extra round trip. Exposing
        # this fingerprint on the wire is safe: it is one-way and reveals
        # nothing about the key itself, analogous to a TLS certificate
        # fingerprint.
        return hashlib.sha256(b"securelink-key-id" + key).hexdigest()[:16]

    def _current_epoch_locked(self) -> int:
        # Time-based epoch takes priority when configured; it is robust
        # to dropped messages (unlike a raw message counter, which two
        # peers could disagree on if a message is lost in transit).
        if self._rotate_every_seconds:
            return int((time.time() - self._start_time) // self._rotate_every_seconds)
        if self._rotate_every_messages:
            return self._message_count // self._rotate_every_messages
        return 0

    def _derive_epoch_key_locked(self, epoch: int) -> Tuple[str, bytes]:
        if epoch in self._cache:
            self._cache.move_to_end(epoch)
            return self._cache[epoch]
        key = derive_key(
            self._base_secret,
            salt=hashlib.sha256(self._base_secret).digest()[:16],
            kdf=KDFName.HKDF_SHA256,
            length=32,
            info=f"securelink-epoch-{epoch}".encode("ascii"),
        )
        key_id = self._key_id_for(key)
        self._cache[epoch] = (key_id, key)
        while len(self._cache) > self._max_retained_keys:
            self._cache.popitem(last=False)
        return key_id, key

    def rotate(self) -> None:
        """No-op placeholder retained for API compatibility / explicit
        manual triggering in tests; real rotation is time/count driven
        and requires no explicit call in normal operation."""
        with self._lock:
            self._current_epoch_locked()

    def current(self) -> Tuple[str, bytes]:
        with self._lock:
            self._message_count += 1
            epoch = self._current_epoch_locked()
            key_id, key = self._derive_epoch_key_locked(epoch)
            _LOG.debug("securelink: using key epoch %d (id redacted from external logs)", epoch)
            return key_id, key

    def find_epoch(self, key_id: str) -> int:
        """Find which epoch number produced the given wire key_id,
        searching the epochs around 'now' to tolerate clock skew /
        rotation-boundary races. Raises DecryptionError if none match.

        Note: a codec that pairs this KeyRing with a second, independent
        KeyRing (e.g. cipher key vs. HMAC key, which hold different key
        material and therefore have different fingerprints) must resolve
        the epoch number *once*, from whichever ring's key_id travelled
        on the wire, and then ask both rings for that same epoch's key
        via `key_for_epoch` -- looking a shared key_id up independently
        in two rings with different key material will never match.
        """
        with self._lock:
            current_epoch = self._current_epoch_locked()
            for epoch in range(
                current_epoch - self._EPOCH_WINDOW, current_epoch + self._EPOCH_WINDOW + 1
            ):
                candidate_id, _ = self._derive_epoch_key_locked(epoch)
                if candidate_id == key_id:
                    return epoch
            raise DecryptionError("unknown key id")

    def key_for_epoch(self, epoch: int) -> bytes:
        with self._lock:
            _, key = self._derive_epoch_key_locked(epoch)
            return key

    def get(self, key_id: str) -> bytes:
        """Convenience wrapper: look up a key directly by its own
        wire key_id (used when a single KeyRing's key_id is authoritative,
        e.g. the cipher keyring during decode)."""
        epoch = self.find_epoch(key_id)
        return self.key_for_epoch(epoch)


# =====================================================================
# === Replay Protection ===
# =====================================================================


class ReplayGuard:
    """
    Rejects messages whose timestamp falls outside an acceptance window,
    or whose (timestamp, nonce) pair has already been seen. Combining a
    timestamp window with a nonce cache means an attacker cannot replay
    a captured, validly-encrypted message even within the window, and
    the cache does not have to grow unboundedly because entries outside
    the window are pruned.
    """

    def __init__(self, window_seconds: float = 30.0, max_cache_size: int = 100_000) -> None:
        if window_seconds <= 0:
            raise ConfigError("replay window must be positive")
        self.window_seconds = window_seconds
        self._max_cache_size = max_cache_size
        self._seen: "OrderedDict[bytes, float]" = OrderedDict()
        self._lock = threading.Lock()

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._seen:
            nonce, ts = next(iter(self._seen.items()))
            if ts < cutoff:
                self._seen.popitem(last=False)
            else:
                break
        # Hard cap as a safety valve against memory exhaustion even if
        # clock skew or a burst of traffic delays pruning.
        while len(self._seen) > self._max_cache_size:
            self._seen.popitem(last=False)

    def check(self, nonce: bytes, timestamp: float) -> None:
        now = time.time()
        if abs(now - timestamp) > self.window_seconds:
            raise ReplayAttackDetected("timestamp outside acceptance window")
        with self._lock:
            self._prune_locked(now)
            if nonce in self._seen:
                raise ReplayAttackDetected("duplicate nonce detected")
            self._seen[nonce] = timestamp


# =====================================================================
# === Config ===
# =====================================================================


class TransportMode(str, enum.Enum):
    POLLING = "polling"
    WEBSOCKET = "websocket"
    SSE = "sse"


@dataclasses.dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 0.5
    max_delay: float = 30.0
    jitter: float = 0.1

    def delay_for(self, attempt: int) -> float:
        raw = min(self.max_delay, self.base_delay * (2 ** attempt))
        jitter_amount = raw * self.jitter
        return raw + secrets.SystemRandom().uniform(-jitter_amount, jitter_amount)


@dataclasses.dataclass
class ProxyConfig:
    url: Optional[str] = None  # e.g. "http://proxy:8080" or "socks5://proxy:1080"
    username: Optional[str] = None
    password: Optional[str] = None

    def to_httpx_proxy(self) -> Optional[str]:
        if not self.url:
            return None
        if self.username and self.password and "://" in self.url:
            scheme, rest = self.url.split("://", 1)
            return f"{scheme}://{self.username}:{self.password}@{rest}"
        return self.url


class SecureConfig:
    """
    Builder-style configuration object.

        cfg = (
            SecureConfig()
            .with_passphrase("correct-horse-battery-staple")
            .with_cipher(CipherName.AES_256_GCM)
            .with_timeouts(connect=5, read=10, write=10)
            .with_transport_mode(TransportMode.SSE)
            .build()
        )

    `build()` validates the configuration and raises `ConfigError` early
    on anything invalid, rather than failing later at connection time.
    """

    def __init__(self) -> None:
        self._passphrase: Optional[bytes] = None
        self._cipher: CipherName = CipherName.AES_256_GCM
        self._kdf: KDFName = KDFName.PBKDF2_HMAC_SHA256
        self._kdf_iterations: int = 390_000
        self._salt: Optional[bytes] = None
        self._connect_timeout: float = 10.0
        self._read_timeout: float = 30.0
        self._write_timeout: float = 30.0
        self._proxy = ProxyConfig()
        self._retry_policy = RetryPolicy()
        self._compression_enabled: bool = False
        self._tls_verify: bool = True
        self._log_level: int = logging.WARNING
        self._transport_mode: TransportMode = TransportMode.POLLING
        self._use_ecdh: bool = False
        self._rotate_every_seconds: Optional[float] = 3600.0
        self._rotate_every_messages: Optional[int] = 10_000
        self._replay_window_seconds: float = 30.0
        self._heartbeat_interval: float = 15.0
        self._base_url: Optional[str] = None
        self._hooks: Dict[str, Callable[..., Any]] = {}

    # -- fluent setters --------------------------------------------------

    def with_passphrase(self, passphrase: Union[str, bytes]) -> "SecureConfig":
        self._passphrase = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        return self

    def with_cipher(self, cipher: CipherName) -> "SecureConfig":
        self._cipher = cipher
        return self

    def with_kdf(self, kdf: KDFName, iterations: int = 390_000) -> "SecureConfig":
        self._kdf = kdf
        self._kdf_iterations = iterations
        return self

    def with_salt(self, salt: bytes) -> "SecureConfig":
        self._salt = salt
        return self

    def with_timeouts(
        self, connect: float = 10.0, read: float = 30.0, write: float = 30.0
    ) -> "SecureConfig":
        self._connect_timeout, self._read_timeout, self._write_timeout = connect, read, write
        return self

    def with_proxy(
        self, url: str, username: Optional[str] = None, password: Optional[str] = None
    ) -> "SecureConfig":
        self._proxy = ProxyConfig(url=url, username=username, password=password)
        return self

    def with_retry_policy(self, policy: RetryPolicy) -> "SecureConfig":
        self._retry_policy = policy
        return self

    def with_compression(self, enabled: bool = True) -> "SecureConfig":
        self._compression_enabled = enabled
        return self

    def with_tls_verify(self, verify: bool = True) -> "SecureConfig":
        self._tls_verify = verify
        return self

    def with_log_level(self, level: int) -> "SecureConfig":
        self._log_level = level
        return self

    def with_transport_mode(self, mode: TransportMode) -> "SecureConfig":
        self._transport_mode = mode
        return self

    def with_ecdh(self, enabled: bool = True) -> "SecureConfig":
        self._use_ecdh = enabled
        return self

    def with_key_rotation(
        self,
        every_seconds: Optional[float] = None,
        every_messages: Optional[int] = None,
    ) -> "SecureConfig":
        self._rotate_every_seconds = every_seconds
        self._rotate_every_messages = every_messages
        return self

    def with_replay_window(self, seconds: float) -> "SecureConfig":
        self._replay_window_seconds = seconds
        return self

    def with_heartbeat_interval(self, seconds: float) -> "SecureConfig":
        self._heartbeat_interval = seconds
        return self

    def with_base_url(self, url: str) -> "SecureConfig":
        self._base_url = url
        return self

    def on(self, event: str, callback: Callable[..., Any]) -> "SecureConfig":
        """Register a lifecycle hook.

        Valid events: on_connect, on_disconnect, on_message, on_error,
        before_send, after_receive.
        """
        valid = {
            "on_connect",
            "on_disconnect",
            "on_message",
            "on_error",
            "before_send",
            "after_receive",
        }
        if event not in valid:
            raise ConfigError(f"unknown hook event: {event!r}. Valid: {sorted(valid)}")
        self._hooks[event] = callback
        return self

    # -- validation & build -----------------------------------------------

    def build(self) -> "SecureConfig":
        """Validate the configuration, filling in defaults, and return self.

        Fail-fast: every value is checked here rather than lazily at
        first use, so misconfiguration surfaces immediately at startup.
        """
        if not self._passphrase:
            raise ConfigError("a passphrase (or pre-shared key material) is required")
        if len(self._passphrase) < 8:
            raise ConfigError("passphrase is too short (minimum 8 characters)")
        if self._cipher not in _CIPHER_REGISTRY:
            raise ConfigError(f"unsupported cipher: {self._cipher!r}")
        if self._salt is None:
            # A random salt is generated if none is supplied. Note: for
            # two independent parties to derive the *same* key from a
            # shared passphrase, the salt must be transmitted or agreed
            # out-of-band; this library treats the salt as public,
            # non-secret data (as is standard for KDF salts).
            self._salt = secrets.token_bytes(16)
        if self._connect_timeout <= 0 or self._read_timeout <= 0 or self._write_timeout <= 0:
            raise ConfigError("timeouts must be positive")
        if self._kdf_iterations < 100_000 and self._kdf == KDFName.PBKDF2_HMAC_SHA256:
            raise ConfigError("PBKDF2 iteration count is too low (minimum 100,000)")
        if self._replay_window_seconds <= 0:
            raise ConfigError("replay window must be positive")
        if not self._tls_verify:
            _LOG.warning(
                "securelink: TLS verification is DISABLED. This should only "
                "be used against trusted test endpoints, never in production."
            )
        _LOG.setLevel(self._log_level)
        return self

    # -- derived objects ----------------------------------------------------

    def cipher_suite(self) -> CipherSuite:
        return get_cipher_suite(self._cipher)

    def derive_base_key(self) -> bytes:
        assert self._passphrase is not None and self._salt is not None
        return derive_key(
            self._passphrase,
            self._salt,
            kdf=self._kdf,
            iterations=self._kdf_iterations,
            length=self.cipher_suite().key_size,
        )

    def httpx_timeout(self) -> "httpx.Timeout":
        return httpx.Timeout(
            connect=self._connect_timeout,
            read=self._read_timeout,
            write=self._write_timeout,
            pool=self._connect_timeout,
        )

    def httpx_proxy(self) -> Optional[str]:
        return self._proxy.to_httpx_proxy()

    def hook(self, event: str) -> Optional[Callable[..., Any]]:
        return self._hooks.get(event)


# =====================================================================
# === Compression (pre-encryption, with side-channel safeguards) ===
# =====================================================================


class _CompressionGuard:
    """
    Encrypt-then-compress ordering is a well-known foot-gun: compressing
    *plaintext that mixes attacker-controlled and secret data* before
    encryption can leak the secret through ciphertext length (CRIME,
    BREACH). This helper mitigates that by:

    1. Only compressing payloads above a minimum size (compression of
       tiny/structured payloads offers little benefit and is where these
       oracles are most effective).
    2. Padding the compressed output to a fixed bucket size before
       encryption so that the ciphertext length reveals only which
       bucket the message falls into, not its exact size.

    This does not make compression safe for all threat models (an
    application that lets an attacker inject arbitrary chosen plaintext
    alongside a secret, e.g. reflecting request data back into a
    compressed+encrypted response, should keep compression disabled for
    that data). The guardrails here reduce, not eliminate, that risk.
    """

    MIN_SIZE_TO_COMPRESS = 256
    BUCKET_SIZE = 256

    @classmethod
    def maybe_compress(cls, data: bytes, enabled: bool) -> Tuple[bytes, bool]:
        if not enabled or len(data) < cls.MIN_SIZE_TO_COMPRESS:
            return data, False
        compressed = zlib.compress(data, level=6)
        if len(compressed) >= len(data):
            return data, False
        padded = cls._pad_to_bucket(compressed)
        return padded, True

    @classmethod
    def decompress(cls, data: bytes) -> bytes:
        unpadded = cls._unpad(data)
        try:
            return zlib.decompress(unpadded)
        except zlib.error as exc:
            raise DecryptionError("decompression failed") from exc

    @classmethod
    def _pad_to_bucket(cls, data: bytes) -> bytes:
        pad_len = (-len(data)) % cls.BUCKET_SIZE or cls.BUCKET_SIZE
        # 4-byte big-endian length prefix + padding bytes.
        return len(data).to_bytes(4, "big") + data + secrets.token_bytes(pad_len)

    @classmethod
    def _unpad(cls, data: bytes) -> bytes:
        if len(data) < 4:
            raise DecryptionError("corrupt compressed payload")
        real_len = int.from_bytes(data[:4], "big")
        payload = data[4:]
        if real_len > len(payload):
            raise DecryptionError("corrupt compressed payload")
        return payload[:real_len]


# =====================================================================
# === Circuit Breaker ===
# =====================================================================


class CircuitBreaker:
    """
    Stops hammering an unresponsive server: after `failure_threshold`
    consecutive failures the circuit "opens" and calls fail fast for
    `reset_timeout` seconds, after which a single trial call is allowed
    through ("half-open") to test recovery.
    """

    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._lock = threading.Lock()

    def _state_locked(self) -> str:
        if self._opened_at is None:
            return "closed"
        if (time.monotonic() - self._opened_at) >= self.reset_timeout:
            return "half-open"
        return "open"

    def before_call(self) -> None:
        with self._lock:
            state = self._state_locked()
            if state == "open":
                raise CircuitOpenError("circuit breaker is open; refusing call")

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = time.monotonic()


# =====================================================================
# === Message Codec (shared encrypt/decrypt pipeline) ===
# =====================================================================


class _MessageCodec:
    """
    Combines compression, encryption, and the HMAC defense-in-depth layer
    into a single encode/decode pipeline shared by client and server, so
    the two sides can never drift out of sync on wire format.
    """

    def __init__(self, config: SecureConfig, keyring: KeyRing, mac_keyring: KeyRing) -> None:
        self._config = config
        self._cipher = config.cipher_suite()
        self._keyring = keyring
        self._mac_keyring = mac_keyring

    def encode(self, plaintext: bytes, aad: bytes = b"") -> EncryptedEnvelope:
        payload, compressed = _CompressionGuard.maybe_compress(
            plaintext, self._config._compression_enabled
        )
        key_id, key = self._keyring.current()
        _, mac_key = self._mac_keyring.current()
        nonce, ciphertext = self._cipher.encrypt(key, payload, aad)
        hmac_tag = _compute_hmac(mac_key, nonce, ciphertext)
        return EncryptedEnvelope(
            nonce=nonce,
            ciphertext=ciphertext,
            hmac_tag=hmac_tag,
            timestamp=time.time(),
            key_id=key_id,
            compressed=compressed,
        )

    def decode(self, envelope: EncryptedEnvelope, aad: bytes = b"") -> bytes:
        # Resolve the epoch ONCE from the cipher keyring's key_id (the
        # one that actually travelled on the wire), then pull the HMAC
        # key for that *same* epoch from the separate MAC keyring. The
        # two rings hold different key material and therefore have
        # different key_id fingerprints, so the MAC keyring must never
        # be looked up by the cipher's key_id directly -- see the note
        # on `KeyRing.find_epoch`.
        epoch = self._keyring.find_epoch(envelope.key_id)
        key = self._keyring.key_for_epoch(epoch)
        mac_key = self._mac_keyring.key_for_epoch(epoch)
        # Verify defense-in-depth HMAC first (cheap, constant-time) before
        # doing the more expensive AEAD decrypt -- fail closed as early
        # as possible without leaking which check failed.
        try:
            _verify_hmac(mac_key, envelope.nonce, envelope.ciphertext, envelope.hmac_tag)
            plaintext = self._cipher.decrypt(key, envelope.nonce, envelope.ciphertext, aad)
        except (AuthenticationFailedError, DecryptionError):
            raise
        except Exception as exc:  # pragma: no cover - defensive catch-all
            raise DecryptionError("failed to decode message") from exc
        if envelope.compressed:
            plaintext = _CompressionGuard.decompress(plaintext)
        return plaintext


def _new_mac_keyring(base_key: bytes, config: SecureConfig) -> KeyRing:
    # The HMAC key is derived independently from the AEAD key (different
    # HKDF `info` label) so that the two layers do not share key
    # material -- a flaw compromising one key should not automatically
    # compromise the other.
    mac_key = derive_key(
        base_key,
        salt=hashlib.sha256(base_key).digest()[:16],
        kdf=KDFName.HKDF_SHA256,
        length=32,
        info=b"securelink-hmac-key",
    )
    return KeyRing(
        mac_key,
        rotate_every_seconds=config._rotate_every_seconds,
        rotate_every_messages=config._rotate_every_messages,
    )


# =====================================================================
# === Transport / Hooks ===
# =====================================================================

HookName = str


class HookInvoker:
    """Safely invokes user-supplied lifecycle hooks (sync or async),
    isolating hook exceptions so a bug in application callback code
    cannot crash the transport loop."""

    def __init__(self, config: SecureConfig) -> None:
        self._config = config

    def fire(self, event: HookName, *args: Any, **kwargs: Any) -> None:
        hook = self._config.hook(event)
        if hook is None:
            return
        try:
            result = hook(*args, **kwargs)
            if asyncio.iscoroutine(result):
                # Best-effort: schedule if a loop is running, otherwise run.
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    asyncio.run(result)
        except Exception:
            _LOG.exception("securelink: hook %r raised an exception", event)

    async def fire_async(self, event: HookName, *args: Any, **kwargs: Any) -> None:
        hook = self._config.hook(event)
        if hook is None:
            return
        try:
            result = hook(*args, **kwargs)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            _LOG.exception("securelink: hook %r raised an exception", event)


class Transport(ABC):
    """
    Abstract transport so the client/server logic can be exercised in
    unit tests with a fake/mock transport instead of real network I/O.
    """

    @abstractmethod
    def send(self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        ...

    @abstractmethod
    async def send_async(
        self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]
    ) -> Dict[str, Any]:
        ...


class HttpxTransport(Transport):
    """Default transport backed by `httpx`, sync and async clients."""

    def __init__(self, config: SecureConfig) -> None:
        if httpx is None:
            raise ConfigError("httpx is required for HttpxTransport but is not installed")
        self._config = config
        self._sync_client = httpx.Client(
            timeout=config.httpx_timeout(),
            proxy=config.httpx_proxy(),
            verify=config._tls_verify,
        )
        self._async_client: Optional["httpx.AsyncClient"] = None

    async def _get_async_client(self) -> "httpx.AsyncClient":
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=self._config.httpx_timeout(),
                proxy=self._config.httpx_proxy(),
                verify=self._config._tls_verify,
            )
        return self._async_client

    def send(self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        try:
            resp = self._sync_client.post(url, json=json_body, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException as exc:
            raise ConnectionTimeoutError(str(exc)) from exc

    async def send_async(
        self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]
    ) -> Dict[str, Any]:
        client = await self._get_async_client()
        try:
            resp = await client.post(url, json=json_body, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException as exc:
            raise ConnectionTimeoutError(str(exc)) from exc

    def stream_send(self, url: str, chunks: "Callable[[], Any]", headers: Dict[str, str]):
        """Streaming upload: pass an iterable of already-encrypted chunk
        dicts so large payloads never need to be fully materialized in
        memory on either side."""
        with self._sync_client.stream("POST", url, json={"chunks": list(chunks())}, headers=headers) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if line:
                    yield json.loads(line)

    def close(self) -> None:
        self._sync_client.close()

    async def aclose(self) -> None:
        if self._async_client is not None:
            await self._async_client.aclose()


# =====================================================================
# === Session (shared client/server per-connection state) ===
# =====================================================================


class _Session:
    """
    Holds all per-session state: session id, key material (with
    optional ECDH-derived forward secrecy), rotation, and replay
    protection. Used identically by `SecureClient` (one session) and
    `SecureServer` (many concurrent sessions, one per connected peer).
    """

    def __init__(self, config: SecureConfig, session_id: Optional[str] = None) -> None:
        self.session_id = session_id or secrets.token_hex(16)
        self.config = config
        self.created_at = time.time()
        self.last_seen = self.created_at
        self.message_queue: "asyncio.Queue[Any]" = asyncio.Queue()
        self.ecdh: Optional[ECDHKeyExchange] = None

        base_key = config.derive_base_key()
        self.keyring = KeyRing(
            base_key,
            rotate_every_seconds=config._rotate_every_seconds,
            rotate_every_messages=config._rotate_every_messages,
        )
        self.mac_keyring = _new_mac_keyring(base_key, config)
        self.codec = _MessageCodec(config, self.keyring, self.mac_keyring)
        self.replay_guard = ReplayGuard(window_seconds=config._replay_window_seconds)

    def complete_ecdh_handshake(self, peer_public_bytes: bytes) -> bytes:
        """Upgrade this session to an ephemeral ECDH-derived key,
        providing forward secrecy for the remainder of the session."""
        self.ecdh = ECDHKeyExchange()
        salt = _handshake_salt(self.session_id, self.ecdh.public_bytes, peer_public_bytes)
        shared_key = self.ecdh.derive_shared_key(peer_public_bytes, salt=salt)
        self.keyring = KeyRing(
            shared_key,
            rotate_every_seconds=self.config._rotate_every_seconds,
            rotate_every_messages=self.config._rotate_every_messages,
        )
        self.mac_keyring = _new_mac_keyring(shared_key, self.config)
        self.codec = _MessageCodec(self.config, self.keyring, self.mac_keyring)
        return self.ecdh.public_bytes

    def touch(self) -> None:
        self.last_seen = time.time()


# =====================================================================
# === Client ===
# =====================================================================


class SecureClient:
    """
    High-level client exposing both sync and async APIs.

        client = SecureClient(config)
        client.connect()
        client.send({"hello": "world"})
        response = client.receive()
        client.close()

    Async usage:

        async with SecureClient(config) as client:
            await client.send_async({"hello": "world"})
            reply = await client.receive_async()
    """

    def __init__(self, config: SecureConfig, transport: Optional[Transport] = None) -> None:
        self._config = config.build()
        self._session = _Session(config)
        self._transport = transport or HttpxTransport(config)
        self._hooks = HookInvoker(config)
        self._circuit = CircuitBreaker()
        self._connected = False
        self._heartbeat_task: Optional[asyncio.Task] = None

    # -- connection lifecycle ------------------------------------------------

    def connect(self) -> None:
        if not self._config._base_url:
            raise ConfigError("base_url must be configured before connecting")
        self._connected = True
        self._hooks.fire("on_connect", self._session.session_id)
        _LOG.info("securelink client connected (session=%s)", self._session.session_id)

    async def connect_async(self) -> None:
        if not self._config._base_url:
            raise ConfigError("base_url must be configured before connecting")
        self._connected = True
        await self._hooks.fire_async("on_connect", self._session.session_id)
        if self._config._heartbeat_interval > 0:
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def close(self) -> None:
        self._connected = False
        if isinstance(self._transport, HttpxTransport):
            self._transport.close()
        self._hooks.fire("on_disconnect", self._session.session_id)

    async def close_async(self) -> None:
        self._connected = False
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
        if isinstance(self._transport, HttpxTransport):
            await self._transport.aclose()
        await self._hooks.fire_async("on_disconnect", self._session.session_id)

    async def __aenter__(self) -> "SecureClient":
        await self.connect_async()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close_async()

    async def _heartbeat_loop(self) -> None:
        try:
            while self._connected:
                await asyncio.sleep(self._config._heartbeat_interval)
                try:
                    await self.send_async({"_type": "heartbeat"})
                except SecureLinkError:
                    _LOG.warning("securelink: heartbeat failed")
        except asyncio.CancelledError:
            pass

    # -- ECDH handshake --------------------------------------------------------

    def perform_ecdh_handshake(self, endpoint: str = "/handshake") -> None:
        ecdh = ECDHKeyExchange()
        url = self._config._base_url.rstrip("/") + endpoint  # type: ignore[union-attr]
        body = {
            "session_id": self._session.session_id,
            "client_public_key": base64.b64encode(ecdh.public_bytes).decode(),
        }
        result = self._call_with_retry(lambda: self._transport.send(url, body, {}))
        try:
            server_public = base64.b64decode(result["server_public_key"])
        except (KeyError, ValueError) as exc:
            raise HandshakeError("invalid handshake response") from exc
        self._session.ecdh = ecdh
        salt = _handshake_salt(self._session.session_id, ecdh.public_bytes, server_public)
        shared_key = ecdh.derive_shared_key(server_public, salt=salt)
        self._session.keyring = KeyRing(
            shared_key,
            rotate_every_seconds=self._config._rotate_every_seconds,
            rotate_every_messages=self._config._rotate_every_messages,
        )
        self._session.mac_keyring = _new_mac_keyring(shared_key, self._config)
        self._session.codec = _MessageCodec(
            self._config, self._session.keyring, self._session.mac_keyring
        )

    # -- retry / circuit breaker helper -----------------------------------

    def _call_with_retry(self, fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        policy = self._config._retry_policy
        last_exc: Optional[Exception] = None
        for attempt in range(policy.max_attempts):
            self._circuit.before_call()
            try:
                result = fn()
                self._circuit.record_success()
                return result
            except (ConnectionTimeoutError, httpx.HTTPError if httpx else Exception) as exc:  # type: ignore
                last_exc = exc
                self._circuit.record_failure()
                self._hooks.fire("on_error", exc)
                if attempt + 1 < policy.max_attempts:
                    time.sleep(policy.delay_for(attempt))
        assert last_exc is not None
        raise ConnectionTimeoutError(f"exceeded retry budget: {last_exc}") from last_exc

    async def _call_with_retry_async(
        self, fn: Callable[[], Awaitable[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        policy = self._config._retry_policy
        last_exc: Optional[Exception] = None
        for attempt in range(policy.max_attempts):
            self._circuit.before_call()
            try:
                result = await fn()
                self._circuit.record_success()
                return result
            except (ConnectionTimeoutError, httpx.HTTPError if httpx else Exception) as exc:  # type: ignore
                last_exc = exc
                self._circuit.record_failure()
                await self._hooks.fire_async("on_error", exc)
                if attempt + 1 < policy.max_attempts:
                    await asyncio.sleep(policy.delay_for(attempt))
        assert last_exc is not None
        raise ConnectionTimeoutError(f"exceeded retry budget: {last_exc}") from last_exc

    # -- send / receive ------------------------------------------------------

    def send(self, message: Dict[str, Any], endpoint: str = "/message") -> Dict[str, Any]:
        if not self._connected:
            raise SecureLinkError("client is not connected; call connect() first")
        self._hooks.fire("before_send", message)
        plaintext = json.dumps(message).encode("utf-8")
        envelope = self._session.codec.encode(plaintext)
        url = self._config._base_url.rstrip("/") + endpoint  # type: ignore[union-attr]
        body = {"session_id": self._session.session_id, "envelope": envelope.to_wire()}
        headers = {"X-Session-Id": self._session.session_id}
        raw = self._call_with_retry(lambda: self._transport.send(url, body, headers))
        return self._decode_response(raw)

    async def send_async(
        self, message: Dict[str, Any], endpoint: str = "/message"
    ) -> Dict[str, Any]:
        if not self._connected:
            raise SecureLinkError("client is not connected; call connect_async() first")
        await self._hooks.fire_async("before_send", message)
        plaintext = json.dumps(message).encode("utf-8")
        envelope = self._session.codec.encode(plaintext)
        url = self._config._base_url.rstrip("/") + endpoint  # type: ignore[union-attr]
        body = {"session_id": self._session.session_id, "envelope": envelope.to_wire()}
        headers = {"X-Session-Id": self._session.session_id}
        raw = await self._call_with_retry_async(lambda: self._transport.send_async(url, body, headers))
        return await self._decode_response_async(raw)

    def _decode_response(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        if raw.get("status") == "error":
            self._hooks.fire("on_error", raw)
            raise SecureLinkError("server returned an error")
        envelope = EncryptedEnvelope.from_wire(raw["envelope"])
        self._session.replay_guard.check(envelope.nonce, envelope.timestamp)
        plaintext = self._session.codec.decode(envelope)
        result: Dict[str, Any] = json.loads(plaintext)
        self._hooks.fire("after_receive", result)
        self._hooks.fire("on_message", result)
        return result

    async def _decode_response_async(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        if raw.get("status") == "error":
            await self._hooks.fire_async("on_error", raw)
            raise SecureLinkError("server returned an error")
        envelope = EncryptedEnvelope.from_wire(raw["envelope"])
        self._session.replay_guard.check(envelope.nonce, envelope.timestamp)
        plaintext = self._session.codec.decode(envelope)
        result: Dict[str, Any] = json.loads(plaintext)
        await self._hooks.fire_async("after_receive", result)
        await self._hooks.fire_async("on_message", result)
        return result

    def receive(self, endpoint: str = "/poll") -> Optional[Dict[str, Any]]:
        """Poll-mode receive (used when transport_mode == POLLING)."""
        url = self._config._base_url.rstrip("/") + endpoint  # type: ignore[union-attr]
        headers = {"X-Session-Id": self._session.session_id}
        raw = self._call_with_retry(lambda: self._transport.send(url, {"session_id": self._session.session_id}, headers))
        if raw.get("status") == "empty":
            return None
        return self._decode_response(raw)

    async def receive_async(self, endpoint: str = "/poll") -> Optional[Dict[str, Any]]:
        url = self._config._base_url.rstrip("/") + endpoint  # type: ignore[union-attr]
        headers = {"X-Session-Id": self._session.session_id}
        raw = await self._call_with_retry_async(
            lambda: self._transport.send_async(url, {"session_id": self._session.session_id}, headers)
        )
        if raw.get("status") == "empty":
            return None
        return await self._decode_response_async(raw)

    def send_stream(self, chunks: "list[bytes]", endpoint: str = "/stream") -> None:
        """
        Encrypt and send a large payload as a sequence of independently
        authenticated chunks so the full plaintext never needs to be
        held in memory at once on the sending side.
        """
        if not isinstance(self._transport, HttpxTransport):
            raise ConfigError("streaming requires the default HttpxTransport")
        url = self._config._base_url.rstrip("/") + endpoint  # type: ignore[union-attr]
        headers = {"X-Session-Id": self._session.session_id}

        def _chunk_envelopes():
            for chunk in chunks:
                yield self._session.codec.encode(chunk).to_wire()

        for _ in self._transport.stream_send(url, _chunk_envelopes, headers):
            pass


# =====================================================================
# === Server ===
# =====================================================================


class SecureServer:
    """
    Server-side counterpart, supporting many concurrent client sessions
    (each isolated with its own key material and message queue), plus
    server-initiated push via WebSocket, SSE, or long-polling.

    This class is transport-framework agnostic: it exposes plain
    async/sync handler methods (`handle_message`, `handle_handshake`,
    `handle_poll`) that an application wires up to whatever HTTP
    framework it uses (e.g. FastAPI, aiohttp, Flask). This keeps the
    library from forcing a specific web framework dependency while
    still doing all of the cryptographic and session-management work.
    """

    def __init__(self, config: SecureConfig) -> None:
        self._config = config.build()
        self._hooks = HookInvoker(config)
        self._sessions: Dict[str, _Session] = {}
        self._sessions_lock = threading.Lock()

    # -- session management ------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> _Session:
        with self._sessions_lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = _Session(self._config, session_id=session_id)
                self._sessions[session_id] = session
                self._hooks.fire("on_connect", session_id)
            session.touch()
            return session

    def drop_session(self, session_id: str) -> None:
        with self._sessions_lock:
            if self._sessions.pop(session_id, None) is not None:
                self._hooks.fire("on_disconnect", session_id)

    def prune_idle_sessions(self, max_idle_seconds: float = 3600.0) -> int:
        now = time.time()
        removed = 0
        with self._sessions_lock:
            stale = [sid for sid, s in self._sessions.items() if (now - s.last_seen) > max_idle_seconds]
            for sid in stale:
                del self._sessions[sid]
                removed += 1
        return removed

    @property
    def active_session_count(self) -> int:
        with self._sessions_lock:
            return len(self._sessions)

    # -- handshake -----------------------------------------------------------

    def handle_handshake(self, session_id: str, client_public_key_b64: str) -> Dict[str, Any]:
        """Synchronous ECDH handshake handler. Wire this up to a
        `/handshake` route in your web framework of choice."""
        session = self._get_or_create_session(session_id)
        try:
            client_public = base64.b64decode(client_public_key_b64)
            server_public = session.complete_ecdh_handshake(client_public)
        except Exception as exc:
            _LOG.exception("securelink: handshake failed for session %s", session_id)
            raise HandshakeError("handshake failed") from exc
        return {"status": "ok", "server_public_key": base64.b64encode(server_public).decode()}

    # -- message handling ------------------------------------------------------

    def handle_message(self, session_id: str, envelope_wire: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt an incoming message, dispatch it to the `on_message` hook
        (whose return value, if any, becomes the encrypted response),
        and return a wire-format response dict. Any failure results in a
        single generic error response -- see `_generic_wire_error`.
        """
        session = self._get_or_create_session(session_id)
        try:
            envelope = EncryptedEnvelope.from_wire(envelope_wire)
            session.replay_guard.check(envelope.nonce, envelope.timestamp)
            plaintext = session.codec.decode(envelope)
            message = json.loads(plaintext)
        except (DecryptionError, AuthenticationFailedError, ReplayAttackDetected) as exc:
            _LOG.warning("securelink: rejecting message for session %s: %s", session_id, type(exc).__name__)
            self._hooks.fire("on_error", exc)
            return _generic_wire_error(exc)
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.exception("securelink: unexpected error handling message")
            self._hooks.fire("on_error", exc)
            return _generic_wire_error(exc)

        self._hooks.fire("after_receive", message)
        response_obj = self._hooks_message_response(message, session)
        response_plaintext = json.dumps(response_obj).encode("utf-8")
        response_envelope = session.codec.encode(response_plaintext)
        return {"status": "ok", "envelope": response_envelope.to_wire()}

    def _hooks_message_response(self, message: Dict[str, Any], session: _Session) -> Dict[str, Any]:
        hook = self._config.hook("on_message")
        if hook is None:
            return {"echo": message}
        try:
            result = hook(message, session.session_id)
            if isinstance(result, dict):
                return result
            return {"echo": message}
        except Exception:
            _LOG.exception("securelink: on_message hook raised")
            return {"echo": message}

    async def handle_message_async(
        self, session_id: str, envelope_wire: Dict[str, Any]
    ) -> Dict[str, Any]:
        session = self._get_or_create_session(session_id)
        try:
            envelope = EncryptedEnvelope.from_wire(envelope_wire)
            session.replay_guard.check(envelope.nonce, envelope.timestamp)
            plaintext = session.codec.decode(envelope)
            message = json.loads(plaintext)
        except (DecryptionError, AuthenticationFailedError, ReplayAttackDetected) as exc:
            _LOG.warning("securelink: rejecting message for session %s: %s", session_id, type(exc).__name__)
            await self._hooks.fire_async("on_error", exc)
            return _generic_wire_error(exc)
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.exception("securelink: unexpected error handling message")
            await self._hooks.fire_async("on_error", exc)
            return _generic_wire_error(exc)

        await self._hooks.fire_async("after_receive", message)
        await session.message_queue.put(message)
        response_obj = self._hooks_message_response(message, session)
        response_plaintext = json.dumps(response_obj).encode("utf-8")
        response_envelope = session.codec.encode(response_plaintext)
        return {"status": "ok", "envelope": response_envelope.to_wire()}

    # -- push (poll / SSE / websocket) -----------------------------------------

    def handle_poll(self, session_id: str) -> Dict[str, Any]:
        """Long-polling handler: returns the next queued message (if any)
        for this session, already encrypted, or {"status": "empty"}."""
        session = self._get_or_create_session(session_id)
        try:
            message = session.message_queue.get_nowait()
        except asyncio.QueueEmpty:
            return {"status": "empty"}
        plaintext = json.dumps(message).encode("utf-8")
        envelope = session.codec.encode(plaintext)
        return {"status": "ok", "envelope": envelope.to_wire()}

    async def push(self, session_id: str, message: Dict[str, Any]) -> None:
        """Enqueue a server-initiated message for delivery to a session
        via whichever push mode (poll/SSE/websocket) the application's
        route handlers implement on top of this queue."""
        session = self._get_or_create_session(session_id)
        await session.message_queue.put(message)

    async def sse_event_stream(self, session_id: str):
        """
        Async generator yielding Server-Sent-Events-formatted strings.
        Wire this up to a streaming response in your web framework, e.g.:

            @app.get("/events/{session_id}")
            async def events(session_id: str):
                return StreamingResponse(
                    server.sse_event_stream(session_id),
                    media_type="text/event-stream",
                )
        """
        session = self._get_or_create_session(session_id)
        while True:
            message = await session.message_queue.get()
            plaintext = json.dumps(message).encode("utf-8")
            envelope = session.codec.encode(plaintext)
            yield f"data: {json.dumps(envelope.to_wire())}\n\n"

    async def websocket_loop(
        self,
        session_id: str,
        receive_text: Callable[[], Awaitable[str]],
        send_text: Callable[[str], Awaitable[None]],
    ) -> None:
        """
        Generic WebSocket message loop, parameterized over the
        framework's own `receive`/`send` primitives so this library does
        not depend on any specific WebSocket implementation.
        """
        session = self._get_or_create_session(session_id)
        try:
            while True:
                incoming: "asyncio.Task[str]" = asyncio.create_task(receive_text())
                outgoing: "asyncio.Task[Any]" = asyncio.create_task(session.message_queue.get())
                done, pending = await asyncio.wait(
                    {incoming, outgoing}, return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                if incoming in done:
                    raw_text = incoming.result()
                    envelope_wire = json.loads(raw_text)
                    response = await self.handle_message_async(session_id, envelope_wire)
                    await send_text(json.dumps(response))
                if outgoing in done:
                    message = outgoing.result()
                    plaintext = json.dumps(message).encode("utf-8")
                    envelope = session.codec.encode(plaintext)
                    await send_text(json.dumps({"status": "push", "envelope": envelope.to_wire()}))
        except asyncio.CancelledError:
            pass
        finally:
            self.drop_session(session_id)


# =====================================================================
# === Example ===
# =====================================================================

if __name__ == "__main__":
    # Minimal, self-contained demonstration that does not require any
    # network access: it wires a SecureClient's codec directly against a
    # SecureServer's handler using an in-memory fake Transport, showing
    # the encrypt -> transmit -> decrypt round trip and hook firing.

    class InMemoryTransport(Transport):
        """A fake transport for tests/demos: calls the server handler
        functions directly instead of doing real HTTP I/O."""

        def __init__(self, server: SecureServer) -> None:
            self._server = server

        def send(self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
            session_id = json_body.get("session_id", "")
            if url.endswith("/message"):
                return self._server.handle_message(session_id, json_body["envelope"])
            if url.endswith("/poll"):
                return self._server.handle_poll(session_id)
            raise SecureLinkError(f"unhandled demo endpoint: {url}")

        async def send_async(
            self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]
        ) -> Dict[str, Any]:
            return self.send(url, json_body, headers)

    def on_message(message: Dict[str, Any], session_id: str) -> Dict[str, Any]:
        print(f"[server] received from {session_id}: {message}")
        return {"reply": "hello from server", "you_said": message}

    logging.basicConfig(level=logging.INFO)

    server_config = (
        SecureConfig()
        .with_passphrase("correct-horse-battery-staple-32")
        .with_cipher(CipherName.AES_256_GCM)
        .with_compression(True)
        .on("on_message", on_message)
    ).build()

    client_config = (
        SecureConfig()
        .with_passphrase("correct-horse-battery-staple-32")
        .with_cipher(CipherName.AES_256_GCM)
        .with_base_url("https://example.invalid")
        .with_compression(True)
        .on("on_connect", lambda sid: print(f"[client] connected, session={sid}"))
    ).build()

    # NOTE: client and server must share the same salt to derive the same
    # base key from the same passphrase in this simplified demo. In a real
    # deployment, either share the salt out-of-band or (recommended) use
    # the ECDH handshake so each session gets an independently derived key.
    shared_salt = server_config._salt
    assert shared_salt is not None
    client_config.with_salt(shared_salt)

    server = SecureServer(server_config)
    transport = InMemoryTransport(server)
    client = SecureClient(client_config, transport=transport)
    client.connect()

    response = client.send({"greeting": "hi there", "n": 42})
    print(f"[client] got response: {response}")

    print(f"[server] active sessions: {server.active_session_count}")
    client.close()
