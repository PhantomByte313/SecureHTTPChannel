# SecureHTTPChannel

A single-file, production-oriented Python library for building an **encrypted
communication protocol over HTTP**. Drop `securelink.py` into any project and
get authenticated encryption, forward secrecy, replay protection, retries,
and a builder-style configuration API — with a `requests`/`httpx`-like feel.

```python
from securelink import SecureClient, SecureServer, SecureConfig
```

---

## Table of Contents

1. [Why securelink](#why-securelink)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [Quickstart](#quickstart)
5. [Configuration Reference (`SecureConfig`)](#configuration-reference-secureconfig)
6. [Client API (`SecureClient`)](#client-api-secureclient)
7. [Server API (`SecureServer`)](#server-api-secureserver)
8. [Lifecycle Hooks](#lifecycle-hooks)
9. [Forward Secrecy with ECDH](#forward-secrecy-with-ecdh)
10. [Key Rotation](#key-rotation)
11. [Replay Protection](#replay-protection)
12. [Compression](#compression)
13. [Errors & Failure Handling](#errors--failure-handling)
14. [Transport Modes: Polling, SSE, WebSocket](#transport-modes-polling-sse-websocket)
15. [Streaming Large Payloads](#streaming-large-payloads)
16. [Wiring the Server into an HTTP Framework](#wiring-the-server-into-an-http-framework)
17. [Full Example: A Tiny Chat App](#full-example-a-tiny-chat-app)
18. [Testing](#testing)
19. [Security Notes & Threat Model](#security-notes--threat-model)
20. [FAQ](#faq)

---

## Why securelink

HTTP alone gives you transport, but not confidentiality, integrity, or
protection from replay at the *application* layer (that's normally TLS's
job, and TLS is terminated at proxies/load balancers you may not fully
trust). `securelink` adds an authenticated, application-level encryption
layer on top of HTTP so that:

- Every message is individually encrypted and authenticated, independent
  of whatever TLS termination happens in front of your server.
- Two peers can establish an ephemeral session key (via ECDH) so that even
  if a long-term secret leaks later, past traffic stays unreadable.
- Replayed or tampered messages are rejected before your application logic
  ever sees them.
- You get a clean, typed, builder-style configuration surface instead of
  wiring raw `cryptography` primitives by hand.

It is **not** a replacement for TLS — use both. Think of it as an
end-to-end envelope inside your HTTP payloads.

---

## Installation

`securelink.py` is a single file — copy it into your project. It has two
runtime dependencies:

```bash
pip install cryptography httpx
```

- `cryptography` is required always (AES-GCM, ChaCha20-Poly1305, X25519,
  HKDF, PBKDF2).
- `httpx` is required only if you use the built-in `SecureClient` /
  `HttpxTransport`. If you supply your own `Transport` implementation
  (see [Wiring the Server](#wiring-the-server-into-an-http-framework)),
  `httpx` is not needed on the server side at all.

Python 3.9+ is recommended (the codebase uses modern type hints and
`asyncio` features).

---

## Core Concepts

| Concept | What it is |
|---|---|
| `SecureConfig` | A builder object describing everything: passphrase, cipher, timeouts, proxy, retries, compression, TLS verification, transport mode, hooks. |
| `SecureClient` | High-level client. Sync **and** async APIs. Owns one session. |
| `SecureServer` | High-level server-side counterpart. Framework-agnostic — you wire its handler methods into whatever HTTP server/framework you use. Manages many concurrent sessions. |
| `EncryptedEnvelope` | The wire format of one encrypted message: nonce, ciphertext, HMAC tag, timestamp, key id, compression flag. |
| `CipherSuite` | Pluggable AEAD strategy — `AESGCMCipherSuite` (default) or `ChaCha20CipherSuite`. |
| Session | Per-connection state: session id, rotating key material, replay-guard cache, optional ECDH state. The server holds one per connected client. |

---

## Quickstart

### 1. Minimal client + server, no real network (in-memory transport)

This is the fastest way to see the whole pipeline (encrypt → transmit →
decrypt) without standing up an HTTP server — useful for tests.

```python
from securelink import SecureConfig, SecureClient, SecureServer, Transport, CipherName

class InMemoryTransport(Transport):
    """Directly calls the server's handlers instead of doing real HTTP I/O."""
    def __init__(self, server):
        self._server = server

    def send(self, url, json_body, headers):
        session_id = json_body.get("session_id", "")
        if url.endswith("/message"):
            return self._server.handle_message(session_id, json_body["envelope"])
        if url.endswith("/poll"):
            return self._server.handle_poll(session_id)
        raise ValueError(f"unhandled endpoint: {url}")

    async def send_async(self, url, json_body, headers):
        return self.send(url, json_body, headers)

def on_message(message, session_id):
    print(f"server got: {message}")
    return {"reply": "got it"}

shared_passphrase = "correct horse battery staple 2026"

server_config = (
    SecureConfig()
    .with_passphrase(shared_passphrase)
    .with_cipher(CipherName.AES_256_GCM)
    .on("on_message", on_message)
).build()

client_config = (
    SecureConfig()
    .with_passphrase(shared_passphrase)
    .with_base_url("https://example.invalid")   # unused by InMemoryTransport
    .with_salt(server_config._salt)              # demo only, see note below
).build()

server = SecureServer(server_config)
client = SecureClient(client_config, transport=InMemoryTransport(server))
client.connect()

response = client.send({"hello": "world"})
print(response)   # {'reply': 'got it'}
```

> **Note on the shared salt in this demo:** a KDF salt is not secret, but
> two peers deriving a key from the *same passphrase* must use the *same
> salt* to land on the same key. In this toy example we simply copy the
> server's randomly generated salt into the client's config. In real
> deployments, either transmit the salt out-of-band (it's fine to send it
> in the clear) or — better — skip static-passphrase key agreement
> entirely and use the [ECDH handshake](#forward-secrecy-with-ecdh)
> instead, which derives a fresh session key with no shared salt needed
> ahead of time.

### 2. Real HTTP, using Python's built-in `http.server`

`SecureServer` is framework-agnostic on purpose — you wire three plain
handler methods (`handle_handshake`, `handle_message`, `handle_poll`) into
whatever HTTP layer you want. Here's the minimal version using only the
standard library (no FastAPI, no Flask):

```python
# server.py
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from securelink import SecureConfig, SecureServer, CipherName

config = (
    SecureConfig()
    .with_passphrase("correct horse battery staple 2026")
    .with_cipher(CipherName.AES_256_GCM)
).build()

server = SecureServer(config)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")

        if self.path == "/handshake":
            result = server.handle_handshake(payload["session_id"], payload["client_public_key"])
        elif self.path == "/message":
            result = server.handle_message(payload["session_id"], payload["envelope"])
        elif self.path == "/poll":
            result = server.handle_poll(payload["session_id"])
        else:
            result = {"status": "error", "detail": "not found"}

        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
```

```python
# client.py
from securelink import SecureConfig, SecureClient, CipherName

config = (
    SecureConfig()
    .with_passphrase("correct horse battery staple 2026")
    .with_cipher(CipherName.AES_256_GCM)
    .with_base_url("http://127.0.0.1:8000")
).build()

client = SecureClient(config)
client.connect()
client.perform_ecdh_handshake()          # optional, recommended: forward secrecy
response = client.send({"hello": "world"})
print(response)
client.close()
```

Run `server.py`, then `client.py`, and you have a fully encrypted
request/response exchange over plain HTTP.

---

## Configuration Reference (`SecureConfig`)

`SecureConfig` is a fluent builder. Call `.build()` at the end — it
validates everything up front (fail-fast) and fills in sane defaults.

```python
from securelink import SecureConfig, CipherName, KDFName, TransportMode, RetryPolicy

config = (
    SecureConfig()
    .with_passphrase("a long, high-entropy shared secret")
    .with_cipher(CipherName.AES_256_GCM)             # or CipherName.CHACHA20_POLY1305
    .with_kdf(KDFName.PBKDF2_HMAC_SHA256, iterations=390_000)
    .with_salt(b"...16+ random bytes...")            # optional; auto-generated if omitted
    .with_timeouts(connect=5, read=30, write=30)
    .with_proxy("socks5://proxy.local:1080", username="u", password="p")
    .with_retry_policy(RetryPolicy(max_attempts=5, base_delay=0.5, max_delay=30.0))
    .with_compression(True)
    .with_tls_verify(True)
    .with_log_level("WARNING")
    .with_transport_mode(TransportMode.SSE)          # POLLING | WEBSOCKET | SSE
    .with_ecdh(True)                                 # declarative flag; call perform_ecdh_handshake() to actually run it
    .with_key_rotation(every_seconds=3600, every_messages=10_000)
    .with_replay_window(30)                          # seconds
    .with_heartbeat_interval(15)                     # seconds
    .with_base_url("https://api.example.com")
    .on("on_message", my_handler)
).build()
```

| Method | Purpose |
|---|---|
| `.with_passphrase(str \| bytes)` | **Required.** Minimum 8 characters. Never used as a key directly — always passed through a KDF. |
| `.with_cipher(CipherName)` | `AES_256_GCM` (default) or `CHACHA20_POLY1305`. |
| `.with_kdf(KDFName, iterations)` | `PBKDF2_HMAC_SHA256` (default, min. 100,000 iterations enforced) or `HKDF_SHA256`. |
| `.with_salt(bytes)` | KDF salt, ≥16 bytes. Auto-generated randomly if you don't supply one — see the note on sharing it in [Quickstart](#quickstart). |
| `.with_timeouts(connect, read, write)` | Per-operation HTTP timeouts, in seconds. |
| `.with_proxy(url, username, password)` | HTTP or SOCKS5 proxy, with optional auth embedded into the URL. |
| `.with_retry_policy(RetryPolicy)` | Exponential backoff with jitter: `max_attempts`, `base_delay`, `max_delay`, `jitter`. |
| `.with_compression(bool)` | Pre-encryption compression with padding safeguards — see [Compression](#compression). |
| `.with_tls_verify(bool)` | Disable only against trusted test endpoints; a warning is logged if disabled. |
| `.with_log_level(level)` | Standard `logging` level for the `securelink` logger. |
| `.with_transport_mode(TransportMode)` | Declarative hint for which push mechanism your application will implement (`POLLING`, `WEBSOCKET`, `SSE`). |
| `.with_ecdh(bool)` | Declarative flag. Actually performing the handshake is done via `client.perform_ecdh_handshake()`. |
| `.with_key_rotation(every_seconds, every_messages)` | See [Key Rotation](#key-rotation). |
| `.with_replay_window(seconds)` | Acceptance window for the replay guard. |
| `.with_heartbeat_interval(seconds)` | Interval for the client's async heartbeat loop (`0` disables it). |
| `.with_base_url(str)` | Base URL the `SecureClient` targets. |
| `.on(event, callback)` | Register a [lifecycle hook](#lifecycle-hooks). |

`.build()` raises `ConfigError` immediately if, for example, the
passphrase is missing/too short, timeouts are non-positive, the replay
window is non-positive, or the PBKDF2 iteration count is unsafely low.

---

## Client API (`SecureClient`)

```python
client = SecureClient(config, transport=None)  # transport defaults to HttpxTransport
```

### Sync

```python
client.connect()
client.perform_ecdh_handshake()          # optional
response = client.send({"key": "value"})
incoming = client.receive()              # polling-mode receive; None if nothing queued
client.close()
```

### Async

```python
async with SecureClient(config) as client:
    await client.send_async({"key": "value"})
    reply = await client.receive_async()
```

`async with` calls `connect_async()` on enter and `close_async()` on
exit, and — if `with_heartbeat_interval` is non-zero — starts a
background heartbeat task automatically.

### Streaming large payloads

```python
chunks = [big_data[i:i+65536] for i in range(0, len(big_data), 65536)]
client.send_stream(chunks)   # each chunk independently encrypted & authenticated
```

Every method that touches the network goes through the client's retry
policy and circuit breaker automatically; you don't need to wrap calls in
your own retry loop.

---

## Server API (`SecureServer`)

`SecureServer` never opens a socket itself — it exposes plain handler
methods you call from your own HTTP layer (see
[Wiring the Server](#wiring-the-server-into-an-http-framework)):

| Method | Use for |
|---|---|
| `handle_handshake(session_id, client_public_key_b64)` | ECDH handshake endpoint. |
| `handle_message(session_id, envelope_wire)` | Sync message endpoint. |
| `handle_message_async(session_id, envelope_wire)` | Async message endpoint. |
| `handle_poll(session_id)` | Long-polling receive endpoint. |
| `push(session_id, message)` | Enqueue a server-initiated message (async). |
| `sse_event_stream(session_id)` | Async generator producing SSE-formatted lines. |
| `websocket_loop(session_id, receive_text, send_text)` | Generic WebSocket message loop, parameterized over your framework's send/receive primitives. |
| `drop_session(session_id)` / `prune_idle_sessions(max_idle_seconds)` | Session lifecycle management. |
| `active_session_count` | Current number of tracked sessions. |

Sessions are created lazily on first contact and isolated from each
other: each has its own key material, replay-guard cache, and message
queue.

---

## Lifecycle Hooks

Register hooks via `.on(event, callback)` on `SecureConfig`. Callbacks
may be sync or `async def` — both are supported transparently.

| Event | Fires when | Typical signature |
|---|---|---|
| `on_connect` | Client connects / server sees a new session | `(session_id)` |
| `on_disconnect` | Client closes / server drops a session | `(session_id)` |
| `on_message` | **Server:** after successfully decrypting an incoming message — its return value (a dict) becomes the encrypted response. **Client:** after decrypting any response. | `(message, session_id)` on the server; `(message)` on the client |
| `on_error` | Any transport or crypto error | `(exception_or_error_payload)` |
| `before_send` | Client, right before encrypting an outgoing message | `(message)` |
| `after_receive` | Right after successfully decrypting a message, before dispatch | `(message)` |

Exceptions raised inside a hook are caught and logged — they never crash
the send/receive pipeline.

---

## Forward Secrecy with ECDH

By default, both peers derive their key from the same
passphrase+salt — meaning if that passphrase ever leaks, **all** past
traffic encrypted under it becomes decryptable. The ECDH handshake fixes
this: it generates fresh X25519 key pairs per session, computes a shared
secret that only existed in memory for that session, and derives the
session key from it via HKDF.

```python
client.connect()
client.perform_ecdh_handshake()   # POSTs to /handshake by default
client.send({"now": "forward-secret"})
```

On the server side, `handle_handshake` does the matching half of the
exchange automatically — no extra code needed beyond wiring the
`/handshake` route.

Once a session has done ECDH, all its `KeyRing`s (cipher + HMAC) are
re-derived from the shared secret, so key rotation and replay protection
continue to work exactly as before, just on ephemeral keys.

---

## Key Rotation

Configured via `.with_key_rotation(every_seconds=..., every_messages=...)`.

**Why rotation is deterministic, not random:** two independent peers each
run their own key-tracking logic with no side channel to say "I just
rotated." securelink's `KeyRing` derives each rotation "epoch" key as
`HKDF(base_secret, info=f"epoch-{n}")`, where `n` is a pure function of
elapsed wall-clock time (or message count) applied to the *same* base
secret and the *same* rotation policy on both ends. As long as both sides
share the base secret (from the passphrase+salt or an ECDH exchange), they
independently compute identical epoch keys with zero additional
coordination messages — similar in spirit to the epoch/ratchet idea used
by protocols like Signal, simplified for a request/response transport.

A small window of adjacent epochs is kept derivable so that clock skew or
messages that straddle a rotation boundary can still be decrypted.

---

## Replay Protection

Every `EncryptedEnvelope` carries a `timestamp` and a unique `nonce`.
`ReplayGuard`:

1. Rejects any message whose timestamp falls outside the configured
   `replay_window_seconds` (`ReplayAttackDetected`).
2. Rejects any message whose `(nonce)` has already been seen within that
   window, even if it's a byte-for-byte valid replay of a previously
   accepted message.
3. Prunes its internal cache automatically as the window slides forward,
   with a hard cap as a safety valve against memory exhaustion.

This happens transparently inside `handle_message` / `handle_message_async`
— on rejection, the caller gets a single generic error, never a
distinguishing reason (see [Errors](#errors--failure-handling)).

---

## Compression

```python
config.with_compression(True)
```

Compressing plaintext before encryption is a well-known foot-gun
(CRIME/BREACH-style oracles) when compressed data mixes
attacker-controlled and secret content. securelink mitigates this by:

- Only compressing payloads above a minimum size threshold.
- Padding compressed output to a fixed bucket size before encryption, so
  ciphertext length reveals only which size bucket a message falls into,
  not its exact size.

This reduces, but does not eliminate, the risk for all threat models. If
your application reflects attacker-controlled data back into a compressed
response alongside a secret, keep compression **off** for that data path.

---

## Errors & Failure Handling

All errors that could be triggered by a remote (possibly hostile) peer
are typed:

| Exception | Meaning |
|---|---|
| `DecryptionError` | AEAD authentication/decryption failed. |
| `AuthenticationFailedError` | The defense-in-depth HMAC layer failed. |
| `HandshakeError` | ECDH handshake couldn't be completed. |
| `ReplayAttackDetected` | Timestamp out of window, or duplicate nonce. |
| `ConnectionTimeoutError` | A network operation exceeded its timeout, or the retry budget was exhausted. |
| `ConfigError` | Invalid or incomplete `SecureConfig`. |
| `CircuitOpenError` | The circuit breaker is open; the call was rejected without hitting the network. |

**Fail-closed by design:** on the server, any authentication/integrity
failure returns a single generic `{"status": "error", "detail": "..."}`
payload to the remote party — full details are logged locally only, with
sensitive data never included, so an attacker probing the endpoint can't
use error content as an oracle to tell "bad MAC" apart from "replay
detected" apart from "malformed envelope."

A built-in `CircuitBreaker` stops hammering an unresponsive server: after
a configurable number of consecutive failures, further calls fail fast
for a cooldown period before a single trial call is allowed through.

---

## Transport Modes: Polling, SSE, WebSocket

Raw HTTP is request/response only, so server-initiated push needs one of
three patterns, all built on the same `session.message_queue`:

- **Polling** — `client.receive()` / `handle_poll`. Simplest; call it on
  an interval.
- **SSE** — `server.sse_event_stream(session_id)` is an async generator
  of `data: ...` lines; wire it into a streaming response in your
  framework of choice.
- **WebSocket** — `server.websocket_loop(session_id, receive_text,
  send_text)` is a generic loop parameterized over your framework's own
  send/receive primitives, so securelink doesn't hard-depend on any
  specific WebSocket implementation.

`.with_transport_mode(...)` on `SecureConfig` is a declarative label for
which of these your application wires up — securelink itself doesn't
open sockets, so switching modes is a matter of which server route you
implement, not a config flag that changes behavior by itself.

---

## Streaming Large Payloads

For payloads too large to hold entirely in memory, `send_stream` splits
data into chunks, encrypting each one independently, and streams them to
the server without materializing the whole plaintext (or whole
ciphertext) at once:

```python
def read_chunks(path, size=1 << 16):
    with open(path, "rb") as f:
        while chunk := f.read(size):
            yield chunk

client.send_stream(list(read_chunks("large_file.bin")))
```

---

## Wiring the Server into an HTTP Framework

`SecureServer`'s handler methods take and return plain dicts, so wiring
them into any framework is a matter of a few lines. Examples:

**FastAPI**
```python
@app.post("/message")
async def message(payload: dict):
    return await server.handle_message_async(payload["session_id"], payload["envelope"])
```

**Flask**
```python
@app.post("/message")
def message():
    payload = request.get_json()
    return jsonify(server.handle_message(payload["session_id"], payload["envelope"]))
```

**Plain `http.server`** — see [Quickstart](#quickstart) above.

---

## Full Example: A Tiny Chat App

A complete two-file chat example (`chat_server.py`, `chat_client.py`)
built on top of `securelink.py` is included alongside this README. It
demonstrates:

- A stdlib-only server (`http.server`, no external HTTP framework).
- ECDH handshake for forward secrecy on every chat session.
- Broadcasting an incoming chat message to all other connected sessions
  via the `on_message` hook and `server.push(...)`.
- A background polling thread on the client that prints incoming
  messages while the main thread reads what you type.

Run the server, then run the client in two or more terminals:

```bash
pip install cryptography httpx
python chat_server.py
python chat_client.py   # repeat in another terminal for a second user
```

---

## Testing

Because `Transport` is an injectable interface, you can unit-test both
sides without any real networking:

```python
class FakeTransport(Transport):
    def send(self, url, json_body, headers): ...
    async def send_async(self, url, json_body, headers): ...

client = SecureClient(config, transport=FakeTransport())
```

`SecureServer`'s handlers are plain functions taking/returning dicts, so
they can be called directly in tests without spinning up an HTTP server
at all — see the `InMemoryTransport` pattern in
[Quickstart](#quickstart).

---

## Security Notes & Threat Model

- **This is application-layer encryption on top of HTTP, not a
  replacement for TLS.** Run it over HTTPS in production; securelink
  protects your payloads from anything that can see or modify traffic
  *after* TLS termination (proxies, load balancers, logging
  middleware), and gives you cryptographic guarantees that don't depend
  on your TLS configuration being perfect everywhere.
- Nonces are generated fresh (CSPRNG) for every message and never reused
  under the same key — nonce reuse under AES-GCM/ChaCha20-Poly1305 is
  catastrophic (it can leak the authentication key and enable forgeries).
- Passphrases are never used as keys directly — always passed through
  PBKDF2 or HKDF.
- Prefer the ECDH handshake over static passphrase-derived keys whenever
  you can, for forward secrecy.
- `.with_tls_verify(False)` should only ever be used against trusted test
  endpoints; it logs a warning when set.
- Compression safeguards reduce, but do not eliminate, CRIME/BREACH-style
  risk — keep compression off for any data path where attacker-controlled
  and secret content are mixed before encryption.
- Error responses are intentionally generic on the wire; don't add your
  own code that echoes exception details back to a remote peer.

---

## FAQ

**Do I need `httpx` on my server?**
No — the server side is transport-agnostic (see
[Wiring the Server](#wiring-the-server-into-an-http-framework)). `httpx`
is only used by `SecureClient`'s default `HttpxTransport`.

**Can I use a completely different transport (e.g., raw sockets, MQTT)?**
Yes — implement the `Transport` interface (`send` / `send_async`) and
pass it to `SecureClient(config, transport=your_transport)`.

**What happens if the passphrase leaks after the fact?**
Any traffic that used a passphrase-derived key directly (no ECDH) is
retroactively decryptable. Traffic from sessions that completed an ECDH
handshake stays safe, because the session key never depended on the
passphrase alone and the ephemeral private keys are discarded at session
end.

**Why do I get `ConfigError: PBKDF2 iteration count is too low`?**
securelink enforces a minimum of 100,000 PBKDF2 iterations as a floor
against brute-force attacks on the passphrase. Raise it further
(`with_kdf(iterations=600_000)` or more) for extra margin if your
threat model calls for it.
