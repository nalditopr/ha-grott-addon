"""Local TCP responder for the grott add-on.

Modes, set by env var GROTT_SINK_MODE:

- ``discard``: accept connections, read & discard, never reply.
  Used when ``forward_to_cloud=false`` and we just need grott's proxy
  forward to succeed so decode + MQTT publish run normally.

- ``capture``: log every byte received (hex + ASCII), with timestamps
  and per-connection IDs. For each connection, peek the first byte:
    * 0x16 → TLS ClientHello. Terminate TLS with a self-signed cert
      (auto-generated in /data) and log the decrypted plaintext from
      the dongle. This lets us see the application protocol inside.
    * anything else → assume plaintext probe (e.g. ``hello``). Echo
      back so the dongle gets an ACK.

Cert is generated on first run via openssl and persisted across
restarts/upgrades.
"""

import datetime
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time


CERT_PATH = "/data/sink_cert.pem"
KEY_PATH = "/data/sink_key.pem"
CERT_CN = os.environ.get("GROTT_SINK_CN", "gw-solar-dc.vidagrid.com")


def hexdump(data: bytes) -> str:
    hexed = data.hex()
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{hexed}   |{ascii_repr}|"


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def _log(cid: int, msg: str) -> None:
    print(f"[{_ts()}] [conn#{cid}] {msg}", flush=True)


def _frame(msg_type: int, payload: bytes) -> bytes:
    """Wrap payload in the dongle's framing: 2B type (BE) + 4B length (BE) + payload."""
    return struct.pack(">HI", msg_type, len(payload)) + payload


def build_reply(data: bytes, cid: int) -> bytes:
    """Guess an appropriate framed JSON ack based on the request.

    The protocol so far: ``[type:2B][len:4B][JSON]``. For the type=0x2002
    'registration' frame the dongle includes ``id``/``rand``/``sign``/``uptime``.
    We attempt a generic success reply mirroring its framing so the dongle
    advances to whatever comes next.
    """
    if len(data) < 6:
        _log(cid, "payload too short to parse — skipping reply")
        return b""

    msg_type, msg_len = struct.unpack(">HI", data[:6])
    body = data[6:6 + msg_len]
    _log(cid, f"parsed type=0x{msg_type:04x} length={msg_len} body_bytes={len(body)}")

    parsed = None
    try:
        parsed = json.loads(body.decode("utf-8"))
        _log(cid, f"parsed JSON: {parsed!r}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        _log(cid, "body is not UTF-8 JSON — treating as opaque")

    ack = {"result": 0, "time": int(time.time())}
    if isinstance(parsed, dict):
        if "id" in parsed:
            ack["id"] = parsed["id"]
        if "rand" in parsed:
            ack["rand"] = parsed["rand"]
    ack_body = json.dumps(ack, separators=(",", ":")).encode("utf-8")
    return _frame(msg_type, ack_body)


def ensure_cert() -> None:
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return
    print(f"[localsink] generating self-signed cert CN={CERT_CN}", flush=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_PATH, "-out", CERT_PATH,
            "-days", "3650", "-nodes",
            "-subj", f"/CN={CERT_CN}",
        ],
        check=True,
    )


def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_PATH, KEY_PATH)
    # Maximize chances of completing the handshake with quirky clients.
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx


def handle_capture(conn: socket.socket, addr, cid: int, ssl_ctx: ssl.SSLContext) -> None:
    _log(cid, f"OPEN from {addr[0]}:{addr[1]}")
    try:
        conn.settimeout(15)
        try:
            head = conn.recv(1, socket.MSG_PEEK)
        except OSError as e:
            _log(cid, f"peek failed: {e}")
            return
        if not head:
            _log(cid, "EOF before any data")
            return

        if head == b"\x16":
            _log(cid, "first byte 0x16 → TLS ClientHello, attempting termination")
            try:
                tls = ssl_ctx.wrap_socket(conn, server_side=True, do_handshake_on_connect=True)
            except ssl.SSLError as e:
                _log(cid, f"TLS handshake FAILED: {e}")
                return
            except OSError as e:
                _log(cid, f"TLS handshake socket error: {e}")
                return
            try:
                _log(cid, f"TLS handshake OK — cipher={tls.cipher()} version={tls.version()}")
            except Exception:
                _log(cid, "TLS handshake OK")

            try:
                while True:
                    data = tls.recv(8192)
                    if not data:
                        _log(cid, "TLS EOF")
                        break
                    _log(cid, f"TLS RX {len(data)}B: {hexdump(data)}")
                    reply = build_reply(data, cid)
                    if not reply:
                        _log(cid, "no reply built — keep reading")
                        continue
                    try:
                        tls.sendall(reply)
                        _log(cid, f"TLS TX {len(reply)}B: {hexdump(reply)}")
                    except OSError as e:
                        _log(cid, f"TLS TX failed: {e}")
                        break
            finally:
                try:
                    tls.close()
                except OSError:
                    pass
        else:
            _log(cid, f"first byte 0x{head.hex()} → plaintext, echo mode")
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                _log(cid, f"RX {len(data)}B: {hexdump(data)}")
                try:
                    conn.sendall(data)
                    _log(cid, f"TX {len(data)}B (echo)")
                except OSError as e:
                    _log(cid, f"TX failed: {e}")
                    break
    except OSError as e:
        _log(cid, f"socket error: {e}")
    finally:
        _log(cid, "CLOSE")
        try:
            conn.close()
        except OSError:
            pass


def handle_discard(conn: socket.socket, addr, cid: int, ssl_ctx) -> None:
    try:
        while conn.recv(4096):
            pass
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5280
    mode = os.environ.get("GROTT_SINK_MODE", "discard").strip().lower()
    handler = handle_capture if mode == "capture" else handle_discard
    ssl_ctx = None
    if mode == "capture":
        ensure_cert()
        ssl_ctx = make_ssl_context()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    print(f"localsink mode={mode} listening on 127.0.0.1:{port}", flush=True)

    cid = 0
    while True:
        conn, addr = srv.accept()
        cid += 1
        threading.Thread(target=handler, args=(conn, addr, cid, ssl_ctx), daemon=True).start()


if __name__ == "__main__":
    main()
