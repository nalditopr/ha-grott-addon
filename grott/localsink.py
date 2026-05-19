"""Local TCP responder / TLS MITM / MQTT publisher for the grott add-on.

Modes, set by env var GROTT_SINK_MODE:

- ``discard``: accept connections, read & discard, never reply.
- ``capture``: log every byte, terminate TLS, parse framed JSON, and
  publish decoded payloads to MQTT.

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

# MQTT is optional — only used when env vars are provided
try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None


def _make_mqtt_client():
    """Create an MQTT client compatible with paho-mqtt v1 and v2."""
    if mqtt is None:
        return None
    try:
        # paho-mqtt v2 requires CallbackAPIVersion
        import paho.mqtt.enums as mqtt_enums
        return mqtt.Client(mqtt_enums.CallbackAPIVersion.VERSION1)
    except Exception:
        # paho-mqtt v1
        return mqtt.Client()


CERT_PATH = "/data/sink_cert.pem"
KEY_PATH = "/data/sink_key.pem"
CERT_CN = os.environ.get("GROTT_SINK_CN", "gw-solar-dc.vidagrid.com")

# MQTT config from environment (injected by run.sh)
MQTT_HOST = os.environ.get("GROTT_MQTT_HOST", "")
MQTT_PORT = int(os.environ.get("GROTT_MQTT_PORT", "1883"))
MQTT_TOPIC = os.environ.get("GROTT_MQTT_TOPIC", "energy/growatt")
MQTT_USER = os.environ.get("GROTT_MQTT_USER", "")
MQTT_PSW = os.environ.get("GROTT_MQTT_PSW", "")
MQTT_RETAIN = os.environ.get("GROTT_MQTT_RETAIN", "false").lower() == "true"

_mqtt_client = None
_mqtt_lock = threading.Lock()


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def _log(cid: int, msg: str) -> None:
    print(f"[{_ts()}] [conn#{cid}] {msg}", flush=True)


def hexdump(data: bytes) -> str:
    hexed = data.hex()
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{hexed}   |{ascii_repr}|"


def _frame(msg_type: int, payload: bytes) -> bytes:
    """Wrap payload in the dongle's framing: 2B type (BE) + 4B length (BE) + payload."""
    return struct.pack(">HI", msg_type, len(payload)) + payload


def get_mqtt_client():
    global _mqtt_client
    if mqtt is None:
        return None
    if _mqtt_client is not None:
        return _mqtt_client
    with _mqtt_lock:
        if _mqtt_client is not None:
            return _mqtt_client
        if not MQTT_HOST:
            return None
        client = _make_mqtt_client()
        if client is None:
            return None
        if MQTT_USER:
            client.username_pw_set(MQTT_USER, MQTT_PSW)
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            client.loop_start()
            _mqtt_client = client
            print(f"[localsink] MQTT connected to {MQTT_HOST}:{MQTT_PORT} topic={MQTT_TOPIC}", flush=True)
        except Exception as e:
            print(f"[localsink] MQTT connect failed: {e}", flush=True)
            return None
    return _mqtt_client


def mqtt_publish(subtopic: str, payload: dict, cid: int = 0) -> None:
    client = get_mqtt_client()
    if client is None:
        return
    topic = f"{MQTT_TOPIC}/{subtopic}" if subtopic else MQTT_TOPIC
    try:
        client.publish(topic, json.dumps(payload), retain=MQTT_RETAIN)
        _log(cid, f"MQTT → {topic}")
    except Exception as e:
        _log(cid, f"MQTT publish failed: {e}")


def build_reply(data: bytes, cid: int) -> bytes:
    """Guess an appropriate framed JSON ack based on the request."""
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

    # Publish raw received frame to MQTT for observation / debugging
    if isinstance(parsed, dict):
        mqtt_publish("raw", {"type": msg_type, "data": parsed}, cid)

    ack = {"result": 1, "time": int(time.time())}
    if isinstance(parsed, dict):
        # Echo back all fields the dongle sent — some devices expect
        # sign/uptime/others to be mirrored in the ack.
        for key in ["id", "rand", "sign", "uptime"]:
            if key in parsed:
                ack[key] = parsed[key]
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
                    try:
                        data = tls.recv(8192)
                    except OSError as e:
                        _log(cid, f"TLS recv error: {e}")
                        break
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
                try:
                    data = conn.recv(4096)
                except OSError:
                    break
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
    bind_addr = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    mode = os.environ.get("GROTT_SINK_MODE", "discard").strip().lower()
    handler = handle_capture if mode == "capture" else handle_discard
    ssl_ctx = None
    if mode == "capture":
        ensure_cert()
        ssl_ctx = make_ssl_context()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_addr, port))
    srv.listen(64)
    print(f"localsink mode={mode} listening on {bind_addr}:{port}", flush=True)

    cid = 0
    while True:
        conn, addr = srv.accept()
        cid += 1
        threading.Thread(target=handler, args=(conn, addr, cid, ssl_ctx), daemon=True).start()


if __name__ == "__main__":
    main()
