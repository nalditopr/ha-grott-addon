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

# MITM upstream — when set, terminates TLS, opens parallel TLS to upstream,
# and shuttles bytes both ways (logging + MQTT publish). Bypasses local
# reply generation. Use to observe the real cloud's responses.
MITM_HOST = os.environ.get("GROTT_MITM_HOST", "").strip()
MITM_PORT = int(os.environ.get("GROTT_MITM_PORT", "0") or "0")

# MQTT config from environment (injected by run.sh)
MQTT_HOST = os.environ.get("GROTT_MQTT_HOST", "")
MQTT_PORT = int(os.environ.get("GROTT_MQTT_PORT", "1883"))
MQTT_TOPIC = os.environ.get("GROTT_MQTT_TOPIC", "energy/growatt")
MQTT_USER = os.environ.get("GROTT_MQTT_USER", "")
MQTT_PSW = os.environ.get("GROTT_MQTT_PSW", "")
MQTT_RETAIN = os.environ.get("GROTT_MQTT_RETAIN", "false").lower() == "true"

_mqtt_client = None
_mqtt_lock = threading.Lock()
_ha_discovery_sent = False


# Sensors to expose via HA MQTT discovery. Each entry:
#   key — the field name in the energy/growatt/status JSON
#   sensor config keys per HA spec (name, unit, device_class, state_class, icon)
HA_SENSORS = [
    {"key": "wifi_rssi", "name": "WiFi RSSI", "unit": "dBm",
     "device_class": "signal_strength", "state_class": "measurement"},
    {"key": "wifi_name", "name": "WiFi SSID", "icon": "mdi:wifi"},
    {"key": "firmware", "name": "Firmware", "icon": "mdi:chip"},
    {"key": "hardware_model", "name": "Hardware Model", "icon": "mdi:chip"},
    {"key": "inverter_model", "name": "Inverter Model", "icon": "mdi:solar-power"},
    {"key": "serial", "name": "Datalogger Serial", "icon": "mdi:barcode"},
    {"key": "reset_reason", "name": "Last Reset Reason", "icon": "mdi:restart"},
    {"key": "timezone", "name": "Timezone", "icon": "mdi:clock-outline"},
    {"key": "device_timestamp_us", "name": "Device Timestamp µs",
     "icon": "mdi:clock-digital"},
    {"key": "frame_size", "name": "Last Frame Size", "unit": "B",
     "state_class": "measurement", "icon": "mdi:format-size"},
    {"key": "upload_seq", "name": "Upload Sequence", "state_class": "measurement",
     "icon": "mdi:counter"},
    {"key": "upload_ts_us", "name": "Upload Timestamp µs",
     "state_class": "measurement", "icon": "mdi:timer-sand"},

    # Candidate sensors — provisional mappings pending day/night verification.
    # Whichever AC voltage stays near grid + battery voltage drops overnight
    # + SOC tracks battery state is the correct one.
    {"key": "candidate_ac_v_a", "name": "AC Voltage cand. A (+63)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_ac_v_b", "name": "AC Voltage cand. B (+110)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_ac_v_c", "name": "AC Voltage cand. C (+132)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_ac_v_d", "name": "AC Voltage cand. D (+216)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_bat_v_a", "name": "Battery V cand. A (+90)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_bat_v_b", "name": "Battery V cand. B (+95)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_bat_v_c", "name": "Battery V cand. C (+122)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_bat_v_d", "name": "Battery V cand. D (+148)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_bat_v_e", "name": "Battery V cand. E (+230)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_bat_v_f", "name": "Battery V cand. F (+232)",
     "unit": "V", "device_class": "voltage", "state_class": "measurement"},
    {"key": "candidate_soc_a", "name": "SOC cand. A (+91)",
     "unit": "%", "device_class": "battery", "state_class": "measurement"},
    {"key": "candidate_soc_b", "name": "SOC cand. B (+167)",
     "unit": "%", "device_class": "battery", "state_class": "measurement"},
    {"key": "candidate_soc_c", "name": "SOC cand. C (+180)",
     "unit": "%", "device_class": "battery", "state_class": "measurement"},
    {"key": "candidate_soc_d", "name": "SOC cand. D (+182)",
     "unit": "%", "device_class": "battery", "state_class": "measurement"},
]


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


def ha_publish_discovery(meta: dict, cid: int) -> None:
    """Send HA MQTT discovery configs so the status fields auto-create as sensors.

    Idempotent: publishes once per process. Uses serial as device id; falls
    back to a fixed id if serial is unknown.
    """
    global _ha_discovery_sent
    if _ha_discovery_sent:
        return
    client = get_mqtt_client()
    if client is None:
        return
    serial = meta.get("serial") or "unknown"
    device_id = f"grott_{serial}"
    device = {
        "identifiers": [device_id],
        "name": f"Grott Datalogger {serial}",
        "manufacturer": "Vidagrid (Growatt OEM)",
    }
    if "hardware_model" in meta:
        device["model"] = meta["hardware_model"]
    if "firmware" in meta:
        device["sw_version"] = meta["firmware"]

    state_topic = f"{MQTT_TOPIC}/status"
    sent = 0
    for s in HA_SENSORS:
        key = s["key"]
        cfg = {
            "name": s["name"],
            "state_topic": state_topic,
            "value_template": "{{ value_json." + key + " | default('') }}",
            "unique_id": f"{device_id}_{key}",
            "object_id": f"{device_id}_{key}",
            "device": device,
        }
        if "unit" in s:
            cfg["unit_of_measurement"] = s["unit"]
        if "device_class" in s:
            cfg["device_class"] = s["device_class"]
        if "state_class" in s:
            cfg["state_class"] = s["state_class"]
        if "icon" in s:
            cfg["icon"] = s["icon"]
        topic = f"homeassistant/sensor/{device_id}/{key}/config"
        try:
            # Discovery configs MUST be retained so HA picks them up on restart
            client.publish(topic, json.dumps(cfg), retain=True)
            sent += 1
        except Exception as e:
            _log(cid, f"HA discovery publish failed for {key}: {e}")
    if sent:
        _ha_discovery_sent = True
        _log(cid, f"HA discovery published — {sent} sensors as {device_id}")


def extract_metadata(data: bytes) -> dict:
    """Extract known metadata strings from a 0x260f binary payload."""
    import re
    text = data.decode("latin-1", errors="ignore")
    meta = {}

    # WiFi info — binary payload has control bytes between fields,
    # so we scan for field name substrings and extract nearby text.
    # Pattern is `field":"value"` with optional binary noise between them.
    rssi_match = re.search(r'wifi_rssi"\s*:\s*[\x00-\x1f]*([-]?\d+)', text)
    if rssi_match:
        try:
            meta["wifi_rssi"] = int(rssi_match.group(1))
        except ValueError:
            pass
    name_match = re.search(r'name"\s*:\s*"([^"]+)"', text)
    if name_match:
        meta["wifi_name"] = name_match.group(1)

    # Firmware version: pattern like x.x.x.x
    fw_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', text)
    if fw_match:
        meta["firmware"] = fw_match.group(1)

    # Model / serial patterns
    if "VC510103" in text:
        meta["hardware_model"] = "VC510103"
    if "VZP1N8602Z" in text:
        meta["inverter_model"] = "VZP1N8602Z"

    # Serial number: digits after VC510103
    serial_match = re.search(r'VC510103[^0-9]*(\d{6,})', text)
    if serial_match:
        meta["serial"] = serial_match.group(1)

    # Reset reason
    if "ESP_RST_" in text:
        rst_match = re.search(r'ESP_RST_\w+', text)
        if rst_match:
            meta["reset_reason"] = rst_match.group()

    # Timezone
    tz_match = re.search(r'GMT[+-]\d+', text)
    if tz_match:
        meta["timezone"] = tz_match.group()

    # Timestamp at end of payload: [1234567890123]
    ts_match = re.search(r'\[(\d{13,16})\]', text)
    if ts_match:
        meta["device_timestamp_us"] = int(ts_match.group(1))

    # MAC address fragments (best effort)
    mac_match = re.search(r'mac\s+([0-9A-Fa-f:]+)', text)
    if mac_match:
        meta["mac"] = mac_match.group(1)

    # Binary fields at known offsets inside the 0x260f payload.
    # data starts with the 2-byte 0x260f type marker, then the payload.
    # Verified by diffing 13 captures:
    #   data[18]    = upload sequence counter (1 byte, increments per upload)
    #   data[34:38] = upload microsecond timestamp delta (4-byte BE)
    if len(data) >= 38 and data[:2] == b"\x26\x0f":
        meta["upload_seq"] = data[18]
        meta["upload_ts_us"] = struct.unpack(">I", data[34:38])[0]

    # Candidate telemetry fields, anchored at "ULSP05" inside the payload.
    # Identified by night-time captures showing values consistent with
    # AC voltage (220-260V) and 16-cell LiFePO4 battery (45-55V). Marked
    # _candidate_ pending day/night verification — the correct one is
    # the one that drops slowly overnight + rises with morning sun.
    anchor_idx = data.find(b"ULSP05")
    if anchor_idx >= 0:
        a = anchor_idx + 6  # position right after ULSP05
        def be16(off, scale=1.0):
            if a + off + 2 > len(data):
                return None
            return struct.unpack(">H", data[a + off:a + off + 2])[0] / scale

        def u8(off):
            if a + off + 1 > len(data):
                return None
            return data[a + off]

        # AC voltage candidates (BE16 / 10 → volts)
        for off, suffix in [(63, "ac_v_a"), (110, "ac_v_b"),
                             (132, "ac_v_c"), (216, "ac_v_d")]:
            v = be16(off, 10)
            if v is not None:
                meta[f"candidate_{suffix}"] = v

        # Battery voltage candidates (BE16 / 100 → volts)
        for off, suffix in [(90, "bat_v_a"), (95, "bat_v_b"),
                             (122, "bat_v_c"), (148, "bat_v_d"),
                             (230, "bat_v_e"), (232, "bat_v_f")]:
            v = be16(off, 100)
            if v is not None:
                meta[f"candidate_{suffix}"] = v

        # SOC candidates (BE16, range 0-100)
        for off, suffix in [(91, "soc_a"), (167, "soc_b"),
                             (180, "soc_c"), (182, "soc_d")]:
            v = be16(off, 1)
            if v is not None:
                meta[f"candidate_{suffix}"] = int(v)

    return meta


def log_frame(data: bytes, meta: dict, cid: int) -> None:
    """Persist frame hex + metadata to /data for offline analysis."""
    import pathlib, glob
    frame_dir = pathlib.Path("/data/frames")
    frame_dir.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = frame_dir / f"{ts}_conn{cid}"
    try:
        (base.with_suffix(".hex")).write_text(data.hex())
        (base.with_suffix(".json")).write_text(json.dumps(meta, indent=2, default=str))
    except OSError as e:
        _log(cid, f"frame log failed: {e}")
        return
    # Keep only the newest 200 frames
    files = sorted(frame_dir.glob("*.hex"), key=lambda p: p.stat().st_mtime)
    for old in files[:-200]:
        old.unlink(missing_ok=True)
        old.with_suffix(".json").unlink(missing_ok=True)


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

    # Real server replies observed by forwarding to gw-solar-dc.vidagrid.com:22015:
    #   0x2002 registration → 0x2102 {"code":0}
    #   0x260f data upload  → 0x2302 [<ts_us>, <next_ts_us>]
    #   0x2002 bad sign     → 0x2a02 {"action":"quit","reason":"..."}
    if msg_type == 0x2002:
        ack_body = b'{"code":0}'
        reply_type = 0x2102
    elif msg_type == 0x260f:
        now_us = int(time.time() * 1_000_000)
        ack_body = json.dumps([now_us, now_us + 60_000_000], separators=(",", ":")).encode("utf-8")
        reply_type = 0x2302
        # Extract and publish metadata from the binary payload
        meta = extract_metadata(data)
        if meta:
            meta["frame_type"] = "0x260f"
            meta["frame_size"] = len(data)
            mqtt_publish("status", meta, cid)
            _log(cid, f"metadata: {meta!r}")
            ha_publish_discovery(meta, cid)
        # Also publish raw hex for external decoders
        mqtt_publish("raw_hex", {"type": "0x260f", "hex": data.hex()}, cid)
        # Persist to disk for time-series comparison / RE
        log_frame(data, meta or {}, cid)
    else:
        # Generic fallback for unknown message types
        ack = {"result": 1, "time": int(time.time())}
        if isinstance(parsed, dict):
            for key in ["id", "rand"]:
                if key in parsed:
                    ack[key] = parsed[key]
        ack_body = json.dumps(ack, separators=(",", ":")).encode("utf-8")
        reply_type = msg_type & 0x0FFF
    return _frame(reply_type, ack_body)


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


def make_client_ssl_context() -> ssl.SSLContext:
    """Outbound TLS — disable cert verification (upstream may use a private CA)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _observe_frame(data: bytes, cid: int, direction: str) -> None:
    """Best-effort frame parse + MQTT publish for an observed buffer."""
    if len(data) < 6:
        return
    msg_type, msg_len = struct.unpack(">HI", data[:6])
    body = data[6:6 + msg_len]
    _log(cid, f"{direction} parsed type=0x{msg_type:04x} length={msg_len} body_bytes={len(body)}")
    parsed = None
    try:
        parsed = json.loads(body.decode("utf-8"))
        _log(cid, f"{direction} JSON: {parsed!r}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    sub = "mitm_dongle" if direction == "DONGLE→SRV" else "mitm_server"
    if isinstance(parsed, dict):
        mqtt_publish(sub, {"type": f"0x{msg_type:04x}", "data": parsed}, cid)
    elif isinstance(parsed, list):
        mqtt_publish(sub, {"type": f"0x{msg_type:04x}", "data": parsed}, cid)
    if msg_type == 0x260f and direction == "DONGLE→SRV":
        meta = extract_metadata(data)
        if meta:
            meta["frame_type"] = "0x260f"
            meta["frame_size"] = len(data)
            mqtt_publish("status", meta, cid)
            ha_publish_discovery(meta, cid)
        mqtt_publish("raw_hex", {"type": "0x260f", "hex": data.hex()}, cid)
        log_frame(data, meta or {}, cid)


def handle_mitm(conn: socket.socket, addr, cid: int, ssl_ctx: ssl.SSLContext) -> None:
    """TLS MITM: accept dongle TLS, open TLS to upstream, shuttle + observe both ways."""
    _log(cid, f"OPEN (MITM) from {addr[0]}:{addr[1]} → {MITM_HOST}:{MITM_PORT}")
    tls_in = None
    tls_up = None
    try:
        conn.settimeout(30)
        try:
            head = conn.recv(1, socket.MSG_PEEK)
        except OSError as e:
            _log(cid, f"peek failed: {e}")
            return
        if not head:
            _log(cid, "EOF before any data")
            return
        if head != b"\x16":
            _log(cid, f"first byte 0x{head.hex()} — plain (probe), echoing locally")
            # Dongle sends a "hello" probe before opening TLS. The real cloud
            # doesn't respond to it — it's purely a reachability check the
            # dongle does locally. Echo back so the dongle considers us reachable.
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    _log(cid, f"plain RX {len(data)}B: {hexdump(data)}")
                    try:
                        conn.sendall(data)
                    except OSError:
                        break
            except OSError:
                pass
            return

        # Accept dongle TLS
        try:
            tls_in = ssl_ctx.wrap_socket(conn, server_side=True, do_handshake_on_connect=True)
        except (ssl.SSLError, OSError) as e:
            _log(cid, f"dongle TLS handshake failed: {e}")
            return
        try:
            _log(cid, f"dongle TLS OK — {tls_in.version()} {tls_in.cipher()}")
        except Exception:
            pass

        # Open upstream TCP + TLS
        try:
            up_raw = socket.create_connection((MITM_HOST, MITM_PORT), timeout=10)
        except OSError as e:
            _log(cid, f"upstream connect failed: {e}")
            return
        client_ctx = make_client_ssl_context()
        try:
            tls_up = client_ctx.wrap_socket(up_raw, server_hostname=None)
        except (ssl.SSLError, OSError) as e:
            _log(cid, f"upstream TLS handshake failed: {e}")
            return
        try:
            _log(cid, f"upstream TLS OK — {tls_up.version()} {tls_up.cipher()}")
        except Exception:
            pass

        _shuttle_tls(tls_in, tls_up, cid)
    except OSError as e:
        _log(cid, f"socket error: {e}")
    finally:
        _log(cid, "CLOSE")
        for s in (tls_in, tls_up):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass


def _shuttle_tls(tls_in, tls_up, cid: int) -> None:
    stop = threading.Event()
    # Per-connection-per-direction buffer of EVERY byte seen.
    # Written out as one file per direction on connection close.
    buffers = {"DONGLE→SRV": bytearray(), "SRV→DONGLE": bytearray()}

    def pump(src, dst, label):
        try:
            while not stop.is_set():
                try:
                    data = src.recv(16384)
                except OSError as e:
                    _log(cid, f"{label} recv error: {e}")
                    break
                if not data:
                    _log(cid, f"{label} EOF")
                    break
                # Hexdump only the first 200B to avoid log spam on huge frames
                preview = data[:200]
                more = "" if len(data) <= 200 else f" ...+{len(data)-200}B"
                _log(cid, f"{label} {len(data)}B: {hexdump(preview)}{more}")
                try:
                    dst.sendall(data)
                except OSError as e:
                    _log(cid, f"{label} send error: {e}")
                    break
                buffers[label].extend(data)
                try:
                    _observe_frame(data, cid, label)
                except Exception as e:
                    _log(cid, f"{label} observe error: {e}")
        finally:
            stop.set()

    t1 = threading.Thread(target=pump, args=(tls_in, tls_up, "DONGLE→SRV"), daemon=True)
    t2 = threading.Thread(target=pump, args=(tls_up, tls_in, "SRV→DONGLE"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

    # Persist full transcripts for offline analysis
    try:
        import pathlib
        d = pathlib.Path("/data/mitm")
        d.mkdir(exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        unix_ts = int(time.time())
        for label, buf in buffers.items():
            if not buf:
                continue
            side = "dongle_to_srv" if label.startswith("DONGLE") else "srv_to_dongle"
            (d / f"{ts}_conn{cid}_{side}.bin").write_bytes(bytes(buf))

        # Also append to a rolling chronological log (NDJSON) for time-series
        # analysis. One line per connection. Hex only — no decoding here.
        log_path = d / "transcripts.ndjson"
        d_buf = bytes(buffers.get("DONGLE→SRV", b""))
        s_buf = bytes(buffers.get("SRV→DONGLE", b""))
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps({
                    "ts": unix_ts,
                    "iso": datetime.datetime.now().isoformat(),
                    "cid": cid,
                    "d_to_s_hex": d_buf.hex(),
                    "s_to_d_hex": s_buf.hex(),
                    "d_to_s_len": len(d_buf),
                    "s_to_d_len": len(s_buf),
                }) + "\n")
            # Rotate ndjson if it gets too big (>50MB)
            try:
                if log_path.stat().st_size > 50 * 1024 * 1024:
                    log_path.rename(d / f"transcripts_{unix_ts}.ndjson.bak")
            except OSError:
                pass
        except OSError as e:
            _log(cid, f"ndjson append failed: {e}")

        _log(cid, f"transcripts saved — D→S {len(d_buf)}B, S→D {len(s_buf)}B")
        # Rotate per-conn bins: keep last 50 connections (100 files)
        files = sorted(d.glob("*_conn*.bin"), key=lambda p: p.stat().st_mtime)
        for old in files[:-100]:
            old.unlink(missing_ok=True)
    except OSError as e:
        _log(cid, f"transcript persist failed: {e}")


def _shuttle_plain(c_in, c_out, cid: int) -> None:
    stop = threading.Event()

    def pump(src, dst, label):
        try:
            while not stop.is_set():
                try:
                    data = src.recv(16384)
                except OSError:
                    break
                if not data:
                    break
                _log(cid, f"{label} {len(data)}B: {hexdump(data)}")
                try:
                    dst.sendall(data)
                except OSError:
                    break
        finally:
            stop.set()

    t1 = threading.Thread(target=pump, args=(c_in, c_out, "DONGLE→SRV-plain"), daemon=True)
    t2 = threading.Thread(target=pump, args=(c_out, c_in, "SRV→DONGLE-plain"), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()


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
    ssl_ctx = None
    if mode == "mitm":
        if not MITM_HOST or not MITM_PORT:
            print("[localsink] mitm mode requires GROTT_MITM_HOST and GROTT_MITM_PORT", flush=True)
            sys.exit(2)
        ensure_cert()
        ssl_ctx = make_ssl_context()
        handler = handle_mitm
        print(f"[localsink] MITM upstream: {MITM_HOST}:{MITM_PORT}", flush=True)
    elif mode == "capture":
        ensure_cert()
        ssl_ctx = make_ssl_context()
        handler = handle_capture
    else:
        handler = handle_discard

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
