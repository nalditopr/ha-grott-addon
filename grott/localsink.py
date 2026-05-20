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
    {"key": "inverter_clock", "name": "Inverter Clock", "icon": "mdi:clock-outline"},
]

# Live telemetry sensors, decoded from the 2nd (live) 0x260f message.
# These read from the `telemetry` subtopic (kept separate from `status` so
# metadata-only frames don't blank them out). See decode_telemetry().
HA_TELEMETRY_SENSORS = [
    {"key": "pv_power", "name": "PV Power", "unit": "W", "topic": "telemetry",
     "device_class": "power", "state_class": "measurement"},
    {"key": "pv1_voltage", "name": "PV1 Voltage", "unit": "V", "topic": "telemetry",
     "device_class": "voltage", "state_class": "measurement"},
    {"key": "pv1_current", "name": "PV1 Current", "unit": "A", "topic": "telemetry",
     "device_class": "current", "state_class": "measurement"},
    {"key": "pv1_power", "name": "PV1 Power", "unit": "W", "topic": "telemetry",
     "device_class": "power", "state_class": "measurement"},
    {"key": "pv2_voltage", "name": "PV2 Voltage", "unit": "V", "topic": "telemetry",
     "device_class": "voltage", "state_class": "measurement"},
    {"key": "pv2_current", "name": "PV2 Current", "unit": "A", "topic": "telemetry",
     "device_class": "current", "state_class": "measurement"},
    {"key": "pv2_power", "name": "PV2 Power", "unit": "W", "topic": "telemetry",
     "device_class": "power", "state_class": "measurement"},
    {"key": "grid_frequency", "name": "Grid Frequency", "unit": "Hz", "topic": "telemetry",
     "device_class": "frequency", "state_class": "measurement"},
    {"key": "grid_voltage", "name": "Grid Voltage", "unit": "V", "topic": "telemetry",
     "device_class": "voltage", "state_class": "measurement"},
    {"key": "battery_voltage", "name": "Battery Voltage", "unit": "V", "topic": "telemetry",
     "device_class": "voltage", "state_class": "measurement"},
]


# Stale discovery keys from old experimental versions (v0.6.5 "candidate"
# sensors) that were never real telemetry. Their retained discovery configs
# linger on the broker and show as dead entities under the device — purge them
# once on startup by publishing an empty retained payload to each config topic.
STALE_DISCOVERY_KEYS = [
    "candidate_ac_v_a", "candidate_ac_v_b", "candidate_ac_v_c", "candidate_ac_v_d",
    "candidate_bat_v_a", "candidate_bat_v_b", "candidate_bat_v_c",
    "candidate_bat_v_d", "candidate_bat_v_e", "candidate_bat_v_f",
    "candidate_soc_a", "candidate_soc_b", "candidate_soc_c", "candidate_soc_d",
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

    sent = 0
    for s in HA_SENSORS + HA_TELEMETRY_SENSORS:
        key = s["key"]
        # Sensor reads from its own subtopic ("status" for metadata,
        # "telemetry" for live PV fields).
        state_topic = f"{MQTT_TOPIC}/{s.get('topic', 'status')}"
        # No `| default('')` — HA rejects voltage/battery sensors whose state
        # is empty string. Letting Jinja return Undefined makes the entity
        # show 'unavailable' instead, which HA accepts.
        cfg = {
            "name": s["name"],
            "state_topic": state_topic,
            "value_template": "{{ value_json." + key + " }}",
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
    # Purge stale "candidate" discovery configs from old versions (idempotent).
    purged = 0
    for key in STALE_DISCOVERY_KEYS:
        topic = f"homeassistant/sensor/{device_id}/{key}/config"
        try:
            client.publish(topic, "", retain=True)
            purged += 1
        except Exception:
            pass

    if sent:
        _ha_discovery_sent = True
        _log(cid, f"HA discovery published — {sent} sensors as {device_id}"
                  f" ({purged} stale topics purged)")


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

    # Inverter real-time clock. Verified against capture wall-clock across
    # 267 night captures: a 6-byte field [HH, 00, MM, 0b, 00, SS] appears
    # ~232 bytes after the "ULSP05" anchor, where HH/MM/SS are plain bytes
    # (not BCD). The 0x0b separator confirms alignment; if it's absent the
    # field has shifted (variable-length upstream) so we skip rather than
    # emit a wrong time.
    anchor_idx = data.find(b"ULSP05")
    if anchor_idx >= 0:
        a = anchor_idx + 6
        # Search a small window for the [HH,00,MM,0b,00,SS] clock signature
        for off in range(228, 240):
            if a + off + 6 > len(data):
                break
            c = data[a + off:a + off + 6]
            hh, z1, mm, sep, z2, ss = c
            if z1 == 0 and sep == 0x0b and z2 == 0 and hh < 24 and mm < 60 and ss < 60:
                meta["inverter_clock"] = f"{hh:02d}:{mm:02d}:{ss:02d}"
                break

    return meta


def decode_telemetry(data: bytes) -> dict:
    """Decode live PV telemetry from the 2nd (live) 0x260f message.

    The live message starts with the marker ``26 0f 0b "gw"`` and a 40-byte
    header ending in ``0x81a4``; the body that follows is a Modbus-register-
    ordered block (Growatt ``divideBy10`` scaling). Field offsets were
    reverse-engineered and validated against the inverter's physical display
    plus a P = V*I self-consistency check across many captures (2026-05-20):

        body[5]  BE32  Ppv  total PV power    /10 -> W
        body[9]  BE16  Vpv1 string-1 voltage  /10 -> V
        body[11] BE16  Ipv1 string-1 current  /10 -> A
        body[13] BE32  Ppv1 string-1 power    /10 -> W   (== Vpv1*Ipv1)
        body[17] BE16  Vpv2 string-2 voltage  /10 -> V

    The live body reliably begins ``00 00 7d 00 01``. A big frame carries two
    0x260f messages (config snapshot + live batch) — we take the LAST marker.
    Returns {} if the message/anchor can't be located, the body signature is
    wrong, values fall outside sane ranges, or the P=V*I check fails (any of
    which means the variable-length front shifted alignment — better to emit
    nothing than a wrong reading).
    """
    sig = b"\x26\x0f\x0b\x67\x77"  # 26 0f 0b "gw"
    idx = data.rfind(sig)
    if idx < 0:
        return {}
    a = data.find(b"\x81\xa4", idx + 30, idx + 64)
    if a < 0:
        return {}
    body = data[a + 2:]
    # Live-body signature guard: distinguishes the live batch from the
    # config-snapshot 0x260f (which shares the gw-uploader marker).
    if len(body) < 19 or body[0:3] != b"\x00\x00\x7d":
        return {}
    try:
        ppv = struct.unpack_from(">I", body, 5)[0] / 10.0
        vpv1 = struct.unpack_from(">H", body, 9)[0] / 10.0
        ipv1 = struct.unpack_from(">H", body, 11)[0] / 10.0
        ppv1 = struct.unpack_from(">I", body, 13)[0] / 10.0
        vpv2 = struct.unpack_from(">H", body, 17)[0] / 10.0
    except struct.error:
        return {}
    # Sanity ranges (reject drifted alignment rather than publish garbage).
    # Vpv2 is checked separately below — it sits one field later and its offset
    # occasionally drifts at night, so a bad Vpv2 shouldn't sink the whole frame.
    if not (0 <= ppv <= 60000 and 0 <= vpv1 <= 1000 and 0 <= ipv1 <= 100
            and 0 <= ppv1 <= 60000):
        return {}
    # P = V*I cross-check on string 1 (the proof the offsets are right)
    vi = vpv1 * ipv1
    if ppv1 > 50 and abs(vi - ppv1) > max(60, 0.30 * ppv1):
        return {}
    result = {
        "pv_power": round(ppv, 1),
        "pv1_voltage": round(vpv1, 1),
        "pv1_current": round(ipv1, 1),
        "pv1_power": round(ppv1, 1),
    }
    if 0 <= vpv2 <= 500:  # plausible PV string voltage; drop drifted reads
        result["pv2_voltage"] = round(vpv2, 1)
    # Derived PV2 power/current. The dongle emits Ppv (total) and Ppv1 (string 1)
    # but NOT Ipv2/Ppv2 at any decodable position. For this 2-MPPT array,
    # Ppv2 = Ppv - Ppv1 and Ipv2 = Ppv2 / Vpv2 — both follow exactly from the
    # already-validated fields, so they're as reliable as Ppv/Ppv1/Vpv2.
    pv2_power = round(max(0.0, ppv - ppv1), 1)
    result["pv2_power"] = pv2_power
    if result.get("pv2_voltage", 0) > 10:
        result["pv2_current"] = round(pv2_power / result["pv2_voltage"], 1)

    # --- Grid block (anchored, since the variable-length PV region shifts it) ---
    # Grid frequency is a near-constant ~60.00 Hz (/100), a perfect anchor: scan
    # past the PV block for a value in 59-61 Hz, then grid voltage sits 2 bytes
    # after it (/10 V). Validated every frame: ~60.0 Hz, 121-125 V (PR 120V).
    for i in range(30, len(body) - 3):
        f = struct.unpack_from(">H", body, i)[0]
        if 5900 <= f <= 6100:
            vac = struct.unpack_from(">H", body, i + 2)[0]
            if 900 <= vac <= 2700:  # 90-270 V
                result["grid_frequency"] = round(f / 100.0, 2)
                result["grid_voltage"] = round(vac / 10.0, 1)
                break

    # --- Battery voltage (anchored) ---
    # Battery block: marker `00 07 b8`, then a counter byte, then a 3-value
    # sandwich `02 XX  01 BATT  02 XX` (BATT = pack voltage /10 V). The matching
    # flanks confirm alignment; require a sane 48V-bank range. Reliable at night;
    # daytime alignment occasionally drifts (then guards skip rather than emit).
    anc = body.find(b"\x00\x07\xb8")
    if anc >= 0 and anc + 10 <= len(body):
        if (body[anc + 4] == 0x02 and body[anc + 6] == 0x01
                and struct.unpack_from(">H", body, anc + 4)[0]
                == struct.unpack_from(">H", body, anc + 8)[0]):
            f1 = struct.unpack_from(">H", body, anc + 4)[0]
            batt_raw = struct.unpack_from(">H", body, anc + 6)[0]
            batt = batt_raw / 10.0
            # Daytime alignment drifts and yields coincidental sandwich matches.
            # At a genuine battery block the upper flank F1 sits ~10 V above the
            # pack voltage (raw diff ~96-108, verified across the night); require
            # that to reject daytime garbage. Net effect: battery_voltage is
            # published only when trustworthy (reliably overnight).
            if 45.0 <= batt <= 55.0 and 85 <= (f1 - batt_raw) <= 120:
                result["battery_voltage"] = round(batt, 1)

    return result


def publish_telemetry(data: bytes, cid: int) -> None:
    """Decode live PV telemetry and publish to the `telemetry` subtopic."""
    tele = decode_telemetry(data)
    if tele:
        mqtt_publish("telemetry", tele, cid)
        _log(cid, f"telemetry: {tele!r}")


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
        # Decode + publish live PV telemetry from the live 0x260f message
        publish_telemetry(data, cid)
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
        publish_telemetry(data, cid)
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

        # Hold the relay open like a real persistent dongle<->cloud session.
        # The cloud sends 0x2708 keepalives ~40s apart; a short read timeout
        # closes healthy idle connections and makes the cloud see the device
        # flap (so the app shows no live data). Use a timeout well above the
        # keepalive interval so only genuinely dead links get reaped.
        try:
            tls_in.settimeout(300)
            tls_up.settimeout(300)
        except OSError:
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


def _probe_injector(tls_in, cid: int, stop: threading.Event, state: dict) -> None:
    """Reverse-engineer the cloud->dongle command channel (network-only).

    Reads candidate command frames from ``/data/probes.txt`` — one hex string
    per line, ``#`` comments ignored — and sends each (once, when first seen)
    to the dongle over the TLS channel we control, impersonating the server.
    The pump logs the dongle's reaction; a successful read-register command
    should elicit a new response message type and/or change the next 0x260f.

    Editable live over SSH (no rebuild). Fail-safe: any error is logged and
    swallowed so it can never disturb the working MITM/telemetry path.
    Intended for READ (Modbus FC 03/04) experimentation only — never writes.
    """
    import pathlib
    pf = pathlib.Path("/data/probes.txt")
    dpf = pathlib.Path("/data/probe_delay.txt")
    spf = pathlib.Path("/data/probes_sent.txt")
    try:
        pathlib.Path("/data/mitm").mkdir(exist_ok=True)
    except OSError:
        pass
    # Single-shot across reconnects: load already-sent probes so a probe that
    # causes the dongle to drop/reconnect (e.g. action:quit) isn't resent in a
    # loop. Clear /data/probes_sent.txt to allow re-sending everything again.
    try:
        if spf.exists():
            state["sent"].update(x.strip() for x in spf.read_text().splitlines() if x.strip())
    except OSError:
        pass
    while not stop.is_set():
        try:
            # Inter-probe spacing so each command's response is cleanly
            # attributable (default 5s, override via /data/probe_delay.txt).
            delay = 5.0
            try:
                if dpf.exists():
                    delay = max(0.3, float(dpf.read_text().strip()))
            except Exception:
                pass
            if pf.exists():
                for ln in pf.read_text().splitlines():
                    ln = ln.strip().replace(" ", "")
                    if not ln or ln.startswith("#") or ln in state["sent"]:
                        continue
                    state["sent"].add(ln)
                    try:
                        raw = bytes.fromhex(ln)
                    except ValueError:
                        _log(cid, f"PROBE skip (bad hex): {ln[:48]}")
                        continue
                    try:
                        tls_in.sendall(raw)
                        state["last_ts"] = time.time()
                        try:
                            with open(spf, "a") as sf:
                                sf.write(ln + "\n")
                        except OSError:
                            pass
                        _log(cid, f"=== PROBE->DONGLE {len(raw)}B: {raw.hex()} ===")
                    except OSError as e:
                        _log(cid, f"PROBE send failed: {e}")
                        return
                    if stop.wait(delay):  # space sends; bail promptly on stop
                        return
        except Exception as e:
            _log(cid, f"probe injector error: {e}")
        stop.wait(3.0)


def _shuttle_tls(tls_in, tls_up, cid: int) -> None:
    stop = threading.Event()
    # Per-connection-per-direction buffer of EVERY byte seen.
    # Written out as one file per direction on connection close.
    buffers = {"DONGLE→SRV": bytearray(), "SRV→DONGLE": bytearray()}
    # Shared state for the probe injector (command-channel RE).
    probe_state = {"last_ts": 0.0, "sent": set()}

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
                # Flag dongle traffic arriving just after a probe — likely a
                # reaction. Persist it so command-channel hits are obvious.
                if label == "DONGLE→SRV" and (time.time() - probe_state["last_ts"]) < 20:
                    _log(cid, f"[POST-PROBE] DONGLE→SRV {len(data)}B: {hexdump(preview)}{more}")
                    try:
                        with open("/data/mitm/probe_responses.log", "a") as pf:
                            pf.write(f"{datetime.datetime.now().isoformat()} cid{cid} "
                                     f"{data.hex()}\n")
                    except OSError:
                        pass
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
    t3 = threading.Thread(target=_probe_injector, args=(tls_in, cid, stop, probe_state), daemon=True)
    t1.start(); t2.start(); t3.start()
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
