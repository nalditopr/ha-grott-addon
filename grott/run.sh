#!/usr/bin/with-contenv bashio
set -euo pipefail

CONF=/opt/grott/grott.ini

FORWARD_TO_CLOUD="$(bashio::config 'forward_to_cloud')"
GROWATT_HOST="$(bashio::config 'growatt_cloud_host')"
GROWATT_PORT="$(bashio::config 'growatt_cloud_port')"
LISTEN_PORT="$(bashio::config 'grott_listen_port')"
HTTP_PORT="$(bashio::config 'http_api_port')"
MQTT_TOPIC="$(bashio::config 'mqtt_topic')"
MQTT_RETAIN="$(bashio::config 'mqtt_retain')"
VERBOSE="$(bashio::config 'verbose')"
DEBUG_HEX="$(bashio::config 'debug_hex')"
MITM_UPSTREAM_HOST="$(bashio::config 'mitm_upstream_host')"
MITM_UPSTREAM_PORT="$(bashio::config 'mitm_upstream_port')"
EXTRA_INI="$(bashio::config 'extra_ini')"

MANUAL_HOST="$(bashio::config 'mqtt_host')"
if [ -n "${MANUAL_HOST}" ]; then
    MQTT_HOST="${MANUAL_HOST}"
    MQTT_PORT="$(bashio::config 'mqtt_port')"
    MQTT_USER="$(bashio::config 'mqtt_user')"
    MQTT_PSW="$(bashio::config 'mqtt_password')"
    bashio::log.info "Using manually-configured MQTT at ${MQTT_HOST}:${MQTT_PORT}"
elif bashio::services.available "mqtt"; then
    MQTT_HOST="$(bashio::services 'mqtt' 'host')"
    MQTT_PORT="$(bashio::services 'mqtt' 'port')"
    MQTT_USER="$(bashio::services 'mqtt' 'username')"
    MQTT_PSW="$(bashio::services 'mqtt' 'password')"
    bashio::log.info "Using Supervisor-provided MQTT service at ${MQTT_HOST}:${MQTT_PORT}"
else
    bashio::log.fatal "No MQTT available. Either: (a) install + start Mosquitto broker AND add the MQTT integration in Settings → Devices & Services, or (b) set mqtt_host/mqtt_port/mqtt_user/mqtt_password in this add-on's Configuration tab."
    exit 1
fi

MQTT_AUTH=False
if [ -n "${MQTT_USER}" ]; then
    MQTT_AUTH=True
fi

# Export MQTT vars so localsink.py can publish directly
export GROTT_MQTT_HOST="${MQTT_HOST}"
export GROTT_MQTT_PORT="${MQTT_PORT}"
export GROTT_MQTT_TOPIC="${MQTT_TOPIC}"
export GROTT_MQTT_USER="${MQTT_USER}"
export GROTT_MQTT_PSW="${MQTT_PSW}"
export GROTT_MQTT_RETAIN="${MQTT_RETAIN}"

# Determine operating mode
TLS_DIRECT_MODE=false
MITM_MODE=false
if [ -n "${MITM_UPSTREAM_HOST}" ]; then
    MITM_MODE=true
    TLS_DIRECT_MODE=true
    bashio::log.warning "TLS MITM MODE — forwarding to ${MITM_UPSTREAM_HOST}:${MITM_UPSTREAM_PORT}"
elif ! bashio::var.true "${FORWARD_TO_CLOUD}" && bashio::var.true "${DEBUG_HEX}"; then
    TLS_DIRECT_MODE=true
    bashio::log.warning "TLS DIRECT MODE — localsink will listen on 0.0.0.0:${LISTEN_PORT} and handle TLS dongles directly"
fi

if bashio::var.true "${TLS_DIRECT_MODE}"; then
    # In TLS direct mode localsink owns the datalogger port.
    # Move grott to an internal port so its HTTP API still works.
    GROTT_LISTEN_INTERNAL=5278
    bashio::log.info "grott proxy moved to internal port ${GROTT_LISTEN_INTERNAL} (HTTP API stays on :${HTTP_PORT})"
else
    GROTT_LISTEN_INTERNAL="${LISTEN_PORT}"
fi

cat >"${CONF}" <<EOF
[Generic]
minrecl = 100
verbose = $( [ "${VERBOSE}" = "true" ] && echo True || echo False )
trace = False
decrypt = True
compat = False
includeall = False
invtype = default
inverterid = automatic
mode = proxy
ip = 0.0.0.0
port = ${GROTT_LISTEN_INTERNAL}
sendbuf = True
timezone = local

[Growatt]
ip = ${GROWATT_HOST}
port = ${GROWATT_PORT}

[Server]
httphost = 0.0.0.0
httpport = ${HTTP_PORT}
httptoken =

[MQTT]
nomqtt = False
ip = ${MQTT_HOST}
port = ${MQTT_PORT}
topic = ${MQTT_TOPIC}
mtopic = False
inverterintopic = False
retain = $( [ "${MQTT_RETAIN}" = "true" ] && echo True || echo False )
auth = ${MQTT_AUTH}
user = ${MQTT_USER}
password = ${MQTT_PSW}

[PVOutput]
pvoutput = False

[influx]
influx = False
influx2 = False

[extension]
extension = False
EOF

if [ -n "${EXTRA_INI}" ]; then
    bashio::log.info "Appending user-supplied extra_ini block"
    printf '\n%s\n' "${EXTRA_INI}" >>"${CONF}"
fi

if ! bashio::var.true "${FORWARD_TO_CLOUD}"; then
    SINK_PORT=5280
    SINK_MODE="discard"
    SINK_BIND="127.0.0.1"
    if bashio::var.true "${MITM_MODE}"; then
        SINK_MODE="mitm"
        export GROTT_MITM_HOST="${MITM_UPSTREAM_HOST}"
        export GROTT_MITM_PORT="${MITM_UPSTREAM_PORT}"
        bashio::log.warning "localsink in MITM mode — upstream ${GROTT_MITM_HOST}:${GROTT_MITM_PORT}"
    elif bashio::var.true "${DEBUG_HEX}"; then
        SINK_MODE="capture"
        bashio::log.warning "localsink in CAPTURE mode — logging hex + echoing bytes (protocol RE)"
    else
        bashio::log.info "localsink in DISCARD mode — silently accepts grott forwards"
    fi

    if bashio::var.true "${TLS_DIRECT_MODE}"; then
        # localsink becomes the public endpoint
        SINK_PORT="${LISTEN_PORT}"
        SINK_BIND="0.0.0.0"
        bashio::log.info "Starting localsink on ${SINK_BIND}:${SINK_PORT} (TLS direct mode)"
        GROTT_SINK_MODE="${SINK_MODE}" python3 -u /opt/localsink.py "${SINK_PORT}" "${SINK_BIND}" &
        # Point grott's forward target at a discard sink on a different port
        # so grott's proxy tunnel has somewhere to go (even though nothing
        # should reach it in direct mode).
        LOCALSINK_INTERNAL=5280
        bashio::log.info "Starting internal discard sink on 127.0.0.1:${LOCALSINK_INTERNAL} for grott"
        GROTT_SINK_MODE="discard" python3 -u /opt/localsink.py "${LOCALSINK_INTERNAL}" "127.0.0.1" &
        sed -i "/^\[Growatt\]/,/^\[/ s|^ip = .*|ip = 127.0.0.1|" "${CONF}"
        sed -i "/^\[Growatt\]/,/^\[/ s|^port = .*|port = ${LOCALSINK_INTERNAL}|" "${CONF}"
    else
        bashio::log.info "Starting localsink on ${SINK_BIND}:${SINK_PORT}"
        GROTT_SINK_MODE="${SINK_MODE}" python3 -u /opt/localsink.py "${SINK_PORT}" "${SINK_BIND}" &
        sed -i "/^\[Growatt\]/,/^\[/ s|^ip = .*|ip = 127.0.0.1|" "${CONF}"
        sed -i "/^\[Growatt\]/,/^\[/ s|^port = .*|port = ${SINK_PORT}|" "${CONF}"
    fi
fi

if bashio::var.true "${DEBUG_HEX}"; then
    bashio::log.warning "DEBUG_HEX enabled — patching grottproxy.py for protocol capture"
    python3 - <<'PY'
import pathlib, re
p = pathlib.Path("/opt/grott/grottproxy.py")
src = p.read_text()
needle = "validatecc = validate_record(vdata)"
if "HEX [" not in src:
    inject = (
        "try: peer = self.s.getpeername()\n"
        "        except Exception: peer = ('?', '?')\n"
        "        print('\\t - HEX [' + str(peer) + '] (' + str(len(vdata)//2) + ' bytes): ' + vdata)\n"
        "        "
    )
    src = src.replace(needle, inject + needle)
src = src.replace(
    "print(f\"\\t - Grott - grottproxy - Invalid data record received, processing stopped for this record\")\n            #Create response if needed? \n            #self.send_queuereg[qname].put(response)\n            return",
    "print(f\"\\t - Grott - INVALID record kept (debug_hex=true)\")\n            pass  # do not return — keep forwarding for capture",
)
p.write_text(src)
print("grottproxy.py patched for debug_hex")
PY
fi

bashio::log.info "Starting grott — listening on 0.0.0.0:${GROTT_LISTEN_INTERNAL}, HTTP API on :${HTTP_PORT}"
cd /opt/grott
exec python3 -u grott.py -v
