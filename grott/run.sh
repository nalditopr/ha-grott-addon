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
port = ${LISTEN_PORT}
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
    bashio::log.info "Cloud forwarding disabled — starting local TCP sink on 127.0.0.1:${SINK_PORT}"
    python3 -u /opt/localsink.py "${SINK_PORT}" &
    sed -i "/^\[Growatt\]/,/^\[/ s|^ip = .*|ip = 127.0.0.1|" "${CONF}"
    sed -i "/^\[Growatt\]/,/^\[/ s|^port = .*|port = ${SINK_PORT}|" "${CONF}"
fi

bashio::log.info "Starting grott — listening on 0.0.0.0:${LISTEN_PORT}, HTTP API on :${HTTP_PORT}"
cd /opt/grott
exec python3 -u grott.py -v
