# Grott — Home Assistant Add-on

Local proxy + MQTT bridge for Growatt solar inverters. Wraps [johanmeijer/grott](https://github.com/johanmeijer/grott).

The Growatt WiFi/LAN stick normally sends data to `server.growatt.com:5279`. This add-on impersonates that endpoint: the stick connects to Home Assistant, Grott decodes the frames and publishes them to MQTT, and (optionally) forwards them on to the real Growatt cloud so ShinePhone keeps working.

## Install

1. Add this repo: **Settings → Add-ons → Add-on Store → ⋮ → Repositories →** `https://github.com/nalditopr/ha-grott-addon`
2. Refresh the store, install **Grott**, do **not** start it yet.
3. Ensure the **Mosquitto broker** add-on is installed and running. Grott pulls MQTT credentials from the Supervisor MQTT service.
4. Start the add-on. Check the log — you should see `Starting grott — listening on 0.0.0.0:5279`.

## Redirect the datalogger to this add-on

Pick one:

- **DNS override (cleanest)** — on your router/UDM, point `server.growatt.com` at the HA host's IP. Nothing on the dongle to change.
- **Dongle web UI** — log into `http://<dongle-ip>` (default `admin`/`admin`), under server settings change the server hostname to the HA host's IP. Port stays `5279`.

Verify by tailing the add-on log: you should see decoded frames within a couple of minutes (Growatt dongles transmit every ~60s).

## Configuration

| Option | Default | Notes |
|---|---|---|
| `forward_to_cloud` | `false` | If `true`, frames are forwarded to `growatt_cloud_host:port` after being decoded. Keep `false` for fully local operation. |
| `growatt_cloud_host` | `server.growatt.com` | Only used when `forward_to_cloud: true`. |
| `growatt_cloud_port` | `5279` | |
| `grott_listen_port` | `5279` | TCP port the datalogger connects to. |
| `http_api_port` | `5782` | Grott's HTTP API (status, manual commands). |
| `mqtt_topic` | `energy/growatt` | Base MQTT topic. Inverter SN gets appended. |
| `mqtt_retain` | `false` | |
| `verbose` | `true` | |
| `extra_ini` | `""` | Raw INI text appended to `grott.ini` — for advanced sections (PVOutput, InfluxDB, Extension). |

MQTT host/port/user/password are pulled automatically from the Supervisor MQTT service — no need to configure them here.

## Network

| Port | Purpose |
|---|---|
| `5279/tcp` | Datalogger ingress (this is what the Growatt stick sends to) |
| `5782/tcp` | Grott HTTP API |

## Troubleshooting

- **Nothing in the log after 5 min** — the dongle isn't reaching the add-on. Confirm DNS override applies to the dongle's VLAN, or that the web-UI server host change was saved (some dongles need a power-cycle).
- **`No MQTT service available`** — install + start the Mosquitto broker add-on, then restart Grott.
- **MQTT topics not showing in HA** — the upstream grott wiki has the HA MQTT sensor template; copy into `configuration.yaml` under `mqtt:`.
