# Growatt Solar — Home Assistant

Two ways to monitor a Growatt solar inverter in Home Assistant — **no cloud required**:

| Method | What it is | When to use |
|---|---|---|
| **[Grott add-on](./grott)** | Home Assistant add-on that acts as a local proxy + MQTT bridge, intercepting the WiFi datalogger's traffic (MITM) and decoding it. | You can't (or don't want to) wire to the inverter; works with the stock WiFi dongle. |
| **[ESP32 RS485 Modbus](./esp32)** | An ESP32 (ESPHome) reading the inverter **directly over RS485 Modbus RTU**. | You can wire to the inverter's RS485 port; gives clean register-level data + a Bluetooth proxy. |

The ESP32/Modbus path is the more robust option (no dongle, no MITM, no cloud); the
Grott add-on is the no-wiring option that works with the OEM WiFi stick.

## Install the add-on (Grott / MITM)

In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, paste:

```
https://github.com/nalditopr/ha-grott-addon
```

Refresh the store and the **Grott** add-on appears. See [grott/](./grott) for details.

## Set up the ESP32 (direct Modbus)

See [esp32/](./esp32) for wiring, the ESPHome config, and the tuning guide.

## Add-ons

| Add-on | Description |
|---|---|
| [Grott](./grott) | Local proxy + MQTT bridge for Growatt solar inverters (intercepts datalogger traffic). |

---

Community project — not affiliated with Growatt. Maintained by [@nalditopr](https://github.com/nalditopr).
