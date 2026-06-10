# Growatt SPH → Home Assistant via direct RS485 Modbus (ESP32)

A second, more robust way to monitor a Growatt inverter in Home Assistant: read it
**directly over RS485 Modbus RTU** with an ESP32 running [ESPHome](https://esphome.io),
instead of intercepting the WiFi datalogger (the [Grott add-on](../grott) approach).

Direct Modbus gives you measured, register-level values (PV per string, grid
import/export, battery, temperatures, energy totals) with no cloud, no MITM, and no
dongle dependency. This config targets the **Growatt SPH 10000TL-HU-US** (grid-tie
hybrid, split-phase) but the register map applies to the SPH TL-HU-US family.

## Hardware

- **Waveshare ESP32-S3-RS485-CAN** (or any ESP32 + RS485 transceiver).
  - Onboard RS485: **TX=GPIO17, RX=GPIO18, DE/RE=GPIO21** (auto flow-control).
  - Enable the onboard 120 Ω termination jumper (it's a 2-node bus).
- The config also runs a **Home Assistant Bluetooth proxy** on the same board.

## Wiring

Connect to the inverter's **`CN5` "Upper Computer"** RS485 port — **NOT** the BMS port.
The BMS-port RS485 is the inverter↔battery link and will not answer Modbus polls.

| ESP32 board | → | Inverter CN5 RJ45 (T568B) |
|---|---|---|
| RS485 **A+** | → | **pin 2** — orange |
| RS485 **B−** | → | **pin 1** — orange/white |
| GND (optional) | → | **pin 5** — blue/white |

Bus params: **115200 baud, 8N1, Modbus slave address 1**. If you get no data / CRC
errors, swap A↔B.

## Install

1. Install ESPHome (HA add-on, or `pip install esphome`).
2. `cp secrets.yaml.example secrets.yaml` and fill in Wi-Fi + keys
   (the ESPHome dashboard can generate `api_key`/`ota_password`).
3. Flash over USB the first time:
   `esphome run growatt-sph-esp32s3.yaml`
   (ESP32-S3 native USB: hold BOOT + tap RST to enter download mode if it isn't detected;
   only one program may hold the serial port — close any browser flasher tab.)
4. Adopt in HA: **Settings → Devices & Services → ESPHome** (auto-discovered, or add by IP).
   Later updates go over Wi-Fi (OTA).

## What you get

PV1/PV2/PV3 voltage·current·power + PV total, AC output (house load), grid voltage
L1/L2 + frequency + current, grid import/export per-leg and totals, inverter/IPM/boost
temperature, battery voltage/charge/discharge power, and lifetime energy counters.

### Battery SOC, current & power (derived)

Many SPH installs are **not** in closed-loop comms with the battery BMS, so the
inverter's SOC/current registers (1014/1086/1088) read 0. This config derives them
from the values the inverter *does* measure (voltage + charge/discharge power):

- **Battery Current** = `(charge_power − discharge_power) / voltage`
- **Battery Net Power** = `charge_power − discharge_power` (+ charge / − discharge)
- **Battery SOC** = **coulomb counting**: integrate net battery power over time vs.
  usable capacity, re-anchored to 100 % when the pack reaches its full-charge voltage:

  ```
  ΔSOC = (charge_power − discharge_power) × eff × Δt(h) ÷ battery_capacity_wh × 100
  if battery_voltage ≥ soc_full_reset_v → SOC = 100 ; clamp 0–100 ; persisted to flash
  ```

  Tune these `substitutions` to your pack:
  `battery_capacity_wh` (usable Wh = total Ah × ~51.2), `soc_full_reset_v`
  (the voltage your pack actually reaches when full), `charge_efficiency`.

### Other tunables

- `pv_zero_threshold` — clamps the small night-time PV phantom (~tens of W) to 0.
- `power_max_w` — drops out-of-range spikes (the inverter occasionally emits a
  `0xFFFFFFFF` "invalid" sentinel that would otherwise show as a huge value).
- **Inverter Loss Energy** — `(DC sources + grid) − AC output`, integrated to kWh;
  add it as an *Individual device* in the HA Energy Dashboard so the DC→AC conversion
  loss is labeled instead of appearing as "untracked consumption".

## Register map source

Growatt grid-tie "Protocol II" input registers (FC04). Cross-referenced against
[akomakom/esphome-growatt-modbus](https://github.com/akomakom/esphome-growatt-modbus)
(tested on SPH10000TL-HU-US) and the Growatt 2020 v1.24 register map.

## Off-grid SPF inverters

For off-grid **SPF** inverters the register map differs (see the OffGrid Modbus RTU
protocol). The structure here (UART → modbus → modbus_controller) is the same; only the
register addresses/scales change.
