# RACE Toolkit

RACE Toolkit is the tool released alongside our Airoha research. You can find more about that in our [blog post](https://insinuator.net/2025/12/bluetooth-headphone-jacking-full-disclosure-of-airoha-race-vulnerabilities).

This repository contains a Python-based command-line toolkit for interacting with devices that expose the **RACE protocol** over various transports (BLE GATT, Bluetooth Classic RFCOMM, USB HID). It is primarily intended for further security research into the Airoha ecosystem and for end-users to check whether their devices are affected by the vulnerabilities.

The tool supports RAM/flash dumping, device information queries, and has preliminary support for firmware updates (FOTA). Whether a given feature works with a specific device is largely dependent on the device. For example, RAM dumping only works on devices that (still) have the command exposed. The firmware update process currently only supports headphones, not TWS (true-wireless stereo) earbuds. 

RACE toolkit also offers a command to check whether a given device is affected by CVE-2025-20700, CVE-2025-20701, or CVE-2025-20702. However, due to differences in devices, we cannot guarantee the reliability of the check command. If it returns *FIXED*, there might still be a chance the device is vulnerable. For example, some devices require specific circumstances to bypass the Bluetooth Classic pairing. We also saw a device that was only vulnerable to the Classic pairing issue in one of multiple tries and across reboots. We didn't properly investigate all these devices and all these edge-cases. Nonetheless, the `check` command is a good starting point, and it will not generate false positives. If it considers a device as vulnerable, the device is vulnerable.

---

## Features

- Implements a small subset of RACE commands. Mainly the ones relevant for further security research and to confirm whether a device is still vulnerable.
- Supports different RACE transports:
  * BLE GATT (via Bumble using a Bluetooth dongle, or via Bleak using the OS Bluetooth stack)
  * Bluetooth Classic RFCOMM (via Bumble using a Bluetooth dongle)
  * USB HID
- Semi-Automated vulnerability checks for the RACE-related CVEs (CVE-2025-20700, CVE-2025-20701, or CVE-2025-20702)
- Read and write device RAM
- Dump flash memory and partitions
- Query device metadata (SDK info, build version, Bluetooth Classic address)
- Firmware (FOTA) updates (or downgrades)

## Installation

This project supports two installation methods. You can choose either based on your preferred workflow:

* `pip` with `requirements.txt`
* `uv` using `pyproject.toml`

Both methods install the same dependencies. Due to the requirements of the [Bumble Bluetooth library](https://github.com/google/bumble), Python 3.10 is required.

### Option 1: Install with `pip`

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Option 2: Install with `uv`

This repository includes a `pyproject.toml` that can be used with [`uv`](https://github.com/astral-sh/uv).

```bash
uv sync
```

This will:

* Create a virtual environment
* Install all dependencies as pinned in `uv.lock`

To run commands inside the environment:

```bash
uv run python race_toolkit.py --help
```

## Requirements

- Python 3.10+
- A Bluetooth dongle (e.g. USB or UART) that is supported by Bumble. See Bumble's [Transport section](https://google.github.io/bumble/transports/usb.html).
- Some GATT-commands might also work without an additional dongle using the [bleak library](https://github.com/hbldh/bleak)

## Transports

RACE can be communicated via different transports. In this toolkit we implemented a subset of these. Each transport has different capabilities, limitations, and requirements.

### GATT (Bumble) (`--transport gatt`)

**Default transport.**

* Uses Bluetooth Low Energy GATT via the Bumble stack
* Supports scanning by device name or direct address
* Required for BLE-based vulnerability checks

**Notes:**

* Requires a Bumble-compatible Bluetooth controller
* Pairing can optionally be attempted using `--authenticate`

### GATT (Bleak) (`--transport bleak`)

* Uses the Bleak library for BLE GATT access
* Useful when Bumble is unavailable or incompatible

**Limitations:**

* Reduced feature set compared to Bumble-based GATT
* Not thoroughly tested. Once we switched to Bumble we didn't focus on the bleak transport any longer
* Not all checks or commands may work

### Bluetooth Classic RFCOMM (`--transport rfcomm`)

* Uses Bluetooth Classic over RFCOMM

**Notes:**

* Requires a Bumble-compatible Bluetooth controller
* A valid Bluetooth Classic address is required

### USB HID (`--transport usb`)

* Communicates directly with the device over USB HID
* Not many devices expose RACE over USB

**Notes:**

* Device is specified as `VID:PID`
* If omitted, the tool may enumerate devices interactively

## Usage


```bash
python race_toolkit.py [global options] <command> [command options]
```

## Global Options

These options apply to all commands unless stated otherwise.

| Option               | Description                                                                     |
| -------------------- | ------------------------------------------------------------------------------- |
| `-t`, `--transport`  | Transport method. One of `gatt`, `bleak`, `rfcomm`, `usb` (default: `gatt`)     |
| `-c`, `--controller` | Bumble Bluetooth controller (default: `usb:0`)                                  |
| `--target-address`   | Target device Bluetooth classic address                                         |
| `--le-names`         | One or more BLE device names to scan for if no address is provided              |
| `-d`, `--device`     | USB HID device VID:PID (only for `usb` transport)                               |
| `--outfile`          | Write command output to a file instead of stdout                                |
| `--debug`            | Enable debug logging                                                            |
| `--send-delay`       | Delay (in seconds) between RACE messages (might be required for old firmware?)  |
| `--authenticate`     | Attempt pairing/authentication during connection                                |

## Commands

### `check`

Check a device for the RACE vulnerabilities:

- CVE-2025-20700 – Missing GATT authentication
- CVE-2025-20701 – Missing BR/EDR authentication
- CVE-2025-20702 – RACE protocol exposure (BLE and Classic)

```bash
python race_toolkit.py check
```

The command will interactively guide you through the process. It performs the following actions:

1. Scan BLE devices and ask which of these is the user's.
2. Connect to the device and enumerate GATT services.
3. Check if one of the known the RACE UUIDs is present.
4. Test the flash read RACE command.
5. Try to obtain the Bluetooth Classic address via the respective RACE command.
6. Not all devices support this command. If it fails, it will ask the user for the Bluetooth Classic address.
7. Connect to the device via Bluetooth Classic.
8. Enumerate RFCOMM services.
9. Check if one of the known RACE RFCOMM services is present.
10. Connect and attempt to read flash using the RACE command via RFCOMM.

If you know your device's *Bluetooth Classic address* already, you can supply it via the `--target-address` parameter. RACE toolkit will try to obtain the address during the BLE phase. If this fails, it will interactively ask for the address. If the device is not available via BLE the automatic retrieval of the Classic address will not work.

At the end, a summarized vulnerability status is printed.

---

### `ram`

Read from device RAM.

```bash
python race_toolkit.py [global options] ram --address <hex> --size <hex>
```

**Options:**

- `--address` (required): Target RAM address (hex)
- `--size` (required): Number of bytes to read (hex). Must be multiple of 4 as the command reads 4 bytes only.

**Behavior:**

- Output is hex-dumped unless an `--outfile` is specified

---

### `flash`

Dump flash memory.

```bash
python race_toolkit.py [global options] flash --address <hex> --size <hex>
```

**Options:**

- `--address` (required): Flash start address (hex, multiple of `0x100`)
- `--size` (required): Number of bytes to dump (hex, multiple of `0x100`)

---

### `link-keys`

Retrieve stored Bluetooth BR/EDR link keys.

```bash
python race_toolkit.py [global options] link-keys
```

Notes:

- This command does not work on many devices. The output only contains some link keys, not the other devices' Bluetooth addresses.
- This is not the command used for the pivoting live demo. The NVDM partition also contains these keys (see `dump-partition`).

---

### `bdaddr`

Query the Bluetooth Classic address via RACE.

```bash
python race_toolkit.py [global options] bdaddr
```

Notes:

- This is useful as the devices typically are not discoverable. So in order to connect via Bluetooth Classic, this commands removes the need for sniffing device addresses (e.g. by using an Ubertooth).

---

### `sdkinfo`

Retrieve SDK information from the device.

```bash
python race_toolkit.py [global options] sdkinfo
```

Notes:

- The response payload is interpreted as UTF-8 text.
- Usually, this is not particularly helpful. For some devices the output is just version 1.

---

### `buildversion`

Retrieve the firmware build version string.

```bash
python race_toolkit.py [global options] buildversion
```

Notes:

- Many devices do not respond to this command any longer.
- If they do, it's helpful for fingerprinting and identifying versions.

---

### `mediainfo`

Dump metadata about the currently playing media.
Proof-of-concept command for a live demo targeting the Sony WH-CH720N.

```bash
python race_toolkit.py [global options] mediainfo
```

Important notes:

* This is a proof-of-concept feature
* It relies on hard-coded RAM offsets
* Only supports for specific firmware versions and devices (Sony WH-CH720N)

---

### `dump-partition`

Interactively dump a flash partition.

```bash
python race_toolkit.py [global options] --outfile <file> dump-partition
```

Workflow:

1. Reads and parses the partition table
2. Displays all partitions
3. Prompts the user to select a partition
4. Dumps the selected partition to a file

This is usually used to dump the NVDM partition (most of the time it's partition number 6). This partition contains configuration data.

Notes:

- The global `--outfile` option is required here. This command will not print to stdout.

---

### `fota`

**WARNING:** Only use this command if you know what you are doing!

This command perform a FOTA firmware update. We reimplemented the FOTA process as we have observed it during an update of one of our devices. Additional information was retrieved by reverse-engineering the firmware and a mobile app. In the end, this process was confirmed to work with *Sony WH-CH720N* and *Sony WH-1000 XM6*. It likely works with other Sony headphone models, however, we have not confirmed this. The same applies to headphones from other vendors. Additionally, the current implementation of the FOTA process does not work with True Wireless Stereo (TWS) earbuds. This would require additional steps that we have not (yet) implemented.

This implementation allows you to flash valid FOTA images. It also allows firmware downgrades. However, we don't recommend downgrading your production device. Sony firmware can be found in the [MDR Proxy Repository](https://github.com/lzghzr/MDR_Proxy). Make sure to choose the correct device when downloading the firmware and running the FOTA command.

Again, don't use this if you don't know what you are doing. Due to the integrity checks of the firmware during the FOTA process it *should* be fine. During our research we bricked two devices after playing around with the firmware image and running the update.

```bash
python race_toolkit.py [global options] fota --fota-file <file> [options] 
```

**Options:**

- `--fota-file` (required): Path to the FOTA image
- `--dont-reflash`: Do not erase/reflash the FOTA partition
- `--chunks-per-write`: Number of chunks per flash write (default: 3)

Notes:

- `--fota-file` is required unless `--dont-reflash` is set
- Larger chunk sizes may not work on all devices. Usually 3 (default) works best.


## Notice

This tool is intended for **research and educational purposes only**.

- Do not use on devices you do not own or have permission to test!
- Flash and RAM access can permanently brick devices!
- Only use the FOTA command if you know what you are doing! We can't help you with bricked devices!
