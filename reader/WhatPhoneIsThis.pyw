"""WHAT PHONE IS THIS v1.6 — one-click phone identifier for the shop bench
(Python 3.10+, Windows-first, stdlib only).

The problem: a phone comes in with a dead or unreadable screen, no IMEI
printed on the back, and nothing on the SIM tray. Every Moto G looks like
every other Moto G, so there is no way to know the model by looking.

This tool does the looking. It watches the USB ports. The moment a phone
shows up in fastboot mode (or normal adb mode) it reads the phone by
itself, puts the answer on screen in HUGE print, and says it out loud.

No third-party modules. fastboot / adb (Google platform-tools) are
external executables: found on PATH first, then beside this script.
No network calls. Nothing is saved anywhere — a phone's info shows on
screen and is gone when the window closes.

Importing this file does not start the GUI; the parsers, the watcher,
and the speech gating are independently testable headless.
"""
from __future__ import annotations

import array
import hashlib
import json
import math
import os
import platform
import plistlib
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.request
import wave
from dataclasses import dataclass, field

VERSION = "1.6"

SHOP = "iFixx Repairs"
COPYRIGHT_LINE = "© 2026 iFixx Repairs. All rights reserved."
PRIVACY_LINE = "Nothing is saved — close the window and the phone's info is gone."

# Dark Navy Professional palette (same family as the other shop tools).
BG_APP = "#0A2032"
BG_PANEL = "#102C43"
FG_TEXT = "#FFFFFF"
FG_DIM = "#9FB8CC"
ACCENT = "#36C6F4"
GOOD = "#39D98A"
WARN = "#FFC24B"

FASTBOOT_HINT = "Dead screen? Hold Volume Down + Power for 10 seconds, then plug in."
NO_PHONE_TEXT = "No phone found — hold Volume Down + Power, then plug in"
READING_TEXT = "Reading the phone…"
TOOLS_MISSING_TEXT = (
    "I can't find fastboot / adb on this computer yet.\n"
    "One-time setup: install Google platform-tools (see the RUNBOOK), "
    "or drop fastboot.exe and adb.exe in this same folder."
)

POLL_MS = 2000

# ============================================================================
# MOTOROLA CODENAME TABLE — fastboot "product" code name -> retail name.
#
# HOW TO ADD ONE: one line, lower-case code name on the left, the retail
# name a customer would say on the right, and a confidence note. Only add
# a name you have SEEN tied to that code name (a Motorola firmware listing,
# a Motorola Software Fix result, or a known phone in hand). If a code
# name is not in this table the tool shows the code name itself in big
# print plus serial / IMEI — it never guesses a retail name.
#
# Confidence key: "high" = seen across Motorola factory-firmware listings
# and LineageOS device records for years; "med" = consistently reported
# in firmware listings, less widely mirrored.
# ============================================================================
MOTO_CODENAMES = {
    # --- Classics ---------------------------------------------------------
    "shamu":   "Nexus 6 (made by Motorola)",        # high — Google factory images
    "condor":  "Moto E (1st Gen, 2014)",            # med — firmware listings
    "surnia":  "Moto E (2nd Gen LTE, 2015)",        # med — firmware listings
    "osprey":  "Moto G (3rd Gen, 2015)",            # high — LineageOS + firmware
    "merlin":  "Moto G Turbo Edition (2015)",       # med — firmware listings
    "clark":   "Moto X Pure Edition (2015)",        # med — firmware listings
    "harpia":  "Moto G Play (2016)",                # high — LineageOS + firmware
    "athene":  "Moto G4 / G4 Plus (2016)",          # high — LineageOS + firmware
    # --- G5 / E4 / X4 era --------------------------------------------------
    "potter":  "Moto G5 Plus (2017)",               # high — LineageOS + firmware
    "cedric":  "Moto G5 (2017)",                    # med — firmware listings
    "sanders": "Moto G5S Plus (2017)",              # med — firmware listings
    "montana": "Moto G5S (2017)",                   # med — firmware listings
    "perry":   "Moto E4 (2017, Qualcomm)",          # med — firmware listings
    "payton":  "Moto X4 (2017)",                    # med — firmware listings
    # --- G6 / G7 era -------------------------------------------------------
    "ali":     "Moto G6 (2018)",                    # med — firmware listings
    "aljeter": "Moto G6 Play (2018)",               # med — firmware listings
    "evert":   "Moto G6 Plus (2018)",               # med — firmware listings
    "ocean":   "Moto G7 Power (2019)",              # high — LineageOS + firmware
    "river":   "Moto G7 (2019)",                    # high — LineageOS + firmware
    "channel": "Moto G7 Play (2019)",               # med — firmware listings
    "lake":    "Moto G7 Plus (2019)",               # med — firmware listings
    # --- G8 / G9 / G Power / G Stylus era ----------------------------------
    "sofia":   "Moto G Power (2020)",               # high — LineageOS + firmware
    "sofiap":  "Moto G Stylus (2020)",              # med — firmware listings
    "odessa":  "Moto G9 Plus (2020)",               # med — firmware listings
    "cebu":    "Moto G9 Power (2020)",              # med — firmware listings
    "guam":    "Moto G Play (2021)",                # med — firmware listings
    "borneo":  "Moto G Power (2021)",               # med — firmware listings
    "denver":  "Moto G Stylus 5G (2021)",           # med — firmware listings
    "milan":   "Moto G Stylus (2022)",              # med — firmware listings
    "devon":   "Moto G32 (2022)",                   # med — firmware listings
    "rhode":   "Moto G52 (2022)",                   # med — firmware listings
    # --- 2023 era -----------------------------------------------------------
    "pnangn":  "Moto G 5G 2023 (XT2313)",           # high — RabbitEars KB codename record + owner's live fastboot read 2026-10-27 (IMEI/serial read in the same pass)
}


def lookup_codename(codename):
    """Retail name for a fastboot/adb code name, or None if unknown.

    Case-insensitive. Returns None for anything not in the table —
    callers must show the raw code name instead of inventing a name.
    """
    if not codename:
        return None
    return MOTO_CODENAMES.get(str(codename).strip().lower())


# ============================================================================
# PhoneInfo — one read result.
# ============================================================================
@dataclass
class PhoneInfo:
    model_display: str = ""      # what goes in HUGE print
    known_name: bool = False     # True when model_display is a real retail name
    codename: str = ""           # fastboot product / ro.product.device
    marketname: str = ""         # ro.product.marketname (retail name, if any)
    model_prop: str = ""         # ro.product.model
    imei: str = ""
    serial: str = ""
    source: str = ""             # "fastboot" or "adb"
    extras: dict = field(default_factory=dict)  # sku, variant, radio…
    # v1.2 counter reads (adb door; -1 / "" / 0 = not read, never guessed)
    battery_level: int = -1      # percent charge
    battery_volts: float = 0.0   # v1.5: fastboot battery-voltage read
                                 # (mV in the dump) — fastboot has no
                                 # percent; volts is what the door gives
    battery_health: str = ""     # good / overheated / dead / …
    battery_cycles: int = -1     # charge cycles, when the phone reports them
    storage_gb: float = 0.0      # total internal storage
    ram_gb: float = 0.0          # total memory
    android_version: str = ""    # ro.build.version.release
    frp_warning: bool = False    # setup never finished -> possible acct lock
    model_number: str = ""       # v1.4: XT2515-1 / SM-S166U — parts are
                                 # ordered by this, so it is SPOKEN


# ============================================================================
# Command running — every subprocess call goes through one runner so tests
# can inject fakes. The runner NEVER raises: (rc, stdout, stderr).
# ============================================================================
def default_runner(argv, timeout=20):
    try:
        extra = {}
        if platform.system() == "Windows":
            # A no-console parent (pythonw) spawning console tools
            # (adb/fastboot/powershell) flashes a console window on
            # every call without this flag — the poll fires every
            # POLL_MS, so the face appeared to pulse. Never show one.
            extra["creationflags"] = getattr(
                subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            **extra,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception:
        return 1, "", ""


def script_dir():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.getcwd()


def find_tool(name, tool_dir=None, which=shutil.which):
    """Locate a platform-tools binary: PATH first, then beside the script.

    Returns the full path, or None when not found anywhere.
    """
    found = which(name)
    if found:
        return found
    folder = tool_dir if tool_dir is not None else script_dir()
    exe = name + ".exe" if platform.system() == "Windows" else name
    candidate = os.path.join(folder, exe)
    if os.path.isfile(candidate):
        return candidate
    if exe != name:
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate):
            return candidate
    return None


# ============================================================================
# Parsers (pure functions — the tested core).
# ============================================================================
_GETVAR_LINE = re.compile(r"^(?:\(bootloader\)\s*)?([A-Za-z0-9_.\-]+)\s*:\s*(.*?)\s*$")


def parse_fastboot_getvar(text):
    """Parse `fastboot getvar all` output into {key: value}.

    fastboot prints "(bootloader) key: value" lines, mostly to stderr,
    so callers merge stdout+stderr before calling. Keys are lower-cased.
    The trailing "all: Done!!" line and timing lines are ignored.
    """
    result = {}
    if not text:
        return result
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Finished") or line.startswith("OKAY"):
            continue
        m = _GETVAR_LINE.match(line)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2)
        if key == "all":  # "all: Done!!" trailer
            continue
        if value:
            result[key] = value
    return result


def parse_devices_list(text):
    """Parse `fastboot devices` / `adb devices` output.

    Returns a list of (serial, state) tuples. fastboot reports state
    "fastboot"; adb reports "device" / "unauthorized" / "offline".
    """
    devices = []
    if not text:
        return devices
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1].lower()))
        elif len(parts) == 1:
            devices.append((parts[0], ""))
    return devices


_GETPROP_LINE = re.compile(r"^\[([^\]]+)\]:\s*\[(.*)\]\s*$")


def parse_getprop(text):
    """Parse `adb shell getprop` dump lines "[key]: [value]" into a dict."""
    result = {}
    if not text:
        return result
    for raw in text.splitlines():
        m = _GETPROP_LINE.match(raw.strip())
        if m:
            result[m.group(1).strip()] = m.group(2).strip()
    return result


_PARCEL_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+:\s*(.*)$")


def parse_iphonesubinfo(text):
    """Best-effort IMEI out of `service call iphonesubinfo 1` parcel text.

    The parcel dumps UTF-16LE characters packed into 8-hex-digit words.
    We rebuild the bytes, decode, and accept ONLY a clean run of exactly
    15 digits. Anything less clean returns None — never guess an IMEI.
    """
    if not text or "Parcel" not in text:
        return None
    words = []
    for raw in text.splitlines():
        m = _PARCEL_LINE.match(raw)
        if not m:
            continue
        for token in m.group(1).split():
            if re.fullmatch(r"[0-9a-fA-F]{8}", token):
                words.append(token)
            else:
                break  # the ASCII gutter starts here
    if not words:
        return None
    try:
        blob = b"".join(int(w, 16).to_bytes(4, "little") for w in words)
        decoded = blob.decode("utf-16-le", errors="ignore")
    except Exception:
        return None
    runs = re.findall(r"\d+", decoded)
    for run in runs:
        if len(run) == 15:
            return run
    return None


_BATTERY_HEALTH = {1: "unknown", 2: "good", 3: "overheated", 4: "dead",
                   5: "over voltage", 6: "failed", 7: "cold"}


def parse_dumpsys_battery(text):
    """(level_percent|None, health_word) out of `dumpsys battery`.

    Health arrives as a numeric code; the words are Android's own
    BATTERY_HEALTH_* names in plain form. Missing lines stay unknown.
    """
    level, health = None, ""
    if not text:
        return level, health
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("level:"):
            try:
                level = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("health:"):
            try:
                health = _BATTERY_HEALTH.get(
                    int(line.split(":", 1)[1].strip()), "")
            except ValueError:
                pass
    return level, health


def parse_cycle_count(text):
    """Charge cycles from the power-supply sysfs file: a bare integer.

    Many phones do not expose it (permission or absent) — then None.
    """
    if not text:
        return None
    m = re.search(r"\d+", text)
    if not m:
        return None
    try:
        return int(m.group(0))
    except ValueError:
        return None


def parse_memtotal_gb(text):
    """Total RAM in GB (float) from /proc/meminfo's MemTotal line."""
    if not text:
        return 0.0
    m = re.search(r"MemTotal:\s*(\d+)\s*kB", text)
    if not m:
        return 0.0
    return int(m.group(1)) / 1048576.0


def _size_to_gb(token):
    """One df size token -> GB float. Suffix G/M/K honored; a bare
    number is 1K-blocks (the classic df unit)."""
    token = token.strip().rstrip(",")
    if not token:
        return 0.0
    mult = {"G": 1.0, "M": 1 / 1024.0, "K": 1 / 1048576.0, "T": 1024.0}
    suffix = token[-1].upper()
    try:
        if suffix in mult:
            return float(token[:-1]) * mult[suffix]
        return float(token) / 1048576.0
    except ValueError:
        return 0.0


def parse_df_data_gb(text):
    """Total storage in GB from `df /data` output (the /data row)."""
    if not text:
        return 0.0
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) >= 2 and parts[-1] == "/data":
            return _size_to_gb(parts[1])
    return 0.0


def storage_tier(gb):
    """The shop size a storage total means: 119.2 GB is a 128 phone.
    Nearest catalog size within 12%, else the rounded number."""
    for tier in (8, 16, 24, 32, 48, 64, 128, 256, 512, 1024):
        if abs(gb - tier) <= tier * 0.12:
            return tier
    return int(round(gb))


def ram_tier(gb):
    """Same idea for memory: 7.6 GB is an 8 GB phone."""
    for tier in (1, 2, 3, 4, 6, 8, 12, 16, 24, 32):
        if abs(gb - tier) <= tier * 0.15:
            return tier
    return int(round(gb))


_MODEL_NUMBER_RE = re.compile(
    r"^(?:[A-Za-z]{1,4}-?[A-Za-z]?[0-9]{3,}[A-Za-z0-9-]*|[0-9]{4,}[A-Za-z0-9]*)$")


def looks_like_model_number(value):
    """True for XT2515-1 / SM-S166U / 2311DRK48G shapes; False for
    retail names ('moto g power (2025)', 'Pixel 8'). Conservative on
    purpose — a wrong model number is worse than a missing one."""
    v = (value or "").strip()
    if not v or " " in v or "(" in v or ")" in v:
        return False
    return bool(_MODEL_NUMBER_RE.match(v))


def model_number_from_props(props):
    """The XT/SM model number out of an adb getprop dump, or ""."""
    for key in ("ro.boot.hardware.sku", "ro.product.vendor.model",
                "ro.vendor.product.model", "ro.product.model"):
        v = (props.get(key) or "").strip()
        if looks_like_model_number(v):
            return v
    return ""


def speak_model_number(value):
    """'XT2515-1' -> 'X T 2515 dash 1'; 'SM-S166U' -> 'S M dash S 166 U'.
    Letters are spelled, digit runs stay whole (long runs grouped)."""
    out = []
    for part in str(value or "").split("-"):
        if not part:
            continue
        runs = re.findall(r"[A-Za-z]+|[0-9]+", part)
        spoken = []
        for run in runs:
            if run.isalpha():
                spoken.append(" ".join(run.upper()))
            elif len(run) >= 5:
                spoken.append(group_digits(run, 3))
            else:
                spoken.append(run)
        out.append(" ".join(spoken))
    return " dash ".join(out)


def group_digits(number, size=3):
    """Group a digit string for speech / display: '353302…' -> '353 302 …'."""
    digits = re.sub(r"\D", "", str(number or ""))
    return " ".join(digits[i:i + size] for i in range(0, len(digits), size))


# ============================================================================
# Readers — talk to one phone through the injected runner.
# ============================================================================
def read_fastboot(runner, fastboot_path):
    """Read the first fastboot device. Returns (PhoneInfo|None, count)."""
    rc, out, err = runner([fastboot_path, "devices"], timeout=10)
    devices = parse_devices_list(out + "\n" + err)
    if not devices:
        return None, 0
    count = len(devices)
    list_serial = devices[0][0]

    rc, out, err = runner([fastboot_path, "getvar", "all"], timeout=25)
    var = parse_fastboot_getvar(out + "\n" + err)
    product = var.get("product", "")
    if not product:
        rc, out, err = runner([fastboot_path, "getvar", "product"], timeout=10)
        product = parse_fastboot_getvar(out + "\n" + err).get("product", "")

    info = PhoneInfo(source="fastboot")
    info.codename = product
    sku = var.get("sku", "")
    if looks_like_model_number(sku):
        info.model_number = sku
    elif var.get("variant"):
        first = var["variant"].split()[0]
        if looks_like_model_number(first):
            info.model_number = first
    m_bv = re.search(r"\d{3,5}", var.get("battery-voltage", ""))
    if m_bv:
        mv = int(m_bv.group(0))
        if 2500 <= mv <= 5000:
            info.battery_volts = mv / 1000.0
    raw_soc = var.get("battery-soc", "")
    if raw_soc.isdigit() and 0 <= int(raw_soc) <= 100:
        info.battery_level = int(raw_soc)
    info.serial = var.get("serialno", "") or list_serial
    info.imei = var.get("imei", "")
    for key in ("sku", "variant", "radio", "baseband", "baseband-version",
                "hw-revision", "carrier", "max-download-size"):
        if var.get(key):
            info.extras[key] = var[key]
    retail = lookup_codename(product)
    if retail:
        info.model_display = retail
        info.known_name = True
    elif product:
        info.model_display = product  # raw code name — never invent a name
    else:
        info.model_display = "Phone in fastboot mode (no product name read)"
    return info, count


def read_adb(runner, adb_path):
    """Read the first usable adb device. Returns (PhoneInfo|None, count)."""
    rc, out, err = runner([adb_path, "devices"], timeout=10)
    devices = [(s, st) for (s, st) in parse_devices_list(out + "\n" + err)
               if st == "device"]
    if not devices:
        return None, 0
    count = len(devices)
    serial = devices[0][0]

    rc, out, err = runner([adb_path, "-s", serial, "shell", "getprop"],
                          timeout=20)
    props = parse_getprop(out)
    if not props:
        return None, count

    info = PhoneInfo(source="adb")
    info.model_number = model_number_from_props(props)
    info.marketname = props.get("ro.product.marketname", "")
    info.model_prop = props.get("ro.product.model", "")
    info.codename = props.get("ro.product.device", "")
    info.serial = (props.get("ro.boot.serialno", "")
                   or props.get("ro.serialno", "") or serial)

    # v1.2 counter reads — each guarded; a phone that does not answer
    # one simply leaves that field unread, never guessed.
    info.android_version = props.get("ro.build.version.release", "")
    try:
        rc, out, err = runner(
            [adb_path, "-s", serial, "shell", "dumpsys", "battery"],
            timeout=15)
        lvl, health = parse_dumpsys_battery(out)
        if lvl is not None:
            info.battery_level = lvl
        if health:
            info.battery_health = health
    except Exception:
        pass
    try:
        rc, out, err = runner(
            [adb_path, "-s", serial, "shell", "cat",
             "/sys/class/power_supply/battery/cycle_count"], timeout=10)
        cyc = parse_cycle_count(out)
        if cyc is not None:
            info.battery_cycles = cyc
    except Exception:
        pass
    try:
        rc, out, err = runner(
            [adb_path, "-s", serial, "shell", "df", "/data"], timeout=10)
        gb = parse_df_data_gb(out)
        if gb:
            info.storage_gb = gb
    except Exception:
        pass
    try:
        rc, out, err = runner(
            [adb_path, "-s", serial, "shell", "cat", "/proc/meminfo"],
            timeout=10)
        gb = parse_memtotal_gb(out)
        if gb:
            info.ram_gb = gb
    except Exception:
        pass
    try:
        rc, out, err = runner(
            [adb_path, "-s", serial, "shell", "settings", "get", "secure",
             "user_setup_complete"], timeout=10)
        if (out or "").strip() == "0":
            # Setup wizard never finished: the phone may be sitting on
            # an account lock (FRP). A warning light, not a verdict.
            info.frp_warning = True
    except Exception:
        pass

    # IMEI: one guarded attempt; a messy parcel means no IMEI, not a guess.
    try:
        rc, out, err = runner(
            [adb_path, "-s", serial, "shell", "service", "call",
             "iphonesubinfo", "1"], timeout=15)
        info.imei = parse_iphonesubinfo(out) or ""
    except Exception:
        info.imei = ""

    if info.marketname:
        info.model_display = info.marketname
        info.known_name = True
    elif info.model_prop:
        info.model_display = info.model_prop
        info.known_name = True
    else:
        retail = lookup_codename(info.codename)
        if retail:
            info.model_display = retail
            info.known_name = True
        elif info.codename:
            info.model_display = info.codename
        else:
            info.model_display = "Phone found (no model name read)"
    return info, count


# ============================================================================
# iPhone door (macOS only) — usbmuxd + lockdownd, stdlib only.
#
# iPhones have no adb/fastboot. On a Mac, every iPhone talks to the
# system's usbmuxd at /var/run/usbmuxd; through it we open lockdownd
# and ask for the same counter facts. The full read needs the phone
# UNLOCKED and paired ("Trust This Computer" tapped once) — that is
# Apple's rule for every tool, not ours. An unpaired phone still
# answers at the usbmux level with its UDID, so the window can say
# "iPhone here, locked" instead of nothing. Battery cycles are NOT
# exposed on this door in v1.3; battery percent is.
# ============================================================================
IPHONE_MODELS = {
    "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2020)",
    "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (2022)", "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus", "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max", "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus", "iPhone17,5": "iPhone 16e",
    "iPhone18,1": "iPhone 17 Pro", "iPhone18,2": "iPhone 17 Pro Max",
    "iPhone18,3": "iPhone 17", "iPhone18,4": "iPhone Air",
}

_USB_MUXD_SOCK = "/var/run/usbmuxd"
_LOCKDOWN_PORT = 62078


def _plist_frame(payload):
    """One usbmuxd message: 16-byte header + XML plist body."""
    body = plistlib.dumps(payload)
    return struct.pack("<IIII", 16 + len(body), 1, 8, 1) + body


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def _usbmux_roundtrip(sock, payload):
    sock.sendall(_plist_frame(payload))
    header = _recv_exact(sock, 16)
    length, _ver, _typ, _tag = struct.unpack("<IIII", header)
    body = _recv_exact(sock, length - 16)
    return plistlib.loads(body)


def parse_usbmux_devices(message):
    """usbmuxd ListDevices reply -> [(device_id, udid), ...]."""
    out = []
    for entry in (message or {}).get("DeviceList") or []:
        props = entry.get("Properties") or {}
        did = props.get("DeviceID", entry.get("DeviceID"))
        udid = props.get("SerialNumber") or props.get("UDID") or ""
        if did is not None:
            out.append((did, udid))
    return out


def _lockdown_send(sock, payload):
    sock.sendall(plistlib.dumps(payload))


def _lockdown_recv(sock):
    buf = b""
    sock.settimeout(10)
    while b"</plist>" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return plistlib.loads(buf)


def _der_pem(data, kind):
    import base64
    b64 = base64.encodebytes(bytes(data)).decode()
    return ("-----BEGIN %s-----\n%s-----END %s-----\n"
            % (kind, b64, kind)).encode()


def iphone_info_from_values(udid, values, battery_percent=None):
    """Map lockdownd GetValue answers onto a PhoneInfo (pure)."""
    info = PhoneInfo(source="iphone")
    info.serial = values.get("SerialNumber") or udid
    info.imei = values.get("InternationalMobileEquipmentIdentity") or ""
    product = values.get("ProductType") or ""
    info.codename = product
    info.model_number = product
    retail = IPHONE_MODELS.get(product)
    if retail:
        info.model_display = retail
        info.known_name = True
    elif product:
        info.model_display = product
    else:
        info.model_display = "iPhone"
        info.known_name = True
    total = values.get("TotalDiskCapacity")
    if isinstance(total, (int, float)) and total:
        info.storage_gb = total / 1e9
    if isinstance(battery_percent, (int, float)):
        info.battery_level = int(battery_percent)
    return info


def _iphone_locked_info(udid):
    info = PhoneInfo(source="iphone")
    info.serial = udid
    info.model_display = ("iPhone — locked (unlock it, tap Trust "
                          "This Computer, then read again)")
    return info


def read_iphone():
    """Read the first USB iPhone via usbmuxd. macOS only.

    Returns (PhoneInfo|None, count). Never raises: any failure on a
    paired read falls back to the locked-phone answer (UDID known),
    and a transport failure returns None.
    """
    if platform.system() != "Darwin":
        return None, 0
    mux = None
    try:
        mux = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        mux.settimeout(10)
        mux.connect(_USB_MUXD_SOCK)
        reply = _usbmux_roundtrip(mux, {
            "MessageType": "ListDevices",
            "ClientVersionString": "WhatPhoneIsThis",
            "ProgName": "WhatPhoneIsThis"})
        devices = parse_usbmux_devices(reply)
        if not devices:
            return None, 0
        device_id, udid = devices[0]
        count = len(devices)
        # Pair record: without it the phone never paired with this Mac.
        pair = None
        try:
            rec = _usbmux_roundtrip(mux, {
                "MessageType": "ReadPairRecord", "PairRecordID": udid})
            data = rec.get("PairRecordData")
            if data:
                pair = plistlib.loads(bytes(data))
        except Exception:
            pair = None
        if not pair:
            return _iphone_locked_info(udid), count
        buid = pair.get("SystemBUID", "")
        host_id = pair.get("HostID", "")
        # Connect: the same socket becomes the lockdownd stream.
        port_wire = struct.unpack(">H", struct.pack("<H", _LOCKDOWN_PORT))[0]
        reply = _usbmux_roundtrip(mux, {
            "MessageType": "Connect", "DeviceID": device_id,
            "PortNumber": port_wire})
        if (reply or {}).get("Number") not in (0, None):
            return _iphone_locked_info(udid), count
        _lockdown_send(mux, {"Label": "WhatPhoneIsThis",
                             "Request": "QueryType"})
        _lockdown_recv(mux)
        _lockdown_send(mux, {"Label": "WhatPhoneIsThis",
                             "Request": "StartSession",
                             "HostID": host_id, "SystemBUID": buid})
        session = _lockdown_recv(mux)
        if not session.get("SessionID"):
            return _iphone_locked_info(udid), count
        stream = mux
        if session.get("EnableSessionSSL"):
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tmpdir = tempfile.mkdtemp(prefix="wpit-pair-")
            cert_p = os.path.join(tmpdir, "c.pem")
            key_p = os.path.join(tmpdir, "k.pem")
            try:
                with open(cert_p, "wb") as f:
                    f.write(_der_pem(pair["HostCertificate"],
                                     "CERTIFICATE"))
                with open(key_p, "wb") as f:
                    f.write(_der_pem(pair["HostPrivateKey"],
                                     "PRIVATE KEY"))
                ctx.load_cert_chain(cert_p, key_p)
                stream = ctx.wrap_socket(mux)
            finally:
                for p in (cert_p, key_p):
                    try:
                        os.unlink(p)
                    except Exception:
                        pass

        def get_value(key, domain=None):
            req = {"Label": "WhatPhoneIsThis", "Request": "GetValue",
                   "Key": key}
            if domain:
                req["Domain"] = domain
            _lockdown_send(stream, req)
            return (_lockdown_recv(stream) or {}).get("Value")

        values = {}
        for key in ("ProductType", "SerialNumber", "DeviceName",
                    "InternationalMobileEquipmentIdentity",
                    "TotalDiskCapacity"):
            try:
                v = get_value(key)
                if v is not None:
                    values[key] = v
            except Exception:
                pass
        battery = None
        try:
            battery = get_value("BatteryCurrentCapacity",
                                domain="com.apple.mobile.battery")
        except Exception:
            battery = None
        try:
            _lockdown_send(stream, {"Label": "WhatPhoneIsThis",
                                    "Request": "StopSession",
                                    "SessionID": session["SessionID"]})
            _lockdown_recv(stream)
        except Exception:
            pass
        return iphone_info_from_values(udid, values, battery), count
    except Exception:
        return None, 0
    finally:
        try:
            if mux is not None:
                mux.close()
        except Exception:
            pass


# ============================================================================
# Speech — guarded. A speech failure must never block the display.
# ============================================================================
def build_speech_text(info):
    if info.known_name:
        text = f"This phone is a {info.model_display}."
    elif info.codename:
        text = (f"I don't know this one's shop name yet. "
                f"Its code name is {info.codename}.")
    else:
        text = f"This phone is a {info.model_display}."
    if info.model_number:
        text += f" Model number: {speak_model_number(info.model_number)}."
    if info.imei:
        text += f" IMEI: {group_digits(info.imei)}."
    if info.serial:
        text += f" Serial number: {group_digits(info.serial, 4)}."
    if info.android_version:
        text += f" Android {info.android_version}."
    if info.battery_level >= 0:
        seg = f" Battery {info.battery_level} percent"
        if info.battery_health:
            seg += f", health {info.battery_health}"
        if info.battery_cycles >= 0:
            seg += f", {info.battery_cycles} charge cycles"
        text += seg + "."
    elif info.battery_volts:
        text += f" Battery {info.battery_volts:.1f} volts."
    if info.storage_gb:
        text += f" Storage {storage_tier(info.storage_gb)} gigabytes."
    if info.ram_gb:
        text += f" Memory {ram_tier(info.ram_gb)} gigabytes."
    if info.frp_warning:
        text += (" Warning: this phone's setup was never finished. "
                 "It may have an account lock. Check before buying.")
    return text


# ============================================================================
# Self-update (v1.6) — shelf manifest + MD5-verified .pyw swap
# ============================================================================
UPDATE_MANIFEST_URL = ("https://raw.githubusercontent.com/ifixrepairs/"
                       "popup-blocker/main/reader-version.json")


def parse_version_tuple(text):
    out = []
    for part in str(text or "").strip().split("."):
        m = re.match(r"\d+", part)
        out.append(int(m.group(0)) if m else 0)
    return tuple(out) or (0,)


def _fetch_bytes(url, timeout=10):
    req = urllib.request.Request(
        url, headers={"User-Agent": "WhatPhoneIsThis/" + VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_update_manifest(fetcher=None):
    """The shelf manifest dict, or None on any failure."""
    try:
        raw = (fetcher or _fetch_bytes)(UPDATE_MANIFEST_URL, timeout=10)
        data = json.loads(raw.decode("utf-8"))
        if (isinstance(data, dict) and data.get("version")
                and data.get("pyw_url")):
            return data
    except Exception:
        pass
    return None


def update_available(manifest, current=None):
    if not manifest:
        return False
    return (parse_version_tuple(manifest.get("version"))
            > parse_version_tuple(current or VERSION))


def apply_update(manifest, target=None, fetcher=None):
    """Download the shelf .pyw, MD5-verify it, swap it in with a
    .bak backup of the running file. True only on a clean swap."""
    try:
        data = (fetcher or _fetch_bytes)(manifest["pyw_url"], timeout=60)
    except Exception:
        return False
    want = str(manifest.get("pyw_md5") or "").lower()
    if want and hashlib.md5(data).hexdigest() != want:
        return False
    dest = target or os.path.abspath(__file__)
    try:
        tmp = dest + ".new"
        with open(tmp, "wb") as fh:
            fh.write(data)
        shutil.copyfile(dest, dest + ".bak")
        os.replace(tmp, dest)
        return True
    except Exception:
        return False


def sanitize_for_powershell(text):
    """Make `text` safe to embed in a PowerShell single-quoted string."""
    return (str(text).replace("'", " ").replace('"', " ")
            .replace("$", " ").replace("`", " ")
            .replace("\r", " ").replace("\n", " "))


def build_sapi_script(safe_text):
    """The OLD Windows voice (SAPI5) — the fallback, kept forever."""
    return ("Add-Type -AssemblyName System.Speech; "
            "(New-Object System.Speech.Synthesis.SpeechSynthesizer)"
            f".Speak('{safe_text}')")


def build_onecore_file_script(safe_text, out_path):
    """Render speech with the MODERN Windows voice (OneCore / WinRT).

    The owner's reference (identified 2026-10-27 from his own clip,
    transcript + frames checked): Optimus Prime — Peter Cullen's
    studio-processed movie voice. No TTS voice IS that voice; the
    closest installable base is Microsoft's downloadable natural
    MALE voice. For US English, Microsoft's Narrator table lists
    exactly one natural male: Guy (Jenny and Aria are the women).
    Pick order: "Guy" Natural by name, then any Natural male, then
    any Natural voice, then the PC's default modern voice. The
    render plays CLEAN — no effects (every treatment failed the
    owner's ear or Lucy's measurements; see the voice-effects
    note at the speech section). Writes a WAV to `out_path`;
    plays nothing. Any failure returns non-zero so the caller can
    fall back to the SAPI render.
    """
    return (
        "$ErrorActionPreference = 'Stop'; "
        "Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
        "$m = ([System.WindowsRuntimeSystemExtensions].GetMethods() | "
        "Where-Object { $_.Name -eq 'AsTask' -and "
        "$_.GetParameters().Count -eq 1 -and "
        "$_.GetParameters()[0].ParameterType.Name -eq "
        "'IAsyncOperation`1' })[0]; "
        "[Windows.Media.SpeechSynthesis.SpeechSynthesizer, "
        "Windows.Media.SpeechSynthesis, ContentType = WindowsRuntime] "
        "| Out-Null; "
        "$synth = New-Object "
        "Windows.Media.SpeechSynthesis.SpeechSynthesizer; "
        "$allv = [Windows.Media.SpeechSynthesis.SpeechSynthesizer]"
        "::AllVoices; "
        "$pick = $allv | Where-Object { $_.DisplayName -match 'Guy' "
        "-and $_.DisplayName -match 'Natural' } "
        "| Select-Object -First 1; "
        "if (-not $pick) { $pick = $allv | Where-Object { "
        "$_.DisplayName -match 'Natural' -and "
        "$_.Gender.ToString() -eq 'Male' } "
        "| Select-Object -First 1 }; "
        "if (-not $pick) { $pick = $allv | Where-Object { "
        "$_.DisplayName -match 'Natural' } "
        "| Select-Object -First 1 }; "
        "if ($pick) { $synth.Voice = $pick }; "
        "$op = $synth.SynthesizeTextToStreamAsync('"
        + safe_text + "'); "
        "$task = $m.MakeGenericMethod("
        "[Windows.Media.Streams.IRandomAccessStream])"
        ".Invoke($null, @($op)); "
        "$task.Wait(-1) | Out-Null; "
        "$stream = $task.Result; "
        "$in = [System.IO.WindowsRuntimeStreamExtensions]"
        "::AsStreamForRead($stream); "
        "$fs = [System.IO.File]::Create('" + out_path + "'); "
        "$in.CopyTo($fs); $fs.Close(); $in.Close()"
    )


def build_sapi_file_script(safe_text, out_path):
    """Render speech with the OLD SAPI voice to a WAV at `out_path`."""
    return (
        "Add-Type -AssemblyName System.Speech; "
        "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
        "$s.SetOutputToWaveFile('" + out_path + "'); "
        "$s.Speak('" + safe_text + "'); $s.Dispose()"
    )


# ==========================================================================
# Voice effects: NONE ship. The owner's reference is Optimus Prime
# (Peter Cullen, studio-processed — no speech engine reproduces
# him). Three treatments were tried and rejected on evidence:
# v1.1 (female base, owner: "sounds like a girl"), v1.1.2 (bare
# pitch resample — deep but DRAGGED: measured 1.28 words/sec vs
# the reference 1.99; owner: "so slow"), v1.1.3 WSOLA tempo fix
# (length restored but self-checks showed the pitch mangled,
# ~133 Hz measured where ~76 was intended). The shipped voice is
# the clean Guy Natural render at natural speed. A movie-style
# treatment returns only with a real pitch engine, on the
# owner's explicit word — never as another guess.
# ==========================================================================


# ============================================================================
# Built-in voice (v1.4) — Piper neural TTS bundled beside the program
# in a "voice" folder; the owner's pick (2026-10-28, sample 2, at the
# faster pace): en_US-amy-medium, length scale 0.88. Fully local, no
# Microsoft voices, no internet. When the voice folder is absent the
# platform voices below remain the fallback, exactly as before.
# ============================================================================
VOICE_MODEL_NAME = "en_US-amy-medium.onnx"
VOICE_LENGTH_SCALE = "0.88"


def piper_voice_paths(base_dir=None, system=None, machine=None):
    """(piper_exe, model) for this platform, or None when the bundled
    voice folder is not beside the program. Pure selection logic."""
    base = os.path.join(base_dir if base_dir is not None else script_dir(),
                        "voice")
    model = os.path.join(base, VOICE_MODEL_NAME)
    system = system if system is not None else platform.system()
    machine = machine if machine is not None else platform.machine()
    if system == "Windows":
        exe = os.path.join(base, "piper-win", "piper.exe")
    elif system == "Darwin":
        folder = "piper-mac-arm" if machine == "arm64" else "piper-mac-intel"
        exe = os.path.join(base, folder, "piper")
    else:
        exe = os.path.join(base, "piper-linux", "piper")
    if os.path.isfile(exe) and os.path.isfile(model):
        return exe, model
    return None


def render_piper(text, base_dir=None, system=None, machine=None):
    """Render `text` with the bundled Piper voice to a WAV path, or
    None on any failure. Uses subprocess directly (Piper reads the
    text on stdin, which the shared runner does not carry)."""
    paths = piper_voice_paths(base_dir, system, machine)
    if not paths:
        return None
    exe, model = paths
    try:
        tmpdir = tempfile.mkdtemp(prefix="wpit-voice-")
        wav = os.path.join(tmpdir, "speech.wav")
        extra = {}
        if (system or platform.system()) == "Windows":
            extra["creationflags"] = getattr(
                subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            [exe, "--model", model, "--length-scale", VOICE_LENGTH_SCALE,
             "--output_file", wav],
            input=str(text), capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(exe), **extra)
        if proc.returncode == 0 and os.path.isfile(wav):
            return wav
    except Exception:
        pass
    return None


def _play_wav(path):
    """Play a WAV synchronously (Windows winsound). Never raises."""
    try:
        import winsound
        winsound.PlaySound(path, winsound.SND_FILENAME)
        return True
    except Exception:
        return False


def speak(text, platform_name=None, runner=None, player=None):
    """Say `text` out loud — the owner's chosen voice on Windows.

    Windows chain: render clean with the modern OneCore voice (Guy
    Natural when the free pack is installed — the deepest natural
    man Windows offers, picked by the owner's ear as the closest
    honest base to his Optimus Prime reference), fall back to a
    SAPI render, play the WAV. No effects: every treated version
    failed the owner's ear or Lucy's own measurements (see the
    voice-effects note above). macOS: `say`. Never raises.
    """
    system = platform_name if platform_name is not None else platform.system()
    run = runner if runner is not None else default_runner
    play = player if player is not None else _play_wav
    try:
        if system in ("Windows", "Darwin"):
            wav = render_piper(text)
            if wav:
                if system == "Windows":
                    if play(wav):
                        return True
                else:
                    rc, _, _ = run(["afplay", wav], timeout=60)
                    if rc == 0:
                        return True
        if system == "Windows":
            safe = sanitize_for_powershell(text)
            tmpdir = tempfile.mkdtemp(prefix="wpit-speech-")
            raw = os.path.join(tmpdir, "raw.wav").replace("\\", "/")
            rendered = False
            rc, _, _ = run(["powershell", "-NoProfile", "-Command",
                            build_onecore_file_script(safe, raw)],
                           timeout=60)
            if rc == 0 and os.path.isfile(raw):
                rendered = True
            else:
                rc, _, _ = run(["powershell", "-NoProfile", "-Command",
                                build_sapi_file_script(safe, raw)],
                               timeout=60)
                rendered = rc == 0 and os.path.isfile(raw)
            if rendered and play(raw):
                return True
            rc, _, _ = run(["powershell", "-NoProfile", "-Command",
                            build_sapi_script(safe)], timeout=60)
            return rc == 0
        if system == "Darwin":
            rc, _, _ = run(["say", str(text)], timeout=60)
            return rc == 0
    except Exception:
        return False
    return False


# ============================================================================
# Watcher — polls for phones, reads new ones, speaks each phone ONCE.
#
# Speech gating: a phone is spoken the first time it is seen. Polls that
# keep seeing the same plugged-in phone do NOT re-speak. When the phone
# is unplugged its serial is forgotten, so plugging it back in later
# speaks again — that is a new counter visit, not a repeat poll.
# ============================================================================
@dataclass
class PollResult:
    status: str = "none"         # new | current | none | tools_missing
    info: PhoneInfo | None = None
    multiple: bool = False


class PhoneWatcher:
    def __init__(self, runner=None, tool_finder=None, speaker=None,
                 tool_dir=None):
        self.runner = runner if runner is not None else default_runner
        self.tool_finder = tool_finder or (
            lambda name: find_tool(name, tool_dir=tool_dir))
        self.speaker = speaker or (lambda text: speak(text))
        self._seen_serials = set()
        self._current_serial = None

    def _tools(self):
        return self.tool_finder("fastboot"), self.tool_finder("adb")

    def check(self, speak_new=True):
        """One poll. Reads a phone the moment one appears."""
        fastboot_path, adb_path = self._tools()
        if (not fastboot_path and not adb_path
                and platform.system() != "Darwin"):
            return PollResult(status="tools_missing")

        info, count = None, 0
        if fastboot_path:
            info, count = read_fastboot(self.runner, fastboot_path)
        if info is None and adb_path:
            info, count = read_adb(self.runner, adb_path)
        if info is None and platform.system() == "Darwin":
            info, count = read_iphone()

        if info is None:
            # Phone gone (or never here): forget it so a re-plug re-speaks.
            if self._current_serial:
                self._seen_serials.discard(self._current_serial)
                self._current_serial = None
            return PollResult(status="none")

        serial = info.serial or info.imei or info.codename
        multiple = count > 1
        if serial and serial not in self._seen_serials:
            self._seen_serials.add(serial)
            self._current_serial = serial
            if speak_new:
                try:
                    self.speaker(build_speech_text(info))
                except Exception:
                    pass  # speech must never block the display
            return PollResult(status="new", info=info, multiple=multiple)
        self._current_serial = serial
        return PollResult(status="current", info=info, multiple=multiple)

    def read_now(self):
        """Manual READ THE PHONE press: re-read for display, no re-speak
        for a phone that is already on screen."""
        fastboot_path, adb_path = self._tools()
        if (not fastboot_path and not adb_path
                and platform.system() != "Darwin"):
            return PollResult(status="tools_missing")
        info, count = None, 0
        if fastboot_path:
            info, count = read_fastboot(self.runner, fastboot_path)
        if info is None and adb_path:
            info, count = read_adb(self.runner, adb_path)
        if info is None and platform.system() == "Darwin":
            info, count = read_iphone()
        if info is None:
            return PollResult(status="none")
        serial = info.serial or info.imei or info.codename
        if serial:
            self._seen_serials.add(serial)
            self._current_serial = serial
        return PollResult(status="current", info=info, multiple=count > 1)


# ============================================================================
# GUI — built only when run as a program. Importing this file is headless
# and safe: no window, no display calls.
# ============================================================================
def main():
    import tkinter as tk

    watcher = PhoneWatcher()
    results = queue.Queue()
    busy = {"flag": False}

    root = tk.Tk()
    root.title("WHAT PHONE IS THIS")
    root.configure(bg=BG_APP)
    root.geometry("820x790")
    root.minsize(640, 460)

    header = tk.Label(root, text="WHAT PHONE IS THIS",
                      font=("Segoe UI", 20, "bold"),
                      bg=BG_APP, fg=ACCENT)
    header.pack(pady=(16, 2))

    status = tk.Label(root, text=NO_PHONE_TEXT,
                      font=("Segoe UI", 16, "bold"),
                      bg=BG_APP, fg=WARN, wraplength=760, height=2,
                      justify="center")
    status.pack(pady=(4, 10))

    panel = tk.Frame(root, bg=BG_PANEL)
    panel.pack(fill="both", expand=True, padx=18, pady=6)

    tk.Label(panel, text="MODEL", font=("Segoe UI", 13, "bold"),
             bg=BG_PANEL, fg=FG_DIM).pack(pady=(14, 0))
    model_value = tk.Label(panel, text="—", font=("Segoe UI", 42, "bold"),
                           bg=BG_PANEL, fg=FG_TEXT, wraplength=740,
                           justify="center")
    model_value.pack(pady=(2, 8))

    tk.Label(panel, text="MODEL NUMBER", font=("Segoe UI", 13, "bold"),
             bg=BG_PANEL, fg=FG_DIM).pack()
    modelnum_value = tk.Label(panel, text="—",
                              font=("Segoe UI", 24, "bold"),
                              bg=BG_PANEL, fg=FG_TEXT)
    modelnum_value.pack(pady=(0, 8))

    tk.Label(panel, text="IMEI", font=("Segoe UI", 13, "bold"),
             bg=BG_PANEL, fg=FG_DIM).pack()
    imei_value = tk.Label(panel, text="—", font=("Segoe UI", 24, "bold"),
                          bg=BG_PANEL, fg=FG_TEXT)
    imei_value.pack(pady=(0, 8))

    tk.Label(panel, text="SERIAL", font=("Segoe UI", 13, "bold"),
             bg=BG_PANEL, fg=FG_DIM).pack()
    serial_value = tk.Label(panel, text="—", font=("Segoe UI", 24, "bold"),
                            bg=BG_PANEL, fg=FG_TEXT)
    serial_value.pack(pady=(0, 10))

    tk.Label(panel, text="DETAILS", font=("Segoe UI", 13, "bold"),
             bg=BG_PANEL, fg=FG_DIM).pack()
    details_value = tk.Label(panel, text="—", font=("Segoe UI", 15, "bold"),
                             bg=BG_PANEL, fg=FG_TEXT, wraplength=740,
                             justify="center")
    details_value.pack(pady=(0, 10))

    note = tk.Label(panel, text="", font=("Segoe UI", 12),
                    bg=BG_PANEL, fg=FG_DIM, wraplength=740, height=2,
                    justify="center")
    note.pack(pady=(0, 10))

    button = tk.Button(root, text="READ THE PHONE",
                       font=("Segoe UI", 18, "bold"),
                       bg=ACCENT, fg="#06283D", activebackground=GOOD,
                       relief="flat", padx=26, pady=8, cursor="hand2")
    button.pack(pady=12)

    hint = tk.Label(root, text=FASTBOOT_HINT, font=("Segoe UI", 13, "bold"),
                    bg=BG_APP, fg=ACCENT)
    hint.pack()

    update_status = tk.Label(root, text="", font=("Segoe UI", 12, "bold"),
                             bg=BG_APP, fg=ACCENT)
    update_status.pack(pady=(8, 0))
    update_btn = tk.Button(root, text="CHECK FOR UPDATES",
                           font=("Segoe UI", 13, "bold"),
                           bg=BG_PANEL, fg=FG_TEXT, activebackground=ACCENT,
                           relief="flat", padx=18, pady=5, cursor="hand2")
    update_btn.pack(pady=(2, 4))
    tk.Label(root, text=f"{PRIVACY_LINE}  {COPYRIGHT_LINE}",
             font=("Segoe UI", 10), bg=BG_APP, fg=FG_DIM).pack(pady=(4, 10))

    def show_result(result, from_manual=False):
        if result.status == "tools_missing":
            status.config(text=TOOLS_MISSING_TEXT, fg=WARN)
            model_value.config(text="—")
            imei_value.config(text="—")
            serial_value.config(text="—")
            details_value.config(text="—")
            modelnum_value.config(text="—")
            note.config(text="")
            return
        if result.info is None:
            status.config(text=NO_PHONE_TEXT, fg=WARN)
            model_value.config(text="—")
            imei_value.config(text="—")
            serial_value.config(text="—")
            details_value.config(text="—")
            modelnum_value.config(text="—")
            note.config(text="")
            return
        info = result.info
        det = []
        if info.android_version:
            det.append(f"Android {info.android_version}")
        if info.battery_level >= 0:
            seg = f"Battery {info.battery_level}%"
            if info.battery_health:
                seg += f" ({info.battery_health})"
            if info.battery_cycles >= 0:
                seg += f" · {info.battery_cycles} cycles"
            det.append(seg)
        elif info.battery_volts:
            det.append(f"Battery {info.battery_volts:.1f} V")
        if info.storage_gb:
            det.append(f"Storage {storage_tier(info.storage_gb)} GB")
        if info.ram_gb:
            det.append(f"RAM {ram_tier(info.ram_gb)} GB")
        details_value.config(text="  ·  ".join(det) if det else "—")
        via = {"fastboot": "fastboot mode", "iphone": "USB (iPhone)"}.get(
            info.source, "USB (adb)")
        status.config(text=f"Phone found — read by {via}", fg=GOOD)
        model_value.config(text=info.model_display)
        modelnum_value.config(text=info.model_number or "—")
        imei_value.config(text=group_digits(info.imei) if info.imei else "—")
        serial_value.config(text=info.serial or "—")
        bits = []
        if info.frp_warning:
            bits.append("⚠ ACCOUNT-LOCK WARNING — this phone's setup "
                        "was never finished; check for an account "
                        "lock before buying.")
        if not info.known_name and info.codename:
            bits.append(f"Code name “{info.codename}” — not in the name "
                        f"table yet (see RUNBOOK to add it).")
        if info.source == "adb" and info.codename:
            bits.append(f"Code name: {info.codename}")
        if result.multiple:
            bits.append("Two or more phones are plugged in — "
                        "showing the first one.")
        note.config(text="  ".join(bits))

    def run_check(manual):
        if busy["flag"]:
            return
        busy["flag"] = True
        if manual:
            status.config(text=READING_TEXT, fg=ACCENT)

        def work():
            try:
                result = watcher.read_now() if manual else watcher.check()
            except Exception:
                result = PollResult(status="none")
            results.put((result, manual))
            busy["flag"] = False

        threading.Thread(target=work, daemon=True).start()

    def drain():
        try:
            while True:
                result, manual = results.get_nowait()
                show_result(result, from_manual=manual)
        except queue.Empty:
            pass
        root.after(200, drain)

    def poll():
        run_check(manual=False)
        root.after(POLL_MS, poll)

    button.config(command=lambda: run_check(manual=True))

    update_q = queue.Queue()
    upd = {"manifest": None, "busy": False}

    def run_update_check(manual):
        if upd["busy"]:
            return
        upd["busy"] = True
        if manual:
            update_status.config(text="Checking for updates\u2026",
                                 fg=ACCENT)

        def work():
            manifest = fetch_update_manifest()
            update_q.put(("check", manifest, manual))
            upd["busy"] = False

        threading.Thread(target=work, daemon=True).start()

    def run_update_apply():
        manifest = upd["manifest"]
        if not manifest or upd["busy"]:
            return
        upd["busy"] = True
        update_status.config(text="Downloading the update\u2026", fg=ACCENT)

        def work():
            ok = apply_update(manifest)
            update_q.put(("apply", ok, manifest))
            upd["busy"] = False

        threading.Thread(target=work, daemon=True).start()

    def on_update_button():
        if upd["manifest"] and update_available(upd["manifest"]):
            run_update_apply()
        else:
            run_update_check(manual=True)

    def drain_updates():
        try:
            while True:
                kind, payload, extra = update_q.get_nowait()
                if kind == "check":
                    manifest, manual = payload, extra
                    if manifest is None:
                        if manual:
                            update_status.config(
                                text="Couldn't check \u2014 no connection",
                                fg=WARN)
                            speak("Couldn't check for updates. "
                                  "Check the internet connection.")
                    elif update_available(manifest):
                        upd["manifest"] = manifest
                        update_status.config(
                            text=f"Update available: version "
                                 f"{manifest['version']}", fg=GOOD)
                        update_btn.config(
                            text=f"TAP TO UPDATE \u2014 v{manifest['version']}")
                        if manual:
                            speak(f"Version {manifest['version']} is "
                                  f"ready. Tap the update button to "
                                  f"install it.")
                    else:
                        upd["manifest"] = None
                        update_status.config(
                            text=f"Up to date (v{VERSION})", fg=FG_DIM)
                        if manual:
                            speak("You're up to date.")
                else:
                    ok, manifest = payload, extra
                    if ok:
                        upd["manifest"] = None
                        update_btn.config(text="CHECK FOR UPDATES")
                        update_status.config(
                            text=f"Updated to v{manifest['version']} \u2014 "
                                 f"restart the reader", fg=GOOD)
                        speak(f"Updated to version {manifest['version']}. "
                              f"Close the reader and open it again.")
                    else:
                        update_status.config(
                            text="Update didn't go through \u2014 try again",
                            fg=WARN)
                        speak("The update didn't go through. "
                              "You're still on the version you had.")
        except queue.Empty:
            pass
        root.after(400, drain_updates)

    update_btn.config(command=on_update_button)
    root.after(500, drain_updates)
    root.after(2500, lambda: run_update_check(manual=False))
    root.after(300, drain)
    root.after(600, poll)
    root.mainloop()


if __name__ == "__main__":
    main()
