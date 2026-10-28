"""WHAT PHONE IS THIS v1.11 — one-click phone identifier for the shop bench
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
import io
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
import zipfile
from dataclasses import dataclass, field

VERSION = "1.11"

SHOP = "iFixx Repairs"
COPYRIGHT_LINE = "© 2026 iFixx Repairs. All rights reserved."
PRIVACY_LINE = "Nothing is saved — close the window and the phone's info is gone."

# Dark Navy Professional palette (same family as the other shop tools).
BG_APP = "#0B141D"
BG_PANEL = "#12283F"
FG_TEXT = "#F4F7FA"
FG_DIM = "#9FB8CC"
ACCENT = "#35A6FF"
GOLD = "#E8A91C"
GOLD_DEEP = "#8A5F0E"
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
    # --- 2024 era -----------------------------------------------------------
    "fogona":  "Moto G 5G 2024 (XT2413)",           # high — firmware file XT2413V_FOGONA_TRACFONE + XDA fogo-family record + owner's live fastboot read 2026-10-28 (XT2413V, IMEI/serial/volts read in the same pass)
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


def is_windows(system=None):
    """Platform seam: True when running on Windows.

    Every Windows-only behavior keys off this one small function so
    the tests can stub the platform instead of the machine.
    """
    return (system if system is not None else platform.system()) == "Windows"


def fallback_tools_dir(env=None, system=None):
    """Where self-healed tools live when the app folder is not
    writable: %LOCALAPPDATA%\\WhatPhoneIsThis\\tools on Windows.
    None anywhere else (the heal is a Windows-only road)."""
    if not is_windows(system):
        return None
    env = os.environ if env is None else env
    base = env.get("LOCALAPPDATA")
    if not base:
        base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(base, "WhatPhoneIsThis", "tools")


def find_tool(name, tool_dir=None, which=shutil.which):
    """Locate a platform-tools binary: PATH first, then beside the
    script, then the self-healed tools folder (v1.11).

    Returns the full path, or None when not found anywhere.
    """
    found = which(name)
    if found:
        return found
    folders = [tool_dir if tool_dir is not None else script_dir()]
    if tool_dir is None:
        healed = fallback_tools_dir()
        if healed:
            folders.append(healed)
    exe = name + ".exe" if is_windows() else name
    for folder in folders:
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
LOGO_PNG_B64 = (
    "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"
    "scs+SAuBUgqLPgGYtAIdaR3pKCClyRgwCkzksvYk+MWsK7MZF4XrgoMZ13eEYAOklOMawm3sbLh+rhdgUWaXkI1AJGQA15FjlTLV"
    "197z0DFXSttvzNYNMWTYaPONVxfk2Amz9ArGvGHMWjNIIjW072jhro+pbtMVyrpNHpKOepIVahUFkQ4jIGJ0QLpWCkl1hJCBcUEK"
    "69wygAACwqDXe+P11z3Pi3q98lD1wKFDGnFibHR+bi7odje3tludThQpRLZFzACAySYoM9pKwQg2f6Pb3KlUxjcXXhodGdl3YP+l"
    "cxcK+b21Wq1WqyX2FUn1uLMOJjJEiIhoWEhDJIx23YzjODs7O3/9V1/61jefu/e+e9/71OPH7zgqBBrSKEGr6OKFi416U6LExLoj"
    "JtXVLdZARCJanLv8wKNP7T96+zun3njivU+vra5Wh0dGRsZbzdpXvvSFM6ffRBSTk9Pv+8APvP8DHzl39sza2jIiTs3sOXrsjm4Q"
    "+a6XzWQa9fpQtZqKYEy7IyqltFL2c8OsiQ4cPvr1L/WADcosZspQnjG5Y+6Jo/d99Gjj7aXXL9bUgcPRxXnYXIDGEnbWIahx1EHV"
    "Ax0CKSYNrIAMkDBGAyujwph+08pEoTSqnHOzfj6Tzfie43sSSLNh13E8DtDo+aXt+4/sGa9mRsrlcs4fqZbKBb+Ud4vFXKlQ/IVf"
    "/tdfOd30D91phAegEFAWqhvtcLa39P/6xX8zOTVuczgQQAgL/qDTrL/7Qz+1xqOem0UVACOjYYY4uOfI8j0/cO7M+q//5D3HD01u"
    "bjd3msFOo7m2tdMMda2jmu2uISB3SEd67a1FAFAqbEbsjR4ojy3WW4a0JmIUkgQgClK4unydiRYQcsXStfm5bL7gOThUrphC4bbj"
    "t7U63dpOc3VtZXV1Tco0TsGMSY4jIQtWUS+Keuhwp7544raTlaHSHXfdsbS4lCvmp2amtja3Njc2jTFMKmxvY1wWVhgWtgoNGWMg"
    "NFp5vu95mTCMnn/+xZdeeuXkyTt++md+fHyyyijWVlaWl9c6vUCgTGwjM4PTp08ZAFgIubO1hmyGRycunJrTYc+RjjEUBcELz339"
    "xe9+XUhXoLxwfnN9feWn/+E/uefeB1rdDgJ/55tfW7h26dHHPyBQOq6TusZpmIEBiCgIAgtDiFkThVGU893h8ZlufRW9AuRHZfVE"
    "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"
    "FF4W8+nk9CTgUOmaRE+X+71FM72txVDZr993+V9fOfrKf/t7XB9JMyff63O4/8LmJ5/42K2DU/Uj5/nSevz+n/2rW3fr05Y31s9c"
    "vv/iufO7VVV4BwD7ezdff+O1nZ0zDz30sYtb5+eLeZQoMYaY00OqUSRKgIod/54sg93e7Vv7+4efeubZ77/26ivXTz739PaPPVa9"
    "/MHph6SOcTJv29TeIKrpCOwQ2xjjyeH+Z3/sE3/n7/8X/vBff57l3/zB91/5wj/9y59++h998TAXRmtaymR5mS2vmiBAduCPdsE1"
    "+XKffs8yUV225R6vCuSKQ6PlSzaZUBS6482SqJNojUEDWUrXCcBmTp7BKIHAbhri//3HLzU//lg1um975+zOuQuhqUVCvVhMpouD"
    "4zuF1g/sjteHg71Q4OAOFwVvPfLBRN77k7f+6M9eGVe0c2bn4oVdifPbt27e3Ds+bSjQQIsNv/WJ4r5nF+NHQ13hzGXiwmstV17W"
    "+R1QCXYgh7RFSAna1tNv/V+48KPq1lCMUIkOt0mjli0VylRSE0DKRosIoRgeHkyHzJ6kD6rB0tSqhXIlV757+s4XOdbo76hi/vYP"
    "aPuBxc4nnXOIrSDUoTkh970rrVLD45uB+b//J38wcnMSabTo9cYfu7zzqScu/dSnH/daAz248l984cvff/P9h+5/8Nf/w1945pmn"
    "HVNoG9P2RTVJ/KKST4O2M3z7/f7/8Ru/Manxzt2adx6fnV77kzf3PvfM1s8+s/Onbx6+t7dwzp3MmrptG00nSUeJItrU7Sef3Pr7"
    "f/enfaXY/be3n/XXf/vV51+9/vCnURW+bhZkk4pMoVHtGps6+9MuiZKg2/J3AFVVn2CbCc5LD7cMnhkjqmZFiJY5kg7zGf5dggBa"
    "VpEppXi3Ip0vnWY+IwoKdidt/H++eaW8tNsv9P13337v/Q9efPnt19+7fnx8HOvDcRkV1aG/XF463xx9IM1Ubr1Unn147ZFPia/m"
    "5D4oBu/MEBcnselzNeFSuRgou1a0uX0FDdPFp91owAcvxpf/uZzeAveUHVGhqUbGyhAA6ml74g5e03IMYmKnvgdfoHBUlMTQOy+6"
    "onBEzFwVXo4+mF+JLYknJ+TaKFRHQsG+px9+g8IpMyM2tH65dWs4nqNwdbWJcp19ieHAjbZKPZCXf6ue33G7zx4VvSNH6nvelUH1"
    "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"
    "X3I+z5IgaEkqAAAAAElFTkSuQmCC"
)


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


# ============================================================================
# Self-healing phone tools (v1.11) — a Windows copy whose folder lacks
# adb.exe / fastboot.exe used to be a dead reader: the tools-missing
# banner showed and it could never read a phone (the counter-PC field
# case, 2026-10-28: the live copy sat in a tool-less folder). Now the
# copy fetches the tools itself. The five Windows platform-tools files
# ride as a zip on the shop Drive shelf (a binary cannot ride the
# text-only GitHub shelf), MD5-pinned in the manifest as tools_md5,
# verified exactly like the payload's own pyw_md5 — a wrong or
# HTML-error download fails the MD5 check and is never unpacked.
# Windows only, only when BOTH tools are missing, always in a
# background thread — the UI never waits on it.
# ============================================================================
TOOLS_PACK_URL = ("https://drive.usercontent.google.com/download"
                  "?id=1-PvvzpAfoiUXNfQI_CHhwthycPMs6pCf"
                  "&export=download&confirm=t")
TOOL_FILES = ("adb.exe", "fastboot.exe", "AdbWinApi.dll",
              "AdbWinUsbApi.dll", "libwinpthread-1.dll")
TOOLS_GETTING_TEXT = "Getting the phone tools…"
TOOLS_READY_TEXT = "Phone tools are ready — plug a phone in."
TOOLS_FAILED_TEXT = ("The phone tools could not be fetched — check "
                     "the internet, then close and reopen the reader.")


def tools_missing(tool_dir=None, which=shutil.which):
    """True when NEITHER fastboot nor adb can be found anywhere."""
    return (find_tool("fastboot", tool_dir=tool_dir, which=which) is None
            and find_tool("adb", tool_dir=tool_dir, which=which) is None)


def needs_tools_heal(system=None, tool_dir=None, which=shutil.which):
    """The heal decision: Windows, and both phone tools missing.

    Never true on macOS/Linux (their tools ride inside the bundle),
    and never true once any one tool can be found.
    """
    return is_windows(system) and tools_missing(tool_dir=tool_dir,
                                                which=which)


def _dir_writable(folder):
    """Probe a folder for writability by really writing in it."""
    try:
        os.makedirs(folder, exist_ok=True)
        probe = os.path.join(folder, ".wpit-write-test")
        with open(probe, "wb") as fh:
            fh.write(b"")
        os.remove(probe)
        return True
    except Exception:
        return False


def choose_tools_dir(app_dir=None, writable=None, env=None, system=None):
    """Where the healed tools go: beside the .pyw when that folder is
    writable, else the %LOCALAPPDATA% fallback find_tool also checks.
    Returns None when neither road exists (not Windows)."""
    folder = app_dir if app_dir is not None else script_dir()
    if (writable or _dir_writable)(folder):
        return folder
    return fallback_tools_dir(env=env, system=system)


def heal_tools(manifest=None, fetcher=None, app_dir=None, writable=None,
               env=None, system=None):
    """Download the shelf tools pack, MD5-verify it against the
    manifest's tools_md5, and unpack the five tool files (only those
    five names — anything else in the pack is ignored). True only
    when all five land on disk. Never raises: any failure is False,
    and the caller keeps the tools-missing banner.
    """
    try:
        manifest = manifest or fetch_update_manifest(fetcher=fetcher)
        want = str((manifest or {}).get("tools_md5") or "").lower()
        if not want:
            return False
        data = (fetcher or _fetch_bytes)(TOOLS_PACK_URL, timeout=60)
        if hashlib.md5(data).hexdigest() != want:
            return False
        dest = choose_tools_dir(app_dir=app_dir, writable=writable,
                                env=env, system=system)
        if not dest:
            return False
        os.makedirs(dest, exist_ok=True)
        written = 0
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                base = os.path.basename(info.filename)
                if info.is_dir() or base not in TOOL_FILES:
                    continue
                with zf.open(info) as src, open(
                        os.path.join(dest, base), "wb") as out:
                    shutil.copyfileobj(src, out)
                written += 1
        return written == len(TOOL_FILES)
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
def fit_window_size(screen_w, screen_h):
    """Window size that always FITS the screen it opens on.

    Owner rule (2026-10-28, after v1.9 opened bigger than his bench
    screen): the app must never open wider or taller than the display.
    Full design size is 860x980; on smaller screens the window takes
    94% of the width and 92% of the height instead, with sane floors.
    """
    w = min(860, int(screen_w * 0.94))
    h = min(980, int(screen_h * 0.92))
    return max(640, w), max(520, h)


def clamp_window_position(x, y, win_w, win_h, screen_w, screen_h):
    """Pull a window position back so the WHOLE window is on screen.

    v1.11: v1.10 sized the window to fit the screen, but a window can
    still OPEN partly off-screen — a cascade or a second window
    opening low leaves rows or buttons past the edge. The position
    clamps into [0, screen - window] on both axes; a window bigger
    than the screen pins to 0. A position already inside is returned
    untouched, so the centered default stays centered.
    """
    max_x = max(0, screen_w - win_w)
    max_y = max(0, screen_h - win_h)
    return min(max(0, x), max_x), min(max(0, y), max_y)


def main():
    import tkinter as tk

    watcher = PhoneWatcher()
    results = queue.Queue()
    busy = {"flag": False}
    # Self-healing tools (v1.11): idle | getting | ready | failed.
    heal = {"state": "idle"}
    heal_q = queue.Queue()

    if os.name == "nt":
        # Windows display scaling must not blow the window up past the
        # screen edges: declare DPI awareness before the window exists
        # so Tk works in true pixels (v1.9 overflowed a scaled screen).
        try:
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    root = tk.Tk()
    root.title("WHAT PHONE IS THIS")
    root.configure(bg=BG_APP)
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    win_w, win_h = fit_window_size(screen_w, screen_h)
    win_x, win_y = clamp_window_position(
        (screen_w - win_w) // 2, (screen_h - win_h) // 2,
        win_w, win_h, screen_w, screen_h)
    root.geometry(f"{win_w}x{win_h}+{win_x}+{win_y}")
    root.minsize(640, 520)

    logo_img = None
    try:
        logo_img = tk.PhotoImage(data=LOGO_PNG_B64)
    except Exception:
        logo_img = None
    # Size tiers: the face shrinks in steps so EVERY row and button
    # stays visible even on a small screen (v1.10 first cut still
    # clipped rows at 706px tall — the tiers fix that by construction).
    if win_h >= 920:
        tier = 0
    elif win_h >= 780:
        tier = 1
    else:
        tier = 2
    logo_sub = (1, 2, 3)[tier]
    status_fs = (15, 15, 13)[tier]
    head_fs = (14, 14, 12)[tier]
    head_pady = ((12, 8), (12, 8), (6, 2))[tier]
    cap_fs = (12, 12, 11)[tier]
    val_fs = (14, 14, 12)[tier]
    model_fs = (16, 16, 14)[tier]
    det_fs = (12, 12, 11)[tier]
    row_pady = (4, 2, 1)[tier]
    lbl_pady = (10, 6, 3)[tier]
    read_fs = (20, 20, 17)[tier]
    hint_fs = (13, 13, 11)[tier]
    upd_fs = (14, 14, 12)[tier]

    if logo_img is not None and logo_sub > 1:
        try:
            logo_img = logo_img.subsample(logo_sub)
        except Exception:
            pass
    if logo_img is not None:
        tk.Label(root, image=logo_img, bg=BG_APP).pack(pady=(10, 0))
        root._logo_img = logo_img  # keep a reference alive
    else:
        tk.Label(root, text="WHAT PHONE IS THIS",
                 font=("Segoe UI", 20, "bold"),
                 bg=BG_APP, fg=GOLD).pack(pady=(16, 2))

    status = tk.Label(root, text=NO_PHONE_TEXT,
                      font=("Segoe UI", status_fs, "bold"),
                      bg=BG_APP, fg=WARN, wraplength=max(300, win_w - 100),
                      justify="center")
    status.pack(pady=(0, 2) if tier == 2 else (2, 6))

    panel = tk.Frame(root, bg=BG_PANEL, highlightbackground="#294761",
                     highlightthickness=1, bd=0)

    head = tk.Frame(panel, bg=BG_PANEL)
    head.pack(fill="x", padx=16, pady=head_pady)
    tk.Frame(head, bg=GOLD, width=4, height=20).pack(side="left")
    tk.Label(head, text="DEVICE INFORMATION",
             font=("Segoe UI", head_fs, "bold"), bg=BG_PANEL,
             fg=FG_TEXT).pack(side="left", padx=(10, 0))

    ROW_BG = "#16334E"
    ROW_BORDER = "#294761"
    MUTED = "#9FB3C8"

    def make_row(caption):
        row = tk.Frame(panel, bg=ROW_BG, highlightbackground=ROW_BORDER,
                       highlightthickness=1, bd=0)
        row.pack(fill="x", padx=14, pady=row_pady)
        tk.Label(row, text=caption, font=("Segoe UI", cap_fs, "bold"),
                 bg=ROW_BG, fg=MUTED).pack(side="left", padx=(14, 8),
                                           pady=lbl_pady)
        value = tk.Label(row, text="—", font=("Segoe UI", val_fs, "bold"),
                         bg=ROW_BG, fg=FG_TEXT)
        value.pack(side="right", padx=(8, 14), pady=10)
        return value

    model_value = make_row("MODEL")
    model_value.config(font=("Segoe UI", model_fs, "bold"), fg="#FFC857",
                       wraplength=max(180, win_w - 380), justify="right")
    modelnum_value = make_row("MODEL NUMBER")
    imei_value = make_row("IMEI")
    serial_value = make_row("SERIAL")
    battery_value = make_row("BATTERY")
    details_value = make_row("DETAILS")
    details_value.config(font=("Segoe UI", det_fs, "bold"),
                         wraplength=max(180, win_w - 430),
                         justify="right")

    note = tk.Label(panel, text="", font=("Segoe UI", 12),
                    bg=BG_PANEL, fg=FG_DIM, wraplength=max(300, win_w - 120),
                    height=2,
                    justify="center")
    if tier < 2:
        note.pack(pady=(2, 6))

    controls = tk.Frame(root, bg=BG_APP)
    controls.pack(side="bottom", fill="x", pady=(0, 2) if tier == 2 else (0, 6))
    panel.pack(fill="both", expand=True, padx=18, pady=4)

    button = tk.Button(controls, text="READ THE PHONE",
                       font=("Segoe UI", read_fs, "bold"), width=22,
                       bg=GOLD, fg="#0B141D", activebackground="#F2C14E",
                       relief="flat", padx=26, pady=8, cursor="hand2")
    button.pack(pady=(6, 2) if tier == 2 else (10, 4))

    hint = tk.Label(controls, text=FASTBOOT_HINT, font=("Segoe UI", hint_fs, "bold"),
                    bg=BG_APP, fg=ACCENT)
    hint.pack()

    update_status = tk.Label(controls, text="",
                             font=("Segoe UI", 12, "bold"),
                             bg=BG_APP, fg=GOLD)
    update_status.pack(pady=(4, 0) if tier == 2 else (8, 0))
    update_wrap = tk.Frame(controls, bg="#168DE2")
    update_wrap.pack(pady=(1, 2) if tier == 2 else (2, 4))
    update_btn = tk.Button(update_wrap, text="CHECK FOR UPDATES",
                           font=("Segoe UI", upd_fs, "bold"), width=22,
                           bg="#16334E", fg=FG_TEXT,
                           activebackground="#214A6C",
                           relief="flat", padx=18, pady=6, cursor="hand2")
    update_btn.pack(padx=2, pady=2)
    tk.Label(controls, text=f"{PRIVACY_LINE}  {COPYRIGHT_LINE}",
             font=("Segoe UI", 10), bg=BG_APP, fg=FG_DIM).pack(
                 pady=(2, 4) if tier == 2 else (4, 10))

    def show_result(result, from_manual=False):
        if result.status == "tools_missing":
            if heal["state"] == "getting":
                status.config(text=TOOLS_GETTING_TEXT, fg=ACCENT)
            elif heal["state"] == "failed":
                status.config(text=TOOLS_FAILED_TEXT, fg=WARN)
            else:
                status.config(text=TOOLS_MISSING_TEXT, fg=WARN)
            model_value.config(text="—")
            imei_value.config(text="—")
            serial_value.config(text="—")
            details_value.config(text="—")
            modelnum_value.config(text="—")
            battery_value.config(text="—")
            note.config(text="")
            return
        if result.info is None:
            status.config(text=NO_PHONE_TEXT, fg=WARN)
            model_value.config(text="—")
            imei_value.config(text="—")
            serial_value.config(text="—")
            details_value.config(text="—")
            modelnum_value.config(text="—")
            battery_value.config(text="—")
            note.config(text="")
            return
        info = result.info
        if info.battery_level >= 0:
            seg = f"{info.battery_level}%"
            if info.battery_health:
                seg += f" ({info.battery_health})"
            if info.battery_cycles >= 0:
                seg += f" · {info.battery_cycles} cycles"
            battery_value.config(text=seg)
        elif info.battery_volts:
            battery_value.config(text=f"{info.battery_volts:.1f} V")
        else:
            battery_value.config(text="—")
        det = []
        if info.android_version:
            det.append(f"Android {info.android_version}")
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
                            text=f"TAP TO UPDATE \u2014 v{manifest['version']}",
                            bg="#168DE2", fg="#FFFFFF")
                        if manual:
                            speak(f"Version {manifest['version']} is "
                                  f"ready. Tap the update button to "
                                  f"install it.")
                    else:
                        upd["manifest"] = None
                        update_status.config(
                            text=f"Up to date (v{VERSION})", fg=FG_DIM)
                        update_btn.config(bg="#16334E", fg=FG_TEXT)
                        if manual:
                            speak("You're up to date.")
                else:
                    ok, manifest = payload, extra
                    if ok:
                        upd["manifest"] = None
                        update_btn.config(text="CHECK FOR UPDATES",
                                          bg="#16334E", fg=FG_TEXT)
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

    def run_tools_heal():
        """Startup, Windows only, tools missing: fetch them in the
        background and say so in plain words on the status line."""
        if heal["state"] != "idle" or not needs_tools_heal():
            return
        heal["state"] = "getting"
        status.config(text=TOOLS_GETTING_TEXT, fg=ACCENT)

        def work():
            heal_q.put(heal_tools())

        threading.Thread(target=work, daemon=True).start()

    def drain_heal():
        try:
            while True:
                ok = heal_q.get_nowait()
                if ok:
                    heal["state"] = "ready"
                    status.config(text=TOOLS_READY_TEXT, fg=GOOD)
                    # Re-run the tools check with the tools in place:
                    # the banner clears and phone watching takes over.
                    run_check(manual=False)
                else:
                    heal["state"] = "failed"
                    status.config(text=TOOLS_FAILED_TEXT, fg=WARN)
        except queue.Empty:
            pass
        root.after(400, drain_heal)

    root.after(500, drain_updates)
    root.after(2500, lambda: run_update_check(manual=False))
    root.after(300, drain)
    root.after(500, drain_heal)
    root.after(800, run_tools_heal)
    root.after(600, poll)
    root.mainloop()


if __name__ == "__main__":
    main()
