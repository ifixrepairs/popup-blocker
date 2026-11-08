# -*- coding: utf-8 -*-
"""The Phone Checker -- IMEI / identity + diagnostics (v2.1).

WHAT IT DOES
    One counter window. Plug a phone in (or type an IMEI) and get:
      * the phone's identity read off the cable -- Android over ADB,
        iPhone over the idevice tools (lockdown) -- IMEI(s), serial,
        model; a typed entry fills only the gaps the cable left;
      * Luhn validation of both IMEIs, in plain words;
      * the carrier of origin from the Samsung sales-code table;
      * the free checks, each one a separate module that shows what
        it proves and what it does NOT prove:
          - Local identity verdict (runs on this PC, no network);
          - CTIA Stolen Phone Checker (lost/stolen verdict in the
            spec's "NO - not flagged" format);
          - imeicheck-style free device record (serial, color,
            production date, warranty, country, carrier of origin);
          - Carrier BYOD / compatibility (T-Mobile format proven);
          - iCloud Lock check (iUnlocker.com -- Activation Lock
            ON / OFF, run by IMEI or serial; added 2026-10-31 on
            the owner's word. iUnlocker's Carrier & Warranty
            report rides the imeicheck-style record module above).
        The website checks are run by the technician on the
        checker's own site (no account wall on our side, ever) and
        the result is pasted in; this app parses the pasted result,
        stamps WHO ran it and WHEN, and prints it next to the local
        verdicts. Nothing is scraped and no live verdict is faked:
        a check that was not run says NOT RUN on the readout.
      * a printable readout (stdlib PDF) with the shop letterhead,
        every value's source, every check's verdict, and the
        honesty line on every page of the story.

    HONESTY RULES (hard, from the v1 build spec):
      * Never print "unlocked" from an IMEI alone. No free source
        certifies a live SIM-lock verdict; the readout shows what
        the checks prove, then points at the phone-side verdict
        (Settings -> Network unlock screen, or another carrier's
        SIM test).
      * A value the cable could not read is "COULD NOT BE READ",
        never a guess. A check that was not run is "NOT RUN".
      * No account wall, ever: no Samsung account, no Apple ID,
        no vendor sign-in anywhere in this tool.
      * No paid carrier-check APIs. Reads are LOCAL: nothing about
        the customer's phone leaves this machine.

    MODULE 2 -- THE DIAGNOSTICS GRID (new in v2.0)
      * Samsung's 21 tests + Torch + USB = 23, copied in
        structure: automatic runs first, then guided tests one
        by one with an x/23 progress counter, skip-and-return,
        and an end summary that names failures plainly.
      * A = the PC reads it off the cable (Android over ADB;
        iPhone over lockdown + the diagnostics relay, whose
        battery read is deeper than the phone's own Settings:
        cycle count and design-vs-actual capacity = health %).
        B = guided: the technician does the physical thing while
        the PC prompts -- and reads the result itself wherever
        the cable allows (proximity, buttons, wireless charging,
        camera files, headset state). C = biometrics, sealed to
        everyone: sensor + enrollment reads plus a technician-
        observed unlock step, labelled as observed. A pass is
        never faked, on any class.
      * iPhone Face ID / Multi-Touch / pixel / camera-quality
        verdicts route to Apple's own free diagnostics console
        (diagnostics.apple.com) as a labelled hand-off from
        inside the flow -- Apple runs those suites; the
        technician transcribes Apple's verdict. Nothing about
        Apple's site is scraped or automated.
      * Verdicts sit in plain words NEXT TO the numbers (dBm,
        +/-metres, cycles, watts) -- Samsung shows a bare grade;
        we show both.

    MODULE 3 -- THE FULL COUNTER REPORT (new in v2.0)
      * One printable PDF: shop letterhead, the Module 1
        identity + free checks, then every diagnostics test
        with its verdict, its measured values, and an honesty
        label per line (measured by PC / guided / observed by
        technician / not testable without manufacturer service
        tools), a summary that names the failures, and the
        same SHA-256 fingerprint discipline as Module 1.

SCOPE OF THIS BUILD
    Modules 1 + 2 + 3 (build order 2026-10-31, second run).
    The Module 1 core is the gated v1.0 code carried forward
    unchanged in behaviour. Prior art -- the v0.2 toolbox
    (app-v0.2/) and the pc-0.3-lookup number-lookup feature --
    is NOT part of this build and is left untouched; v0.2's
    A-class diagnostics parsers were ported and extended.

STANDALONE
    Own product, own version line, own code. House patterns only
    are mirrored from the sibling tools (stdlib-only, dark face,
    stdlib PDF writer, dormant license hooks) so the tools feel
    like family. Packaging into the Mac app with the crowned logo
    comes in a later run; this source is one file + its icon so it
    packages cleanly.

(C) 2026 iFixx Phone Repairs, LLC. All rights reserved.
"""

import datetime
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

VERSION = "2.1"
APP_NAME = "The Phone Checker"
COPYRIGHT_LINE = "(C) 2026 iFixx Phone Repairs, LLC. All rights reserved."

SHOP_NAME = "iFixx Repairs"
SHOP_HEADER = ("iFixx Repairs \u2014 2828 S McCall Rd Unit 346, "
               "Englewood, FL 34224 \u2014 (941) 875-7511")

IMEI_HONEST_LIMIT = (
    "Free checks show carrier of origin and blacklist status -- "
    "no free source certifies live SIM-lock; the phone's own "
    "Network Unlock screen is the final word.")

PHONE_SIDE_POINTER = (
    "Phone-side verdict: on the phone, open Settings -> Connections "
    "-> More connection settings -> Network unlock (Samsung) or "
    "Settings -> General -> About -> Carrier Lock (iPhone), or test "
    "another carrier's SIM. That screen -- not any IMEI check -- "
    "is the final word on SIM lock.")

# Bold Modern theme tokens (same family face as the shop's other
# tools; design owner-approved 2026-10-16). Verdicts are colored
# TEXT only -- never circles, pills, boxes, ribbons, or bands.
DBG = "#0B0F14"      # app background
DPANEL = "#111827"   # cards / panels
DRAISED = "#172334"  # inputs, hover surfaces
DBORDER = "#294154"  # borders / dividers
DBAR = DPANEL        # header / status bars
DGREEN = "#00E676"   # pass green (text)
DCYAN = "#00B0FF"    # accent / info
DRED = "#FF3B30"     # fail / error text
DWARN = "#FFB020"    # warning text
DSUCCESS = "#22C55E" # verified-success text
DTEXT = "#FFFFFF"
DSECOND = "#CBD5E1"
DMUTED = "#94A3B8"
DFONT = "Segoe UI"

SHELF_BASE = ("https://raw.githubusercontent.com/ifixrepairs/"
              "popup-blocker/main/")
UPDATE_MANIFEST_URL = SHELF_BASE + "phone-checker-version.json"
# New version must stay alive this long. 30 s, not v0.1's 10 s:
# the AdTrapper lesson -- a 10 s window caused false rollbacks
# on slow machines (sanctioned change in the v2.1 restore).
UPDATE_ALIVE_SECONDS = 30

# ---------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------


def _script_dir():
    try:
        return Path(sys.argv[0]).resolve().parent
    except Exception:
        return Path.cwd()


def _now_str():
    # Print rule: timestamps carry their timezone.
    return datetime.datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z").strip()


def _canonical(obj):
    """Deterministic JSON for hashing: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def _version_tuple(text):
    parts = []
    for chunk in str(text).strip().split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def _run_tool(cmd, timeout=30):
    """Run a local tool and return stdout text. Raises RuntimeError
    with a plain-words message on failure."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
            creationflags=(0x08000000 if os.name == "nt" else 0))
    except FileNotFoundError:
        raise RuntimeError("%s not found" % cmd[0])
    except subprocess.TimeoutExpired:
        raise RuntimeError("%s timed out" % cmd[0])
    out = proc.stdout or ""
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        raise RuntimeError("%s failed (%s)%s"
                           % (cmd[0], proc.returncode,
                              (": " + err[:200]) if err else ""))
    return out


# ---------------------------------------------------------------------
# Android cable layer (ADB) -- thin wrapper; core logic talks to a
# runner object with this run() signature so tests can drive the
# whole pipeline off canned output.
# ---------------------------------------------------------------------


def find_adb_candidates():
    """Everywhere the shop's platform-tools might live, in search
    order: PATH, app folder, the Android SDK, common shop spots,
    and the What Phone Is This rig folder in Downloads."""
    exe = "adb.exe" if os.name == "nt" else "adb"
    here = _script_dir()
    home = Path.home()
    candidates = []
    found = shutil.which("adb")
    if found:
        candidates.append(Path(found))
    candidates.append(here / "platform-tools" / exe)
    candidates.append(here / exe)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(Path(local) / "Android" / "Sdk"
                          / "platform-tools" / exe)
    candidates.append(home / "Downloads" / "platform-tools" / exe)
    candidates.append(home / "platform-tools" / exe)
    candidates.append(home / "Downloads" / "WhatPhoneIsThis-Mac" / exe)
    candidates.append(Path("C:/platform-tools") / exe)
    return candidates


def find_adb():
    for cand in find_adb_candidates():
        try:
            if cand and Path(cand).is_file():
                return Path(cand)
        except Exception:
            pass
    return None


class AdbRunner:
    def __init__(self, adb_path=None):
        self.adb_path = Path(adb_path) if adb_path else find_adb()

    def available(self):
        return self.adb_path is not None

    def run(self, args, timeout=60):
        if self.adb_path is None:
            raise RuntimeError("ADB not found -- install platform-tools")
        return _run_tool([str(self.adb_path)]
                         + [str(a) for a in args], timeout=timeout)


def check_android(runner):
    """(ok, message). ok only when exactly one authorized Android
    device is attached -- a reading must never come off the wrong
    phone."""
    if not runner.available():
        return False, "ADB not found on this computer"
    try:
        out = runner.run(["devices"], timeout=20)
    except Exception as e:
        return False, "ADB error: %s" % e
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    if not devices:
        return False, "No Android phone found"
    if len(devices) > 1:
        return False, ("More than one Android phone is plugged in -- "
                       "keep only the customer's phone attached")
    return True, "Android phone connected"


# ---------------------------------------------------------------------
# iPhone cable layer (idevice tools / lockdown). Same runner shape.
# The phone must be unlocked and the Trust tap + passcode done by
# the customer standing at the counter -- no way around it, and
# there should not be.
# ---------------------------------------------------------------------


def find_idevice_candidates(tool):
    """Where the idevice tools live: PATH, Homebrew (Apple silicon
    + Intel), app folder, the What Phone Is This Mac rig folder."""
    here = _script_dir()
    home = Path.home()
    candidates = []
    found = shutil.which(tool)
    if found:
        candidates.append(Path(found))
    candidates.append(Path("/opt/homebrew/bin") / tool)
    candidates.append(Path("/usr/local/bin") / tool)
    candidates.append(here / tool)
    candidates.append(home / "Downloads" / "WhatPhoneIsThis-Mac" / tool)
    return candidates


def find_idevice_tool(tool):
    for cand in find_idevice_candidates(tool):
        try:
            if cand and Path(cand).is_file():
                return Path(cand)
        except Exception:
            pass
    return None


class IdeviceRunner:
    """Runs idevice_id / ideviceinfo off one tools folder."""

    def __init__(self, tools_dir=None):
        if tools_dir:
            base = Path(tools_dir)
            self.id_path = base / "idevice_id"
            self.info_path = base / "ideviceinfo"
            self.diag_path = base / "idevicediagnostics"
            if not self.id_path.is_file():
                self.id_path = None
            if not self.info_path.is_file():
                self.info_path = None
            if not self.diag_path.is_file():
                self.diag_path = None
        else:
            self.id_path = find_idevice_tool("idevice_id")
            self.info_path = find_idevice_tool("ideviceinfo")
            self.diag_path = find_idevice_tool("idevicediagnostics")

    def available(self):
        return self.id_path is not None and self.info_path is not None

    def diag_available(self):
        # The diagnostics relay is a separate tool; identity must
        # keep working on a machine that lacks it.
        return self.diag_path is not None

    def run(self, tool, args, timeout=30):
        path = {"idevice_id": self.id_path,
                "ideviceinfo": self.info_path,
                "idevicediagnostics": self.diag_path}.get(tool)
        if path is None:
            raise RuntimeError("%s not found -- the iPhone tools are "
                               "not installed on this computer" % tool)
        return _run_tool([str(path)] + [str(a) for a in args],
                         timeout=timeout)


def check_iphone(runner):
    """(ok, message, udid). ok only when exactly one iPhone is
    attached and answers lockdown."""
    if not runner.available():
        return False, ("iPhone tools (idevice) not installed on this "
                       "computer"), ""
    try:
        out = runner.run("idevice_id", ["-l"], timeout=20)
    except Exception as e:
        return False, "iPhone check error: %s" % e, ""
    udids = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if not udids:
        return False, "No iPhone found", ""
    if len(udids) > 1:
        return False, ("More than one iPhone is plugged in -- keep "
                       "only the customer's phone attached"), ""
    return True, "iPhone connected", udids[0]


# ---------------------------------------------------------------------
# parsers for cable output (pure functions; unit-tested off fixtures)
# ---------------------------------------------------------------------

_PROP_RE = re.compile(r"^\[(.+?)\]: \[(.*)\]$")


def parse_getprop(text):
    props = {}
    for line in (text or "").splitlines():
        m = _PROP_RE.match(line.strip())
        if m:
            props[m.group(1)] = m.group(2)
    return {
        "brand": props.get("ro.product.brand", ""),
        "manufacturer": props.get("ro.product.manufacturer", ""),
        "model": props.get("ro.product.model", ""),
        "device": props.get("ro.product.device", ""),
        "serial": props.get("ro.serialno", ""),
        "system_version": props.get("ro.build.version.release", ""),
        "sdk": props.get("ro.build.version.sdk", ""),
        "fingerprint": props.get("ro.build.fingerprint", ""),
        "sales_code": (props.get("ro.csc.sales_code")
                       or props.get("ril.sales_code")
                       or props.get("ro.boot.sales_code") or ""),
        "sim_state": props.get("gsm.sim.state", ""),
        "operator": props.get("gsm.operator.alpha", ""),
    }


_HEXDIGITS_RE = re.compile(r"\b([0-9a-fA-F]{8})\b")


def parse_iphonesubinfo_parcel(text):
    """Extract the IMEI from `service call iphonesubinfo 1` parcel
    output. The parcel carries the IMEI as a UTF-16LE string; we
    rebuild the byte stream from the printed hex words, decode, and
    return the first digit run that is a Luhn-valid 15-digit IMEI.
    Returns '' when nothing valid is in there -- the caller then
    records COULD NOT BE READ, never a guess."""
    if not text or "Parcel" not in text:
        return ""
    words = _HEXDIGITS_RE.findall(text)
    if not words:
        return ""
    raw = bytearray()
    for w in words:
        raw += int(w, 16).to_bytes(4, "little")
    try:
        decoded = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        return ""
    # A run counts only when it is EXACTLY 15 digits: a longer digit
    # string is some other value, and truncating it to 15 would
    # manufacture an IMEI the phone never reported.
    for run in re.findall(r"\d+", decoded):
        if len(run) == 15 and luhn_check(run):
            return run
    return ""


def parse_dumpsys_iphonesubinfo(text):
    """Older builds answer `dumpsys iphonesubinfo` in plain text
    ('Device ID = 35...'). Returns the IMEI or ''."""
    for line in (text or "").splitlines():
        m = re.search(r"Device ID\s*=\s*(\d{14,17})", line)
        if m:
            candidate = m.group(1)[:15]
            if len(candidate) == 15 and luhn_check(candidate):
                return candidate
    return ""


# iPhone marketing names by ProductType (house table, mirrored from
# the proven What Phone Is This rig). An unknown ProductType prints
# the raw code -- the tool never invents a name.
IPHONE_MODELS = {
    "iPhone10,1": "iPhone 8", "iPhone10,4": "iPhone 8",
    "iPhone10,2": "iPhone 8 Plus", "iPhone10,5": "iPhone 8 Plus",
    "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X",
    "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (2020)",
    "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (2022)",
    "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
    "iPhone17,5": "iPhone 16e",
    "iPhone18,1": "iPhone 17 Pro", "iPhone18,2": "iPhone 17 Pro Max",
    "iPhone18,3": "iPhone 17", "iPhone18,4": "iPhone Air",
}


def parse_ideviceinfo(text):
    """`ideviceinfo` prints 'Key: Value' lines. Returns the identity
    fields Module 1 needs; everything absent stays ''."""
    values = {}
    for line in (text or "").splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            values[key.strip()] = val.strip()
    product = values.get("ProductType", "")
    model = IPHONE_MODELS.get(product, "")
    return {
        "brand": "Apple",
        "manufacturer": "Apple",
        "model": model,
        "product_type": product,
        "device_name": values.get("DeviceName", ""),
        "serial": values.get("SerialNumber", ""),
        "imei": values.get("InternationalMobileEquipmentIdentity", ""),
        "imei2": values.get(
            "InternationalMobileEquipmentIdentity2", ""),
        "system_version": values.get("ProductVersion", ""),
        "build": values.get("BuildVersion", ""),
        "activation_state": values.get("ActivationState", ""),
        "sim_status": values.get("SIMStatus", ""),
        "udid": values.get("UniqueDeviceID", ""),
        "raw": values,
    }


# ---------------------------------------------------------------------
# IMEI check core: Luhn, Samsung sales codes, identity reads
# ---------------------------------------------------------------------


def normalize_digits(value):
    return "".join(c for c in str(value or "") if c.isdigit())


def luhn_check(digits):
    """Standard IMEI Luhn: double every second digit from the right
    (skipping the check digit), sum digits, total % 10 == 0."""
    digits = normalize_digits(digits)
    if len(digits) != 15 or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_verdict(value):
    """Plain-words verdict for one IMEI value (may be ''/None)."""
    if not value:
        return "COULD NOT BE READ"
    digits = normalize_digits(value)
    if len(digits) != 15:
        return "NOT 15 DIGITS (got %d)" % len(digits)
    return "VALID" if luhn_check(digits) else "INVALID -- Luhn fails"


# Samsung sales (CSC) codes -> carrier of origin. Starter set; XAU is
# owner-proven at this counter (Galaxy A16, imeicheck + sticker,
# 2026-10-15). A code names who the phone was BUILT for -- carrier of
# origin, not who it is locked to today.
SALES_CODES = {
    "XAU": "T-Mobile USA",
    "TMB": "T-Mobile USA",
    "XAA": "USA -- factory unlocked / open market",
    "ATT": "AT&T USA",
    "VZW": "Verizon USA",
    "SPR": "Sprint USA (legacy -- now T-Mobile)",
    "USC": "U.S. Cellular",
    "ACG": "U.S. regional carriers (ACG)",
    "LRA": "Verizon regional (LRA)",
    "XAR": "Cellular South / C Spire USA",
    "KOO": "Korea -- factory unlocked",
    "SKC": "SK Telecom (Korea)",
    "KTC": "KT (Korea)",
    "LGT": "LG U+ (Korea)",
    "BTU": "United Kingdom -- factory unlocked",
    "XEU": "United Kingdom / Ireland -- open market",
    "DBT": "Germany -- factory unlocked",
    "XEF": "France -- open market",
    "ITV": "Italy -- open market",
    "PHE": "Spain -- open market",
    "XEO": "Poland -- open market",
    "XSA": "Australia -- open market",
    "TGY": "Hong Kong -- open market",
    "XSG": "United Arab Emirates -- open market",
    "INS": "India -- open market",
    "XXV": "Vietnam -- open market",
    "SER": "Russia -- open market",
}


def sales_code_lookup(code):
    """Carrier-of-origin text for a Samsung sales code, or the
    honest unknown wording. Case-insensitive; '' in -> '' out."""
    code = (code or "").strip().upper()
    if not code:
        return ""
    return SALES_CODES.get(
        code, "Unknown sales code (%s) -- carrier of origin not in "
              "the table yet" % code)


def model_variant_note(model, brand=""):
    """The US model-suffix rule proven at this counter: a Samsung
    model ending in U is a US carrier model; U1 is the factory-
    unlocked US model. Anything else gets no note (no guessing).
    The rule is Samsung's: when the brand is known and is NOT
    Samsung, no note is made."""
    if brand and "samsung" not in str(brand).strip().lower():
        return ""
    m = (model or "").strip().upper()
    if m.endswith("U1"):
        return ("Model ends in U1 -- factory-unlocked US model "
                "variant.")
    if m.endswith("U"):
        return ("Model ends in U -- US carrier model variant "
                "(built for a carrier; today's lock state is a "
                "separate question).")
    return ""


def capture_identity_android(runner):
    """Read an Android phone's identity over ADB. Every field
    carries its source. Fields Android withholds come back '' WITH
    the source saying so -- the typed-entry fallback covers them."""
    ident = {"platform": "Android", "sources": {}}
    props = parse_getprop(runner.run(["shell", "getprop"],
                                     timeout=30))
    ident.update(props)
    ident["sources"]["identity"] = "adb shell getprop"
    for field, prop in (("brand", "ro.product.brand"),
                        ("model", "ro.product.model"),
                        ("serial", "ro.serialno"),
                        ("system_version", "ro.build.version.release")):
        ident["sources"][field] = (
            "adb shell getprop (%s)" % prop
            if ident.get(field) else "not read")

    imei = ""
    imei_source = ""
    try:
        dump = runner.run(["shell", "dumpsys", "iphonesubinfo"],
                          timeout=30)
        imei = parse_dumpsys_iphonesubinfo(dump)
        if imei:
            imei_source = "adb shell dumpsys iphonesubinfo"
    except Exception:
        imei = ""
    if not imei:
        try:
            parcel = runner.run(
                ["shell", "service", "call", "iphonesubinfo", "1",
                 "s16", "com.android.shell"], timeout=30)
            imei = parse_iphonesubinfo_parcel(parcel)
            if imei:
                imei_source = "adb shell service call iphonesubinfo 1"
        except Exception:
            imei = ""
    ident["imei"] = imei
    # Dual-SIM second IMEI is not exposed to the shell without
    # privileges on current builds -- typed fallback covers it.
    ident["imei2"] = ""
    ident["sources"]["imei"] = (
        imei_source if imei else
        "unavailable -- this Android build does not release the "
        "IMEI to the shell; type it from the phone's About screen "
        "or the SIM tray")
    ident["sources"]["imei2"] = (
        "not read -- the shell cannot read the second IMEI "
        "without privileges; the typed-entry fallback covers it")
    ident["sources"]["sales_code"] = (
        "adb shell getprop (ro.csc.sales_code)"
        if ident.get("sales_code") else
        "unavailable -- no sales code reported")
    return ident


def capture_identity_iphone(runner):
    """Read an iPhone's identity over lockdown (ideviceinfo). The
    phone must be unlocked with the Trust tap done; if lockdown
    refuses, ideviceinfo fails and the caller gets the error in
    plain words rather than a partial guess."""
    ok, msg, udid = check_iphone(runner)
    if not ok:
        raise RuntimeError(msg)
    text = runner.run("ideviceinfo", [], timeout=30)
    parsed = parse_ideviceinfo(text)
    ident = {"platform": "iPhone", "sources": {}}
    for field in ("brand", "model", "serial", "imei", "imei2",
                  "system_version", "product_type", "device_name",
                  "activation_state", "sim_status"):
        ident[field] = parsed.get(field, "")
    ident["sales_code"] = ""  # sales codes are a Samsung thing
    src = "ideviceinfo (lockdown, over the cable)"
    for field in ("brand", "model", "serial", "imei", "imei2",
                  "system_version"):
        ident["sources"][field] = src if ident.get(field) \
            else "not read"
    if not ident["model"] and ident.get("product_type"):
        ident["sources"]["model"] = (
            "lockdown reported product type %s, which is not in "
            "the model table yet -- the raw code is shown, not a "
            "guessed name" % ident["product_type"])
        ident["model"] = ident["product_type"]
    ident["sources"]["imei2"] = (
        src if ident.get("imei2") else
        "not read -- lockdown did not report a second IMEI; the "
        "typed-entry fallback covers it")
    ident["sources"]["sales_code"] = (
        "not applicable -- sales codes are Samsung's")
    return ident


def read_phone(adb_runner, idevice_runner):
    """Try Android, then iPhone. Returns (platform, ident, message):
    on success platform is 'Android'/'iPhone' and ident is the
    identity dict; on failure platform is None and message says in
    plain words what to do."""
    notes = []
    ok, msg = check_android(adb_runner)
    if ok:
        return "Android", capture_identity_android(adb_runner), msg
    notes.append(msg)
    try:
        ident = capture_identity_iphone(idevice_runner)
        return "iPhone", ident, "iPhone connected"
    except RuntimeError as e:
        notes.append(str(e))
    except Exception as e:
        notes.append("iPhone read error: %s" % e)
    return None, None, " -- ".join(notes)


IDENTITY_FIELDS = ("brand", "model", "serial", "system_version",
                   "imei", "imei2", "sales_code")


def build_identity_report(readings, typed=None, checks=None,
                          now=None):
    """Assemble the Module 1 identity record from cable readings +
    typed fallbacks + check results. A typed value only fills a
    field the cable could not read -- cable truth wins over typing,
    and the source says which one each value came from."""
    typed = typed or {}
    readings = readings or {}
    values, sources = {}, {}
    for field in IDENTITY_FIELDS:
        value = readings.get(field) or ""
        source = readings.get("sources", {}).get(field, "")
        if not value and typed.get(field):
            value = str(typed[field]).strip()
            source = "typed at the counter"
        values[field] = value
        sources[field] = source or "not read"
    report = {
        "app": APP_NAME,
        "record_type": "imei_check",
        "module": "Module 1 -- IMEI / identity",
        "version": VERSION,
        "checked_at": now or _now_str(),
        "platform": readings.get("platform", ""),
        "values": values,
        "sources": sources,
        "imei_verdict": luhn_verdict(values["imei"]),
        "imei2_verdict": luhn_verdict(values["imei2"]),
        "carrier_of_origin": sales_code_lookup(values["sales_code"]),
        "variant_note": model_variant_note(values["model"],
                                           values["brand"]),
        "checks": list(checks or []),
        "honest_limit": IMEI_HONEST_LIMIT,
        "phone_side_pointer": PHONE_SIDE_POINTER,
    }
    report["fingerprint"] = _sha256_text(_canonical(
        {k: v for k, v in report.items() if k != "fingerprint"}))
    return report


# ---------------------------------------------------------------------
# The free checks -- one module per check, kept separate on purpose.
#
# Every check result is a dict:
#   {check_id, title, state, verdict, detail, source, proves,
#    does_not_prove, phone_side_pointer, recorded_at}
# state is one of:
#   "run"             -- this PC produced the verdict locally;
#   "recorded"        -- the technician ran the check on the
#                        checker's own site and pasted the result;
#                        this app parsed the paste;
#   "not_run"         -- nobody ran it. The readout says so.
#   "could_not_parse" -- a paste arrived but no verdict could be
#                        read out of it; nothing was recorded.
#
# The website checks are NEVER scraped or auto-submitted by this
# app: the sites are the checkers' own, they ask a human to type
# the IMEI, and faking a "live" call would fake the verdict. The
# live leg is the technician's browser + this app's parser, and
# the source line on every recorded verdict says exactly that.
# ---------------------------------------------------------------------


def _check_result(module, state, verdict, detail, source,
                  recorded_at=""):
    return {
        "check_id": module.check_id,
        "title": module.title,
        "state": state,
        "verdict": verdict,
        "detail": detail,
        "source": source,
        "proves": module.proves,
        "does_not_prove": module.does_not_prove,
        "phone_side_pointer": module.phone_side_pointer,
        "recorded_at": recorded_at,
    }


def _paste_imei_note(text, record_imei):
    """If the pasted result names an IMEI and it is not the phone's,
    say so in the detail -- a verdict about a different phone must
    never ride on this phone's readout."""
    if not record_imei:
        return ""
    found = re.findall(r"\d{15}", text or "")
    if found and record_imei not in found:
        return (" WARNING: the pasted result names IMEI %s, not "
                "this phone's %s -- check the paste."
                % (found[0], record_imei))
    return ""


class LocalIdentityCheck:
    """Runs entirely on this PC from the cable/typed record."""
    check_id = "local_identity"
    title = "Local identity verdict (this PC)"
    site_name = ""
    proves = ("The IMEIs are well-formed (Luhn), the make/model is "
              "what the cable reports, and the Samsung sales code "
              "names the carrier the phone was built for.")
    does_not_prove = ("Does not prove the phone is SIM-unlocked, "
                      "and does not prove it is clean -- the "
                      "lost/stolen check is the CTIA module.")
    phone_side_pointer = PHONE_SIDE_POINTER

    def default_result(self, values):
        return self.run_local(values)

    def run_local(self, values):
        parts = ["IMEI 1: %s" % luhn_verdict(values.get("imei"))]
        if values.get("imei2"):
            parts.append("IMEI 2: %s"
                         % luhn_verdict(values.get("imei2")))
        origin = sales_code_lookup(values.get("sales_code", ""))
        if origin:
            parts.append("Carrier of origin: %s" % origin)
        elif values.get("sales_code"):
            parts.append("Sales code %s not in the table"
                         % values["sales_code"])
        note = model_variant_note(values.get("model", ""),
                                  values.get("brand", ""))
        detail = note or ""
        return _check_result(
            self, "run", " -- ".join(parts), detail,
            "This PC -- computed from the cable read / typed "
            "values. No network was used.", _now_str())

    def parse_pasted(self, text, values):
        return None  # local check takes no paste


class CtiaStolenCheck:
    """CTIA Stolen Phone Checker -- lost/stolen verdict in the
    format the spec proves: 'NO - not flagged'."""
    check_id = "ctia_stolen"
    title = "CTIA Stolen Phone Checker (lost / stolen)"
    site_name = "the CTIA Stolen Phone Checker website"
    proves = ("Whether the IMEI has been reported lost or stolen "
              "to the industry checker.")
    does_not_prove = ("Does not prove the phone is SIM-unlocked, "
                      "and does not prove ownership -- a phone can "
                      "be unreported and still not be the "
                      "seller's to sell.")
    phone_side_pointer = PHONE_SIDE_POINTER

    def default_result(self, values):
        return _check_result(
            self, "not_run", "NOT RUN",
            "Run it on %s with the phone's IMEI, then paste the "
            "result here." % self.site_name,
            "Nobody has run this check yet.")

    def parse_pasted(self, text, values):
        t = (text or "").lower()
        clean = ("not flagged" in t or "not been reported" in t
                 or "has not been reported" in t
                 or "not reported lost" in t)
        flagged = ("reported lost or stolen" in t
                   or "yes - flagged" in t
                   or "is flagged" in t)
        if clean:
            verdict = "NO - not flagged"
            detail = ("The checker shows no lost or stolen report "
                      "for this IMEI.")
        elif flagged:
            verdict = "YES - FLAGGED (reported lost or stolen)"
            detail = ("Do not buy or resell this phone until the "
                      "report is cleared.")
        else:
            return _check_result(
                self, "could_not_parse", "COULD NOT BE READ",
                "No lost/stolen verdict could be read out of the "
                "pasted text. Nothing was recorded -- paste the "
                "checker's result wording, or leave the check "
                "NOT RUN.",
                "Paste could not be parsed.", _now_str())
        detail += _paste_imei_note(text, values.get("imei", ""))
        return _check_result(
            self, "recorded", verdict, detail,
            "Technician ran %s and pasted the result; this app "
            "parsed the paste." % self.site_name, _now_str())


class ImeiRecordCheck:
    """imeicheck-style free device record: serial, color,
    production date, warranty status + estimated end date,
    country, carrier of origin (the field set the spec lists).
    Named pages in this class: the imeicheck-style record pages,
    and iUnlocker.com's Carrier & Warranty report (carrier,
    country, warranty status -- named 2026-10-31 on the owner's
    word; its label: value lines parse through this module)."""
    check_id = "imei_record"
    title = "Free device record (imeicheck-style)"
    site_name = "a free imeicheck-style record page"
    proves = ("The manufacturer's record for this IMEI: serial, "
              "color, production date, warranty status and its "
              "estimated end date, country, and carrier of "
              "origin -- as that page reports them.")
    does_not_prove = ("Does not prove the phone is SIM-unlocked "
                      "(the record pages themselves say a carrier "
                      "of origin is not a lock verdict), and "
                      "warranty dates are the page's estimates.")
    phone_side_pointer = PHONE_SIDE_POINTER

    _LABELS = (
        ("imei", ("imei",)),
        ("serial", ("serial", "serial number")),
        ("model", ("model", "model name")),
        ("brand", ("brand",)),
        ("color", ("color", "colour")),
        ("production_date", ("production date",
                             "estimated production date",
                             "manufacture date", "manufactured")),
        ("warranty_status", ("warranty status", "warranty")),
        ("warranty_end", ("estimated warranty end", "warranty end",
                          "warranty until", "warranty expires")),
        ("country", ("country", "country of sale")),
        ("carrier_of_origin", ("carrier of origin", "carrier",
                               "original carrier")),
    )

    def default_result(self, values):
        return _check_result(
            self, "not_run", "NOT RUN",
            "Run it on %s with the phone's IMEI, then paste the "
            "record here." % self.site_name,
            "Nobody has run this check yet.")

    def parse_record(self, text):
        """Label-based parse of a pasted free record. Returns the
        fields dict (only what the page actually printed)."""
        found = {}
        for line in (text or "").splitlines():
            if ":" not in line:
                continue
            label, _, val = line.partition(":")
            label = label.strip().lower()
            val = val.strip()
            if not val:
                continue
            for field, names in self._LABELS:
                if label in names and field not in found:
                    found[field] = val
        return found

    def parse_pasted(self, text, values):
        found = self.parse_record(text)
        # 'warranty status' swallows a bare 'warranty' line first;
        # a page that prints only "Warranty: Active" still lands.
        if len(found) < 2:
            return _check_result(
                self, "could_not_parse", "COULD NOT BE READ",
                "No device record could be read out of the pasted "
                "text. Nothing was recorded -- paste the record "
                "page's lines (label: value), or leave the check "
                "NOT RUN.",
                "Paste could not be parsed.", _now_str())
        bits = []
        if found.get("warranty_status"):
            w = "Warranty: %s" % found["warranty_status"]
            if found.get("warranty_end"):
                w += " (est. end %s)" % found["warranty_end"]
            bits.append(w)
        if found.get("production_date"):
            bits.append("Produced: %s" % found["production_date"])
        if found.get("color"):
            bits.append("Color: %s" % found["color"])
        if found.get("country"):
            bits.append("Country: %s" % found["country"])
        if found.get("carrier_of_origin"):
            bits.append("Carrier of origin (per record): %s"
                        % found["carrier_of_origin"])
        detail = " -- ".join(bits)
        detail += _paste_imei_note(text, values.get("imei", ""))
        result = _check_result(
            self, "recorded",
            "Record read (%d fields)" % len(found), detail,
            "Technician ran %s and pasted the record; this app "
            "parsed the paste." % self.site_name, _now_str())
        result["record_fields"] = found
        return result


class CarrierByodCheck:
    """Carrier BYOD / compatibility checker (T-Mobile's is the one
    proven at this counter; the module is carrier-named at record
    time by the technician's paste)."""
    check_id = "carrier_byod"
    title = "Carrier BYOD / compatibility check"
    site_name = "the carrier's BYOD / compatibility checker page"
    proves = ("Whether that carrier's page accepts this IMEI for "
              "its network (bands and activation eligibility, as "
              "the page judges them).")
    does_not_prove = ("Does not prove the phone is SIM-unlocked: "
                      "a carrier page can call a phone compatible "
                      "without certifying its lock state.")
    phone_side_pointer = PHONE_SIDE_POINTER

    def default_result(self, values):
        return _check_result(
            self, "not_run", "NOT RUN",
            "Run it on %s with the phone's IMEI, then paste the "
            "result here." % self.site_name,
            "Nobody has run this check yet.")

    def parse_pasted(self, text, values):
        t = (text or "").lower()
        if "not compatible" in t or "isn't compatible" in t \
                or "is not compatible" in t:
            verdict = "NOT COMPATIBLE (per the carrier's page)"
            detail = ("The carrier's page refuses this IMEI for "
                      "its network.")
        elif "compatible" in t:
            verdict = "COMPATIBLE (per the carrier's page)"
            detail = ("The carrier's page accepts this IMEI for "
                      "its network. This is not a SIM-unlock "
                      "verdict -- see the phone-side pointer.")
        else:
            return _check_result(
                self, "could_not_parse", "COULD NOT BE READ",
                "No compatibility verdict could be read out of "
                "the pasted text. Nothing was recorded -- paste "
                "the page's result wording, or leave the check "
                "NOT RUN.",
                "Paste could not be parsed.", _now_str())
        detail += _paste_imei_note(text, values.get("imei", ""))
        return _check_result(
            self, "recorded", verdict, detail,
            "Technician ran %s and pasted the result; this app "
            "parsed the paste." % self.site_name, _now_str())


class IunlockerIcloudCheck:
    """iUnlocker.com iCloud Lock check -- Apple's Activation
    Lock (iCloud Lock / Find My) reported ON or OFF for an IMEI
    or a serial number. The result format is the one the owner
    brought in on 2026-10-31: model, serial, 'iCloud Lock: OFF',
    the iUnlocker.Com provider line, and the check date. Added
    2026-10-31 on the owner's word. iCloud Lock is the Apple ID
    lock -- a different lock from the carrier SIM lock, and an
    OFF here is never an 'unlocked' verdict."""
    check_id = "icloud_lock"
    title = "iCloud Lock check (iUnlocker)"
    site_name = "the iUnlocker.com check page"
    proves = ("Whether iUnlocker.com reports Apple's iCloud "
              "Lock (Activation Lock / Find My) as ON or OFF for "
              "this IMEI or serial number -- as that page "
              "reports it.")
    does_not_prove = ("Does not prove the phone is SIM-unlocked: "
                      "iCloud Lock is the Apple ID lock, the "
                      "carrier lock is a different lock, and an "
                      "OFF here says nothing about it. Does not "
                      "prove ownership either.")
    phone_side_pointer = PHONE_SIDE_POINTER

    _LOCK_LINE = re.compile(
        r"(icloud lock|activation lock|find my (?:iphone|ipad)?"
        r"|icloud status)\s*[:\-]?\s*(off|on)\b")

    def default_result(self, values):
        return _check_result(
            self, "not_run", "NOT RUN",
            "Run it on %s with the phone's IMEI or serial "
            "number, then paste the result here." % self.site_name,
            "Nobody has run this check yet.")

    def parse_pasted(self, text, values):
        m = self._LOCK_LINE.search((text or "").lower())
        if m is None:
            return _check_result(
                self, "could_not_parse", "COULD NOT BE READ",
                "No iCloud Lock verdict could be read out of the "
                "pasted text. Nothing was recorded -- paste the "
                "checker's result wording (the 'iCloud Lock: "
                "OFF / ON' line), or leave the check NOT RUN.",
                "Paste could not be parsed.", _now_str())
        if m.group(2) == "off":
            verdict = "OFF - iCloud Lock is OFF (per iUnlocker.com)"
            detail = ("iUnlocker reports Activation Lock off for "
                      "this phone's record -- per that page, a new "
                      "owner can activate it. This is the Apple ID "
                      "lock only; it is not a SIM-unlock verdict.")
        else:
            verdict = "ON - iCloud Lock is ON (per iUnlocker.com)"
            detail = ("iUnlocker reports Activation Lock ON -- "
                      "the phone is tied to an Apple ID. Do not "
                      "buy or resell this phone until the owner "
                      "removes it. This is the Apple ID lock only; "
                      "it is not a SIM-unlock verdict.")
        detail += _paste_imei_note(text, values.get("imei", ""))
        return _check_result(
            self, "recorded", verdict, detail,
            "Technician ran %s and pasted the result; this app "
            "parsed the paste." % self.site_name, _now_str())


CHECK_MODULES = [LocalIdentityCheck(), CtiaStolenCheck(),
                 ImeiRecordCheck(), CarrierByodCheck(),
                 IunlockerIcloudCheck()]
CHECK_BY_ID = {c.check_id: c for c in CHECK_MODULES}


def default_checks(values):
    """Every check at its starting state for a fresh readout: the
    local check runs; the website checks say NOT RUN."""
    return [c.default_result(values) for c in CHECK_MODULES]


def record_paste(checks, check_id, text, values):
    """Fold a technician's paste into the checks list. Only a
    parseable verdict replaces the NOT RUN state; an unparseable
    paste leaves the previous state and returns the parse result
    so the face can show why. Returns (checks, result)."""
    module = CHECK_BY_ID.get(check_id)
    if module is None or module.parse_pasted(text, values) is None:
        return checks, None
    result = module.parse_pasted(text, values)
    if result["state"] != "recorded":
        return checks, result
    out = []
    for existing in checks:
        if existing["check_id"] == check_id:
            out.append(result)
        else:
            out.append(existing)
    return out, result


# ---------------------------------------------------------------------
# Module 2 -- the diagnostics grid (Samsung's 21 + Torch + USB = 23).
#
# Feasibility grades come from the dossier (Part 3 combined table):
#   A = the PC reads/drives it over the cable, automatic;
#   B = guided: the technician does a short physical thing at the
#       phone while the PC prompts -- and, where the cable allows,
#       the PC reads the result itself;
#   C = the biometric stack is sealed to third parties; the PC
#       reads sensor presence + enrollment, and the verdict comes
#       from a technician-observed unlock step. NEVER a faked pass.
#
# Every test result is a dict:
#   {num, name, platform, test_class, status, verdict, value,
#    detail, honesty_label, source, recorded_at}
# status is one of: "not_run", "pass", "fail", "skipped",
#   "could_not_check", "not_testable".
# honesty_label is one of: "measured by PC", "guided",
#   "observed by technician",
#   "not testable without manufacturer service tools".
#
# All parsers are pure functions over cable output text, gated on
# fixtures in fixtures/diag/. Captures guard every read the same
# way v0.2's diagnostics capture did: one flaky dumpsys never
# aborts the run -- the line just says COULD NOT BE CHECKED.
# ---------------------------------------------------------------------

LBL_MEASURED = "measured by PC"
LBL_GUIDED = "guided"
LBL_OBSERVED = "observed by technician"
LBL_NOT_TESTABLE = "not testable without manufacturer service tools"

ST_NOT_RUN = "not_run"
ST_PASS = "pass"
ST_FAIL = "fail"
ST_SKIPPED = "skipped"
ST_NOCHECK = "could_not_check"
ST_NOT_TESTABLE = "not_testable"

STATUS_WORDS = {
    ST_NOT_RUN: "NOT RUN",
    ST_PASS: "PASS",
    ST_FAIL: "FAIL",
    ST_SKIPPED: "SKIPPED",
    ST_NOCHECK: "COULD NOT BE CHECKED",
    ST_NOT_TESTABLE: "NOT TESTABLE",
}


def _diag_result(num, name, platform, test_class, status, verdict,
                 value="", detail="", honesty_label=LBL_MEASURED,
                 source=""):
    return {
        "num": num, "name": name, "platform": platform,
        "test_class": test_class, "status": status,
        "verdict": verdict, "value": value, "detail": detail,
        "honesty_label": honesty_label, "source": source,
        "recorded_at": _now_str(),
    }


# The 23 tests, in Samsung's order, Torch + USB added at the end
# (the dossier's own call: Samsung dropping them from the phone
# grid is no reason for us to). Guided text is what the face shows
# the technician, in big plain words.
TEST_DEFS = [
    {"num": 1, "name": "System software",
     "android": "A", "iphone": "A",
     "guide_android": "", "guide_iphone": ""},
    {"num": 2, "name": "Battery status",
     "android": "A", "iphone": "A",
     "guide_android": "", "guide_iphone": ""},
    {"num": 3, "name": "NFC",
     "android": "A", "iphone": "B",
     "guide_android": "",
     "guide_iphone": "Hold a shop NFC tag or bank card against the "
                     "TOP of the iPhone. It should react (a banner "
                     "or the Wallet). Then record what happened."},
    {"num": 4, "name": "SIM card",
     "android": "A", "iphone": "B",
     "guide_android": "",
     "guide_iphone": "The cable already read the SIM state and "
                     "ICCID (shown with this test). Now look at the "
                     "phone: signal bars showing, and Settings -> "
                     "Cellular names the carrier. Record what the "
                     "phone shows."},
    {"num": 5, "name": "Mobile network",
     "android": "A", "iphone": "B",
     "guide_android": "",
     "guide_iphone": "Watch the phone: signal bars present, then "
                     "place a short test call or load a web page. "
                     "Record whether the network worked."},
    {"num": 6, "name": "Sensors",
     "android": "A", "iphone": "B",
     "guide_android": "",
     "guide_iphone": "Open the Compass app and turn the phone -- "
                     "the needle should follow. Open Measure -> "
                     "Level and tilt the phone -- the level should "
                     "move. Cover and uncover the top of the phone "
                     "-- brightness should react if Auto-Brightness "
                     "is on. Record what you saw."},
    {"num": 7, "name": "Location accuracy",
     "android": "A", "iphone": "B",
     "guide_android": "",
     "guide_iphone": "Open Maps or Compass. The blue dot should "
                     "settle on this shop with a small accuracy "
                     "ring. Record whether it found the phone in "
                     "the right place."},
    {"num": 8, "name": "Wi-Fi",
     "android": "A", "iphone": "B",
     "guide_android": "",
     "guide_iphone": "On the phone: Settings -> Wi-Fi. The shop "
                     "network should be listed and connected, with "
                     "signal bars. Record what the phone shows."},
    {"num": 9, "name": "Bluetooth",
     "android": "A", "iphone": "B",
     "guide_android": "",
     "guide_iphone": "On the phone: Settings -> Bluetooth. It "
                     "should be ON and see nearby devices (pair to "
                     "the shop speaker if it is handy). Record what "
                     "the phone shows."},
    {"num": 10, "name": "Proximity recognition",
     "android": "B", "iphone": "B",
     "guide_android": "When this PC says GO, cover the TOP of the "
                      "phone (the earpiece / camera area) with your "
                      "palm, hold one second, then let go. This PC "
                      "watches the sensor reading itself.",
     "guide_iphone": "Start a call (or a voice memo recording) "
                     "and cover the earpiece with your hand -- the "
                     "screen must go dark. Move your hand away -- "
                     "it must light up again. Record what the "
                     "screen did."},
    {"num": 11, "name": "Buttons",
     "android": "B", "iphone": "B",
     "guide_android": "Press each key when this PC names it: "
                      "VOLUME UP, VOLUME DOWN, then the SIDE / "
                      "POWER key. This PC listens for the real key "
                      "presses on the cable -- it never injects "
                      "them.",
     "guide_iphone": "Press each one and watch the phone react: "
                     "Volume Up (click + volume shows), Volume "
                     "Down, Side button (screen sleeps / wakes), "
                     "and the Ring / Silent switch (bell shows). "
                     "Record any key that did not react."},
    {"num": 12, "name": "Vibration",
     "android": "B", "iphone": "B",
     "guide_android": "This PC will buzz the phone. Hold the "
                      "phone in your hand and record whether you "
                      "felt a strong, clean buzz.",
     "guide_iphone": "Flip the Ring / Silent switch, then open "
                     "Settings -> Sounds & Haptics and tap a "
                     "vibration preview. Record whether the phone "
                     "buzzed strong and clean."},
    {"num": 13, "name": "Speaker",
     "android": "B", "iphone": "B",
     "guide_android": "This PC will play a test tone on the "
                      "phone's loudspeaker. Listen, then record "
                      "whether it played loud and clear. The "
                      "earpiece speaker is checked by ear on a "
                      "call if the job needs it.",
     "guide_iphone": "Play a ringtone or a voice memo out loud on "
                     "the phone and listen. (Apple's own Audio "
                     "suite in the APPLE DIAGNOSTICS panel below "
                     "runs this test the official way.) Record "
                     "what you heard."},
    {"num": 14, "name": "Mic",
     "android": "B", "iphone": "B",
     "guide_android": "On the phone, open the Voice Recorder app, "
                      "record about 3 seconds of talking, then "
                      "play it back. Record whether your voice "
                      "came back clear.",
     "guide_iphone": "On the phone, open Voice Memos, record "
                     "about 3 seconds of talking, then play it "
                     "back. Record whether your voice came back "
                     "clear."},
    {"num": 15, "name": "Camera",
     "android": "B", "iphone": "B",
     "guide_android": "This PC opens the camera on the phone. "
                      "Take one photo with the REAR camera and one "
                      "with the FRONT camera, aiming at anything "
                      "clear. This PC then reads the photo files "
                      "off the phone and checks them.",
     "guide_iphone": "On the phone, open Camera. Take one photo "
                     "with the rear camera and one with the front "
                     "camera, and look at both. (Apple's Camera "
                     "Image Quality suite in the APPLE DIAGNOSTICS "
                     "panel judges quality the official way.) "
                     "Record whether both cameras captured."},
    {"num": 16, "name": "Fingerprint / Touch ID",
     "android": "C", "iphone": "C",
     "guide_android": "Biometrics are sealed -- no computer can "
                      "run this test. This PC read the sensor and "
                      "enrollment from the phone (shown with this "
                      "test). Now watch the customer (or an "
                      "enrolled finger) unlock the phone with a "
                      "fingerprint, and record what you saw.",
     "guide_iphone": "Biometrics are sealed -- no computer can "
                     "run this test. Watch the customer unlock "
                     "the phone with Touch ID. Also check Settings "
                     "-> General -> About -> Parts and Service "
                     "History for a non-genuine sensor note. "
                     "Record what you saw."},
    {"num": 17, "name": "Face recognition / Face ID",
     "android": "C", "iphone": "B",
     "guide_android": "Biometrics are sealed -- no computer can "
                      "run this test. This PC read the sensor and "
                      "enrollment from the phone (shown with this "
                      "test). Now watch the customer unlock the "
                      "phone with their face, and record what you "
                      "saw.",
     "guide_iphone": "Apple's own Face ID suite (in the APPLE "
                     "DIAGNOSTICS panel below) really exercises "
                     "the TrueDepth hardware -- that is the strong "
                     "road. The quick road: watch the customer "
                     "unlock the phone with their face. Record "
                     "what you saw."},
    {"num": 18, "name": "Touch screen",
     "android": "B", "iphone": "B",
     "guide_android": "This PC puts a trace grid on the phone's "
                      "browser. Swipe a finger over EVERY square "
                      "of the grid -- the squares you touch light "
                      "up here, and this PC counts the coverage. "
                      "Untouched squares are the dead zones.",
     "guide_iphone": "Apple's Multi-Touch suite (in the APPLE "
                     "DIAGNOSTICS panel below) maps the responsive "
                     "areas the official way. The quick road: drag "
                     "an app icon slowly over every part of the "
                     "screen and watch for it dropping or jumping. "
                     "Record what you saw."},
    {"num": 19, "name": "Cable charging",
     "android": "A", "iphone": "A",
     "guide_android": "", "guide_iphone": ""},
    {"num": 20, "name": "Wireless charging",
     "android": "B", "iphone": "B",
     "guide_android": "Put the phone on the shop's wireless "
                      "charging pad when this PC says GO. This PC "
                      "watches the charge state itself.",
     "guide_iphone": "Put the phone on the shop's Qi / MagSafe "
                     "pad when this PC says GO. This PC watches "
                     "the battery readings for the charge rising."},
    {"num": 21, "name": "Wired headphones",
     "android": "B", "iphone": "B",
     "guide_android": "Plug the wired earbuds into the phone. "
                      "This PC checks the phone sees them, plays "
                      "the test tone, and you record whether it "
                      "came through the earbuds clear.",
     "guide_iphone": "Plug the Lightning / USB-C earbuds into "
                     "the phone and play any sound. Record "
                     "whether it came through the earbuds clear."},
    {"num": 22, "name": "Torch (flashlight)",
     "android": "A", "iphone": "B",
     "guide_android": "This PC does not fire the torch during "
                     "RUN ALL -- a light switching itself on "
                     "mid-run helps nobody. Press RUN THE PC PART "
                     "and this PC will try to switch the "
                     "flashlight on and off itself and record "
                     "the result. If this build keeps the torch "
                     "sealed from the shell, the button says so "
                     "and your eyes record it instead.",
     "guide_iphone": "Turn the flashlight ON from the Lock Screen "
                     "or Control Center -- the torch must light. "
                     "Turn it off again. Record what it did."},
    {"num": 23, "name": "USB connection",
     "android": "A", "iphone": "A",
     "guide_android": "", "guide_iphone": ""},
]

TEST_BY_NUM = {t["num"]: t for t in TEST_DEFS}


def default_diag_results(platform):
    """A fresh grid: every test NOT RUN, classed for the platform
    that was read ('Android' / 'iPhone')."""
    key = "android" if platform == "Android" else "iphone"
    out = []
    for t in TEST_DEFS:
        out.append(_diag_result(
            t["num"], t["name"], platform, t[key], ST_NOT_RUN,
            "NOT RUN", honesty_label=LBL_MEASURED, source=""))
    return out


def diag_summary(results):
    """Counts + the failure names, in plain words, for the end
    summary and the printed report."""
    counts = {s: 0 for s in STATUS_WORDS}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    done = len(results) - counts.get(ST_NOT_RUN, 0)
    failed = ["%d. %s" % (r["num"], r["name"]) for r in results
              if r["status"] == ST_FAIL]
    return {"counts": counts, "done": done, "total": len(results),
            "failed_names": failed}


# ------------------------------------------------------------ parsers

def parse_getprop_diag(text):
    """Full getprop -> dict of every property (the diagnostics
    reads need more keys than the identity parse keeps)."""
    props = {}
    for line in (text or "").splitlines():
        m = _PROP_RE.match(line.strip())
        if m:
            props[m.group(1)] = m.group(2)
    return props


BATTERY_HEALTH_WORDS = {1: "unknown", 2: "good", 3: "overheat",
                        4: "dead", 5: "over voltage",
                        6: "unspecified failure", 7: "cold"}
BATTERY_STATUS_WORDS = {1: "unknown", 2: "charging",
                        3: "discharging", 4: "not charging",
                        5: "full"}


def parse_battery_diag(text):
    """`dumpsys battery` -> dict, extended from v0.2's parser with
    the charge counter and the max charging current (the live
    charging numbers). Missing fields stay None."""
    out = {"level": None, "scale": None, "health_code": None,
           "health": "", "status_code": None, "status": "",
           "temperature_c": None, "voltage_mv": None,
           "technology": "", "plugged": "",
           "charge_counter_uah": None, "max_current_ua": None}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        try:
            if key == "level":
                out["level"] = int(val)
            elif key == "scale":
                out["scale"] = int(val)
            elif key == "health":
                out["health_code"] = int(val)
                out["health"] = BATTERY_HEALTH_WORDS.get(
                    int(val), "code %s" % val)
            elif key == "status":
                out["status_code"] = int(val)
                out["status"] = BATTERY_STATUS_WORDS.get(
                    int(val), "code %s" % val)
            elif key == "temperature":
                out["temperature_c"] = int(val) / 10.0
            elif key == "voltage":
                out["voltage_mv"] = int(val)
            elif key == "technology":
                out["technology"] = val
            elif key == "charge counter":
                out["charge_counter_uah"] = int(val)
            elif key == "max charging current":
                out["max_current_ua"] = int(val)
            elif key == "ac powered" and val.lower() == "true":
                out["plugged"] = "AC"
            elif key == "usb powered" and val.lower() == "true":
                out["plugged"] = "USB"
            elif key == "wireless powered" \
                    and val.lower() == "true":
                out["plugged"] = "wireless"
        except ValueError:
            continue
    return out


def parse_nfc_state(text):
    """`dumpsys nfc` -> 'on' / 'off' / '' (no adapter text found)."""
    m = re.search(r"mState\s*=\s*(\w+)", text or "")
    if m:
        return "on" if m.group(1).lower().startswith("on") else "off"
    return ""


def parse_telephony(text):
    """`dumpsys telephony.registry` (first phone slot) -> service
    state words + LTE signal in dBm when the dump carries it."""
    out = {"voice_state": "", "data_state": "", "rsrp_dbm": None,
           "rssi_dbm": None, "operator": ""}
    t = text or ""
    m = re.search(r"mVoiceRegState=\d+\((\w+)\)", t)
    if m:
        out["voice_state"] = m.group(1)
    m = re.search(r"mDataRegState=\d+\((\w+)\)", t)
    if m:
        out["data_state"] = m.group(1)
    m = re.search(r"\brsrp=(-?\d+)", t)
    if m:
        out["rsrp_dbm"] = int(m.group(1))
    m = re.search(r"\brssi=(-?\d+)", t)
    if m:
        out["rssi_dbm"] = int(m.group(1))
    m = re.search(r"mOperatorAlphaLong=([^,}]+)", t)
    if m and m.group(1).strip() not in ("", "null"):
        out["operator"] = m.group(1).strip()
    return out


_SENSOR_CORE = (("accelerometer", ("accelerometer",)),
                ("gyroscope", ("gyroscope",)),
                ("compass (magnetometer)", ("magnetic field",
                                            "magnetometer")),
                ("light", ("light",)),
                ("proximity", ("proximity",)),
                ("barometer (pressure)", ("pressure",
                                          "barometer")))


def parse_sensor_list(text):
    """`dumpsys sensorservice` Sensor List -> the sensor names.
    Entry lines look like '0x00000001) Accelerometer | vendor |..'
    """
    names = []
    in_list = False
    for line in (text or "").splitlines():
        if "Sensor List" in line:
            in_list = True
            continue
        if in_list:
            m = re.match(r"\s*0x[0-9a-fA-F]+\)\s*([^|]+)\|", line)
            if m:
                names.append(m.group(1).strip())
            elif names:
                break
    return names


def sensor_core_report(names):
    """Which of the core sensors are present, by friendly name."""
    low = [n.lower() for n in names]
    found, missing = [], []
    for friendly, needles in _SENSOR_CORE:
        hit = any(any(nd in n for nd in needles) for n in low)
        (found if hit else missing).append(friendly)
    return found, missing


def parse_proximity_last(text):
    """The proximity sensor's latest reading (cm) from the Recent
    Sensor events section of `dumpsys sensorservice`, or None.
    Tolerant by design: builds that don't print readings give
    None, and the guided session falls back to the technician's
    eyes -- never to a guess."""
    in_recent = False
    for line in (text or "").splitlines():
        if "Recent Sensor events" in line:
            in_recent = True
            continue
        if in_recent and "proxim" in line.lower():
            m = re.search(r"last=\(\s*(-?[\d.]+)", line)
            if m:
                try:
                    return float(m.group(1))
                except ValueError:
                    return None
    return None


def proximity_sequence_verdict(texts):
    """A guided cover/release poll: the readings across the poll
    window. PASS only when the sensor was seen FAR and then NEAR
    (or the reverse) -- the value actually changed the way a
    working proximity sensor changes."""
    readings = [parse_proximity_last(t) for t in texts]
    readings = [r for r in readings if r is not None]
    if not readings:
        return None, []
    near = any(r <= 0.5 for r in readings)
    far = any(r >= 4.0 for r in readings)
    return (True if (near and far) else False), readings


def parse_location(text):
    """`dumpsys location` -> last fix per provider with accuracy in
    metres, + satellites used when the dump prints them."""
    out = {"fixes": {}, "satellites_used": None,
           "satellites_view": None}
    for m in re.finditer(
            r"Location\[(\w+)\s+(-?[\d.]+),(-?[\d.]+)\s+"
            r"hAcc=([\d.]+)", text or ""):
        out["fixes"][m.group(1)] = {"lat": float(m.group(2)),
                                    "lon": float(m.group(3)),
                                    "acc_m": float(m.group(4))}
    m = re.search(r"satellites used in fix:\s*(\d+)\s*of\s*(\d+)",
                  text or "")
    if m:
        out["satellites_used"] = int(m.group(1))
        out["satellites_view"] = int(m.group(2))
    return out


_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def parse_wifi(text):
    """`dumpsys wifi` -> connection facts + how many distinct
    networks the radio can see in scan results."""
    out = {"ssid": "", "rssi_dbm": None, "link_mbps": None,
           "freq_mhz": None, "connected": False, "seen": 0}
    t = text or ""
    m = re.search(r'SSID:\s*"([^"]+)"', t)
    if m:
        out["ssid"] = m.group(1)
    m = re.search(r"RSSI:\s*(-?\d+)", t)
    if m:
        out["rssi_dbm"] = int(m.group(1))
    m = re.search(r"Link speed:\s*(\d+)\s*Mbps", t)
    if m:
        out["link_mbps"] = int(m.group(1))
    m = re.search(r"Frequency:\s*(\d+)\s*MHz", t)
    if m:
        out["freq_mhz"] = int(m.group(1))
    out["connected"] = "Supplicant state: COMPLETED" in t
    bssids = set(_MAC_RE.findall(t))
    # The phone's own MAC + its connected BSSID are not "seen"
    # networks; the scan rows are what prove the receiver works.
    out["seen"] = len(bssids)
    return out


def parse_bluetooth(text):
    out = {"enabled": None, "name": "", "address": ""}
    t = text or ""
    m = re.search(r"enabled:\s*(true|false)", t, re.I)
    if m:
        out["enabled"] = m.group(1).lower() == "true"
    m = re.search(r"^\s*name:\s*(.+)$", t, re.M)
    if m:
        out["name"] = m.group(1).strip()
    m = re.search(r"^\s*address:\s*(\S+)$", t, re.M)
    if m:
        out["address"] = m.group(1).strip()
    return out


def parse_usb(text):
    out = {"connected": None, "state": ""}
    t = text or ""
    m = re.search(r"(?:connected|mConnected)\s*[:=]\s*(true|false)",
                  t, re.I)
    if m:
        out["connected"] = m.group(1).lower() == "true"
    m = re.search(r"current state:\s*(\w+)", t, re.I)
    if m:
        out["state"] = m.group(1)
    return out


def parse_biometric(text, kind):
    """`dumpsys fingerprint` / `dumpsys face` -> (service_present,
    enrolled_count or None). Tolerant: the counts are the useful
    truth; the biometric act itself stays sealed."""
    t = text or ""
    present = ("fingerprint" in t.lower() if kind == "fingerprint"
               else "face" in t.lower())
    count = None
    word = "fingerprint" if kind == "fingerprint" else "face"
    m = re.search(r"(\d+)\s+%ss?\s+enrolled" % word, t, re.I)
    if not m:
        m = re.search(r"enrolled\D{0,24}?(\d+)", t, re.I)
    if m:
        count = int(m.group(1))
    return present, count


def parse_audio_headset(text):
    """`dumpsys audio` -> True when a wired headset shows in the
    connected-devices picture, False when the dump clearly lists
    connected devices without one, None when it says neither."""
    t = text or ""
    m = re.search(r"connected devices:(.{0,2500})", t, re.I | re.S)
    if m:
        return "WIRED_HEADSET" in m.group(1).upper()
    if re.search(r"wired[ _]headset\D{0,30}(true|connected)", t,
                 re.I):
        return True
    return None


_KEY_EVENT_RE = re.compile(r"KEY_([A-Z0-9_]+)\s+(DOWN|UP)")


def parse_getevent_keys(text):
    """`getevent -l` stream text -> the set of keys seen pressed
    (DOWN events only: a real finger, never an injection)."""
    keys = set()
    for m in _KEY_EVENT_RE.finditer(text or ""):
        if m.group(2) == "DOWN":
            keys.add(m.group(1))
    return keys


BUTTON_KEYS = ("VOLUMEUP", "VOLUMEDOWN", "POWER")


def buttons_verdict(keys_seen):
    """PASS when all three physical keys were seen on the cable."""
    missing = [k for k in BUTTON_KEYS if k not in keys_seen]
    return (not missing), missing


def parse_ls_listing(text):
    """`ls -lt` output -> [(name, size_bytes, 'YYYY-MM-DD HH:MM')]
    newest first, skipping the 'total' header."""
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0].startswith("-"):
            try:
                size = int(parts[4])
            except ValueError:
                continue
            rows.append((parts[-1], size,
                         "%s %s" % (parts[5], parts[6])))
    return rows


def newest_since(rows, since_stamp):
    """Listing rows strictly newer than a 'YYYY-MM-DD HH:MM'
    stamp -- the 'a new photo appeared during this test' check."""
    return [r for r in rows if r[2] > since_stamp]


def jpeg_size(data):
    """(width, height) from JPEG bytes by walking the markers to
    SOF0/SOF2 -- stdlib only, no image library on the shop PC."""
    if not data or len(data) < 4 or data[0:2] != b"\xff\xd8":
        return None
    i = 2
    while i + 3 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xC0, 0xC1, 0xC2):
            if i + 8 >= len(data):
                return None
            h = (data[i + 5] << 8) | data[i + 6]
            w = (data[i + 7] << 8) | data[i + 8]
            return w, h
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seglen = (data[i + 2] << 8) | data[i + 3]
        if seglen < 2:
            return None
        i += 2 + seglen
    return None


def build_tone_wav(seconds=1.0, freq=880, rate=22050):
    """A clean test tone as WAV bytes (stdlib wave/struct) -- the
    speaker + headphones tests play this on the phone."""
    import io
    import math
    import struct
    import wave
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        frames = b"".join(
            struct.pack("<h", int(12000 * math.sin(
                2 * math.pi * freq * (n / rate))))
            for n in range(int(seconds * rate)))
        wf.writeframes(frames)
    return buf.getvalue()


# ------------------------------------------------- iPhone diag reads

def parse_key_values(text):
    """ideviceinfo-style 'Key: Value' text -> dict (disk-usage
    domain, and any other lockdown domain that prints this way)."""
    out = {}
    for line in (text or "").splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            out[key.strip()] = val.strip()
    return out


def _int_or_none(val):
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return None


def parse_ioreg_battery(text):
    """`idevicediagnostics ioreg` AppleSmartBattery output -> the
    battery truth. Format-tolerant on purpose: the tool prints a
    dict style ('"CycleCount" = 512;'), an XML plist
    (<key>CycleCount</key><integer>512</integer>), or plain
    'Key: Value' lines depending on build -- all three are read.
    Truth values arrive as Yes/No, true/false, or <true/>."""
    t = text or ""
    raw = {}
    for m in re.finditer(
            r"<key>([A-Za-z0-9_]+)</key>\s*<integer>(\d+)</integer>",
            t):
        raw[m.group(1)] = int(m.group(2))
    for m in re.finditer(
            r"<key>([A-Za-z0-9_]+)</key>\s*<(true|false)\s*/>", t):
        raw[m.group(1)] = m.group(2) == "true"
    for m in re.finditer(
            r'"?([A-Za-z][A-Za-z0-9_]*)"?\s*=\s*"?(\d+)"?\s*;?', t):
        raw.setdefault(m.group(1), int(m.group(2)))
    for m in re.finditer(
            r'"?([A-Za-z][A-Za-z0-9_]*)"?\s*=\s*(Yes|No)\b', t):
        raw.setdefault(m.group(1), m.group(2) == "Yes")
    for m in re.finditer(
            r"^([A-Za-z][A-Za-z0-9_]*):\s*(\d+)\s*$", t, re.M):
        raw.setdefault(m.group(1), int(m.group(2)))

    def num(*keys):
        for k in keys:
            v = raw.get(k)
            if isinstance(v, int):
                return v
        return None

    def flag(*keys):
        for k in keys:
            v = raw.get(k)
            if isinstance(v, bool):
                return v
        return None

    design = num("DesignCapacity")
    actual = num("AppleRawMaxCapacity", "NominalChargeCapacity")
    if actual is None:
        mx = num("MaxCapacity")
        if mx is not None and mx > 200:
            actual = mx
    health = None
    if design and actual:
        health = round(100.0 * actual / design)
    temp_raw = num("Temperature")
    temp_c = None
    if temp_raw is not None:
        if temp_raw >= 1000:
            temp_c = temp_raw / 100.0
        elif temp_raw >= 100:
            temp_c = temp_raw / 10.0
        else:
            temp_c = float(temp_raw)
    return {
        "cycles": num("CycleCount"),
        "design_mah": design,
        "actual_mah": actual,
        "health_pct": health,
        "current_pct": num("BatteryCurrentCapacity",
                           "CurrentCapacity"),
        "temperature_c": temp_c,
        "voltage_mv": num("Voltage"),
        "external_connected": flag("ExternalConnected"),
        "is_charging": flag("BatteryIsCharging", "IsCharging"),
        "fully_charged": flag("FullyCharged"),
        "raw": raw,
    }


def iphone_storage_values(disk_text):
    """Disk-usage domain text -> (total_gb, free_gb) or
    (None, None); GB as Apple counts them (bytes / 1e9)."""
    kv = parse_key_values(disk_text)
    total = _int_or_none(kv.get("TotalDiskCapacity"))
    free = _int_or_none(kv.get("AmountDataAvailable"))
    return ((total / 1e9) if total else None,
            (free / 1e9) if free else None)


# ------------------------------------------- Android automatic reads

def _android_auto_results(read):
    """Verdict builders over one guarded capture dict. `read` maps
    capture keys to parsed values (None when a read failed)."""
    P = "Android"
    out = []
    props = read.get("props") or {}
    batt = read.get("battery") or {}

    # 1 -- System software
    fp = props.get("ro.build.fingerprint", "")
    vbs = props.get("ro.boot.verifiedbootstate", "")
    wbit = props.get("ro.boot.warranty_bit", "")
    ver = props.get("ro.build.version.release", "")
    patch = props.get("ro.build.version.security_patch", "")
    bits = []
    if ver:
        bits.append("Android %s" % ver)
    if patch:
        bits.append("security patch %s" % patch)
    if fp:
        bits.append("build %s" % fp)
    if vbs:
        bits.append("verified boot: %s" % vbs)
    if wbit:
        bits.append("Knox warranty bit: %s" % wbit)
    if not fp and not ver:
        out.append(_diag_result(
            1, "System software", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The phone did not answer the software read.",
            source="adb shell getprop"))
    elif vbs == "orange" or "test-keys" in fp or "dev-keys" in fp:
        out.append(_diag_result(
            1, "System software", P, "A", ST_FAIL,
            "MODIFIED SOFTWARE -- not the maker's official build",
            value=" -- ".join(bits),
            detail="Verified-boot state or build keys say this "
                   "software was modified. On a buy-in, price and "
                   "warranty talk should treat it that way.",
            source="adb shell getprop"))
    elif wbit in ("0x1", "1"):
        out.append(_diag_result(
            1, "System software", P, "A", ST_FAIL,
            "Official build, but the Knox warranty bit is TRIPPED "
            "(0x1) -- the phone was once modified",
            value=" -- ".join(bits),
            source="adb shell getprop"))
    else:
        out.append(_diag_result(
            1, "System software", P, "A", ST_PASS,
            "Official software (maker's release build)",
            value=" -- ".join(bits),
            source="adb shell getprop"))

    # 2 -- Battery status
    lvl = batt.get("level")
    if batt.get("scale"):
        lvl = round(100.0 * batt["level"] / batt["scale"])
    if lvl is None and not batt.get("health"):
        out.append(_diag_result(
            2, "Battery status", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The battery service did not answer.",
            source="adb shell dumpsys battery"))
    else:
        bbits = []
        if lvl is not None:
            bbits.append("charge %d%%" % lvl)
        if batt.get("status"):
            bbits.append(batt["status"])
        if batt.get("temperature_c") is not None:
            bbits.append("%.1f C" % batt["temperature_c"])
        if batt.get("voltage_mv"):
            bbits.append("%d mV" % batt["voltage_mv"])
        cycles = read.get("battery_cycles")
        if cycles:
            bbits.append("%s charge cycles (fuel gauge)" % cycles)
        if batt.get("health_code") == 2:
            st, vd = ST_PASS, "Battery health: good"
        elif batt.get("health"):
            st = ST_FAIL
            vd = ("Battery health: %s -- service advised"
                  % batt["health"])
        else:
            st, vd = ST_NOCHECK, "Battery present; health unread"
        out.append(_diag_result(
            2, "Battery status", P, "A", st, vd,
            value=" -- ".join(bbits),
            source="adb shell dumpsys battery"))

    # 3 -- NFC
    nfc = read.get("nfc_state")
    if nfc == "on":
        out.append(_diag_result(
            3, "NFC", P, "A", ST_PASS, "NFC is present and ON",
            value="adapter state: on",
            source="adb shell dumpsys nfc"))
    elif nfc == "off":
        out.append(_diag_result(
            3, "NFC", P, "A", ST_NOCHECK,
            "NFC is switched OFF -- turn NFC on in Settings and "
            "re-run before calling it bad",
            value="adapter state: off",
            source="adb shell dumpsys nfc"))
    elif nfc is None:
        out.append(_diag_result(
            3, "NFC", P, "A", ST_NOCHECK, "COULD NOT BE CHECKED",
            detail="The NFC service did not answer.",
            source="adb shell dumpsys nfc"))
    else:
        out.append(_diag_result(
            3, "NFC", P, "A", ST_FAIL,
            "No NFC adapter answered on this phone",
            source="adb shell dumpsys nfc"))

    # 4 -- SIM card
    sim_states = [s.strip() for s in
                  (props.get("gsm.sim.state", "")).split(",")
                  if s.strip()]
    operator = props.get("gsm.operator.alpha", "")
    if any(s in ("LOADED", "READY") for s in sim_states):
        out.append(_diag_result(
            4, "SIM card", P, "A", ST_PASS,
            "SIM is in and recognized",
            value="slot state: %s%s" % (
                ", ".join(sim_states),
                (" -- carrier %s" % operator) if operator else ""),
            source="adb shell getprop (gsm.sim.state)"))
    elif any("PIN" in s for s in sim_states):
        out.append(_diag_result(
            4, "SIM card", P, "A", ST_NOCHECK,
            "A SIM is in but PIN-locked -- unlock it on the phone "
            "and re-run",
            value="slot state: %s" % ", ".join(sim_states),
            source="adb shell getprop (gsm.sim.state)"))
    elif sim_states:
        out.append(_diag_result(
            4, "SIM card", P, "A", ST_FAIL,
            "No usable SIM detected",
            value="slot state: %s" % ", ".join(sim_states),
            detail="If the job is a no-service complaint, rule "
                   "out the SIM before the phone.",
            source="adb shell getprop (gsm.sim.state)"))
    else:
        out.append(_diag_result(
            4, "SIM card", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The phone did not report a SIM state.",
            source="adb shell getprop (gsm.sim.state)"))

    # 5 -- Mobile network
    tel = read.get("telephony") or {}
    if tel.get("voice_state") == "IN_SERVICE":
        sig = ""
        if tel.get("rsrp_dbm") is not None:
            sig = "signal %d dBm (LTE RSRP)" % tel["rsrp_dbm"]
        elif tel.get("rssi_dbm") is not None:
            sig = "signal %d dBm (RSSI)" % tel["rssi_dbm"]
        out.append(_diag_result(
            5, "Mobile network", P, "A", ST_PASS,
            "Registered on the network",
            value=" -- ".join(x for x in [
                sig, ("carrier %s" % tel["operator"])
                if tel.get("operator") else ""] if x),
            source="adb shell dumpsys telephony.registry"))
    elif tel.get("voice_state"):
        out.append(_diag_result(
            5, "Mobile network", P, "A", ST_FAIL,
            "Not registered (%s)" % tel["voice_state"],
            detail="With a good SIM in, this points at the phone "
                   "or the account -- check the SIM test first.",
            source="adb shell dumpsys telephony.registry"))
    else:
        out.append(_diag_result(
            5, "Mobile network", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The telephony service did not report a "
                   "registration state.",
            source="adb shell dumpsys telephony.registry"))

    # 6 -- Sensors
    names = read.get("sensor_names")
    if names is None:
        out.append(_diag_result(
            6, "Sensors", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The sensor service did not answer.",
            source="adb shell dumpsys sensorservice"))
    else:
        found, missing = sensor_core_report(names)
        core_missing = [mname for mname in missing
                        if not mname.startswith("barometer")]
        val = "%d sensors found -- present: %s" % (
            len(names), ", ".join(found) if found else "none")
        if core_missing:
            out.append(_diag_result(
                6, "Sensors", P, "A", ST_FAIL,
                "Missing core sensors: %s" % ", ".join(core_missing),
                value=val,
                source="adb shell dumpsys sensorservice"))
        else:
            note = (" (no barometer -- normal on many models)"
                    if any(mname.startswith("barometer")
                           for mname in missing) else "")
            out.append(_diag_result(
                6, "Sensors", P, "A", ST_PASS,
                "All core sensors answer", value=val + note,
                source="adb shell dumpsys sensorservice"))

    # 7 -- Location accuracy
    loc = read.get("location") or {}
    fixes = loc.get("fixes") or {}
    if fixes:
        best = min(fixes.values(), key=lambda f: f["acc_m"])
        who = [k for k, v in fixes.items()
               if v["acc_m"] == best["acc_m"]][0]
        val = "best fix +/-%s m (%s)" % (
            ("%g" % best["acc_m"]), who)
        for prov, f in fixes.items():
            if prov != who:
                val += "; %s +/-%s m" % (prov, "%g" % f["acc_m"])
        if loc.get("satellites_used") is not None:
            val += "; %d of %d satellites used" % (
                loc["satellites_used"], loc["satellites_view"])
        st = ST_PASS if best["acc_m"] <= 50 else ST_NOCHECK
        vd = ("Location works" if st == ST_PASS else
              "A fix exists but it is rough (+/-%s m) -- GPS is "
              "weak indoors; near a window it should tighten"
              % ("%g" % best["acc_m"]))
        out.append(_diag_result(
            7, "Location accuracy", P, "A", st, vd, value=val,
            source="adb shell dumpsys location"))
    else:
        out.append(_diag_result(
            7, "Location accuracy", P, "A", ST_NOCHECK,
            "No location fix on record -- turn Location on and "
            "give it a minute (indoors, GPS is weak)",
            source="adb shell dumpsys location"))

    # 8 -- Wi-Fi
    wifi = read.get("wifi") or {}
    if wifi.get("connected"):
        out.append(_diag_result(
            8, "Wi-Fi", P, "A", ST_PASS,
            "Wi-Fi connected and receiving",
            value="%s -- %s dBm, %s Mbps, %s MHz -- sees %d "
                  "networks" % (
                      wifi.get("ssid") or "network",
                      wifi.get("rssi_dbm"), wifi.get("link_mbps"),
                      wifi.get("freq_mhz"), wifi.get("seen", 0)),
            source="adb shell dumpsys wifi"))
    elif wifi.get("seen"):
        out.append(_diag_result(
            8, "Wi-Fi", P, "A", ST_PASS,
            "Wi-Fi radio works (not connected right now)",
            value="sees %d networks in a scan" % wifi["seen"],
            source="adb shell dumpsys wifi"))
    elif read.get("wifi") is None:
        out.append(_diag_result(
            8, "Wi-Fi", P, "A", ST_NOCHECK, "COULD NOT BE CHECKED",
            detail="The Wi-Fi service did not answer.",
            source="adb shell dumpsys wifi"))
    else:
        out.append(_diag_result(
            8, "Wi-Fi", P, "A", ST_FAIL,
            "Wi-Fi sees nothing and is not connected",
            detail="If Wi-Fi is switched on, the radio or "
                   "antenna is the suspect.",
            source="adb shell dumpsys wifi"))

    # 9 -- Bluetooth
    bt = read.get("bluetooth") or {}
    if bt.get("enabled") is True:
        out.append(_diag_result(
            9, "Bluetooth", P, "A", ST_PASS,
            "Bluetooth adapter is ON",
            value=" -- ".join(x for x in [
                ("name %s" % bt["name"]) if bt.get("name") else "",
                ("address %s" % bt["address"])
                if bt.get("address") else ""] if x),
            source="adb shell dumpsys bluetooth_manager"))
    elif bt.get("enabled") is False:
        out.append(_diag_result(
            9, "Bluetooth", P, "A", ST_NOCHECK,
            "Bluetooth is switched OFF -- turn it on and re-run "
            "before calling it bad",
            source="adb shell dumpsys bluetooth_manager"))
    else:
        out.append(_diag_result(
            9, "Bluetooth", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The Bluetooth service did not answer.",
            source="adb shell dumpsys bluetooth_manager"))

    # 19 -- Cable charging (this phone is already on our cable)
    if lvl is None and not batt:
        out.append(_diag_result(
            19, "Cable charging", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The battery service did not answer.",
            source="adb shell dumpsys battery"))
    else:
        cbits = []
        if batt.get("plugged"):
            cbits.append("powered by %s" % batt["plugged"])
        if batt.get("status"):
            cbits.append(batt["status"])
        if batt.get("voltage_mv"):
            cbits.append("%d mV" % batt["voltage_mv"])
        if batt.get("max_current_ua"):
            ma = batt["max_current_ua"] / 1000.0
            cbits.append("up to %g mA negotiated" % ma)
            if batt.get("voltage_mv"):
                watts = (batt["voltage_mv"] / 1000.0) * (ma / 1000.0)
                cbits.append("about %.1f W" % watts)
        tier = ("This phone is plugged into this PC's USB port; "
                "a wall brick can negotiate more -- the report "
                "names the source it measured.")
        if batt.get("plugged") == "USB" \
                and batt.get("status") == "charging":
            out.append(_diag_result(
                19, "Cable charging", P, "A", ST_PASS,
                "Charging over the cable right now",
                value=" -- ".join(cbits), detail=tier,
                source="adb shell dumpsys battery"))
        elif batt.get("status") == "full":
            out.append(_diag_result(
                19, "Cable charging", P, "A", ST_PASS,
                "Battery is full -- charge path proven",
                value=" -- ".join(cbits), detail=tier,
                source="adb shell dumpsys battery"))
        elif batt.get("plugged"):
            out.append(_diag_result(
                19, "Cable charging", P, "A", ST_NOCHECK,
                "Cable power is present but the battery is not "
                "taking a charge (%s)" % (batt.get("status")
                                           or "state unread"),
                value=" -- ".join(cbits), detail=tier,
                source="adb shell dumpsys battery"))
        else:
            out.append(_diag_result(
                19, "Cable charging", P, "A", ST_FAIL,
                "No cable power reaching the battery",
                value=" -- ".join(cbits),
                detail="Try a known-good cable and port first -- "
                       "then the phone's charge port.",
                source="adb shell dumpsys battery"))

    # 23 -- USB connection
    usb = read.get("usb") or {}
    if usb.get("connected") is True:
        out.append(_diag_result(
            23, "USB connection", P, "A", ST_PASS,
            "USB link is up (this whole read came over it)",
            value="state: %s" % (usb.get("state") or "connected"),
            source="adb shell dumpsys usb"))
    elif usb.get("connected") is False:
        out.append(_diag_result(
            23, "USB connection", P, "A", ST_FAIL,
            "The phone reports the USB link down",
            source="adb shell dumpsys usb"))
    else:
        answered = bool(props) or batt.get("level") is not None \
            or bool(read.get("sensor_names")) \
            or bool((read.get("telephony") or {}).get(
                "voice_state")) \
            or bool((read.get("wifi") or {}).get("ssid"))
        if answered:
            out.append(_diag_result(
                23, "USB connection", P, "A", ST_PASS,
                "USB link is up (this whole read came over it)",
                detail="The USB service did not print a state "
                       "line, but the other cable reads in this "
                       "run prove the link itself.",
                source="adb (the cable reads in this run)"))
        else:
            out.append(_diag_result(
                23, "USB connection", P, "A", ST_NOCHECK,
                "COULD NOT BE CHECKED",
                detail="Nothing answered on the cable in this "
                       "run -- there is no read here that could "
                       "prove the link, so none is claimed.",
                source="adb shell dumpsys usb"))
    return out


def _c_data_result(num, name, platform, cls, present, count, kind):
    """The C-class data half: sensor presence + enrollment, read
    by the PC. The verdict itself waits for the observed unlock
    step (recorded separately on the face)."""
    if present is None:
        return _diag_result(
            num, name, platform, cls, ST_NOT_TESTABLE,
            "NOT TESTABLE from this PC -- the biometric service "
            "did not answer",
            detail="Biometrics are sealed to third parties. With "
                   "no sensor readout and no observed unlock, "
                   "there is no honest verdict.",
            honesty_label=LBL_NOT_TESTABLE,
            source="adb shell dumpsys %s" % kind)
    bits = []
    bits.append("sensor present" if present
                else "no %s sensor answered" % kind)
    if count is not None:
        bits.append("%d %s enrolled"
                    % (count, "fingerprint" if kind == "fingerprint"
                       else "face"))
    return _diag_result(
        num, name, platform, cls, ST_NOT_TESTABLE,
        "Sensor data read -- the unlock step has not been "
        "observed yet",
        value=" -- ".join(bits),
        detail="Biometrics are sealed: no computer can run this "
               "test. Record the observed unlock on this test's "
               "panel and the verdict becomes the technician's "
               "observation -- never a cable claim.",
        honesty_label=LBL_NOT_TESTABLE,
        source="adb shell dumpsys %s" % kind)


def capture_android_diag(runner):
    """Every A-class read + the C-class data halves, each guarded.
    Returns the results list (A tests + C data halves); B tests
    stay NOT RUN until their guided sessions record them."""
    read = {}

    def grab(key, args, parser, timeout=30):
        try:
            read[key] = parser(runner.run(["shell"] + args,
                                          timeout=timeout))
        except Exception:
            read[key] = None

    grab("props", ["getprop"], parse_getprop_diag)
    grab("battery", ["dumpsys", "battery"], parse_battery_diag)
    grab("nfc_state", ["dumpsys", "nfc"], parse_nfc_state)
    grab("telephony", ["dumpsys", "telephony.registry"],
         parse_telephony)
    grab("sensor_names", ["dumpsys", "sensorservice"],
         parse_sensor_list)
    grab("location", ["dumpsys", "location"], parse_location)
    grab("wifi", ["dumpsys", "wifi"], parse_wifi)
    grab("bluetooth", ["dumpsys", "bluetooth_manager"],
         parse_bluetooth)
    grab("usb", ["dumpsys", "usb"], parse_usb)
    try:
        read["battery_cycles"] = runner.run(
            ["shell", "cat",
             "/sys/class/power_supply/battery/cycle_count"],
            timeout=20).strip() or None
    except Exception:
        read["battery_cycles"] = None

    results = _android_auto_results(read)
    biometrics = {}
    for kind in ("fingerprint", "face"):
        try:
            biometrics[kind] = parse_biometric(
                runner.run(["shell", "dumpsys", kind], timeout=30),
                kind)
        except Exception:
            biometrics[kind] = (None, None)
    results.append(_c_data_result(
        16, "Fingerprint / Touch ID", "Android", "C",
        biometrics["fingerprint"][0], biometrics["fingerprint"][1],
        "fingerprint"))
    results.append(_c_data_result(
        17, "Face recognition / Face ID", "Android", "C",
        biometrics["face"][0], biometrics["face"][1], "face"))
    return results


# -------------------------------------------- iPhone automatic reads

def _iphone_auto_results(info_text, disk_text, relay):
    """info_text = ideviceinfo output, disk_text = the disk-usage
    domain output (may be ''), relay = parse_ioreg_battery dict."""
    P = "iPhone"
    out = []
    info = parse_ideviceinfo(info_text) if info_text else {}
    raw = info.get("raw", {})

    # 1 -- System software: factual only. Lockdown carries no
    # verified-boot read, so there is no "official" stamp -- the
    # dossier is explicit about this and so is this verdict.
    if info.get("system_version"):
        out.append(_diag_result(
            1, "System software", P, "A", ST_PASS,
            "iOS read off the cable (version and build, as "
            "reported)",
            value="iOS %s (build %s)" % (
                info["system_version"], info.get("build") or "?"),
            detail="An iPhone gives no cable proof of tampering "
                   "either way -- this line reports the version "
                   "factually and stamps nothing beyond it.",
            source="ideviceinfo (lockdown)"))
    else:
        out.append(_diag_result(
            1, "System software", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="Lockdown did not report the iOS version.",
            source="ideviceinfo (lockdown)"))

    # 2 -- Battery status: the real truth, off the relay.
    if relay and (relay.get("cycles") is not None
                  or relay.get("design_mah")):
        bbits = []
        if relay.get("cycles") is not None:
            bbits.append("%d cycles" % relay["cycles"])
        if relay.get("health_pct") is not None:
            bbits.append("health %d%% (%s mAh of %s mAh design)"
                         % (relay["health_pct"],
                            relay["actual_mah"],
                            relay["design_mah"]))
        if relay.get("current_pct") is not None:
            bbits.append("charge %d%%" % relay["current_pct"])
        if relay.get("temperature_c") is not None:
            bbits.append("%.1f C" % relay["temperature_c"])
        if relay.get("voltage_mv"):
            bbits.append("%d mV" % relay["voltage_mv"])
        hp = relay.get("health_pct")
        if hp is None:
            st, vd = ST_NOCHECK, "Battery read; health unread"
        elif hp >= 80:
            st, vd = ST_PASS, "Battery health is good"
        else:
            st = ST_FAIL
            vd = ("Battery health %d%% -- under 80%%, Apple "
                  "counts this battery as needing service" % hp)
        out.append(_diag_result(
            2, "Battery status", P, "A", st, vd,
            value=" -- ".join(bbits),
            source="idevicediagnostics ioreg (AppleSmartBattery)"))
    else:
        out.append(_diag_result(
            2, "Battery status", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The diagnostics relay did not answer -- the "
                   "phone must be unlocked and trusted.",
            source="idevicediagnostics ioreg (AppleSmartBattery)"))

    # 19 -- Cable charging: power reaching the phone, per relay.
    if relay and relay.get("external_connected") is not None:
        cbits = []
        if relay.get("current_pct") is not None:
            cbits.append("charge %d%%" % relay["current_pct"])
        if relay.get("voltage_mv"):
            cbits.append("%d mV" % relay["voltage_mv"])
        if relay["external_connected"]:
            if relay.get("is_charging"):
                vd, st = "Charging over the cable right now", \
                    ST_PASS
            elif relay.get("fully_charged"):
                vd, st = "Battery is full -- charge path proven", \
                    ST_PASS
            else:
                vd = ("Cable power is connected but the battery "
                      "is not taking a charge")
                st = ST_NOCHECK
            out.append(_diag_result(
                19, "Cable charging", P, "A", st, vd,
                value=" -- ".join(cbits),
                source="idevicediagnostics ioreg "
                       "(AppleSmartBattery)"))
        else:
            out.append(_diag_result(
                19, "Cable charging", P, "A", ST_FAIL,
                "No external power reaching the phone",
                value=" -- ".join(cbits),
                detail="Try a known-good cable first -- then "
                       "the charge port.",
                source="idevicediagnostics ioreg "
                       "(AppleSmartBattery)"))
    else:
        out.append(_diag_result(
            19, "Cable charging", P, "A", ST_NOCHECK,
            "COULD NOT BE CHECKED",
            detail="The diagnostics relay did not answer.",
            source="idevicediagnostics ioreg (AppleSmartBattery)"))

    # 23 -- USB connection.
    out.append(_diag_result(
        23, "USB connection", P, "A", ST_PASS,
        "USB link is up (lockdown answered over it)",
        value="activation state: %s" % (
            info.get("activation_state") or "read"),
        source="ideviceinfo (lockdown)"))
    return out


def capture_iphone_diag(runner, info_text=None):
    """The iPhone automatic core: ideviceinfo (already read for
    identity when available), the disk-usage domain, and the
    diagnostics relay. Each leg guarded like the Android side.
    Returns (results, extras) -- extras carries the cable facts
    the guided tests and the full report want (storage, ICCID,
    MACs, SIM status)."""
    if info_text is None:
        try:
            info_text = runner.run("ideviceinfo", [], timeout=30)
        except Exception:
            info_text = ""
    disk_text = ""
    try:
        disk_text = runner.run(
            "ideviceinfo", ["-d", "com.apple.disk_usage"],
            timeout=30)
    except Exception:
        disk_text = ""
    relay = None
    try:
        relay = parse_ioreg_battery(runner.run(
            "idevicediagnostics", ["ioreg"], timeout=30))
    except Exception:
        relay = None
    results = _iphone_auto_results(info_text, disk_text, relay)
    info = parse_ideviceinfo(info_text) if info_text else {}
    raw = info.get("raw", {})
    total_gb, free_gb = iphone_storage_values(disk_text)
    extras = {
        "storage_total_gb": total_gb,
        "storage_free_gb": free_gb,
        "iccid": raw.get("IntegratedCircuitCardIdentity", ""),
        "wifi_mac": raw.get("WiFiAddress", ""),
        "bluetooth_mac": raw.get("BluetoothAddress", ""),
        "sim_status": info.get("sim_status", ""),
        "activation_state": info.get("activation_state", ""),
        "battery_relay": relay,
    }
    return results, extras


# ---------------------------------------------- guided-test helpers

def wireless_poll_verdict(texts, platform="Android"):
    """Place-on-pad poll: PASS when any sample shows wireless
    power (Android dumpsys battery) reaching the phone, or the
    iPhone's charge percentage rising across the window."""
    if platform == "Android":
        for t in texts:
            batt = parse_battery_diag(t)
            if batt.get("plugged") == "wireless":
                return True
        return False
    pcts = []
    for t in texts:
        relay = parse_ioreg_battery(t)
        if relay and relay.get("current_pct") is not None:
            pcts.append(relay["current_pct"])
    return len(pcts) >= 2 and pcts[-1] > pcts[0]


# ------------------------------------------ touch trace (Android B)

class TouchTraceSession:
    """The trace-the-grid page this PC serves to the phone's
    browser (dossier route 1 for the touch test). The page shows
    a grid; every touched square reports back over the shop
    network; coverage is counted here, on the PC. If the phone
    cannot reach this page, the guided fallback (the
    technician's eyes) is the honest road -- never a faked map."""

    COLS = 5
    ROWS = 8

    def __init__(self):
        self.hits = set()
        self.server = None
        self.port = None
        self.thread = None

    @property
    def total(self):
        return self.COLS * self.ROWS

    def record_hit(self, cell):
        try:
            cell = int(cell)
        except (TypeError, ValueError):
            return False
        if 0 <= cell < self.total:
            self.hits.add(cell)
            return True
        return False

    def coverage_pct(self):
        return round(100.0 * len(self.hits) / self.total)

    def dead_cells(self):
        return [c for c in range(self.total) if c not in self.hits]

    def page_html(self):
        cells = "".join(
            '<div class="c" data-c="%d"></div>' % i
            for i in range(self.total))
        html = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,"
            "initial-scale=1,maximum-scale=1,user-scalable=no'>"
            "<title>Touch test</title><style>"
            "html,body{margin:0;height:100%;background:#0B0F14}"
            "#g{display:grid;grid-template-columns:"
            "repeat(__COLS__,1fr);"
            "grid-template-rows:repeat(__ROWS__,1fr);height:100vh}"
            ".c{border:1px solid #294154;background:#172334}"
            ".c.on{background:#00E676}"
            "</style></head><body><div id='g'>__CELLS__</div>"
            "<script>"
            "document.querySelectorAll('.c').forEach(function(el){"
            "function hit(e){e.preventDefault();"
            "el.classList.add('on');"
            "fetch('/hit?c='+el.dataset.c).catch(function(){});}"
            "el.addEventListener('touchstart',hit,{passive:false});"
            "el.addEventListener('mousedown',hit);});"
            "</script></body></html>")
        return (html.replace("__COLS__", str(self.COLS))
                    .replace("__ROWS__", str(self.ROWS))
                    .replace("__CELLS__", cells))

    def start(self):
        import http.server
        session = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.startswith("/hit"):
                    from urllib.parse import parse_qs, urlparse
                    q = parse_qs(urlparse(self.path).query)
                    session.record_hit((q.get("c") or [""])[0])
                    body = b"ok"
                else:
                    body = session.page_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(
            ("", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.port

    def stop(self):
        if self.server is not None:
            try:
                self.server.shutdown()
            except Exception:
                pass
            self.server = None


def lan_ip():
    """This PC's LAN address, for the phone to reach the touch
    page. Falls back to '' (the face then says what to do)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""



# ---------------------------------------------------------------------
# stdlib PDF writer (house pattern: the shop PC may have no PDF
# library, so a report must ALWAYS generate -- this writer is the
# only writer). Carried from the v0.2 core unchanged in behaviour.
# ---------------------------------------------------------------------


def _pdf_sanitize(s):
    t = str(s or "")
    t = (t.replace("\u2022", "-").replace("\u2192", "->")
          .replace("\u2014", "-").replace("\u2013", "-")
          .replace("\u2018", "'").replace("\u2019", "'")
          .replace("\u201c", '"').replace("\u201d", '"')
          .replace("\u2026", "...").replace("\u26a0", "!"))
    return t.encode("latin-1", "replace").decode("latin-1")


def _pdf_escape(t):
    return (_pdf_sanitize(t).replace("\\", "\\\\")
            .replace("(", "\\(").replace(")", "\\)"))


def write_simple_pdf(path, lines):
    """Minimal stdlib PDF writer (core Helvetica only).
    lines: [(text, bold, size, gap_after)] -- wrapped and paginated
    onto US Letter pages."""
    import textwrap
    pages, cur, y = [], [], 749.0
    for text, bold, size, gap in lines:
        maxc = max(24, int(518.0 / (size * 0.50)))
        for wl in (textwrap.wrap(str(text), maxc,
                                 break_on_hyphens=False)
                   or [""]):
            h = size * 1.5
            if y - h < 46:
                pages.append(cur)
                cur, y = [], 749.0
            cur.append((42, y, wl, bold, size))
            y -= h
        y -= gap
    if cur or not pages:
        pages.append(cur)
    objs = []

    def obj(num, body):
        objs.append((num, body if isinstance(body, bytes)
                     else body.encode("latin-1", "replace")))

    page_nums = [4 + 2 * i for i in range(len(pages))]
    bold_num = 4 + 2 * len(pages)
    obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, "<< /Type /Pages /Kids [%s] /Count %d >>"
        % (" ".join("%d 0 R" % n for n in page_nums), len(pages)))
    obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    obj(bold_num,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    for i, pg in enumerate(pages):
        content = []
        for x, yy, wl, bold, size in pg:
            content.append("BT /F%d %d Tf %.1f %.1f Td (%s) Tj ET"
                           % (2 if bold else 1, size, x, yy,
                              _pdf_escape(wl)))
        content.append("BT /F1 8 Tf 47 24 Td (Page %d of %d) "
                       "Tj ET" % (i + 1, len(pages)))
        stream = "\n".join(content).encode("latin-1", "replace")
        obj(5 + 2 * i, ("<< /Length %d >>\nstream\n"
                        % len(stream)).encode("latin-1")
            + stream + b"\nendstream")
        obj(4 + 2 * i,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Resources << /Font << /F1 3 0 R /F2 %d 0 R >> >> "
            "/Contents %d 0 R >>" % (bold_num, 5 + 2 * i))
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for num, body in sorted(objs):
        offsets[num] = len(out)
        out += ("%d 0 obj\n" % num).encode("latin-1") + body \
            + b"\nendobj\n"
    xref = len(out)
    maxnum = max(offsets) if offsets else 0
    out += ("xref\n0 %d\n" % (maxnum + 1)).encode("latin-1")
    out += b"0000000000 65535 f \n"
    for n in range(1, maxnum + 1):
        out += ("%010d 00000 n \n" % offsets.get(n, 0)).encode("latin-1")
    out += ("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n"
            "%%%%EOF\n" % (maxnum + 1, xref)).encode("latin-1")
    Path(path).write_bytes(bytes(out))
    return Path(path)


def _report_header(title):
    return [
        (SHOP_NAME, True, 13, 2),
        (SHOP_HEADER, False, 9, 2),
        (title, True, 20, 8),
    ]


def _val_or(value, fallback="(not read)"):
    return value if value else fallback


def imei_pdf_lines(report):
    v, s = report["values"], report["sources"]
    system_label = ("iOS" if report.get("platform") == "iPhone"
                    else "Android")
    lines = _report_header("THE PHONE CHECKER -- IMEI CHECK READOUT")
    lines += [
        ("Checked: %s" % report["checked_at"], False, 10, 6),
        ("Phone: %s" % (" ".join(x for x in [v["brand"], v["model"]]
                                 if x) or "(unknown)"), True, 11, 1),
        ("Serial: %s  [%s]" % (_val_or(v["serial"]), s["serial"]),
         False, 10, 1),
        ("%s: %s" % (system_label, _val_or(v["system_version"])),
         False, 10, 6),
        ("IMEI: %s  [%s]" % (_val_or(v["imei"], "(could not be read)"),
                             report["imei_verdict"]), True, 11, 1),
        ("IMEI source: %s" % s["imei"], False, 9, 1),
        ("IMEI 2: %s  [%s]"
         % (_val_or(v["imei2"], "(could not be read)"),
            report["imei2_verdict"]), True, 11, 1),
        ("IMEI 2 source: %s" % s["imei2"], False, 9, 6),
    ]
    if v["sales_code"]:
        lines += [
            ("Samsung sales code: %s" % v["sales_code"],
             False, 10, 1),
            ("Carrier of origin: %s"
             % (report["carrier_of_origin"]
                or "(no sales code read)"), True, 11, 1),
        ]
    if report["variant_note"]:
        lines.append((report["variant_note"], False, 10, 1))
    lines += [("", False, 10, 4), ("FREE CHECKS", True, 13, 4)]
    for chk in report.get("checks", []):
        lines.append(("%s: %s" % (chk["title"], chk["verdict"]),
                      True, 11, 1))
        if chk.get("detail"):
            lines.append((chk["detail"], False, 10, 1))
        lines.append(("Proves: %s" % chk["proves"], False, 9, 1))
        lines.append(("Does not prove: %s" % chk["does_not_prove"],
                      False, 9, 1))
        lines.append(("Source: %s" % chk["source"], False, 9, 4))
    lines += [
        ("", False, 10, 4),
        (IMEI_HONEST_LIMIT, True, 11, 2),
        (PHONE_SIDE_POINTER, False, 10, 8),
        ("Reads are local: nothing about this phone left this "
         "computer. No vendor account was signed into.",
         False, 9, 8),
        ("Report fingerprint (SHA-256): %s" % report["fingerprint"],
         False, 8, 6),
        (COPYRIGHT_LINE, False, 8, 0),
    ]
    return lines


def reports_dir(base=None):
    d = (Path(base) if base else _script_dir()) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_imei_pdf(report, base=None):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = reports_dir(base) / ("imei-check-%s.pdf" % stamp)
    return write_simple_pdf(path, imei_pdf_lines(report))


# ---------------------------------------------------------------------
# Module 3 -- the full counter report: Module 1 identity + checks
# and the Module 2 grid in one printable PDF. Every diagnostics
# line carries its verdict, its measured values, and its honesty
# label. The report dict fingerprints the whole record the same
# way Module 1 fingerprints its own.
# ---------------------------------------------------------------------


def merge_diag_results(current, new_results):
    """Fold fresh results into the grid by test number (auto runs
    and guided recordings both land this way)."""
    by_num = {r["num"]: r for r in new_results}
    return [by_num.get(r["num"], r) for r in current]


def guided_record(results, num, platform, status, verdict,
                  value="", detail="",
                  honesty_label=LBL_GUIDED, source=""):
    """Record a guided / observed / console verdict on one test.
    The class comes from the test definition for this platform --
    the face never re-decides it."""
    tdef = TEST_BY_NUM[num]
    key = "android" if platform == "Android" else "iphone"
    rec = _diag_result(num, tdef["name"], platform, tdef[key],
                       status, verdict, value=value, detail=detail,
                       honesty_label=honesty_label, source=source)
    return merge_diag_results(results, [rec])


# Apple's free diagnostics console suites (dossier 2.3). The
# console runs on the counter PC's browser; the iPhone goes into
# Diagnostics mode; Apple produces the verdicts and the
# technician transcribes them here. A guided hand-off -- nothing
# is scraped, automated, or faked.
APPLE_SUITES = (
    "Mobile Resource Inspector",
    "Display Pixel Anomalies",
    "Multi-Touch",
    "Camera Image Quality",
    "Face ID",
    "Audio (Audio Output)",
)

# Suites whose verdict also lands on a grid test (the suite IS
# that test, run by Apple). MRI and Pixel Anomalies have no
# Samsung-grid twin -- they ride the report's Apple section.
APPLE_SUITE_TO_TEST = {
    "Multi-Touch": 18,
    "Camera Image Quality": 15,
    "Face ID": 17,
    "Audio (Audio Output)": 13,
}

APPLE_CONSOLE_STEPS = (
    "1. On the iPhone: power it OFF.\n"
    "2. Hold BOTH volume buttons and plug the iPhone into power "
    "-- it wakes into Diagnostics mode.\n"
    "3. On THIS computer's browser, open diagnostics.apple.com.\n"
    "4. Type the iPhone's serial number (read off the cable "
    "above) and pick the suites.\n"
    "5. The iPhone joins over Wi-Fi. Run the suites there -- "
    "Apple shows the verdicts.\n"
    "6. Record each suite's verdict here, exactly as Apple "
    "showed it. This app never touches Apple's site itself.")


def build_full_report(identity_report, diag_results,
                      apple_suites=None, now=None):
    """identity_report is Module 1's build_identity_report dict;
    diag_results is the 23-line grid; apple_suites is a list of
    {suite, verdict, detail, recorded_at}."""
    summary = diag_summary(diag_results)
    report = {
        "app": APP_NAME,
        "record_type": "full_counter_report",
        "module": "Modules 1 + 2 + 3 -- identity, checks, "
                  "diagnostics",
        "version": VERSION,
        "checked_at": now or _now_str(),
        "checked_at_note": "Identity read at %s"
                           % identity_report.get("checked_at", ""),
        "identity": identity_report,
        "diagnostics": list(diag_results),
        "apple_suites": list(apple_suites or []),
        "summary": summary,
    }
    report["fingerprint"] = _sha256_text(_canonical(
        {k: v for k, v in report.items() if k != "fingerprint"}))
    return report


def full_pdf_lines(report):
    ident = report["identity"]
    v, s = ident["values"], ident["sources"]
    platform = ident.get("platform", "")
    system_label = "iOS" if platform == "iPhone" else "Android"
    lines = _report_header("THE PHONE CHECKER -- COUNTER REPORT")
    lines += [
        ("Checked: %s" % report["checked_at"], False, 10, 6),
        ("Phone: %s" % (" ".join(x for x in [v["brand"], v["model"]]
                                 if x) or "(unknown)"), True, 12, 1),
        ("Serial: %s  [%s]" % (_val_or(v["serial"]), s["serial"]),
         False, 10, 1),
        ("%s: %s" % (system_label, _val_or(v["system_version"])),
         False, 10, 1),
        ("IMEI: %s  [%s]" % (_val_or(v["imei"],
                                    "(could not be read)"),
                             ident["imei_verdict"]), True, 11, 1),
        ("IMEI 2: %s  [%s]" % (_val_or(v["imei2"],
                                       "(could not be read)"),
                               ident["imei2_verdict"]),
         False, 10, 6),
    ]
    if v["sales_code"]:
        lines += [
            ("Samsung sales code: %s" % v["sales_code"],
             False, 10, 1),
            ("Carrier of origin: %s" % (ident["carrier_of_origin"]
                                        or "(no sales code read)"),
             True, 11, 1),
        ]
    if ident["variant_note"]:
        lines.append((ident["variant_note"], False, 10, 1))

    lines += [("", False, 10, 4), ("FREE CHECKS (MODULE 1)",
                                   True, 13, 4)]
    for chk in ident.get("checks", []):
        lines.append(("%s: %s" % (chk["title"], chk["verdict"]),
                      True, 11, 1))
        if chk.get("detail"):
            lines.append((chk["detail"], False, 10, 1))
        lines.append(("Proves: %s" % chk["proves"], False, 9, 1))
        lines.append(("Does not prove: %s"
                      % chk["does_not_prove"], False, 9, 1))
        lines.append(("Source: %s" % chk["source"], False, 9, 4))

    lines += [("", False, 10, 4),
              ("DIAGNOSTICS (MODULE 2) -- 23 TESTS", True, 13, 4)]
    for r in report["diagnostics"]:
        lines.append(("%d. %s: %s" % (r["num"], r["name"],
                                      r["verdict"]),
                      True, 11, 1))
        if r.get("value"):
            lines.append(("Measured: %s" % r["value"],
                          False, 10, 1))
        if r.get("detail"):
            lines.append((r["detail"], False, 9, 1))
        lines.append(("Honesty: %s. Source: %s"
                      % (r["honesty_label"], r["source"] or "-"),
                      False, 9, 4))

    if report.get("apple_suites"):
        lines += [("", False, 10, 2),
                  ("APPLE DIAGNOSTICS CONSOLE (run by the "
                   "technician at diagnostics.apple.com; verdicts "
                   "transcribed exactly as Apple showed them)",
                   True, 12, 4)]
        for su in report["apple_suites"]:
            lines.append(("%s: %s" % (su["suite"], su["verdict"]),
                          True, 11, 1))
            if su.get("detail"):
                lines.append((su["detail"], False, 10, 3))

    sm = report["summary"]
    c = sm["counts"]
    lines += [
        ("", False, 10, 4),
        ("SUMMARY -- %d of %d tests completed: %d passed, "
         "%d failed, %d skipped, %d could not be checked, "
         "%d not testable, %d not run"
         % (sm["done"], sm["total"], c.get(ST_PASS, 0),
            c.get(ST_FAIL, 0), c.get(ST_SKIPPED, 0),
            c.get(ST_NOCHECK, 0), c.get(ST_NOT_TESTABLE, 0),
            c.get(ST_NOT_RUN, 0)), True, 11, 2),
    ]
    if sm["failed_names"]:
        lines.append(("FAILED: %s" % "; ".join(sm["failed_names"]),
                      True, 11, 4))
    lines += [
        ("", False, 10, 2),
        (IMEI_HONEST_LIMIT, True, 11, 2),
        (PHONE_SIDE_POINTER, False, 10, 8),
        ("Reads are local: nothing about this phone left this "
         "computer. No vendor account was signed into.",
         False, 9, 8),
        ("Report fingerprint (SHA-256): %s" % report["fingerprint"],
         False, 8, 6),
        (COPYRIGHT_LINE, False, 8, 0),
    ]
    return lines


def save_full_pdf(report, base=None):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = reports_dir(base) / ("counter-report-%s.pdf" % stamp)
    return write_simple_pdf(path, full_pdf_lines(report))



# ---------------------------------------------------------------------
# self-update (house pattern): phone-checker-version.json on the
# same shelf. A download is installed only after size AND SHA-256
# match the manifest; a helper script performs the swap after this
# process exits and rolls back if the new version fails to start.
# The manifest is NOT published yet -- the app says so honestly.
# ---------------------------------------------------------------------

UPDATE_HELPER_SRC = """import json, os, subprocess, sys, time

def pid_alive(pid):
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(h)
        return code.value == 259
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def main():
    (wait_pid, current, downloaded, target, backup, result_path,
     python_exe, alive_secs, from_v, to_v) = sys.argv[1:11]
    wait_pid = int(wait_pid)
    alive_secs = float(alive_secs)
    deadline = time.time() + 30
    while pid_alive(wait_pid) and time.time() < deadline:
        time.sleep(0.25)
    outcome = "updated"
    try:
        if os.path.exists(backup):
            os.remove(backup)
        os.replace(current, backup)
        os.replace(downloaded, target)
        proc = subprocess.Popen([python_exe, target])
        time.sleep(alive_secs)
        if proc.poll() is not None:
            outcome = "rolled_back"
            try:
                os.remove(target)
            except OSError:
                pass
            os.replace(backup, current)
            subprocess.Popen([python_exe, current])
    except Exception:
        outcome = "rolled_back"
        try:
            if not os.path.exists(current) and os.path.exists(backup):
                os.replace(backup, current)
                subprocess.Popen([python_exe, current])
        except Exception:
            pass
    try:
        with open(result_path, "w") as f:
            json.dump({"outcome": outcome, "from_version": from_v,
                       "to_version": to_v}, f)
    except Exception:
        pass

main()
"""


def _fetch_bytes(url, timeout=20):
    req = urllib.request.Request(url, headers={
        "User-Agent": "PhoneChecker/%s" % VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_update_info(fetch=None):
    """Latest manifest dict, or None when the shelf has none yet
    (phone-checker-version.json is published with the first public
    build)."""
    fetch = fetch or _fetch_bytes
    try:
        raw = fetch(UPDATE_MANIFEST_URL, timeout=15)
        info = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(info, dict) or "version" not in info:
        return None
    return info


def update_available(info):
    return bool(info) and _version_tuple(info["version"]) \
        > _version_tuple(VERSION)


def download_update(info, dest_dir, fetch=None):
    """Download the offered build and verify it against the manifest.
    Returns (path, error) -- exactly one of the two is set. The file
    is installed ONLY when size AND SHA-256 both match."""
    fetch = fetch or _fetch_bytes
    # The contract is size AND SHA-256 (tester D2): a manifest
    # missing either field is refused outright -- a tampered or
    # malformed manifest must never silently disable the only
    # integrity gate the updater has.
    if info.get("size") is None or not info.get("sha256"):
        return None, ("manifest is missing its size or SHA-256 -- "
                      "refusing to install an unverified download")
    try:
        data = fetch(info["url"], timeout=120)
    except Exception as e:
        return None, "download failed (%s)" % e
    if info.get("size") is not None and len(data) != int(info["size"]):
        return None, ("size mismatch (got %d, manifest says %s)"
                      % (len(data), info["size"]))
    digest = hashlib.sha256(data).hexdigest()
    if info.get("sha256") and digest.lower() \
            != str(info["sha256"]).lower():
        return None, "SHA-256 mismatch -- download discarded"
    dest = Path(dest_dir) / ("PhoneChecker-PC-v%s.pyw"
                             % info["version"])
    dest.write_bytes(data)
    return dest, None


def begin_update(current_path, downloaded, to_version, from_version):
    """Hand the swap to the helper script and let this process exit.
    The helper waits for us to die, swaps, relaunches, and rolls back
    if the new build does not stay alive."""
    current_path = Path(current_path)
    helper = current_path.parent / "_checker_update_helper.py"
    helper.write_text(UPDATE_HELPER_SRC, encoding="utf-8")
    backup = current_path.with_suffix(current_path.suffix + ".bak")
    result = current_path.parent / "_checker_update_result.json"
    python_exe = sys.executable or "python"
    args = [python_exe, str(helper), str(os.getpid()),
            str(current_path), str(downloaded), str(current_path),
            str(backup), str(result), python_exe,
            str(UPDATE_ALIVE_SECONDS), str(from_version),
            str(to_version)]
    subprocess.Popen(args, close_fds=True)


# ---------------------------------------------------------------------
# licensing hooks (issue #57 pattern) -- DORMANT.
# The owner edition never asks for a key. Renter builds will
# enforce a hardware-locked, expiring key through these same hooks
# later; there are deliberately NO enforcement callers in this
# build.
# ---------------------------------------------------------------------

LICENSE_FILE = "phone_checker_license.json"


def license_status():
    return {"edition": "owner", "enforced": False, "licensed": True,
            "license_file": LICENSE_FILE}


# ---------------------------------------------------------------------
# UI -- one page, Module 1 only. Verdicts sit next to the numbers,
# in colored text. Plain words everywhere; errors say what to do.
# ---------------------------------------------------------------------

import tkinter as tk
from tkinter import messagebox

TYPED_FIELDS = (
    ("brand", "Brand (typed fallback):"),
    ("model", "Model (typed fallback):"),
    ("serial", "Serial (typed fallback):"),
    ("system_version", "System version (typed):"),
    ("imei", "IMEI (typed fallback):"),
    ("imei2", "IMEI 2 (typed):"),
    ("sales_code", "Samsung sales code (typed):"),
)


class PhoneCheckerApp:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.busy = False
        self.adb = AdbRunner()
        self.idev = IdeviceRunner()
        self.readings = None
        self.checks = default_checks({})
        self.report = None
        self._icon_img = None
        self._logo_img = None
        self.check_status = {}
        self.paste_boxes = {}
        # Module 2 state
        self.diag_results = default_diag_results("")
        self.diag_platform = ""
        self.diag_busy = False
        self.selected_test = None
        self.apple_suites = {}
        self.iphone_extras = {}
        self.touch_session = None
        self._cam_before = None
        self.full_report = None
        self.diag_rows = {}
        self.apple_rows = {}

        root.title("%s v%s -- IMEI / identity + diagnostics -- %s"
                   % (APP_NAME, VERSION, SHOP_NAME))
        root.configure(bg=DBG)
        root.geometry("1060x920")
        root.minsize(880, 640)
        icon_path = _script_dir() / "the-phone-checker-icon-512.png"
        if icon_path.is_file():
            try:
                self._icon_img = tk.PhotoImage(
                    file=str(icon_path)).subsample(8, 8)
                root.iconphoto(True, self._icon_img)
            except Exception:
                self._icon_img = None
        logo_path = _script_dir() / "the-phone-checker-logo-master.png"
        if logo_path.is_file():
            try:
                self._logo_img = tk.PhotoImage(
                    file=str(logo_path)).subsample(6, 6)
            except Exception:
                self._logo_img = None

        self._build_header()
        tk.Label(root, text=SHOP_HEADER, bg=DBG, fg=DMUTED,
                 font=(DFONT, 9)).pack(side="bottom", pady=(4, 0))
        tk.Label(root, text=COPYRIGHT_LINE, bg=DBG, fg=DMUTED,
                 font=(DFONT, 8)).pack(side="bottom", pady=(0, 6))
        log_frame = tk.Frame(root, bg=DBG)
        log_frame.pack(side="bottom", fill="x", padx=12,
                       pady=(0, 4))
        tk.Label(log_frame, text="Activity", bg=DBG, fg=DTEXT,
                 font=(DFONT, 10, "bold")).pack(anchor="w")
        self.logbox = tk.Text(log_frame, height=5, bg=DPANEL,
                              fg=DSECOND, insertbackground=DTEXT,
                              font=("Consolas", 9), relief="flat",
                              wrap="word", highlightthickness=1,
                              highlightbackground=DBORDER)
        self.logbox.pack(fill="x")

        # The middle of the page scrolls: the full Module 1 page
        # is taller than a laptop screen, and the BUILD + PRINT
        # button must never fall off the bottom of a small one.
        wrap = tk.Frame(root, bg=DBG)
        wrap.pack(fill="both", expand=True)
        canvas = tk.Canvas(wrap, bg=DBG, highlightthickness=0)
        vsb = tk.Scrollbar(wrap, orient="vertical",
                           command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = tk.Frame(canvas, bg=DBG)
        win = canvas.create_window((0, 0), window=body,
                                   anchor="nw")

        def _on_body_configure(_e):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(e):
            canvas.itemconfigure(win, width=e.width)

        body.bind("<Configure>", _on_body_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _wheel(e):
            if e.num == 4:
                canvas.yview_scroll(-1, "units")
            elif e.num == 5:
                canvas.yview_scroll(1, "units")
            elif e.delta:
                canvas.yview_scroll(-1 if e.delta > 0 else 1,
                                    "units")

        root.bind_all("<MouseWheel>", _wheel)
        root.bind_all("<Button-4>", _wheel)
        root.bind_all("<Button-5>", _wheel)
        self._build_read_panel(body)
        self._build_checks_panel(body)
        self._build_output_panel(body)
        self._build_diag_panel(body)

        self.root.after(120, self.process_queue)
        threading.Thread(target=self._silent_update_check,
                         daemon=True).start()
        self.log("%s v%s ready -- Modules 1 + 2 + 3 (IMEI / "
                 "identity + diagnostics). %s"
                 % (APP_NAME, VERSION, COPYRIGHT_LINE))

    # ------------------------------------------------------------ --
    def _build_header(self):
        bar = tk.Frame(self.root, bg=DBAR)
        bar.pack(fill="x")
        if self._logo_img is not None:
            tk.Label(bar, image=self._logo_img, bg=DBAR).pack(
                side="left", padx=10, pady=6)
        head = tk.Frame(bar, bg=DBAR)
        head.pack(side="left", pady=8)
        tk.Label(head, text="THE PHONE CHECKER", bg=DBAR, fg=DTEXT,
                 font=(DFONT, 18, "bold")).pack(anchor="w")
        tk.Label(head, text="Plug a phone in, or type an IMEI: "
                            "identity, free checks, and the "
                            "23-test diagnostics grid. No account "
                            "sign-in, ever.",
                 bg=DBAR, fg=DSECOND, font=(DFONT, 10)).pack(
                     anchor="w")
        self.update_btn = tk.Button(
            bar, text="CHECK FOR UPDATES", bg=DRAISED, fg=DTEXT,
            activebackground=DRAISED, activeforeground=DTEXT,
            font=(DFONT, 10, "bold"), relief="flat", padx=14, pady=8,
            highlightthickness=1, highlightbackground=DBORDER,
            highlightcolor=DCYAN,
            command=self._manual_update_check)
        self.update_btn.pack(side="right", padx=10, pady=10)
        tk.Frame(self.root, bg=DBORDER, height=1).pack(fill="x")
        status = tk.Frame(self.root, bg=DBAR)
        status.pack(fill="x")
        self.device_lbl = tk.Label(
            status, text="No phone read yet -- press READ PHONE.",
            bg=DBAR, fg=DMUTED, font=(DFONT, 10, "bold"))
        self.device_lbl.pack(side="left", padx=12, pady=4)
        tk.Frame(self.root, bg=DBORDER, height=1).pack(fill="x")

    def _build_read_panel(self, parent):
        frame = tk.Frame(parent, bg=DBG)
        frame.pack(fill="x", padx=12, pady=(8, 0))
        tk.Button(frame, text="READ PHONE", bg=DCYAN, fg="#0B0F14",
                  activebackground=DCYAN, font=(DFONT, 13, "bold"),
                  relief="flat", padx=16, pady=8,
                  command=self._read_phone).pack(anchor="w")
        self.phone_lbl = tk.Label(
            frame, text="Phone: (nothing read yet)", bg=DBG,
            fg=DSECOND, font=(DFONT, 10), justify="left")
        self.phone_lbl.pack(anchor="w", pady=2)
        form = tk.Frame(frame, bg=DBG)
        form.pack(fill="x", pady=4)
        self.typed_vars = {}
        for row, (field, label) in enumerate(TYPED_FIELDS):
            tk.Label(form, text=label, bg=DBG, fg=DSECOND,
                     font=(DFONT, 10)).grid(row=row, column=0,
                                             sticky="e", pady=2)
            var = tk.StringVar()
            tk.Entry(form, textvariable=var, width=28, bg=DRAISED,
                     fg=DTEXT, insertbackground=DTEXT, relief="flat",
                     highlightthickness=1,
                     highlightbackground=DBORDER,
                     highlightcolor=DCYAN,
                     font=(DFONT, 10)).grid(row=row, column=1,
                                             sticky="w", padx=8)
            self.typed_vars[field] = var
        tk.Label(frame,
                 text="Typed values only fill what the cable could "
                      "not read -- the readout names the source of "
                      "every value.",
                 bg=DBG, fg=DMUTED, font=(DFONT, 9)).pack(anchor="w")

    def _build_checks_panel(self, parent):
        tk.Label(parent, text="FREE CHECKS", bg=DBG, fg=DTEXT,
                 font=(DFONT, 12, "bold")).pack(anchor="w",
                                                 padx=12,
                                                 pady=(8, 2))
        for module in CHECK_MODULES:
            card = tk.Frame(parent, bg=DPANEL,
                            highlightthickness=1,
                            highlightbackground=DBORDER)
            card.pack(fill="x", padx=12, pady=3)
            tk.Label(card, text=module.title, bg=DPANEL, fg=DTEXT,
                     font=(DFONT, 11, "bold")).pack(anchor="w",
                                                     padx=10,
                                                     pady=(6, 0))
            tk.Label(card, text="Proves: %s" % module.proves,
                     bg=DPANEL, fg=DMUTED, font=(DFONT, 9),
                     justify="left", wraplength=980).pack(
                         anchor="w", padx=10)
            status = tk.Label(card, text="", bg=DPANEL, fg=DSECOND,
                              font=(DFONT, 10, "bold"), justify="left",
                              wraplength=980)
            status.pack(anchor="w", padx=10, pady=(2, 2))
            self.check_status[module.check_id] = status
            if module.site_name:
                row = tk.Frame(card, bg=DPANEL)
                row.pack(fill="x", padx=10, pady=(0, 6))
                box = tk.Text(row, height=3, width=76, bg=DRAISED,
                              fg=DTEXT, insertbackground=DTEXT,
                              font=("Consolas", 9), relief="flat",
                              wrap="word", highlightthickness=1,
                              highlightbackground=DBORDER)
                box.pack(side="left", fill="x", expand=True)
                self.paste_boxes[module.check_id] = box
                tk.Button(
                    row, text="RECORD RESULT", bg=DRAISED, fg=DTEXT,
                    activebackground="#223449",
                    activeforeground=DTEXT, font=(DFONT, 10, "bold"),
                    relief="flat", padx=12, pady=6,
                    command=lambda cid=module.check_id:
                        self._record_paste(cid)).pack(
                            side="left", padx=8)
                tk.Label(card,
                         text="Run this check on %s, then paste "
                              "the result wording in the box."
                              % module.site_name,
                         bg=DPANEL, fg=DMUTED,
                         font=(DFONT, 9)).pack(anchor="w", padx=10,
                                               pady=(0, 6))
        self._refresh_check_cards()

    def _build_output_panel(self, parent):
        tk.Button(parent, text="BUILD + PRINT READOUT (PDF)",
                  bg=DCYAN, fg="#0B0F14", activebackground=DCYAN,
                  font=(DFONT, 13, "bold"), relief="flat", padx=16,
                  pady=8, command=self._build_and_print).pack(
                      padx=12, anchor="w", pady=(8, 4))
        self.out = tk.Text(parent, height=10, bg=DPANEL, fg=DSECOND,
                           insertbackground=DTEXT,
                           font=("Consolas", 10), relief="flat",
                           wrap="word", state="disabled",
                           highlightthickness=1,
                           highlightbackground=DBORDER)
        self.out.pack(fill="x", padx=12)
        tk.Label(parent, text=IMEI_HONEST_LIMIT, bg=DBG, fg=DWARN,
                 font=(DFONT, 9, "bold"), justify="left",
                 wraplength=1000).pack(padx=12, anchor="w",
                                       pady=(4, 0))
        tk.Label(parent, text=PHONE_SIDE_POINTER, bg=DBG, fg=DMUTED,
                 font=(DFONT, 9), justify="left",
                 wraplength=1000).pack(padx=12, anchor="w")

    # ------------------------------------------------------------ --
    def log(self, text):
        self.logbox.insert("end", text + "\n")
        self.logbox.see("end")

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _typed(self):
        return {f: var.get().strip()
                for f, var in self.typed_vars.items()}

    def _current_values(self):
        """Cable values merged with typed fallbacks (cable wins),
        exactly as the report builder will see them."""
        readings = self.readings or {}
        values = {}
        typed = self._typed()
        for field in IDENTITY_FIELDS:
            values[field] = readings.get(field) or typed.get(field) \
                or ""
        return values

    def _refresh_check_cards(self):
        color = {"run": DGREEN, "recorded": DGREEN,
                 "not_run": DMUTED, "could_not_parse": DWARN}
        for chk in self.checks:
            lbl = self.check_status.get(chk["check_id"])
            if lbl is None:
                continue
            text = chk["verdict"]
            if chk.get("detail"):
                text += " -- " + chk["detail"]
            lbl.configure(text=text,
                          fg=color.get(chk["state"], DSECOND))

    def _read_phone(self):
        if self.busy:
            return
        self.busy = True
        self.device_lbl.configure(text="Reading the phone ...",
                                  fg=DMUTED)

        def work():
            try:
                platform, ident, msg = read_phone(self.adb, self.idev)
            except Exception as e:
                self.q.put(("error", "Read failed: %s" % e))
                return
            if platform is None:
                self.q.put(("error", msg))
                return
            self.q.put(("read", (platform, ident, msg)))
        threading.Thread(target=work, daemon=True).start()

    def _record_paste(self, check_id):
        box = self.paste_boxes.get(check_id)
        if box is None:
            return
        text = box.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning(
                APP_NAME, "Paste the checker's result wording "
                          "into the box first.")
            return
        values = self._current_values()
        self.checks, result = record_paste(self.checks, check_id,
                                           text, values)
        if result is None:
            return
        if result["state"] == "recorded":
            self.log("Recorded: %s -> %s"
                     % (result["title"], result["verdict"]))
        else:
            messagebox.showwarning(
                APP_NAME,
                "That paste could not be read as a verdict for "
                "this check, so nothing was recorded. Paste the "
                "result wording from the checker's page.")
            self.log("Paste for %s could not be parsed -- nothing "
                     "recorded." % result["title"])
        self._refresh_check_cards()

    def _build_and_print(self):
        values = self._current_values()
        # The local check always re-runs on the freshest values.
        local = CHECK_BY_ID["local_identity"].run_local(values)
        checks = [local if c["check_id"] == "local_identity" else c
                  for c in self.checks]
        self.checks = checks
        report = build_identity_report(self.readings or {},
                                       self._typed(), checks=checks)
        self.report = report
        try:
            pdf_path = save_imei_pdf(report)
        except Exception as e:
            messagebox.showerror(APP_NAME, "Readout failed: %s" % e)
            return
        v = report["values"]
        out = [
            "Phone: %s" % (" ".join(x for x in [v["brand"],
                                                v["model"]] if x)
                           or "(unknown)"),
            "Serial: %s" % (v["serial"] or "(not read)"),
            "IMEI: %s [%s]" % (v["imei"] or "(could not be read)",
                               report["imei_verdict"]),
            "IMEI 2: %s [%s]" % (v["imei2"]
                                 or "(could not be read)",
                                 report["imei2_verdict"]),
            "Carrier of origin: %s"
            % (report["carrier_of_origin"] or "(no sales code read)"),
            "",
            "CHECKS:",
        ]
        for chk in report["checks"]:
            out.append("  %s: %s" % (chk["title"], chk["verdict"]))
        out += ["", IMEI_HONEST_LIMIT, "",
                "Readout PDF: %s" % pdf_path]
        self._set_text(self.out, "\n".join(out))
        self._refresh_check_cards()
        self.log("IMEI readout printed: %s" % pdf_path)

        # ------------------------------------------------------------ --
    # Module 2 face: the 23-test grid + guided panel + Apple door
    # ------------------------------------------------------------ --
    def _build_diag_panel(self, parent):
        tk.Label(parent, text="DIAGNOSTICS (MODULE 2) -- 23 TESTS",
                 bg=DBG, fg=DTEXT,
                 font=(DFONT, 12, "bold")).pack(anchor="w", padx=12,
                                                 pady=(12, 2))
        top = tk.Frame(parent, bg=DBG)
        top.pack(fill="x", padx=12)
        tk.Button(top, text="RUN ALL AUTOMATIC TESTS", bg=DCYAN,
                  fg="#0B0F14", activebackground=DCYAN,
                  font=(DFONT, 12, "bold"), relief="flat", padx=14,
                  pady=7,
                  command=self._run_auto).pack(side="left")
        self.diag_progress = tk.Label(
            top, text="Progress: 0/23", bg=DBG, fg=DTEXT,
            font=(DFONT, 12, "bold"))
        self.diag_progress.pack(side="left", padx=14)
        self.diag_platform_lbl = tk.Label(
            top, text="Read a phone first (READ PHONE, above).",
            bg=DBG, fg=DMUTED, font=(DFONT, 10))
        self.diag_platform_lbl.pack(side="left")

        grid = tk.Frame(parent, bg=DBG)
        grid.pack(fill="x", padx=12, pady=(6, 0))
        self.diag_rows = {}
        for t in TEST_DEFS:
            row = tk.Frame(grid, bg=DPANEL, highlightthickness=1,
                           highlightbackground=DBORDER)
            row.pack(fill="x", pady=1)
            tk.Label(row, text="%2d. %s" % (t["num"], t["name"]),
                     bg=DPANEL, fg=DTEXT, font=(DFONT, 10, "bold"),
                     width=30, anchor="w").pack(side="left",
                                                 padx=(8, 2))
            tag = tk.Label(row, text="", bg=DPANEL, fg=DMUTED,
                           font=(DFONT, 8, "bold"), width=8,
                           anchor="w")
            tag.pack(side="left")
            status = tk.Label(row, text="NOT RUN", bg=DPANEL,
                              fg=DMUTED, font=(DFONT, 10, "bold"),
                              anchor="w")
            status.pack(side="left", padx=6)
            value = tk.Label(row, text="", bg=DPANEL, fg=DSECOND,
                             font=(DFONT, 9), anchor="w")
            value.pack(side="left", fill="x", expand=True)
            tk.Button(row, text="OPEN", bg=DRAISED, fg=DTEXT,
                      activebackground="#223449",
                      activeforeground=DTEXT,
                      font=(DFONT, 9, "bold"), relief="flat",
                      padx=10, pady=2,
                      command=lambda n=t["num"]:
                          self._select_test(n)).pack(
                              side="right", padx=6, pady=2)
            self.diag_rows[t["num"]] = {"status": status,
                                        "value": value,
                                        "tag": tag}

        # Guided panel: one test at a time, big plain words.
        panel = tk.Frame(parent, bg=DPANEL, highlightthickness=1,
                         highlightbackground=DBORDER)
        panel.pack(fill="x", padx=12, pady=(8, 0))
        self.guide_title = tk.Label(
            panel, text="GUIDED TEST -- open a test from the grid",
            bg=DPANEL, fg=DTEXT, font=(DFONT, 12, "bold"))
        self.guide_title.pack(anchor="w", padx=10, pady=(6, 0))
        self.guide_text = tk.Label(
            panel, text="Automatic tests run from the button "
                        "above. Guided tests (the tech's hands + "
                        "this PC's eyes) open here, one at a time.",
            bg=DPANEL, fg=DSECOND, font=(DFONT, 12), justify="left",
            wraplength=980)
        self.guide_text.pack(anchor="w", padx=10, pady=4)
        self.guide_evidence = tk.Label(
            panel, text="", bg=DPANEL, fg=DCYAN,
            font=(DFONT, 10, "bold"), justify="left",
            wraplength=980)
        self.guide_evidence.pack(anchor="w", padx=10)
        btns = tk.Frame(panel, bg=DPANEL)
        btns.pack(fill="x", padx=10, pady=(4, 8))
        tk.Button(btns, text="RUN THE PC PART", bg=DCYAN,
                  fg="#0B0F14", activebackground=DCYAN,
                  font=(DFONT, 11, "bold"), relief="flat", padx=12,
                  pady=6,
                  command=self._guided_pc_part).pack(side="left")
        tk.Button(btns, text="IT WORKED (PASS)", bg=DRAISED,
                  fg=DGREEN, activebackground="#223449",
                  font=(DFONT, 11, "bold"), relief="flat", padx=12,
                  pady=6,
                  command=lambda: self._guided_record(
                      ST_PASS)).pack(side="left", padx=6)
        tk.Button(btns, text="IT FAILED", bg=DRAISED, fg=DRED,
                  activebackground="#223449",
                  font=(DFONT, 11, "bold"), relief="flat", padx=12,
                  pady=6,
                  command=lambda: self._guided_record(
                      ST_FAIL)).pack(side="left")
        tk.Button(btns, text="SKIP", bg=DRAISED, fg=DMUTED,
                  activebackground="#223449",
                  font=(DFONT, 11, "bold"), relief="flat", padx=12,
                  pady=6,
                  command=lambda: self._guided_record(
                      ST_SKIPPED)).pack(side="left", padx=6)
        tk.Button(btns, text="NEXT UNRUN TEST", bg=DRAISED,
                  fg=DTEXT, activebackground="#223449",
                  font=(DFONT, 11, "bold"), relief="flat", padx=12,
                  pady=6,
                  command=self._next_unrun).pack(side="left")

        self.diag_summary = tk.Label(
            parent, text="", bg=DBG, fg=DTEXT,
            font=(DFONT, 11, "bold"), justify="left",
            wraplength=1000)
        self.diag_summary.pack(anchor="w", padx=12, pady=(6, 0))
        self.diag_failed = tk.Label(
            parent, text="", bg=DBG, fg=DRED,
            font=(DFONT, 10, "bold"), justify="left",
            wraplength=1000)
        self.diag_failed.pack(anchor="w", padx=12)

        self._build_apple_panel(parent)

        tk.Button(parent, text="BUILD FULL COUNTER REPORT (PDF)",
                  bg=DCYAN, fg="#0B0F14", activebackground=DCYAN,
                  font=(DFONT, 13, "bold"), relief="flat", padx=16,
                  pady=8,
                  command=self._build_full).pack(padx=12,
                                                 anchor="w",
                                                 pady=(10, 4))
        self.full_out = tk.Label(
            parent, text="", bg=DBG, fg=DSECOND,
            font=(DFONT, 10), justify="left", wraplength=1000)
        self.full_out.pack(anchor="w", padx=12)

    def _build_apple_panel(self, parent):
        panel = tk.Frame(parent, bg=DPANEL, highlightthickness=1,
                         highlightbackground=DBORDER)
        panel.pack(fill="x", padx=12, pady=(10, 0))
        tk.Label(panel, text="APPLE DIAGNOSTICS -- Apple's own "
                             "console (iPhone only)",
                 bg=DPANEL, fg=DTEXT,
                 font=(DFONT, 11, "bold")).pack(anchor="w", padx=10,
                                                pady=(6, 0))
        tk.Label(panel, text=APPLE_CONSOLE_STEPS, bg=DPANEL,
                 fg=DSECOND, font=(DFONT, 10), justify="left",
                 wraplength=980).pack(anchor="w", padx=10)
        self.apple_rows = {}
        for suite in APPLE_SUITES:
            row = tk.Frame(panel, bg=DPANEL)
            row.pack(fill="x", padx=10, pady=1)
            tk.Label(row, text=suite, bg=DPANEL, fg=DTEXT,
                     font=(DFONT, 10), width=28,
                     anchor="w").pack(side="left")
            lbl = tk.Label(row, text="NOT RUN", bg=DPANEL,
                           fg=DMUTED, font=(DFONT, 10, "bold"))
            lbl.pack(side="left", padx=6)
            tk.Button(row, text="APPLE SAID PASS", bg=DRAISED,
                      fg=DGREEN, activebackground="#223449",
                      font=(DFONT, 9, "bold"), relief="flat",
                      padx=8, pady=2,
                      command=lambda su=suite:
                          self._apple_record(su, True)).pack(
                              side="left", padx=4)
            tk.Button(row, text="APPLE SAID FAIL", bg=DRAISED,
                      fg=DRED, activebackground="#223449",
                      font=(DFONT, 9, "bold"), relief="flat",
                      padx=8, pady=2,
                      command=lambda su=suite:
                          self._apple_record(su, False)).pack(
                              side="left")
            self.apple_rows[suite] = lbl
        tk.Label(panel, text="Suites that match a grid test (Audio, "
                             "Camera, Face ID, Multi-Touch) also "
                             "land on that test, labelled 'observed "
                             "by technician' -- the verdict is "
                             "Apple's, transcribed here.",
                 bg=DPANEL, fg=DMUTED, font=(DFONT, 9),
                 justify="left",
                 wraplength=980).pack(anchor="w", padx=10,
                                      pady=(2, 6))

    # ------------------------------------------------------------ --
    def _diag_key(self):
        return "android" if self.diag_platform == "Android" \
            else "iphone"

    def _refresh_diag(self):
        colors = {ST_PASS: DGREEN, ST_FAIL: DRED,
                  ST_NOT_RUN: DMUTED, ST_SKIPPED: DMUTED,
                  ST_NOCHECK: DWARN, ST_NOT_TESTABLE: DWARN}
        tags = {"A": "AUTO", "B": "GUIDED", "C": "SEALED"}
        for r in self.diag_results:
            row = self.diag_rows.get(r["num"])
            if row is None:
                continue
            row["tag"].configure(text=tags.get(r["test_class"], ""))
            row["status"].configure(
                text=STATUS_WORDS.get(r["status"], r["status"]),
                fg=colors.get(r["status"], DSECOND))
            row["value"].configure(text=r.get("value", ""))
        sm = diag_summary(self.diag_results)
        self.diag_progress.configure(
            text="Progress: %d/23" % sm["done"])
        c = sm["counts"]
        self.diag_summary.configure(
            text="Completed %d of 23 -- %d passed, %d failed, "
                 "%d skipped, %d could not be checked, "
                 "%d not testable."
                 % (sm["done"], c.get(ST_PASS, 0), c.get(ST_FAIL, 0),
                    c.get(ST_SKIPPED, 0), c.get(ST_NOCHECK, 0),
                    c.get(ST_NOT_TESTABLE, 0)))
        self.diag_failed.configure(
            text=("FAILED: " + "; ".join(sm["failed_names"]))
                 if sm["failed_names"] else "")

    def _select_test(self, num):
        self.selected_test = num
        t = TEST_BY_NUM[num]
        key = self._diag_key()
        guide = t["guide_" + key] or (
            "This test runs itself from the cable -- press RUN "
            "ALL AUTOMATIC TESTS above. Its readings show in the "
            "grid row.")
        res = [r for r in self.diag_results if r["num"] == num]
        cur = res[0] if res else None
        self.guide_title.configure(
            text="TEST %d -- %s (%s)" % (
                num, t["name"],
                {"A": "automatic", "B": "guided",
                 "C": "sealed -- substitute"}[t[key]]))
        self.guide_text.configure(text=guide)
        ev = ""
        if cur and cur["status"] != ST_NOT_RUN:
            ev = "Recorded: %s -- %s" % (cur["verdict"],
                                         cur.get("value", ""))
        self.guide_evidence.configure(text=ev)

    def _next_unrun(self):
        key = self._diag_key()
        start = (self.selected_test or 0)
        order = list(range(start + 1, 24)) + list(range(1,
                                                        start + 1))
        for num in order:
            r = [x for x in self.diag_results if x["num"] == num]
            if r and r[0]["status"] == ST_NOT_RUN \
                    and TEST_BY_NUM[num][key] in ("B", "C"):
                self._select_test(num)
                return
        self.guide_evidence.configure(
            text="Every guided test has a result. The summary "
                 "below the grid is the final word.")

    def _guided_record(self, status):
        num = self.selected_test
        if num is None or not self.diag_platform:
            messagebox.showwarning(
                APP_NAME, "Read a phone and open a guided test "
                          "first.")
            return
        t = TEST_BY_NUM[num]
        key = self._diag_key()
        if t[key] == "A" and status in (ST_PASS, ST_FAIL):
            messagebox.showwarning(
                APP_NAME, "That test is automatic -- its verdict "
                          "comes from the cable read, not from a "
                          "button. Run the automatic tests.")
            return
        words = {ST_PASS: "Worked -- recorded by the technician",
                 ST_FAIL: "Did not work -- recorded by the "
                          "technician",
                 ST_SKIPPED: "Skipped at the counter"}
        label = LBL_OBSERVED if t[key] == "C" else LBL_GUIDED
        source = ("technician's observation at the counter"
                  if t[key] == "C" else
                  "guided test -- technician performed it, this "
                  "PC recorded the verdict")
        if t[key] == "C":
            data = [r for r in self.diag_results
                    if r["num"] == num]
            keep = data[0].get("value", "") if data else ""
            self.diag_results = guided_record(
                self.diag_results, num, self.diag_platform, status,
                words[status], value=keep,
                detail="The sensor/enrollment read above came off "
                       "the cable; the unlock verdict itself is "
                       "the technician's observation. No cable "
                       "claim is made for it.",
                honesty_label=label, source=source)
        else:
            self.diag_results = guided_record(
                self.diag_results, num, self.diag_platform, status,
                words[status], honesty_label=label, source=source)
        self._refresh_diag()
        self._select_test(num)
        self.log("Test %d (%s): %s" % (num, t["name"],
                                       STATUS_WORDS[status]))

    def _apple_record(self, suite, passed):
        self.apple_suites[suite] = {
            "suite": suite,
            "verdict": "PASS" if passed else "FAIL",
            "detail": "Apple's console verdict, transcribed by "
                      "the technician.",
            "recorded_at": _now_str(),
        }
        lbl = self.apple_rows.get(suite)
        if lbl is not None:
            lbl.configure(text="PASS" if passed else "FAIL",
                          fg=DGREEN if passed else DRED)
        num = APPLE_SUITE_TO_TEST.get(suite)
        if num and self.diag_platform == "iPhone":
            self.diag_results = guided_record(
                self.diag_results, num, "iPhone",
                ST_PASS if passed else ST_FAIL,
                "Apple's console: %s" % ("PASS" if passed
                                         else "FAIL"),
                detail="Apple's own %s suite ran this test at "
                       "diagnostics.apple.com; the verdict is "
                       "Apple's, transcribed by the technician."
                       % suite,
                honesty_label=LBL_OBSERVED,
                source="diagnostics.apple.com (Apple Diagnostics "
                       "for Self Service Repair)")
            self._refresh_diag()
        self.log("Apple console -- %s: %s"
                 % (suite, "PASS" if passed else "FAIL"))

    # ------------------------------------------------------------ --
    def _run_auto(self):
        if self.diag_busy:
            return
        if not self.diag_platform:
            # Try a fresh read first: the grid classes depend on
            # which platform is plugged in.
            messagebox.showwarning(
                APP_NAME, "Press READ PHONE first so the grid "
                          "knows which phone is attached.")
            return
        self.diag_busy = True
        self.diag_platform_lbl.configure(
            text="Running the automatic tests ...", fg=DMUTED)
        platform = self.diag_platform

        def work():
            try:
                if platform == "Android":
                    results = capture_android_diag(self.adb)
                else:
                    results, extras = capture_iphone_diag(self.idev)
                    self.q.put(("diag_extras", extras))
                self.q.put(("diag_results", results))
            except Exception as e:
                self.q.put(("diag_error",
                            "Automatic tests failed: %s" % e))
        threading.Thread(target=work, daemon=True).start()

    def _guided_pc_part(self):
        num = self.selected_test
        if num is None or not self.diag_platform:
            messagebox.showwarning(
                APP_NAME, "Read a phone and open a guided test "
                          "first.")
            return
        if self.diag_busy:
            return
        platform = self.diag_platform
        self.diag_busy = True
        self.guide_evidence.configure(
            text="Working -- watch the phone ...")

        def work():
            try:
                msg = self._pc_part_work(num, platform)
                self.q.put(("diag_evidence", (num, msg)))
            except Exception as e:
                self.q.put(("diag_evidence",
                            (num, "The PC part hit a problem: %s"
                             % e)))
        threading.Thread(target=work, daemon=True).start()

    def _one_result(self, num):
        """The current grid line for one test -- worker threads
        build their single-result updates on this so a slow poll
        can never overwrite a fresher recording."""
        return [r for r in self.diag_results if r["num"] == num]

    def _pc_part_work(self, num, platform):
        """The PC's half of a guided test. Returns an evidence
        line for the face; records a verdict itself only when the
        cable truly proves one (proximity change, all three keys,
        wireless power seen, a new camera file). Everything else
        leaves the verdict to the technician's buttons, honestly.
        Runs on a worker thread."""
        if platform == "iPhone":
            return self._pc_part_iphone(num)
        adb = self.adb
        if num == 10:  # proximity: poll the sensor readings
            texts = []
            for _ in range(14):
                try:
                    texts.append(adb.run(
                        ["shell", "dumpsys", "sensorservice"],
                        timeout=15))
                except Exception:
                    pass
                time.sleep(0.8)
            ok, readings = proximity_sequence_verdict(texts)
            if ok:
                self.q.put(("diag_results", [guided_record(self._one_result(10), 10, platform, ST_PASS,
                    "Proximity sensor reacts -- reading changed "
                    "as the phone was covered",
                    value="readings seen: %s cm" % ", ".join(
                        "%g" % r for r in readings),
                    detail="This PC watched the proximity reading "
                           "itself while the technician covered "
                           "and uncovered the phone.",
                    honesty_label=LBL_GUIDED,
                    source="adb shell dumpsys sensorservice "
                           "(polled)")]))
                return "This PC saw the proximity reading change."
            if readings:
                return ("This PC saw proximity readings (%s cm) "
                        "but no cover/release change. Try again, "
                        "or record what your eyes saw."
                        % ", ".join("%g" % r for r in readings))
            return ("This build does not print proximity readings "
                    "to the shell -- record what your eyes saw "
                    "with the buttons below.")
        if num == 11:  # buttons: listen for real key presses
            keys = self._listen_buttons(seconds=25)
            ok, missing = buttons_verdict(keys)
            if ok:
                self.q.put(("diag_results", [guided_record(self._one_result(11), 11, platform, ST_PASS,
                    "All three keys registered real presses",
                    value="keys seen: VOLUME UP, VOLUME DOWN, "
                          "POWER",
                    detail="This PC listened on the cable with "
                           "getevent and saw the physical keys -- "
                           "nothing was injected.",
                    honesty_label=LBL_GUIDED,
                    source="adb shell getevent -l")]))
                return "All three keys heard. PASS recorded."
            return ("Keys heard so far: %s. Still missing: %s. "
                    "Press RUN THE PC PART again to keep "
                    "listening, or record by eye."
                    % (", ".join(sorted(keys)) or "none",
                       ", ".join(missing)))
        if num == 12:  # vibration: PC fires the motor
            for args in (["shell", "cmd", "vibrator", "vibrate",
                          "500"],
                         ["shell", "cmd", "vibrator_manager",
                          "vibrate", "500"]):
                try:
                    adb.run(args, timeout=15)
                    return ("This PC fired the vibration motor. "
                            "Did you feel a strong, clean buzz? "
                            "Record it below.")
                except Exception:
                    continue
            return ("This build would not let the PC fire the "
                    "motor. Buzz it from the phone's own settings "
                    "and record what you felt.")
        if num in (13, 21):  # speaker / headphones: tone + state
            notes = []
            if num == 21:
                try:
                    detected = parse_audio_headset(adb.run(
                        ["shell", "dumpsys", "audio"], timeout=20))
                    notes.append(
                        "Headset on the cable read: %s."
                        % {True: "SEEN connected",
                           False: "NOT seen -- check the plug",
                           None: "not reported by this build"}
                        [detected])
                except Exception:
                    notes.append("Headset state could not be read.")
            played = self._play_tone()
            notes.append(played)
            return " ".join(notes) + (
                " Record what you heard with the buttons below.")
        if num == 14:  # mic: look for the recording as evidence
            for folder in ("/sdcard/Recordings",
                           "/sdcard/Recordings/Voice recordings"):
                try:
                    rows = parse_ls_listing(adb.run(
                        ["shell", "ls", "-lt", folder],
                        timeout=15))
                    if rows:
                        return ("Newest recording on the phone: "
                                "%s (%d bytes, %s). If that is "
                                "the clip you just made and it "
                                "played back clear, record PASS."
                                % (rows[0][0], rows[0][1],
                                   rows[0][2]))
                except Exception:
                    continue
            return ("No recording file could be listed off the "
                    "phone -- record the verdict from the "
                    "playback you heard.")
        if num == 15:  # camera: open it, then verify the files
            if self._cam_before is None:
                try:
                    self._cam_before = adb.run(
                        ["shell", "ls", "-lt",
                         "/sdcard/DCIM/Camera"], timeout=15)
                except Exception:
                    self._cam_before = ""
                try:
                    adb.run(["shell", "am", "start", "-a",
                             "android.media.action.IMAGE_CAPTURE"],
                            timeout=15)
                except Exception:
                    pass
                return ("Camera opened on the phone and the "
                        "photo folder was snapshotted. Take the "
                        "rear and front photos, then press RUN "
                        "THE PC PART again and this PC will check "
                        "the new files.")
            before = parse_ls_listing(self._cam_before)
            self._cam_before = None
            try:
                after_text = adb.run(
                    ["shell", "ls", "-lt", "/sdcard/DCIM/Camera"],
                    timeout=15)
            except Exception:
                return "The photo folder could not be re-read."
            after = parse_ls_listing(after_text)
            if not after:
                return "The photo folder reads empty."
            newest = after[0]
            stamp = newest[2]
            fresh = newest_since(after, before[0][2]) if before \
                else after
            if not fresh:
                return ("No new photo appeared since the camera "
                        "opened (newest is %s, %s). Take the "
                        "photos, then run this again."
                        % (newest[0], stamp))
            pulled = None
            import tempfile
            try:
                fd, tmp = tempfile.mkstemp(suffix=".jpg")
                os.close(fd)
                adb.run(["pull", "/sdcard/DCIM/Camera/"
                         + fresh[0][0], tmp], timeout=30)
                with open(tmp, "rb") as fh:
                    pulled = jpeg_size(fh.read())
                os.unlink(tmp)
            except Exception:
                pulled = None
            dims = (" -- %dx%d pixels" % pulled) if pulled else ""
            self.q.put(("diag_results", [guided_record(self._one_result(15), 15, platform, ST_PASS,
                "New photos captured during the test",
                value="newest: %s (%d bytes)%s"
                      % (fresh[0][0], fresh[0][1], dims),
                detail="This PC read the photo files off the "
                       "phone. Sharpness and focus stay with "
                       "the technician's eyes -- same as "
                       "Samsung's own test.",
                honesty_label=LBL_GUIDED,
                source="adb (DCIM listing + pulled file)")]))
            return ("New photo found: %s%s. PASS recorded -- "
                    "focus quality is still your eyes' call."
                    % (fresh[0][0], dims))
        if num == 20:  # wireless charging: watch the charge state
            texts = []
            for _ in range(15):
                try:
                    texts.append(adb.run(
                        ["shell", "dumpsys", "battery"],
                        timeout=15))
                except Exception:
                    pass
                time.sleep(1.0)
            if wireless_poll_verdict(texts, "Android"):
                self.q.put(("diag_results", [guided_record(self._one_result(20), 20, platform, ST_PASS,
                    "Wireless power is reaching the phone",
                    detail="This PC read 'Wireless powered: "
                           "true' off the battery service while "
                           "the phone sat on the pad.",
                    honesty_label=LBL_GUIDED,
                    source="adb shell dumpsys battery (polled)")]))
                return "Wireless power seen. PASS recorded."
            return ("Wireless power was not seen in 15 seconds. "
                    "Re-seat the phone on the pad and try again, "
                    "or record by the phone's charging icon.")
        if num == 22:  # torch: try the shell controls
            attempts = (
                ["shell", "cmd", "camera", "set-torch-mode", "0",
                 "true"],
                ["shell", "cmd", "flashlight", "set", "1"],
                ["shell", "cmd", "flashlight", "on"],
            )
            offs = (
                ["shell", "cmd", "camera", "set-torch-mode", "0",
                 "false"],
                ["shell", "cmd", "flashlight", "set", "0"],
                ["shell", "cmd", "flashlight", "off"],
            )
            for i, args in enumerate(attempts):
                try:
                    adb.run(args, timeout=15)
                except Exception:
                    continue
                time.sleep(2)
                try:
                    adb.run(offs[i], timeout=15)
                except Exception:
                    pass
                self.q.put(("diag_results", [guided_record(self._one_result(22), 22, platform, ST_PASS,
                    "Torch driven on and off from this PC",
                    detail="The shell torch control answered. "
                           "The light itself is confirmed by the "
                           "technician's eyes at the counter.",
                    honesty_label=LBL_MEASURED,
                    source="adb shell (torch control)")]))
                return "Torch fired from this PC. PASS recorded."
            return ("This build does not expose torch control to "
                    "the shell. Turn the flashlight on from the "
                    "phone's quick settings and record by eye.")
        if num == 18:  # touch: serve the trace grid to the phone
            if self.touch_session is None:
                self.touch_session = TouchTraceSession()
                port = self.touch_session.start()
                ip = lan_ip()
                url = "http://%s:%d/" % (ip or "<this-PC-IP>",
                                         port)
                try:
                    adb.run(["shell", "am", "start", "-a",
                             "android.intent.action.VIEW", "-d",
                             url], timeout=15)
                except Exception:
                    pass
                return ("Trace page is live at %s and was opened "
                        "on the phone. Swipe EVERY square, then "
                        "press RUN THE PC PART again for the "
                        "coverage count. If the page did not open "
                        "(different Wi-Fi), type that address into "
                        "the phone's browser." % url)
            cov = self.touch_session.coverage_pct()
            dead = self.touch_session.dead_cells()
            total = self.touch_session.total
            hits = len(self.touch_session.hits)
            self.touch_session.stop()
            self.touch_session = None
            if cov >= 95:
                self.q.put(("diag_results", [guided_record(self._one_result(18), 18, platform, ST_PASS,
                    "Touch registered across the screen",
                    value="coverage %d%% (%d of %d squares)"
                          % (cov, hits, total),
                    detail="The phone's own touches reported "
                           "back to this PC over the shop "
                           "network -- real digitizer touches, "
                           "never injected ones.",
                    honesty_label=LBL_GUIDED,
                    source="trace page served by this PC")]))
                return "Coverage %d%%. PASS recorded." % cov
            if hits:
                return ("Coverage so far was %d%% (%d of %d "
                        "squares); untouched squares: %s. The "
                        "session is closed -- re-open the test "
                        "to trace again, or record FAIL if those "
                        "areas are truly dead."
                        % (cov, hits, total,
                           ", ".join(str(d + 1) for d in dead)))
            return ("No touches reached this PC -- the phone may "
                    "be on a different network. Record by eye "
                    "with the buttons, or retry on the shop "
                    "Wi-Fi.")
        return ("No PC step for this test -- follow the words "
                "above and record the verdict with the buttons.")

    def _pc_part_iphone(self, num):
        """iPhone guided tests: the cable gives facts, not
        verdicts. Surface the facts as evidence; the technician's
        buttons carry the verdict."""
        extras = self.iphone_extras or {}
        if num == 4:
            bits = []
            if extras.get("sim_status"):
                bits.append("SIM status off the cable: %s"
                            % extras["sim_status"])
            if extras.get("iccid"):
                bits.append("ICCID: %s" % extras["iccid"])
            if bits:
                return " -- ".join(bits) + (
                    ". Now check the phone's bars and record.")
            return ("The cable read no SIM facts this time -- "
                    "record from the phone's screen.")
        if num == 20:
            texts = []
            for _ in range(12):
                try:
                    texts.append(self.idev.run(
                        "idevicediagnostics", ["ioreg"],
                        timeout=15))
                except Exception:
                    pass
                time.sleep(1.5)
            if wireless_poll_verdict(texts, "iPhone"):
                self.q.put(("diag_results", [guided_record(self._one_result(20), 20, "iPhone", ST_PASS,
                    "Charge rose while the phone sat on the pad",
                    detail="This PC watched the battery readings "
                           "over the cable during the pad watch.",
                    honesty_label=LBL_GUIDED,
                    source="idevicediagnostics ioreg (polled)")]))
                return "Charge rising on the pad. PASS recorded."
            return ("No charge rise was seen during the watch. "
                    "Re-seat the phone and retry, or record by "
                    "the phone's charging bolt.")
        if num in (8, 9):
            which = "wifi_mac" if num == 8 else "bluetooth_mac"
            mac = extras.get(which)
            if mac:
                return ("This phone's %s address off the cable: "
                        "%s. The radio verdict itself is on the "
                        "phone's screen -- record it below."
                        % ("Wi-Fi" if num == 8 else "Bluetooth",
                           mac))
        return ("Lockdown gives no live read for this test -- "
                "the phone's screen and your eyes are the test. "
                "Record below.")

    def _listen_buttons(self, seconds=25):
        """Stream `getevent -l` for a window and collect the real
        key presses. Listening only -- injection would prove
        nothing about the physical switches."""
        keys = set()
        adb_path = getattr(self.adb, "adb_path", None)
        if adb_path is None:
            return keys
        try:
            proc = subprocess.Popen(
                [str(adb_path), "shell", "getevent", "-l"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace",
                creationflags=(0x08000000 if os.name == "nt"
                               else 0))
        except Exception:
            return keys
        deadline = time.time() + seconds
        try:
            while time.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    break
                keys |= parse_getevent_keys(line)
                if all(k in keys for k in BUTTON_KEYS):
                    break
        except Exception:
            pass
        finally:
            try:
                proc.terminate()
            except Exception:
                pass
        return keys

    def _play_tone(self):
        """Push the test tone to the phone and play it. Returns
        an evidence sentence; failures degrade to words, never
        to silence about what happened."""
        import tempfile
        try:
            fd, tmp = tempfile.mkstemp(suffix=".wav")
            with os.fdopen(fd, "wb") as fh:
                fh.write(build_tone_wav())
            remote = "/sdcard/Download/phonechecker_tone.wav"
            self.adb.run(["push", tmp, remote], timeout=30)
            os.unlink(tmp)
        except Exception as e:
            return ("The test tone could not be pushed (%s) -- "
                    "play any sound on the phone instead." % e)
        try:
            self.adb.run(["shell", "media", "volume", "--stream",
                          "3", "--set", "12"], timeout=15)
        except Exception:
            pass
        try:
            self.adb.run(["shell", "am", "start", "-a",
                          "android.intent.action.VIEW", "-d",
                          "file://" + remote, "-t", "audio/wav"],
                         timeout=15)
            return "Test tone played on the phone just now."
        except Exception:
            return ("Test tone is on the phone (Downloads -> "
                    "phonechecker_tone.wav) -- open it to play.")

    # ------------------------------------------------------------ --
    def _build_full(self):
        values = self._current_values()
        local = CHECK_BY_ID["local_identity"].run_local(values)
        checks = [local if c["check_id"] == "local_identity"
                  else c for c in self.checks]
        self.checks = checks
        identity = build_identity_report(self.readings or {},
                                         self._typed(),
                                         checks=checks)
        suites = [self.apple_suites[k]
                  for k in APPLE_SUITES if k in self.apple_suites]
        report = build_full_report(identity, self.diag_results,
                                   suites)
        self.full_report = report
        try:
            pdf_path = save_full_pdf(report)
        except Exception as e:
            messagebox.showerror(APP_NAME,
                                 "Counter report failed: %s" % e)
            return
        sm = report["summary"]
        self.full_out.configure(
            text="Counter report: %s\nCompleted %d of 23 tests "
                 "-- %d passed, %d failed. Failures: %s"
                 % (pdf_path, sm["done"],
                    sm["counts"].get(ST_PASS, 0),
                    sm["counts"].get(ST_FAIL, 0),
                    "; ".join(sm["failed_names"]) or "none"))
        self._refresh_check_cards()
        self.log("Counter report printed: %s" % pdf_path)

    def _handle_diag_msg(self, kind, payload):
        self.diag_busy = False
        if kind == "diag_error":
            self.diag_platform_lbl.configure(text=payload,
                                             fg=DRED)
            self.log(payload)
        elif kind == "diag_extras":
            self.iphone_extras = payload
        elif kind == "diag_results":
            self.diag_results = merge_diag_results(
                self.diag_results, payload)
            self.diag_platform_lbl.configure(
                text="%s connected -- automatic tests recorded."
                     % self.diag_platform, fg=DGREEN)
            self._refresh_diag()
            sm = diag_summary(self.diag_results)
            self.log("Diagnostics: %d of 23 completed (%d passed, "
                     "%d failed)."
                     % (sm["done"], sm["counts"].get(ST_PASS, 0),
                        sm["counts"].get(ST_FAIL, 0)))
        elif kind == "diag_evidence":
            num, msg = payload
            if self.selected_test == num:
                self.guide_evidence.configure(text=msg)
            self._refresh_diag()
            self.log("Test %d: %s" % (num, msg))


# ------------------------------------------------------------ --
    def _silent_update_check(self):
        info = fetch_update_info()
        if update_available(info):
            self.q.put(("update_ready", info))

    def _manual_update_check(self):
        self.log("Checking for updates ...")

        def work():
            info = fetch_update_info()
            if info is None:
                self.q.put(("update_none",
                            "No update information yet -- the "
                            "checker feed (phone-checker-version."
                            "json) is not on the shelf. You're on "
                            "v%s." % VERSION))
            elif update_available(info):
                self.q.put(("update_ready", info))
            else:
                self.q.put(("update_none",
                            "You're on the latest version (v%s)."
                            % VERSION))
        threading.Thread(target=work, daemon=True).start()

    def _offer_update(self, info):
        if self.busy:
            self.log("Update to v%s is available -- finish the "
                     "current phone first." % info["version"])
            return
        if not messagebox.askyesno(
                APP_NAME,
                "The Phone Checker v%s is available (you have "
                "v%s).\n\n%s\n\nInstall it now? The app will "
                "restart." % (info["version"], VERSION,
                              info.get("notes", ""))):
            return
        self.busy = True
        self.log("Downloading The Phone Checker v%s ..."
                 % info["version"])

        def work():
            path, err = download_update(info, _script_dir())
            if err:
                self.q.put(("error", "Update not installed: %s. "
                                     "You're still on v%s."
                                     % (err, VERSION)))
                return
            try:
                begin_update(Path(sys.argv[0]).resolve(), path,
                             info["version"], VERSION)
            except Exception as e:
                self.q.put(("error", "Update could not start (%s). "
                                     "You're still on v%s."
                                     % (e, VERSION)))
                return
            self.root.after(400, self.root.destroy)
        threading.Thread(target=work, daemon=True).start()


    def process_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "error":
                    self.busy = False
                    self.device_lbl.configure(
                        text=payload, fg=DRED)
                    self.log(payload)
                elif kind == "update_ready":
                    self._offer_update(payload)
                elif kind == "update_none":
                    if payload:
                        self.log(payload)
                elif kind in ("diag_results", "diag_evidence",
                              "diag_error", "diag_extras"):
                    self._handle_diag_msg(kind, payload)
                elif kind == "read":
                    platform, ident, msg = payload
                    self.busy = False
                    self.readings = ident
                    self.checks = default_checks(
                        self._current_values())
                    label = ("%s: %s %s -- serial %s -- IMEI %s"
                             % (platform,
                                ident.get("brand", ""),
                                ident.get("model", ""),
                                ident.get("serial") or "?",
                                ident.get("imei")
                                or "(could not be read)"))
                    self.phone_lbl.configure(text=label)
                    self.device_lbl.configure(
                        text="%s connected -- identity read off "
                             "the cable." % platform, fg=DGREEN)
                    self._refresh_check_cards()
                    self.diag_platform = platform
                    self.diag_results = default_diag_results(
                        platform)
                    self.apple_suites = {}
                    for lbl in self.apple_rows.values():
                        lbl.configure(text="NOT RUN", fg=DMUTED)
                    self.iphone_extras = {}
                    self.selected_test = None
                    self._cam_before = None
                    self.diag_platform_lbl.configure(
                        text="%s connected -- grid ready."
                             % platform, fg=DGREEN)
                    self._refresh_diag()
                    self.log(label)
        except queue.Empty:
            pass
        self.root.after(120, self.process_queue)


def main():
    root = tk.Tk()
    PhoneCheckerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
