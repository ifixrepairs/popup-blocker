"""PANIC READER v0.5 — working build (the owner names products last;
"Panic Reader" is a working title only).

One job: read an iPhone's panic logs and tell the technician, in plain
words, which part is most likely faulty — plus the test that proves it
before anybody quotes the job.

Two doors in:
  (a) READ THE PHONE — pulls the panic logs off a plugged-in iPhone with
      the free libimobiledevice tools (idevice_id / idevicecrashreport).
      If those tools are not on this computer, the tool says so in plain
      words and points at door (b). Never a dead button.
  (b) OPEN A PANIC FILE — reads a panic-full .ips / .txt file exported
      from 3uTools, i4Tools, or Settings > Analytics, and analyzes it.

The answers come from rulebook.json, a plain data file sitting beside
this program. Facts in it are drawn from public repair sources (iFixit
wikis, Repair Wiki, REWA's restart chart — each rule carries its source)
and rewritten in our own words. To add or fix a rule, edit that file —
no code change needed. A rule with "bench_verified": false has NOT been
confirmed on this shop's bench yet.

v0.2 adds four things (see BUILD-NOTES "v0.2"):
  * THE CASE BOOK (casebook.json) — after a repair, the technician taps
    WHAT FIXED IT. Three agreeing cures for one pattern, with no
    conflicting winner, promote the pattern to a bench-proven rule that
    outranks the web-sourced rules. The tool teaches itself only from
    real cures on this bench.
  * THE CURE WATCH — after the repair, plug the phone back in: CURE
    CHECK compares every panic's time against the repair stamp, and the
    LIVE WATCH watches the plugged-in phone for new panics. A clean
    watch earns a printable CURE PROOF slip. The slip claims only what
    was observed: "No new panic logged during the watch."
  * THE AI HELPER — ASK THE AI (on no-match verdicts) and EXPLAIN THIS
    LOG. The payload is scrubbed of serials, UDIDs and IMEIs before it
    leaves the machine, and every AI answer renders under the badge
    "AI READING — UNPROVEN. The book and the bench decide." AI text can
    be saved only as a draft rule; drafts never promote themselves.
  * THE WEB WATCH — CHECK FOR NEW CODES fetches the Repair Wiki and
    iFixit panic pages and writes only NEW candidates into drafts.json,
    unproven. Plus PART PICTURES: the verdict shows a real photo of the
    named part (part_images.json + parts-images/), or an honest empty
    slot that says "No picture yet for this part".

v0.4 adds the plain re-skin (the owner's bar: "simple professional"
— the second ChatGPT board's palette and type ladder, styling only)
and the 3-MINUTE TEST in the cure-check area: the face's ONE timer.
Hit START and it counts up live; at 3:00 it flips green — PAST 3
MINUTES — and keeps counting; START again after a stop begins a
fresh count. When a repair case is saved, the same START also runs
the cure watch's panic monitoring and STOP ends it — there are no
watch-length choices anymore (the owner's simplification). The
timer itself reads nothing from the phone; the face says so.

v0.5 aligns the LAYOUT to the plain board as drawn (the owner's
order, 2026-10-31: "Put it back the way it was like this. At a
spot for a picture. A timer. An AI."): the idle face carries the
board's caps subtitle and each door carries the board's small
sub-line inside its block; a bottom status line shows the real
version on the left and the app's state on the right ("Ready."
at idle); the verdict part name renders in primary text white,
as the board draws it. The owner's three locks stand: a spot
for a picture (the honest empty slot), the one timer, the AI
row. Styling and layout only — the engine is untouched.

v1.2 adds the house self-update door: a labeled CHECK FOR UPDATES
button on the bottom status line, beside the version. It reads
analyze-that-part-version.json from the shop shelf, and a download
is installed only after its size AND SHA-256 match the manifest;
a helper script performs the swap after this process exits and
rolls back if the new build does not stay alive (30-second
window). The manifest is published separately — until it is, the
door answers honestly that there is no update information yet.

HONESTY LAW: if no rule matches, the tool says "No known match" and
shows what the log does say. It never invents a part. A panic log is a
strong clue, not a guarantee.

Python 3.10+, stdlib only, Windows-first. Importing this file does not
start the GUI; the parser and matcher are testable headless (see
gate_panic_reader.py).
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.2"

SHOP = "iFixx Phone Repairs, LLC"
COPYRIGHT_LINE = "© 2026 iFixx Phone Repairs, LLC. All rights reserved."
WORKING_TITLE = "Analyze That Part"
CLUE_LINE = ("A panic log is a strong clue, not a guarantee — "
             "always run the proving test before quoting the job.")

# The face's colors, fonts and spacing live in ONE style block at the
# top of the GUI section (search for "FACE STYLE") so a future skin
# swap is a one-block change. Nothing up here styles the face.

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULEBOOK_PATH = os.path.join(SCRIPT_DIR, "rulebook.json")
CASEBOOK_PATH = os.path.join(SCRIPT_DIR, "casebook.json")
DRAFTS_PATH = os.path.join(SCRIPT_DIR, "drafts.json")
PART_IMAGES_PATH = os.path.join(SCRIPT_DIR, "part_images.json")
PARTS_IMAGES_DIR = os.path.join(SCRIPT_DIR, "parts-images")
CURE_PROOFS_DIR = os.path.join(SCRIPT_DIR, "cure-proofs")

# The AI helper's key lives in the shop credentials folder, never in
# this file and never printed. The path can be overridden with the
# PANIC_READER_NVIDIA_KEY_PATH environment variable (the gate uses it).
NVIDIA_KEY_PATH = os.environ.get(
    "PANIC_READER_NVIDIA_KEY_PATH",
    os.path.expanduser("~/workspace/credentials/nvidia-build-api-key.txt"))
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_MODEL = "meta/llama-3.3-70b-instruct"
AI_BADGE = "AI READING — UNPROVEN. The book and the bench decide."
AI_NOT_SETUP_TEXT = (
    "The AI helper is not set up on this computer — its key file is "
    "missing, so nothing was sent anywhere.\n"
    "The rule book above still stands on its own; the bench decides.")
AI_OFFLINE_TEXT = (
    "The AI helper could not be reached — no internet right now, or "
    "the service did not answer.\n"
    "Nothing about this phone was diagnosed by the AI. The rule book "
    "above still stands on its own; the bench decides.")

# Plain part list offered under WHAT FIXED IT -> "Something else".
PART_LIST = [
    "Charging-port assembly",
    "Charging-port flex cable",
    "Battery",
    "Front sensor assembly",
    "Front (proximity) sensor flex",
    "Power-button flex cable",
    "Wireless charging coil",
    "Rear camera",
    "Taptic Engine (vibrator)",
    "Logic board work (board-level)",
    "Storage chip (NAND) - board-level",
    "Software only - a restore fixed it",
    "Not fixed yet",
]

NO_PICTURE_TEXT = "No picture yet for this part"

TOOLS_MISSING_TEXT = (
    "The phone-reading tools are not on this computer yet.\n"
    "One-time setup: install the free libimobiledevice tools and Apple's "
    "drivers (iTunes or the Apple Devices app) — see BUILD-NOTES.\n"
    "Right now you can still use OPEN A PANIC FILE with a panic log "
    "exported from 3uTools or from the phone's Settings > Analytics."
)
NO_PHONE_TEXT = (
    "No iPhone found on the cable.\n"
    "Plug the phone in, unlock it, and tap Trust if the phone asks."
)
NO_LOGS_TEXT = (
    "The phone answered, but it has no panic logs on it.\n"
    "If the phone is restarting on its own, use it until it restarts "
    "once, then read it again."
)

# ===========================================================================
# MODEL TABLE — Apple product id ("iPhone14,5") -> (bucket, friendly name).
#
# Rules in rulebook.json are keyed by bucket. Only add a product id you
# are sure of: a wrong bucket can pull the wrong model's code table.
# The 17-family (iPhone18,x) ids follow Apple's numbering sequence and
# are flagged in BUILD-NOTES as to-confirm at the first bench read; the
# tool always shows the raw product id in "What the log says", so a
# mismatch is visible, never hidden.
# ===========================================================================
PRODUCT_MAP = {
    (10, 1): ("le12", "iPhone 8"), (10, 4): ("le12", "iPhone 8"),
    (10, 3): ("le12", "iPhone X"), (10, 6): ("le12", "iPhone X"),
    (11, 2): ("le12", "iPhone XS"), (11, 4): ("le12", "iPhone XS Max"),
    (11, 6): ("le12", "iPhone XS Max"), (11, 8): ("le12", "iPhone XR"),
    (12, 1): ("le12", "iPhone 11"), (12, 3): ("le12", "iPhone 11 Pro"),
    (12, 5): ("le12", "iPhone 11 Pro Max"),
    (12, 8): ("le12", "iPhone SE (2020)"),
    (13, 1): ("le12", "iPhone 12 mini"), (13, 2): ("le12", "iPhone 12"),
    (13, 3): ("le12", "iPhone 12 Pro"),
    (13, 4): ("le12", "iPhone 12 Pro Max"),
    (14, 4): ("13mini", "iPhone 13 mini"),
    (14, 5): ("13", "iPhone 13"),
    (14, 2): ("13pro", "iPhone 13 Pro"),
    (14, 3): ("13pro", "iPhone 13 Pro Max"),
    (14, 6): ("13", "iPhone SE (2022)"),
    (14, 7): ("14", "iPhone 14"), (14, 8): ("14", "iPhone 14 Plus"),
    (15, 2): ("14pro", "iPhone 14 Pro"),
    (15, 3): ("14pro", "iPhone 14 Pro Max"),
    (15, 4): ("15", "iPhone 15"), (15, 5): ("15", "iPhone 15 Plus"),
    (16, 1): ("15pro", "iPhone 15 Pro"),
    (16, 2): ("15pro", "iPhone 15 Pro Max"),
    (17, 1): ("16pro", "iPhone 16 Pro"),
    (17, 2): ("16pro", "iPhone 16 Pro Max"),
    (17, 3): ("16", "iPhone 16"), (17, 4): ("16", "iPhone 16 Plus"),
    (17, 5): ("16", "iPhone 16e"),
    (18, 1): ("17pro", "iPhone 17 Pro"),
    (18, 2): ("17pro", "iPhone 17 Pro Max"),
    (18, 3): ("17", "iPhone 17"), (18, 4): ("17", "iPhone 17 family"),
}

BUCKET_NAMES = {
    "le12": "iPhone X to 12 era (named sensors)",
    "13": "iPhone 13", "13mini": "iPhone 13 mini",
    "13pro": "iPhone 13 Pro / Pro Max",
    "14": "iPhone 14 / 14 Plus", "14pro": "iPhone 14 Pro / Pro Max",
    "15": "iPhone 15 / 15 Plus", "15pro": "iPhone 15 Pro / Pro Max",
    "16": "iPhone 16 / 16 Plus", "16pro": "iPhone 16 Pro / Pro Max",
    "17": "iPhone 17", "17pro": "iPhone 17 Pro / Pro Max",
    "ipad": "iPad", "unknown": "Unknown model",
}

# Sensor names the older phones (X to 12) print in words when one stops
# answering. Scanned for only in watchdog / SMC logs, where they belong.
KNOWN_SENSORS = ["mic1", "mic2", "prs0", "prs1", "tg0b", "tg0v",
                 "thd0", "tcal", "tsfc", "vdin", "vdsk"]


# ===========================================================================
# RULE BOOK
# ===========================================================================
class RulebookError(Exception):
    """Raised with a plain-words message when the rule book is unusable."""


def load_rulebook(path=RULEBOOK_PATH):
    """Load and sanity-check rulebook.json. Returns the parsed dict."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            book = json.load(fh)
    except FileNotFoundError:
        raise RulebookError(
            "The rule book file (rulebook.json) is missing. It has to sit "
            "in the same folder as this program.")
    except json.JSONDecodeError as exc:
        raise RulebookError(
            "The rule book file (rulebook.json) has a mistake in it and "
            "could not be read: %s" % exc)
    rules = book.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RulebookError("The rule book has no rules in it.")
    for rule in rules:
        for key in ("id", "models", "family", "token", "part",
                    "confidence", "test", "source"):
            if key not in rule:
                raise RulebookError(
                    "Rule %r is missing its %r entry." %
                    (rule.get("id", "?"), key))
    return book


# ===========================================================================
# PARSING — an .ips file is two JSON documents back to back (a short
# header, then the report that carries "panicString"). Files exported by
# other tools can also be plain text holding just the panic string.
# ===========================================================================
@dataclass
class ParsedLog:
    ok: bool = False
    error: str = ""
    raw_product: str = ""
    model_bucket: str = "unknown"
    model_name: str = ""
    board: str = ""
    families: list = field(default_factory=list)   # primary first
    missing_sensors: list = field(default_factory=list)
    smc_code: object = None                        # int or None
    smc_code_text: str = ""                        # as read from the log
    i2c_buses: list = field(default_factory=list)
    date: str = ""
    incident: str = ""
    panic_string: str = ""

    @property
    def family(self):
        return self.families[0] if self.families else "unknown"


def _split_ips(text):
    """Return (header_dict, report_dict) from .ips text; either may be {}."""
    decoder = json.JSONDecoder()
    text = text.strip()
    if not text.startswith("{"):
        return {}, {}
    try:
        header, idx = decoder.raw_decode(text)
    except json.JSONDecodeError:
        return {}, {}
    rest = text[idx:].strip()
    report = {}
    if rest.startswith("{"):
        try:
            report, _ = decoder.raw_decode(rest)
        except json.JSONDecodeError:
            report = {}
    if isinstance(report, dict) and report:
        return (header if isinstance(header, dict) else {}), report
    # Single JSON document: it may be the report itself.
    return {}, (header if isinstance(header, dict) else {})


def _find_panic_string(text, report):
    if isinstance(report, dict):
        value = report.get("panicString") or report.get("panic_string")
        if isinstance(value, str) and value.strip():
            return value
    idx = text.find("panic(cpu")
    if idx >= 0:
        tail = text[idx:]
        cut = tail.find('",')
        if cut > 0:
            tail = tail[:cut]
        return tail.strip()
    idx = text.upper().find("SMC PANIC")
    if idx >= 0:
        tail = text[idx:]
        cut = tail.find('",')
        if cut > 0:
            tail = tail[:cut]
        return tail.strip()
    return ""


def _classify_families(panic):
    """Return the ordered family list for a panic string."""
    low = panic.lower()
    families = []

    def add(name):
        if name not in families:
            families.append(name)

    if "ans2" in low or "appleans" in low or "nvme" in low:
        add("ans2")
    if "smc panic" in low or "smc panic" in panic.upper().lower():
        add("smc")
    if "aop panic" in low:
        add("aop")
    if "sep panic" in low or "seprom" in low.replace(" ", "") \
            or "apple sep" in low or " sep " in low:
        add("sep")
    if "baseband" in low:
        add("baseband")
    if "watchdog" in low or "thermalmonitord" in low:
        add("watchdog")
    buses = sorted({int(n) for n in
                    re.findall(r"i2c[\s\-_]?([0-3])\b", low)})
    if buses:
        add("i2c")
    if not families:
        add("kernel")
    return families, buses


def _extract_smc_code(panic):
    """Read the SMC sensor-array code. Newer iOS prints it in decimal,
    older in hex — either way the VALUE is the same number, and that
    value is what the rule book keys on. Returns (int, text) or
    (None, '')."""
    match = re.search(r"sensor array[^0-9a-zA-Z]{0,12}(0x[0-9a-fA-F]+|\d{3,})",
                      panic, re.IGNORECASE)
    if match:
        raw = match.group(1)
        try:
            return (int(raw, 16) if raw.lower().startswith("0x")
                    else int(raw, 10)), raw
        except ValueError:
            pass
    if "smc" in panic.lower():
        for line in panic.splitlines():
            if "smc" not in line.lower():
                continue
            for token in re.findall(r"0x[0-9a-fA-F]+", line):
                if token.lower().startswith("0xffff"):
                    continue
                try:
                    value = int(token, 16)
                except ValueError:
                    continue
                if 0 < value < 0x1000000:
                    return value, token
    return None, ""


def _extract_sensors(panic, families):
    found = []
    match = re.search(r"missing sensors?\s*:?\s*([a-zA-Z0-9_,\s]+)",
                      panic, re.IGNORECASE)
    if match:
        for name in re.split(r"[,\s]+", match.group(1)):
            name = name.strip().lower()
            if name in KNOWN_SENSORS and name not in found:
                found.append(name)
    if any(f in families for f in ("watchdog", "smc")):
        low = panic.lower()
        for name in KNOWN_SENSORS:
            if re.search(r"\b%s\b" % name, low) and name not in found:
                found.append(name)
    return found


def parse_log_text(text):
    """Parse panic-log text (full .ips, single JSON, or raw text)."""
    parsed = ParsedLog()
    if text is None or not text.strip():
        parsed.error = "That file is empty — there is nothing to read."
        return parsed
    header, report = _split_ips(text)
    panic = _find_panic_string(text, report)
    if not panic:
        parsed.error = ("That file does not look like a panic log. "
                        "Panic logs are the files whose names start "
                        "with \"panic-full\".")
        return parsed
    parsed.ok = True
    parsed.panic_string = panic

    product = ""
    for source in (report, header):
        if isinstance(source, dict):
            product = source.get("product") or source.get("ProductType") \
                or product
    if not product:
        match = re.search(r"iPhone\d+,\d+|iPad\d+,\d+", text)
        product = match.group(0) if match else ""
    parsed.raw_product = product or ""
    if product.startswith("iPad"):
        parsed.model_bucket = "ipad"
        parsed.model_name = product
    elif product.startswith("iPhone"):
        match = re.match(r"iPhone(\d+),(\d+)", product)
        if match:
            key = (int(match.group(1)), int(match.group(2)))
            bucket, name = PRODUCT_MAP.get(key, ("unknown", product))
            parsed.model_bucket = bucket
            parsed.model_name = name
        else:
            parsed.model_name = product
    board_match = re.search(r"\b([Dd]\d{2})[Aa][Pp]\b", text)
    if board_match:
        parsed.board = board_match.group(1).lower()

    for source in (header, report):
        if isinstance(source, dict):
            parsed.date = parsed.date or str(
                source.get("date") or source.get("timestamp") or "")
            parsed.incident = parsed.incident or str(
                source.get("incident") or source.get("incident_id") or "")

    parsed.families, parsed.i2c_buses = _classify_families(panic)
    parsed.missing_sensors = _extract_sensors(panic, parsed.families)
    parsed.smc_code, parsed.smc_code_text = _extract_smc_code(panic)
    return parsed


# ===========================================================================
# MATCHING — rules are keyed (model bucket x panic family x token).
# A specific rule for this exact model always beats a general one.
# Sensor-array codes are bit flags: when no rule covers the whole code,
# the code is split into its single bits and each bit's rule is offered.
# ===========================================================================
CONF_RANK = {"High": 3, "Medium": 2, "Low": 1}
TOKEN_RANK = {"board_code": 55, "code": 50, "sensor": 45,
              "i2c_bus": 30, "phrase": 30, "family": 5}


@dataclass
class Match:
    rule: dict
    score: int
    via: str          # "code", "bit 0x800 of 0x1800", "sensor mic1", ...


@dataclass
class Verdict:
    parsed: ParsedLog
    matches: list = field(default_factory=list)   # ranked, best first
    uncovered_bits: int = 0

    @property
    def headline(self):
        return self.matches[0] if self.matches else None


def _phrase_hit(phrase, panic_low):
    phrase = phrase.lower()
    if len(phrase) <= 3:
        return re.search(r"\b%s\b" % re.escape(phrase), panic_low) is not None
    return phrase in panic_low


def _rule_fires(rule, parsed, panic_low):
    """Return the via-string if this rule matches, else None."""
    token = rule.get("token", {})
    ttype = token.get("type")
    if rule.get("boards"):
        if parsed.board not in [b.lower() for b in rule["boards"]]:
            return None
    if ttype == "code" or ttype == "board_code":
        if parsed.smc_code is not None and parsed.smc_code == token.get("value"):
            return "code %s" % parsed.smc_code_text
        return None
    if ttype == "sensor":
        if str(token.get("value", "")).lower() in parsed.missing_sensors:
            return "sensor %s" % token.get("value")
        return None
    if ttype == "phrase":
        if _phrase_hit(str(token.get("value", "")), panic_low):
            return "words in the log"
        return None
    if ttype == "i2c_bus":
        if token.get("value") in parsed.i2c_buses:
            return "bus i2c%s" % token.get("value")
        return None
    if ttype == "family":
        return "panic kind"
    return None


def _score(rule, parsed, decomposed=False):
    score = 0
    if parsed.model_bucket in rule.get("models", []):
        score += 100
    elif "any" in rule.get("models", []):
        score += 10
    if rule.get("boards"):
        score += 20
    score += TOKEN_RANK.get(rule.get("token", {}).get("type"), 0)
    if decomposed:
        score -= 10
    score += CONF_RANK.get(rule.get("confidence"), 1) * 2
    if rule.get("bench_verified"):
        # A rule this shop has proven on its own bench outranks a
        # web-sourced rule for the same pattern.
        score += 40
    return score


def analyze(parsed, book, extra_rules=()):
    """Match a parsed log against the rule book. Never invents a part:
    no matching rule -> an empty match list, and the caller shows the
    parsed facts instead. extra_rules carries the case book's
    bench-promoted rules (see casebook.json); they compete on score
    like any rule, with the bench-proven bonus in _score."""
    verdict = Verdict(parsed=parsed)
    if not parsed.ok:
        return verdict
    panic_low = parsed.panic_string.lower()
    rules = list(book.get("rules", [])) + list(extra_rules)

    def model_ok(rule):
        models = rule.get("models", [])
        return parsed.model_bucket in models or "any" in models

    def family_ok(rule):
        fam = rule.get("family")
        return fam == "any" or fam in parsed.families

    hits = []
    for rule in rules:
        if not (model_ok(rule) and family_ok(rule)):
            continue
        via = _rule_fires(rule, parsed, panic_low)
        if via:
            hits.append(Match(rule, _score(rule, parsed), via))

    # Bit split: only when no rule covers the whole sensor-array code.
    code = parsed.smc_code
    exact = any(m.rule.get("token", {}).get("type") in ("code", "board_code")
                for m in hits)
    if code is not None and not exact and code >= 0x100:
        bit_rules = []
        for rule in rules:
            token = rule.get("token", {})
            if token.get("type") != "code":
                continue
            if not (model_ok(rule) and family_ok(rule)):
                continue
            value = token.get("value")
            if isinstance(value, int) and value >= 0x100 \
                    and value & code == value:
                bit_rules.append((value, rule))
        covered = 0
        for value, _rule in bit_rules:
            covered |= value
        if bit_rules and covered:
            for value, rule in bit_rules:
                hits.append(Match(rule, _score(rule, parsed, decomposed=True),
                                  "part of code %s (bit 0x%x)"
                                  % (parsed.smc_code_text, value)))
            verdict.uncovered_bits = code & ~covered

    hits.sort(key=lambda m: (-m.score, m.rule.get("id", "")))
    verdict.matches = hits
    return verdict


def family_plain(book, family):
    info = book.get("family_info", {}).get(family, {})
    return info.get("plain", "")


def facts_lines(parsed, book):
    """The honest 'what the log does say' list, used under every verdict
    and on its own when no rule matches."""
    lines = []
    if parsed.model_name:
        lines.append("Phone: %s (%s)" % (parsed.model_name,
                                         parsed.raw_product))
    elif parsed.raw_product:
        lines.append("Phone code in the log: %s" % parsed.raw_product)
    if parsed.board:
        lines.append("Board: %s" % parsed.board.upper())
    plain = family_plain(book, parsed.family)
    if plain:
        lines.append("Kind of panic: %s" % plain)
    else:
        lines.append("Kind of panic: %s" % parsed.family)
    if parsed.missing_sensors:
        lines.append("Sensor(s) not answering: %s"
                     % ", ".join(parsed.missing_sensors))
    if parsed.smc_code is not None:
        lines.append("Sensor code in the log: %s (number %d, hex 0x%x)"
                     % (parsed.smc_code_text, parsed.smc_code,
                        parsed.smc_code))
    if parsed.i2c_buses:
        lines.append("Data bus(es) named: %s"
                     % ", ".join("i2c%d" % b for b in parsed.i2c_buses))
    if parsed.date:
        lines.append("Log date: %s" % parsed.date)
    if parsed.panic_string:
        first = parsed.panic_string.strip().splitlines()[0]
        lines.append("First line of the panic: %s" % first[:180])
    return lines


def analyze_text(text, book, extra_rules=()):
    return analyze(parse_log_text(text), book, extra_rules)


def analyze_file(path, book, extra_rules=()):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return analyze_text(fh.read(), book, extra_rules)


# ===========================================================================
# DOOR (a) — READ THE PHONE over USB with libimobiledevice tools.
# The tools are found on PATH first, then beside this program (the house
# pattern). Every failure returns a plain-words message, never a crash.
# ===========================================================================
def find_reader_tools():
    """Return (idevice_id_path, idevicecrashreport_path); either may be
    None. Checks beside this program first, then PATH."""
    def find(name):
        for folder in (SCRIPT_DIR,):
            for candidate in (name, name + ".exe"):
                path = os.path.join(folder, candidate)
                if os.path.isfile(path):
                    return path
        return shutil.which(name)
    return find("idevice_id"), find("idevicecrashreport")


def _run(cmd, timeout=30):
    try:
        done = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return done.returncode, done.stdout or "", done.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except OSError as exc:
        return -1, "", str(exc)


def pull_panic_texts():
    """Pull every panic log off the plugged-in phone.
    Returns (message, items): on success message is "" and items is a
    list of (file_name, text) oldest first; on any failure message is a
    plain-words explanation and items is []. NO_PHONE_TEXT means the
    phone is not answering at all — the cure watch treats that as the
    phone vanishing mid-watch."""
    id_tool, crash_tool = find_reader_tools()
    if not id_tool or not crash_tool:
        return TOOLS_MISSING_TEXT, []
    code, out, _err = _run([id_tool, "-l"], timeout=15)
    udids = [line.strip() for line in out.splitlines() if line.strip()]
    if code != 0 or not udids:
        return NO_PHONE_TEXT, []
    with tempfile.TemporaryDirectory(prefix="panicreader-") as tmp:
        code, _out, _err = _run([crash_tool, "-k", tmp], timeout=90)
        if code != 0:
            return ("The phone is plugged in, but its logs would not "
                    "come across.\nUnlock the phone, tap Trust if it "
                    "asks, and try again."), []
        files = []
        for pattern in ("panic-full*.ips", "Panic-full*.ips",
                        "panic-full*", "*.ips"):
            files.extend(glob.glob(os.path.join(tmp, "**", pattern),
                                   recursive=True))
        files = sorted(set(files),
                       key=lambda p: os.path.getmtime(p))
        items = []
        for path in files:
            name = os.path.basename(path)
            if "panic" not in name.lower():
                continue
            try:
                with open(path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    items.append((name, fh.read()))
            except OSError:
                continue
        if not items:
            return NO_LOGS_TEXT, []
        return "", items


def read_phone(book, extra_rules=()):
    """Pull panic logs off a plugged-in iPhone and analyze them.
    Returns (message, verdict_or_None, tally_text)."""
    message, items = pull_panic_texts()
    if message:
        return message, None, ""
    verdicts = [analyze_text(text, book, extra_rules)
                for _name, text in items[-25:]]
    good = [v for v in verdicts if v.parsed.ok and v.matches]
    if not good:
        newest = verdicts[-1] if verdicts else None
        if newest is not None and newest.parsed.ok:
            return "", newest, ""
        return NO_LOGS_TEXT, None, ""
    newest = good[-1]
    top_id = newest.headline.rule.get("id")
    same = sum(1 for v in good
               if v.headline and v.headline.rule.get("id") == top_id)
    tally = ""
    if len(good) > 1:
        tally = ("This phone left %d panic logs. %d of them point at "
                 "the same part." % (len(good), same))
    return "", newest, tally


# ===========================================================================
# TIMES — panic logs carry their date in the .ips header ("date") and in
# the file name ("panic-full-2026-10-28-140311.ips"). The cure check
# lives on comparing those stamps against the repair stamp in a case.
# ===========================================================================
_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z",
                 "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                 "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")


def parse_log_datetime(value, name=""):
    """Read a datetime out of an .ips date string or a panic file name.
    Returns an aware datetime (UTC assumed when no zone is printed) or
    None when nothing readable is there."""
    for candidate in (value or "", name or ""):
        if not candidate:
            continue
        candidate = candidate.strip()
        for fmt in _DATE_FORMATS:
            try:
                stamp = datetime.strptime(candidate, fmt)
                return (stamp if stamp.tzinfo
                        else stamp.replace(tzinfo=timezone.utc))
            except (ValueError, TypeError):
                pass
        match = re.search(r"(\d{4})-(\d{2})-(\d{2})[-_ ](\d{2})(\d{2})(\d{2})",
                          candidate)
        if match:
            try:
                return datetime(*[int(x) for x in match.groups()],
                                tzinfo=timezone.utc)
            except ValueError:
                pass
        match = re.search(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})",
                          candidate)
        if match:
            try:
                return datetime(*[int(x) for x in match.groups()],
                                tzinfo=timezone.utc)
            except ValueError:
                pass
    return None


def stamp_of(parsed, name=""):
    return parse_log_datetime(parsed.date, name)


def _watch_len_text(seconds):
    seconds = int(round(seconds))
    if seconds >= 60 and seconds % 60 == 0:
        minutes = seconds // 60
        return "%d minute%s" % (minutes, "" if minutes == 1 else "s")
    if seconds >= 60:
        return "%.1f minutes" % (seconds / 60.0)
    return "%d second%s" % (seconds, "" if seconds == 1 else "s")


# ===========================================================================
# THE CASE BOOK — casebook.json, this shop's own bench record, and the
# self-teaching law. A case stores the pattern that was read (model
# bucket x panic family x token) and the part that actually cured the
# phone. PROMOTION LAW: a pattern with 3 cases, all naming the SAME
# winning part and no case naming a different one, is promoted to a
# bench-proven rule (kept in the case book's "promoted_rules", in
# rulebook shape) that outranks web-sourced rules for that pattern.
# Conflicting winners block promotion — the split is shown, not hidden.
# Promotions are recomputed from the cases alone (refresh_promotions),
# so the whole state can be rebuilt from this one file.
# ===========================================================================
def _empty_book(kind):
    if kind == "cases":
        return {"version": 1, "cases": [], "promoted_rules": []}
    return {"version": 1, "drafts": []}


def _load_json_book(path, kind):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return _empty_book(kind)


def _save_json_book(data, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write("\n")


def load_casebook(path=CASEBOOK_PATH):
    book = _load_json_book(path, "cases")
    book.setdefault("cases", [])
    book.setdefault("promoted_rules", [])
    return book


def save_casebook(casebook, path=CASEBOOK_PATH):
    _save_json_book(casebook, path)


def _token_key(token):
    """Normalize a rule/case token for pattern matching: board_code
    counts as code; code and bus values compare as numbers; sensor and
    phrase values compare as lowercase words."""
    ttype = token.get("type")
    if ttype == "board_code":
        ttype = "code"
    value = token.get("value")
    if ttype in ("code", "i2c_bus"):
        try:
            value = int(value)
        except (TypeError, ValueError):
            pass
    elif isinstance(value, str):
        value = value.lower()
    return (ttype, value)


def pattern_of(verdict):
    """The pattern a verdict teaches from: the headline rule's token
    when there is one, else the strongest fact in the log itself (the
    sensor code, a missing sensor, a bus, or the panic kind alone)."""
    parsed = verdict.parsed
    token = None
    rule_id = ""
    if verdict.headline is not None:
        token = dict(verdict.headline.rule.get("token", {}))
        rule_id = verdict.headline.rule.get("id", "")
    if not token or token.get("type") is None:
        if parsed.smc_code is not None:
            token = {"type": "code", "value": parsed.smc_code}
        elif parsed.missing_sensors:
            token = {"type": "sensor", "value": parsed.missing_sensors[0]}
        elif parsed.i2c_buses:
            token = {"type": "i2c_bus", "value": parsed.i2c_buses[0]}
        else:
            token = {"type": "family"}
    return {"model_bucket": parsed.model_bucket,
            "family": parsed.family,
            "token": token, "rule_id": rule_id}


def pattern_key(pattern):
    ttype, value = _token_key(pattern.get("token", {}))
    return (pattern.get("model_bucket", "unknown"),
            pattern.get("family", "unknown"), ttype, value)


def _case_pattern(case):
    return {"model_bucket": case.get("model_bucket", "unknown"),
            "family": case.get("family", "unknown"),
            "token": case.get("token", {})}


def save_case(casebook, verdict, winning_part, when=None):
    """Record one real repair in the case book and re-run the
    promotion law. Returns the case dict that was written."""
    when = when or datetime.now(timezone.utc)
    pattern = pattern_of(verdict)
    case = {
        "id": "case-%s-%03d" % (when.strftime("%Y%m%d-%H%M%S"),
                                len(casebook.get("cases", [])) + 1),
        "date": when.strftime("%Y-%m-%d %H:%M:%S +0000"),
        "model_bucket": pattern["model_bucket"],
        "model_name": (verdict.parsed.model_name
                       or verdict.parsed.raw_product or ""),
        "family": pattern["family"],
        "token": pattern["token"],
        "rule_id": pattern["rule_id"],
        "winning_part": winning_part,
        "source": "bench",
    }
    casebook.setdefault("cases", []).append(case)
    refresh_promotions(casebook)
    return case


def _promoted_rule(pattern, part, cures):
    token = dict(pattern.get("token", {}))
    ttype, value = _token_key(token)
    slug = str(value).replace(" ", "-").lower() if value is not None \
        else "family"
    return {
        "id": "bench-%s-%s-%s-%s" % (pattern.get("model_bucket", "?"),
                                     pattern.get("family", "?"),
                                     ttype, slug),
        "models": [pattern.get("model_bucket", "unknown")],
        "family": pattern.get("family", "unknown"),
        "token": token,
        "part": part,
        "confidence": "High",
        "test": ("Proven on this shop's bench: %d repairs with this "
                 "exact panic pattern were cured by fitting %s. Fit a "
                 "known-good one, then run the cure watch past the "
                 "restart window and re-read the phone — no new panic "
                 "may appear." % (cures, part)),
        "source": "own bench — %d cures" % cures,
        "bench_verified": True,
        "cures": cures,
    }


def refresh_promotions(casebook):
    """Recompute the case book's promoted rules from its cases alone.
    This is the whole promotion law in one place (Plan B: a successor
    can rebuild the trusted rules from casebook.json with nothing
    else). Returns the promoted rule list."""
    groups = {}
    for case in casebook.get("cases", []):
        pattern = _case_pattern(case)
        groups.setdefault(pattern_key(pattern), []).append((pattern, case))
    promoted = []
    for key in sorted(groups, key=str):
        entries = groups[key]
        winners = {}
        for _pattern, case in entries:
            part = case.get("winning_part", "")
            winners[part] = winners.get(part, 0) + 1
        if len(winners) != 1:
            continue                      # conflicting winners: no trust
        part, count = next(iter(winners.items()))
        if count < 3:
            continue                      # not enough agreeing cures yet
        promoted.append(_promoted_rule(entries[0][0], part, count))
    casebook["promoted_rules"] = promoted
    return promoted


def pattern_summary(casebook, pattern):
    """Honest standing of one pattern in the case book: how many cures,
    which parts they named, and whether it is bench-proven yet."""
    key = pattern_key(pattern)
    counts = {}
    total = 0
    for case in casebook.get("cases", []):
        if pattern_key(_case_pattern(case)) == key:
            part = case.get("winning_part", "")
            counts[part] = counts.get(part, 0) + 1
            total += 1
    promoted = len(counts) == 1 and total >= 3
    if total == 0:
        text = "No bench cases saved for this pattern yet."
    elif promoted:
        part = next(iter(counts))
        text = ("Bench-proven: %d cures for this pattern, all %s. "
                "The book trusts this pattern now." % (total, part))
    elif len(counts) > 1:
        bits = ["%d cure%s %s" % (n, "s" if n != 1 else "", part.lower())
                for part, n in sorted(counts.items(),
                                      key=lambda kv: -kv[1])]
        text = (", ".join(bits)
                + " — not proven yet: the cures for this pattern "
                  "disagree, so the book does not trust it yet.")
    else:
        part = next(iter(counts))
        text = ("Case saved. %d of 3 agreeing cures for this pattern "
                "so far (all %s) — %d more needed before the book "
                "calls it proven." % (total, part, 3 - total))
    return {"total": total, "counts": counts,
            "promoted": promoted, "text": text}


# ===========================================================================
# DRAFT RULES — drafts.json. Candidates from the AI helper and the web
# watch live here, status "draft", bench_verified false, ALWAYS. The
# matcher never reads this file; a draft can never promote itself. The
# only roads to a trusted rule are the case-book cure law above, or a
# human moving a proven draft into rulebook.json by hand.
# ===========================================================================
def load_drafts(path=DRAFTS_PATH):
    data = _load_json_book(path, "drafts")
    data.setdefault("drafts", [])
    return data


def save_drafts(drafts, path=DRAFTS_PATH):
    _save_json_book(drafts, path)


def save_draft(drafts, draft):
    """Append a candidate to the drafts file. Status is forced to
    "draft" and bench_verified to False here, whatever the caller
    passed — a draft is unproven by construction."""
    draft = dict(draft)
    draft["status"] = "draft"
    draft["bench_verified"] = False
    if not draft.get("id"):
        draft["id"] = "draft-%s-%03d" % (
            datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
            len(drafts.get("drafts", [])) + 1)
    drafts.setdefault("drafts", []).append(draft)
    return draft


def _derived_token(parsed):
    if parsed.smc_code is not None:
        return {"type": "code", "value": parsed.smc_code}
    if parsed.missing_sensors:
        return {"type": "sensor", "value": parsed.missing_sensors[0]}
    if parsed.i2c_buses:
        return {"type": "i2c_bus", "value": parsed.i2c_buses[0]}
    return {"type": "family"}


def ai_draft_from_answer(parsed, ai_text):
    """Shape an AI answer into a draft rule for the pattern it was
    asked about. The part stays 'not named' — the AI's words are kept
    in the note for a human to read, never dressed up as a rule."""
    return {
        "models": [parsed.model_bucket],
        "family": parsed.family,
        "token": _derived_token(parsed),
        "part": "Not named — read the AI note",
        "confidence": "Low",
        "test": ("Unproven AI suggestion. Prove it on the bench before "
                 "trusting it; the case book decides what is true."),
        "source": "AI draft",
        "note": ai_text[:2000],
        "date": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S +0000"),
    }


# ===========================================================================
# THE CURE CHECK + LIVE WATCH. Cure check compares every panic's stamp
# against the repair stamp saved in the case. Live watch polls the
# phone while it stays plugged in: a new panic file appearing, or the
# phone stopping answering, ends the watch as NOT CURED. A clean full
# watch proves only what was observed — no new panic was logged during
# the watch — and the wording never claims more.
# ===========================================================================
@dataclass
class CureResult:
    status: str = "unknown"      # clear | not_cured | proven | unknown
    lines: list = field(default_factory=list)
    post_panics: list = field(default_factory=list)


def cure_check(case, pull_fn=None):
    """Compare the phone's panics against the case's repair stamp."""
    pull_fn = pull_fn or pull_panic_texts
    repair_dt = parse_log_datetime(case.get("date", ""))
    if repair_dt is None:
        return CureResult("unknown", [
            "The saved repair case has no readable date stamp, so "
            "the cure check cannot compare times. Save the case again "
            "from the verdict screen."], [])
    message, items = pull_fn()
    if message:
        return CureResult("unknown", [message], [])
    post = []
    pre_count = 0
    unreadable = 0
    for name, text in items:
        parsed = parse_log_text(text)
        if not parsed.ok:
            continue
        stamp = stamp_of(parsed, name)
        if stamp is None:
            unreadable += 1
            continue
        if stamp > repair_dt:
            post.append((stamp, parsed))
        else:
            pre_count += 1
    if post:
        post.sort(key=lambda item: item[0])
        newest_dt, newest = post[-1]
        return CureResult("not_cured", [
            "NOT CURED YET — a new panic was logged after the repair.",
            "Newest post-repair panic: %s — kind of panic: %s."
            % (newest_dt.strftime("%Y-%m-%d %H:%M"), newest.family),
            "The repair is not proven. Keep hunting, starting from "
            "that newest log."], [p for _dt, p in post])
    lines = [
        "No panic on this phone is dated after the repair "
        "(%d panic%s from before the repair)." % (
            pre_count, "s" if pre_count != 1 else ""),
        "That is half the proof. Start the 3-MINUTE TEST with the "
        "phone plugged in — the cure watch rides the count — to "
        "finish it."]
    if unreadable:
        lines.append("%d log%s had no readable date and could not be "
                     "checked." % (unreadable,
                                   "s" if unreadable != 1 else ""))
    return CureResult("clear", lines, [])


def _panic_signature(name, parsed):
    if parsed.incident:
        return "incident:%s" % parsed.incident
    return "file:%s|%s" % (name, parsed.date)


def live_watch(duration_s, pull_fn=None, poll_s=5.0, sleep_fn=None,
               on_tick=None, should_stop=None):
    """Watch the plugged-in phone for new panics for duration_s
    seconds, polling every poll_s. duration is a parameter so the
    gate can prove the logic in seconds. The face runs the watch
    open-ended: it rides the 3-MINUTE TEST count-up timer, with
    should_stop wired to the timer's STOP, so the watch ends when
    the count ends (duration_s is then just a far-off cap). Ends
    early as NOT CURED on a new panic or on the phone vanishing; a
    clean watch returns CURE PROVEN wording that claims only what
    was observed, with the length actually watched."""
    pull_fn = pull_fn or pull_panic_texts
    sleep_fn = sleep_fn or time.sleep
    message, items = pull_fn()
    if message:
        return CureResult("unknown", [message], [])
    baseline = set()
    for name, text in items:
        parsed = parse_log_text(text)
        if parsed.ok:
            baseline.add(_panic_signature(name, parsed))
    started = time.monotonic()
    while True:
        remaining = duration_s - (time.monotonic() - started)
        if remaining <= 0:
            break
        if should_stop is not None and should_stop():
            break
        if on_tick is not None:
            on_tick(remaining)
        sleep_fn(min(poll_s, remaining))
        message, items = pull_fn()
        if message:
            if message == NO_PHONE_TEXT:
                return CureResult("not_cured", [
                    "NOT CURED — the phone stopped answering during "
                    "the watch.",
                    "It may have rebooted on its own, or the cable "
                    "moved. Reconnect it, read it again, and look for "
                    "a fresh panic log."], [])
            return CureResult("unknown", [
                "The watch could not finish: %s"
                % message.splitlines()[0]], [])
        for name, text in items:
            parsed = parse_log_text(text)
            if not parsed.ok:
                continue
            if _panic_signature(name, parsed) not in baseline:
                return CureResult("not_cured", [
                    "NOT CURED — a new panic was logged during the "
                    "watch.",
                    "Kind of panic: %s. Keep hunting, starting from "
                    "that log." % parsed.family], [parsed])
    return CureResult("proven", [
        "CURE PROVEN.",
        "No new panic logged during the watch (%s, phone plugged in "
        "the whole time)." % _watch_len_text(time.monotonic()
                                             - started),
        "That is what was observed — the watch proves the panics "
        "stopped for that window, nothing more."], [])


def _token_plain(token):
    ttype, value = _token_key(token or {})
    if ttype == "code":
        return "sensor code 0x%x" % value if isinstance(value, int) \
            else "a sensor code"
    if ttype == "sensor":
        return "sensor %s not answering" % value
    if ttype == "i2c_bus":
        return "data bus i2c%s" % value
    if ttype == "phrase":
        return "its log words"
    return "the panic kind alone"


def cure_proof_text(case, book, watch_minutes, proven, when=None):
    """The printable CURE PROOF slip. Carries the shop name, the date,
    the phone MODEL (never a serial, UDID or IMEI — cases never store
    them), the panic in plain words, the part changed, the watch
    length, the result, and the copyright line."""
    when = when or datetime.now(timezone.utc)
    model = (case.get("model_name")
             or BUCKET_NAMES.get(case.get("model_bucket", ""),
                                 case.get("model_bucket", "")))
    plain = family_plain(book, case.get("family", ""))
    panic_line = plain if plain else "Kind of panic: %s" % case.get(
        "family", "")
    lines = [
        "iFixx Phone Repairs",
        "CURE PROOF — PANIC REPAIR",
        "",
        "Date: %s" % when.strftime("%B %d, %Y"),
        "Phone: %s" % model,
        "Panic found: %s (%s)" % (panic_line,
                                  _token_plain(case.get("token", {}))),
        "Part changed: %s" % case.get("winning_part", ""),
        "Watch: %s with the phone plugged in after the repair."
        % _watch_len_text(watch_minutes * 60),
        "Result: %s" % (
            "CURE PROVEN — no new panic logged during the watch."
            if proven else
            "NOT CURED YET — a new panic was logged after the repair."),
        "",
        COPYRIGHT_LINE,
    ]
    return "\n".join(lines) + "\n"


def print_slip(text):
    """Save the slip under cure-proofs/ and, on Windows, send it to
    the printer (the house pattern). Returns (path, printed)."""
    os.makedirs(CURE_PROOFS_DIR, exist_ok=True)
    name = "cure-proof-%s.txt" % datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(CURE_PROOFS_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    printed = False
    if sys.platform.startswith("win"):
        try:
            os.startfile(path, "print")      # noqa: S606 - house pattern
            printed = True
        except (AttributeError, OSError):
            printed = False
    return path, printed


# ===========================================================================
# THE AI HELPER — subordinate by design. Before anything leaves this
# machine the payload is scrubbed by redact_for_ai: the AI receives the
# model bucket, the panic kind, the tokens and scrubbed panic text —
# never a serial number, UDID, IMEI or other long identifier. Every AI
# answer is rendered under AI_BADGE. If the key file is missing or the
# network fails, the answer is a plain-words message — never a crash,
# never a hang, never a silent send.
# ===========================================================================
class AiUnavailable(Exception):
    """Raised with the plain-words message the face should show."""


_RE_IDFIELD_JSON = re.compile(
    r'(?i)("(?:serial|serial_number|serialnumber|udid|imei|incident|'
    r'incident_id|crashreporterkey|crash_reporter_key|deviceid|'
    r'device_id|mlb|ecid)"\s*:\s*")[^"]*(")')
_RE_IDFIELD_PLAIN = re.compile(
    r"(?i)\b(serial|udid|imei|incident|crashreporterkey|ecid)\b"
    r"(\s*[:=]\s*)\S+")
_RE_UDID = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\b")
_RE_UUID = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
_RE_IMEI = re.compile(r"\b\d{15}\b")
_RE_LONG_HEX_ID = re.compile(r"\b[0-9A-Fa-f]{24,}\b")


def redact_for_ai(text):
    """Scrub identifiers out of text headed for the AI: labeled serial
    / UDID / IMEI / incident fields (JSON or plain), UDID and UUID
    shapes, bare 15-digit IMEIs, and bare long hex identifiers.
    0x-prefixed code addresses are part of the diagnosis and stay."""
    if not text:
        return ""
    out = _RE_IDFIELD_JSON.sub(r"\1[removed]\2", text)
    out = _RE_UDID.sub("[removed]", out)
    out = _RE_UUID.sub("[removed]", out)
    out = _RE_IDFIELD_PLAIN.sub(
        lambda m: m.group(1) + m.group(2) + "[removed]", out)
    out = _RE_IMEI.sub("[removed]", out)
    out = _RE_LONG_HEX_ID.sub("[removed]", out)
    return out


def build_ai_payload(parsed, verdict=None):
    """What the AI is allowed to see: model bucket and name, panic
    kind, tokens — and the panic text after redact_for_ai."""
    facts = {
        "model_bucket": parsed.model_bucket,
        "model_name": parsed.model_name,
        "family": parsed.family,
        "families": parsed.families,
        "missing_sensors": parsed.missing_sensors,
        "sensor_code": parsed.smc_code,
        "sensor_code_text": parsed.smc_code_text,
        "i2c_buses": parsed.i2c_buses,
        "board": parsed.board,
    }
    if verdict is not None and verdict.headline is not None:
        facts["book_verdict"] = verdict.headline.rule.get("part")
    return {"facts": facts, "panic_text": redact_for_ai(parsed.panic_string)}


def _read_nvidia_key():
    """Read the NVIDIA key at runtime. Never printed, never logged.
    Returns None when the file or a usable key is missing."""
    try:
        with open(NVIDIA_KEY_PATH, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return None
    match = re.search(r"nvapi-[A-Za-z0-9_\-.]+", raw)
    if match:
        return match.group(0)
    for line in raw.splitlines():
        line = line.strip().strip('"').strip("'")
        if line and not line.startswith("#") and "=" not in line \
                and " " not in line and len(line) >= 20:
            return line
    return None


def _nvidia_provider(payload, kind):
    key = _read_nvidia_key()
    if not key:
        raise AiUnavailable(AI_NOT_SETUP_TEXT)
    if kind == "explain":
        ask = ("Explain this iPhone panic log in plain words a repair "
               "technician can act on: what kind of fault it is, which "
               "part or area it points to first, and the order to test "
               "in. Say clearly what the log does NOT prove.")
    else:
        ask = ("Our rule book has NO match for this iPhone panic log. "
               "Read it and suggest the most likely faulty part and "
               "the hunting order. Say how sure you are and what test "
               "would prove it. If the log does not point anywhere "
               "solid, say so plainly — do not guess.")
    user = ("%s\n\nKnown facts (identifiers removed): %s\n\nPanic "
            "text (identifiers removed):\n%s"
            % (ask, json.dumps(payload["facts"], indent=1),
               payload["panic_text"][:6000]))
    body = {
        "model": NVIDIA_MODEL,
        "messages": [
            {"role": "system",
             "content": "You are a careful phone-repair diagnostic "
                        "assistant. You give hunting orders, not "
                        "certainties. You never invent a part number."},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "max_tokens": 700,
    }
    request = urllib.request.Request(
        NVIDIA_API_URL, data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": "Bearer " + key,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        raise AiUnavailable(AI_OFFLINE_TEXT)
    try:
        text = data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError, AttributeError):
        raise AiUnavailable(AI_OFFLINE_TEXT)
    if not text:
        raise AiUnavailable(AI_OFFLINE_TEXT)
    return text


def ask_ai(kind, parsed, verdict=None, provider=None):
    """Run the AI helper. kind is "ask" (no-match hunting help) or
    "explain" (plain-words reading of any log). Returns the text to
    render: either the plain-words unavailable message, or the badge
    line followed by the AI's answer. The provider is injectable so
    the gate can stub it."""
    payload = build_ai_payload(parsed, verdict)
    provider = provider or _nvidia_provider
    try:
        answer = provider(payload, kind)
    except AiUnavailable as exc:
        return str(exc)
    return AI_BADGE + "\n\n" + answer.strip()


# ===========================================================================
# THE WEB WATCH — CHECK FOR NEW CODES. Fetches the Repair Wiki panic
# guide and the iFixit SMC Panic wiki, pulls code->part lines per
# model out of them, diffs against rulebook.json and drafts.json, and
# writes only NEW candidates into drafts.json — marked with their web
# source, unproven, never live rules.
# ===========================================================================
WEB_SOURCES = [
    ("web — Repair Wiki",
     "https://repair.wiki/w/How_to_Troubleshoot_And_Fix_iPhone_"
     "Random_Restarts_Using_Panic_Logs"),
    ("web — iFixit",
     "https://www.ifixit.com/Wiki/iPhone_SMC_Panic_Assertion_Failed"),
]

_SERIES_BUCKETS = {
    "12 and older": ["le12"], "12 series and older": ["le12"],
    "12": ["le12"],
    "13 pro max": ["13pro"], "13 pro": ["13pro"], "13 mini": ["13mini"],
    "13": ["13", "13mini", "13pro"],
    "14 pro max": ["14pro"], "14 pro": ["14pro"], "14 plus": ["14"],
    "14": ["14"],
    "15 pro max": ["15pro"], "15 pro": ["15pro"], "15 plus": ["15"],
    "15": ["15"],
    "16 pro max": ["16pro"], "16 pro": ["16pro"], "16 plus": ["16"],
    "16": ["16"],
    "17 pro max": ["17pro"], "17 pro": ["17pro"], "17": ["17"],
}
_UNIVERSAL_BUCKETS = ["13", "13mini", "13pro", "14", "14pro", "15",
                      "15pro", "16", "16pro", "17", "17pro"]


def _fetch_url(url):
    request = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (PanicReaderWebWatch)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", "replace")


def _page_lines(page_text):
    import html as html_module
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", page_text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|li|tr|h\d|table|section)>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_module.unescape(text)
    lines = [re.sub(r"\s+", " ", line).strip()
             for line in text.splitlines()]
    return [line for line in lines if line]


def _series_buckets(line):
    """If a text line is a per-model section header ('iPhone 13
    series:', 'iPhone 14 Pro & 14 Pro Max:'), return its buckets."""
    low = line.lower()
    if "iphone" not in low or len(line) > 80:
        return None
    if re.search(r"iphone\s*13\s*(and\s+)?up", low):
        return list(_UNIVERSAL_BUCKETS)
    match = re.search(r"iphone\s*(1[2-7])\s*(pro max|pro|plus|mini)?",
                      low)
    if not match:
        if "12 and older" in low or "12 series and older" in low:
            return ["le12"]
        return None
    key = match.group(1)
    if match.group(2):
        key += " " + match.group(2)
    return _SERIES_BUCKETS.get(key)


def _web_part_clean(part):
    part = part.strip().strip(".").strip()
    if part:
        part = part[0].upper() + part[1:]
    return part


def extract_web_candidates(page_text, source_label):
    """Pull (model buckets x family x token -> part) candidates out of
    a wiki page's text. Two line shapes are read: '0x800 - charging
    port flex' under a model header, and 'mic1 - charging port flex'
    sensor lines. Everything extracted is a candidate, not a fact."""
    candidates = []
    buckets = None
    for line in _page_lines(page_text):
        found = _series_buckets(line)
        if found is not None:
            buckets = found
            continue
        if buckets is None:
            continue
        match = re.match(r"^(0x[0-9a-fA-F]+)\s*(?:\(\d+\))?\s*"
                         r"[-–—:]\s*(.+)$", line)
        if match:
            part = _web_part_clean(match.group(2))
            if part:
                candidates.append({
                    "models": list(buckets), "family": "smc",
                    "token": {"type": "code",
                              "value": int(match.group(1), 16)},
                    "part": part, "confidence": "Low",
                    "test": ("Unproven web candidate. Prove it on the "
                             "bench before trusting it."),
                    "source": source_label})
            continue
        match = re.match(r"^([a-z]{2,4}\d[a-z0-9]?)\s*[-–—:]\s*(.+)$",
                         line)
        if match and match.group(1).lower() in KNOWN_SENSORS:
            part = _web_part_clean(match.group(2))
            if part:
                candidates.append({
                    "models": list(buckets), "family": "any",
                    "token": {"type": "sensor",
                              "value": match.group(1).lower()},
                    "part": part, "confidence": "Low",
                    "test": ("Unproven web candidate. Prove it on the "
                             "bench before trusting it."),
                    "source": source_label})
    return candidates


def _candidate_covered(candidate, book, drafts):
    """A candidate is covered when a live rule or an existing draft
    already carries the same token for an overlapping model and a
    compatible family. (A different part wording for a known code is
    a disagreement for a human to settle in the rule book, not draft
    material.)"""
    ckey = _token_key(candidate.get("token", {}))
    cfam = candidate.get("family", "any")
    cmodels = set(candidate.get("models", []))

    def hit(entry):
        if _token_key(entry.get("token", {})) != ckey:
            return False
        efam = entry.get("family", "any")
        if efam != cfam and efam != "any" and cfam != "any":
            return False
        emodels = set(entry.get("models", []))
        return bool(emodels & cmodels) or "any" in emodels

    return (any(hit(rule) for rule in book.get("rules", []))
            or any(hit(d) for d in drafts.get("drafts", [])))


def check_for_new_codes(book, drafts, fetch=None):
    """Run the web watch. Returns (message, new_drafts). The fetch is
    injectable so the gate runs it offline against saved page copies.
    Drafts are written into the drafts dict (the caller saves it);
    rulebook.json is never touched."""
    fetch = fetch or _fetch_url
    new_drafts = []
    reached = 0
    for label, url in WEB_SOURCES:
        try:
            page = fetch(url)
        except Exception:
            page = ""
        if not page:
            continue
        reached += 1
        for candidate in extract_web_candidates(page, label):
            if _candidate_covered(candidate, book, drafts):
                continue
            new_drafts.append(save_draft(drafts, candidate))
    if reached == 0:
        return ("The web watch could not reach Repair Wiki or "
                "iFixit — no internet right now, or the pages moved. "
                "No drafts were added."), []
    if new_drafts:
        return ("Web watch done: %d new draft code%s saved to "
                "drafts.json — unproven. They are review notes only; "
                "the case book decides what becomes a rule."
                % (len(new_drafts), "s" if len(new_drafts) != 1
                   else "")), new_drafts
    return ("Web watch done: nothing new. Every code on the two "
            "pages is already in the rule book or in drafts."), []


# ===========================================================================
# THE 3-MINUTE BENCH TIMER (v0.4) — a plain stopwatch for the
# classic 3-minute-restart test: swap the suspect part, power the
# phone up, press START, and see whether it runs past 3 minutes
# without restarting. Elapsed time is always computed from a
# monotonic start stamp, never by counting ticks, so the count
# cannot drift. HONESTY: this timer is not linked to the phone in
# any way — it reads nothing from it; it only times the phone
# sitting on the bench, and the face says so under the display.
# ===========================================================================
BENCH_TIMER_TARGET_SECONDS = 180.0
BENCH_TIMER_PAST_TEXT = "PAST 3 MINUTES"
BENCH_TIMER_HONESTY_LINE = ("Times the phone on the bench. "
                            "It does not read the phone.")
# The cure watch rides this one timer (owner's simplification,
# 2026-10-31): there are no watch-length choices on the face. When a
# repair case is saved, starting the count also starts live_watch
# with a far-off cap; the timer's STOP is its should_stop, so the
# watch ends when the count ends.
WATCH_RIDE_MAX_SECONDS = 7 * 24 * 60 * 60
WATCH_RIDE_POLL_SECONDS = 3.0


def format_elapsed(seconds):
    """Seconds -> "M:SS" for the timer display. Past an hour the
    minutes keep counting (3661 -> "61:01"); a bench test never
    needs hours broken out."""
    total = max(0, int(seconds))
    return "%d:%02d" % divmod(total, 60)


class BenchTimer:
    """Count-up bench stopwatch. start() stamps a monotonic start;
    elapsed() is always recomputed from that stamp (plus an optional
    start offset), so a busy GUI can delay a repaint but never the
    count itself. stop() freezes the count where it was; reset()
    returns to zero and clears the past-target state. Starting again
    after a stop or a reset begins a fresh count from zero (plus any
    offset) — the timer never resumes a frozen count."""

    def __init__(self, now_fn=None):
        self._now_fn = now_fn or time.monotonic
        self._started_at = None
        self._offset = 0.0
        self._frozen = 0.0

    @property
    def running(self):
        return self._started_at is not None

    def start(self, now=None, offset=0.0):
        if now is None:
            now = self._now_fn()
        self._started_at = now
        self._offset = float(offset)
        self._frozen = 0.0

    def elapsed(self, now=None):
        if self._started_at is None:
            return self._frozen
        if now is None:
            now = self._now_fn()
        return self._offset + max(0.0, now - self._started_at)

    def past_target(self, now=None):
        return self.elapsed(now) >= BENCH_TIMER_TARGET_SECONDS

    def stop(self, now=None):
        if self._started_at is not None:
            self._frozen = self.elapsed(now)
            self._started_at = None
            self._offset = 0.0
        return self._frozen

    def reset(self):
        self._started_at = None
        self._offset = 0.0
        self._frozen = 0.0


# ===========================================================================
# PART PICTURES — part_images.json maps the rule book's part names to
# real photos in parts-images/. A part with no mapped photo, or whose
# photo file is missing or not a real image, gets the honest empty
# slot: "No picture yet for this part". ARTWORK GATE (owner's call,
# 2026-10-30): the borrowed iFixit starter photos were removed and
# the map stands empty — pictures return only through the ChatGPT
# designer-of-record road or this shop's own bench photos. Never a
# drawing, never a render, never a generated image.
# ===========================================================================
_IMAGE_MAGICS = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8")


def image_bytes_ok(path):
    """True when the file exists and starts with a real image's magic
    bytes (PNG, JPEG or GIF)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return any(head.startswith(magic) for magic in _IMAGE_MAGICS)


def load_part_images(path=PART_IMAGES_PATH):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data.setdefault("images", {})
            data.setdefault("aliases", {})
            return data
    except (OSError, ValueError):
        pass
    return {"images": {}, "aliases": {}}


def part_image_entry(part_name, part_map, images_dir=PARTS_IMAGES_DIR):
    """Resolve a rule's part name to its picture entry, or None when
    the honest empty slot should show. The entry dict carries the
    file path plus label/source/credit from the map."""
    if not part_map:
        return None
    key = part_map.get("aliases", {}).get(part_name)
    if not key:
        return None
    entry = part_map.get("images", {}).get(key)
    if not entry or not entry.get("file"):
        return None
    path = os.path.join(images_dir, entry["file"])
    if not image_bytes_ok(path):
        return None
    resolved = dict(entry)
    resolved["key"] = key
    resolved["path"] = path
    return resolved


def validate_part_images(part_map, images_dir=PARTS_IMAGES_DIR):
    """Check every entry in the picture map: its file must exist, be
    a real image, and carry a source string. Returns a list of
    problem strings (empty when the map is clean)."""
    problems = []
    for key, entry in part_map.get("images", {}).items():
        if not entry.get("source"):
            problems.append("%s: no source recorded" % key)
        path = os.path.join(images_dir, entry.get("file", ""))
        if not os.path.isfile(path):
            problems.append("%s: file missing (%s)"
                            % (key, entry.get("file", "")))
        elif not image_bytes_ok(path):
            problems.append("%s: file is not a real image (%s)"
                            % (key, entry.get("file", "")))
    for part_name, key in part_map.get("aliases", {}).items():
        if key not in part_map.get("images", {}):
            problems.append("alias %r points at unknown picture %r"
                            % (part_name, key))
    return problems


# ===========================================================================
# SELF-UPDATE (house pattern, v1.2) — analyze-that-part-version.json
# on the same shelf as the other shop apps (the Phone Checker
# donor's pattern, adapted to this app's os.path/SCRIPT_DIR idiom).
# A download is installed only after size AND SHA-256 match the
# manifest; a helper script performs the swap after this process
# exits and rolls back if the new version fails to start. The
# manifest is NOT published yet — the door says so honestly.
# ===========================================================================

SHELF_BASE = ("https://raw.githubusercontent.com/ifixrepairs/"
              "popup-blocker/main/")
UPDATE_MANIFEST_URL = SHELF_BASE + "analyze-that-part-version.json"
UPDATE_ALIVE_SECONDS = 30  # new version must stay alive this long
                            # (the AdTrapper lesson, 2026-11-05: a
                            # 10-second window rolled good updates
                            # back twice in the live proof, so the
                            # helper now polls through 30 seconds)

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
        waited = 0.0
        while waited < alive_secs and proc.poll() is None:
            time.sleep(0.5)
            waited += 0.5
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


def _version_tuple(text):
    parts = []
    for chunk in str(text).strip().split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def _version_newer(remote, local):
    r, l = _version_tuple(remote), _version_tuple(local)
    n = max(len(r), len(l))
    r += (0,) * (n - len(r))
    l += (0,) * (n - len(l))
    return r > l


def _fetch_bytes(url, timeout=20):
    req = urllib.request.Request(url, headers={
        "User-Agent": "AnalyzeThatPart/%s" % VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_update_info(fetch=None):
    """Latest manifest dict, or None when the shelf has none yet
    (analyze-that-part-version.json is published with the first
    shelf build) or the fetch failed — the door answers in plain
    words either way, never a crash."""
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
    return bool(info) and _version_newer(info["version"], VERSION)


def download_update(info, dest_dir, fetch=None):
    """Download the offered build and verify it against the manifest.
    Returns (path, error) -- exactly one of the two is set. The file
    is installed ONLY when size AND SHA-256 both match."""
    fetch = fetch or _fetch_bytes
    # The contract is size AND SHA-256: a manifest missing either
    # field is refused outright -- a tampered or malformed manifest
    # must never silently disable the only integrity gate the
    # updater has.
    if info.get("size") is None or not info.get("sha256"):
        return None, ("manifest is missing its size or SHA-256 -- "
                      "refusing to install an unverified download")
    try:
        data = fetch(info["url"], timeout=120)
    except Exception as e:
        return None, "download failed (%s)" % e
    if len(data) != int(info["size"]):
        return None, ("size mismatch (got %d, manifest says %s)"
                      % (len(data), info["size"]))
    digest = hashlib.sha256(data).hexdigest()
    if digest.lower() != str(info["sha256"]).lower():
        return None, "SHA-256 mismatch -- download discarded"
    dest = Path(dest_dir) / ("PanicReader-v%s.pyw" % info["version"])
    dest.write_bytes(data)
    return dest, None


def _current_program_path():
    """The running program file the helper should swap: argv[0]
    resolved (the .bat, the .command and the Mac bundle all launch
    this file directly), falling back to this file itself."""
    try:
        p = Path(sys.argv[0]).resolve()
        if p.is_file():
            return p
    except Exception:
        pass
    return Path(__file__).resolve()


def begin_update(current_path, downloaded, to_version, from_version):
    """Hand the swap to the helper script and let this process exit.
    The helper waits for us to die, swaps, relaunches, and rolls
    back if the new build does not stay alive."""
    current_path = Path(current_path)
    helper = current_path.parent / "_analyze_update_helper.py"
    helper.write_text(UPDATE_HELPER_SRC, encoding="utf-8")
    backup = current_path.with_suffix(current_path.suffix + ".bak")
    result = current_path.parent / "_analyze_update_result.json"
    python_exe = sys.executable or "python"
    args = [python_exe, str(helper), str(os.getpid()),
            str(current_path), str(downloaded), str(current_path),
            str(backup), str(result), python_exe,
            str(UPDATE_ALIVE_SECONDS), str(from_version),
            str(to_version)]
    subprocess.Popen(args, close_fds=True)


# ===========================================================================
# THE FACE — one screen. Big buttons up top, the verdict in the biggest
# print with the part's picture beside it, then how to prove it, then
# what fixed it, then the cure check and the live watch, then what
# else it could be, then the small print of what the log says.
# ===========================================================================

# ===========================================================================
# FACE STYLE — THE ONE STYLE BLOCK (v0.4 plain re-skin; v0.5
# aligns the layout to the board as drawn — same block).
#
# Design of record: ChatGPT (owner's artwork law), the second board
# "Panic Reader UI Design Board" (plain) + its written spec, applied
# 2026-10-31. The owner rejected the first, glossy board as
# cartoonish and set the bar in his own words: "simple professional"
# — flat colors, plain dark background, no gradients, no glow, no
# decorative artwork. (The board's bottom palette/spec strip is the
# builder's measuring tape; it is NOT part of the app and is never
# rendered.) EVERY color, font and spacing the face uses is defined
# HERE and nowhere else: a future skin swap edits this block only.
# Wording, button order and behavior are NOT style and do not
# change with the skin.
#
# tkinter honesty note: tkinter has no true rounded corners and no
# semibold weight. The spec's 6px corners are approximated with
# flat relief, 1px borders in BORDER_COLOR and the padding
# constants below; semibold is approximated with bold. No
# dependencies were added for looks.
#
# Color law from the spec: ACCENT is the single normal accent.
# GREEN and RED are reserved for real outcomes (cure proven / not
# cured, the timer's past-3-minutes flip, the ready dot) and AMBER
# for the file door and caution (no-match, status) — never
# decoration. The verdict part name is NOT an outcome color: the
# board draws it in primary text white, and since v0.5 so does the
# face (the owner's "like this" ruling, 2026-10-31).
#
# v0.6 — the compact window (the owner's order, 2026-10-31: "To
# big make it smaller look at all that extra room that you're
# leaving that when I put it on my computer, it's gonna take up
# the whole screen"). The window's size lives here too: the
# default geometry below is the MEASURED natural fit of the idle
# face at the spec's own type sizes — no expand slack anywhere,
# and the "What the log says" box is a fixed LOG_LINES tall in
# every state. When a verdict (or a cure result) makes the
# content genuinely taller than the window, the window grows to
# fit it (WIN_FIT_MARGIN of headroom) rather than clipping or
# scrolling; it never shrinks on its own, and the owner can
# always drag it bigger or smaller by hand.
#
# v0.7 — two screens that swap (the owner's approval,
# 2026-10-31: "Ok build it", on the pitch: "two screens that
# swap. The first screen is just the top, title and the four
# doors, like the left picture, small and clean. When you read
# a phone, the verdict screen takes its place, with the picture
# spot, the timer, and the AI, all still there. Nothing added,
# nothing dropped, the same words."). Screen A (home) carries
# only the title, the caps subtitle, the four doors and the
# bottom status line, and opens at its own compact size below
# (WIN_HOME_*). Screen B (working) carries everything the
# one-screen face carried below the doors, in the same words
# and order, behind the board's own "New Scan" button; it takes
# the window at WIN_WIDTH wide and the v0.6 fit height for its
# content. Per-screen geometry is style, so it lives here.
#
# v0.8 — ONE PAGE AGAIN (the owner killed the swap the same
# morning, 2026-10-31, replying to the v0.7 home-screen
# picture, verbatim: "I don't like the second page just put
# this one on the front page. Just put a timer and AI"). The
# page IS the v0.7 home face — title, caps subtitle, the four
# doors, the bottom status line — with the 3-MINUTE TEST timer
# and the AI row added ON THE FRONT PAGE, right under the
# doors, always visible; a read's result shows on this same
# page below them. There is no second page and no "New Scan"
# button. The WIN_HOME_* tokens are gone: the one page opens
# WIN_WIDTH wide and as tall as its measured idle fit (the
# v0.6 mechanics — natural heights, no expand slack, the
# window grows only to fit a real result). The front-page
# element order is the build order in main(): title block,
# doors, status line, then inside the panel the timer, the AI
# row, the verdict block, Cure check, the log box, and last
# the honesty footer and the bottom status line.
#
# v0.9 — THE OWNER'S WORDS, TO THE LETTER (2026-10-31: "Make
# it the one on the left and just make it smaller. Don't add
# anything else." / "I don't like the second page just put
# this one on the front page. Just put a timer and AI" /
# "Follow my directions and what I said go back and read what
# I said and follow the directions."). The front page AT REST
# is the v0.7 home face + the timer + the AI row and NOTHING
# else: title, caps subtitle, the four doors, the 3-MINUTE
# TEST, the AI row + badge, the bottom status line. The
# verdict block, the picture spot, the cure block, the log
# box and the honesty footer are NOT on the page at rest —
# not even as empty slots. They live in a result area that is
# unmapped until a result exists; a result maps it below the
# AI row on this same page and the window grows to fit it
# (the v0.6 mechanics), and a fresh read clears it back to
# the at-rest inventory. The window opens at the measured fit
# of the at-rest inventory ALONE — that fit is the size law
# now, and the minimum window height is that same fit, so
# the front page always shows whole.
# ===========================================================================
BG_APP = "#0B0F14"          # window background
BG_PANEL = "#151B23"        # main panels
BG_RAISED = "#1E2833"       # raised surfaces (secondary buttons, frame)
BORDER_COLOR = "#2A3440"    # panel / button borders
FG_TEXT = "#F5F7FA"         # primary text
FG_DIM = "#A7B3C2"          # secondary text
ACCENT = "#2F80ED"          # the single normal accent (primary blue)
GOOD = "#22C55E"            # outcome green (cure proven, timer flip)
BAD = "#E53935"             # not-cured red (outcomes only; kept from v0.3)
WARN = "#F2B300"            # amber (file door fill, caution)
GOLD = WARN                 # legacy name; the old gold is the amber now
FG_ON_ACCENT = "#FFFFFF"    # text on the blue accent
FG_ON_AMBER = BG_APP        # dark text on the amber door (board: bold dark)
BTN_FACE = FG_TEXT          # v1.1 writing fix: button faces — macOS Aqua
                            # paints a Button's face light and ignores its
                            # bg, so every button now carries the light
                            # face in code too, on every platform
BTN_TEXT = FG_ON_AMBER      # v1.1: button titles — the amber door's dark
                            # on that light face (the pairing that read)
BTN_TEXT_DISABLED = "#54657A"  # v1.1: disabled button titles on BTN_FACE
NEG_BG = "#7E2A2A"          # restrained dark red (serious negative)

FONT_FAMILY = "Segoe UI"    # system sans fallback where Segoe UI is absent
FONT_TITLE = (FONT_FAMILY, 48, "bold")     # app title
FONT_SUBTITLE = (FONT_FAMILY, 18, "bold")  # the board's caps subtitle
FONT_PART = (FONT_FAMILY, 40, "bold")      # verdict part name
FONT_MAIN_BTN = (FONT_FAMILY, 24, "bold")  # the two door buttons
FONT_HEAD = (FONT_FAMILY, 22, "bold")      # section headings (semibold)
FONT_BODY = (FONT_FAMILY, 18)              # body text
FONT_BODY_BOLD = (FONT_FAMILY, 18, "bold")
FONT_CTRL = (FONT_FAMILY, 18, "bold")      # secondary controls (semibold)
FONT_META = (FONT_FAMILY, 16)              # small / secondary text
FONT_LOG = ("Consolas", 14)                # log text, monospace
FONT_TIMER = ("Consolas", 40, "bold")      # timer display, monospace

PAD_WINDOW = 24             # window padding
PAD_PANEL = 24              # panel internal padding
GAP_SECTION = 24            # space between sections
GAP_CONTROL = 16            # space between controls
MAIN_BTN_MIN_H = 80         # main button height (px, approx.)
SECONDARY_BTN_MIN_H = 56    # secondary button height (px, approx.)
PIC_AREA = 340              # part picture area (px, approx. square)
LOG_LINES = 8               # "What the log says" height, in lines (fixed)
WIN_WIDTH = 1080            # the one page's window width (px)
WIN_FIT_MARGIN = 20         # headroom added when the window grows to fit


def main():
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext

    try:
        book = load_rulebook()
        book_error = ""
    except RulebookError as exc:
        book = None
        book_error = str(exc)
    casebook = load_casebook()
    drafts_data = load_drafts()
    part_map = load_part_images()

    root = tk.Tk()
    root.title("%s v%s" % (WORKING_TITLE, VERSION))
    root.configure(bg=BG_APP)
    # v0.8: ONE page. The window opens WIN_WIDTH wide; its height
    # is set to the page's measured idle fit at the end of main()
    # (the placeholder height here is replaced before the window
    # is ever shown).
    root.geometry("%dx%d" % (WIN_WIDTH, 1000))
    root.minsize(960, 1000)

    # The one page (v0.8). Everything lives on this single frame,
    # in the order it is built below.
    page = tk.Frame(root, bg=BG_APP)
    page.pack(fill="x")

    work = queue.Queue()
    state = {"verdict": None, "case": None, "ai_text": "",
             "cure": None, "watch_minutes": 0, "photo": None}
    if casebook.get("cases"):
        # The latest saved repair, so a cure check can run right after
        # the app is reopened — until a new verdict is read this
        # session, which clears it (a different phone may be read).
        state["case"] = casebook["cases"][-1]

    title = tk.Label(page, text="ANALYZE THAT PART", bg=BG_APP,
                     fg=FG_TEXT, font=FONT_TITLE)
    title.pack(pady=(12, 0))
    # The board's caps subtitle, as drawn — it replaces the long
    # explanatory sentence (the owner's "like this" ruling,
    # 2026-10-31).
    sub = tk.Label(page,
                   text="READS IPHONE PANIC LOGS AND NAMES THE PART "
                        "MOST LIKELY FAULTY",
                   bg=BG_APP, fg=FG_DIM, font=FONT_SUBTITLE,
                   wraplength=900, justify="center")
    sub.pack(pady=(6, 12))

    btn_row = tk.Frame(page, bg=BG_APP)
    btn_row.pack(fill="x", padx=PAD_WINDOW)
    btn_row2 = tk.Frame(page, bg=BG_APP)
    btn_row2.pack(fill="x", padx=PAD_WINDOW, pady=(GAP_CONTROL, 0))

    # (The big status line lives INSIDE the panel now, as the
    # result area's first strip under the AI row — v0.9. It is
    # created with the panel widgets below; the result-area
    # block at the end of main() owns when it is on the page.
    # The bottom status line at the foot of the page (version +
    # Ready. / Working…) mirrors the doors.)

    panel = tk.Frame(page, bg=BG_PANEL,
                     highlightbackground=BORDER_COLOR,
                     highlightthickness=1)
    # Natural height only (v0.6): the panel sizes to its content.
    # It used to expand to fill the window, which stretched the
    # face into dead voids whenever the window stood taller than
    # the content.
    panel.pack(fill="x", padx=PAD_WINDOW,
               pady=(GAP_CONTROL, GAP_CONTROL))

    # (The bottom status line — version + Ready. — is built at
    # the very end of main(), so it closes the page below the
    # honesty footer, as a bottom line should.)

    # 3-MINUTE TEST — the face's ONE timer (v0.4, the owner's asks:
    # "a built in timer you press start and you see if it goes past
    # 3 minutes", then "just put live timer to hit start one count",
    # then "No 3 different timers"). Hit START and it counts up
    # live — that is the whole interaction. While it counts, the
    # button reads STOP; START again after a stop begins a fresh
    # count from 0:00 (there is no separate RESET). At 3:00 the
    # display flips green with PAST 3 MINUTES and keeps counting.
    # The count-up itself is a plain bench stopwatch: it reads
    # nothing from the phone, and the line under the display says
    # exactly that. Riding on the same control: when a repair case
    # has been saved (WHAT FIXED IT), START also starts the cure
    # watch's panic monitoring and STOP ends it, producing the cure
    # verdict below — the watch has no other face control and no
    # length choices. The status line says when the watch is
    # riding.
    timer_head = tk.Label(panel, text="3-MINUTE TEST", bg=BG_PANEL,
                          fg=ACCENT, font=FONT_HEAD, anchor="w")
    timer_head.pack(fill="x", padx=PAD_PANEL, pady=(GAP_SECTION, 0))
    timer_row = tk.Frame(panel, bg=BG_PANEL)
    timer_row.pack(fill="x", padx=PAD_PANEL, pady=(4, 0))
    timer_time = tk.Label(timer_row, text="0:00", bg=BG_PANEL,
                          fg=FG_TEXT, font=FONT_TIMER, anchor="w")
    timer_time.pack(side="left")
    timer_btn = tk.Button(timer_row, text="START",
                          bg=BTN_FACE, fg=BTN_TEXT,
                          activebackground=BTN_FACE,
                          activeforeground=BTN_TEXT,
                          font=FONT_CTRL, relief="flat",
                          highlightbackground=BORDER_COLOR,
                          highlightthickness=1,
                          cursor="hand2")
    timer_btn.pack(side="left", padx=(GAP_CONTROL, GAP_CONTROL),
                   ipady=5)
    timer_past = tk.Label(timer_row, text="", bg=BG_PANEL, fg=GOOD,
                          font=FONT_HEAD, anchor="w")
    timer_past.pack(side="left", padx=(GAP_CONTROL, 0))
    timer_note = tk.Label(panel, text=BENCH_TIMER_HONESTY_LINE,
                          bg=BG_PANEL, fg=FG_DIM, font=FONT_META,
                          wraplength=920, justify="left", anchor="w")
    timer_note.pack(fill="x", padx=PAD_PANEL, pady=(2, 0))

    bench_timer = BenchTimer()
    timer_after = {"id": None}
    # The cure watch riding the current count, if any:
    # {"case": the saved case, "stop": Event, "applied": bool}.
    watch_ride = {"current": None}

    def render_timer():
        elapsed = bench_timer.elapsed()
        timer_time.configure(text=format_elapsed(elapsed))
        if bench_timer.past_target():
            timer_time.configure(fg=GOOD)
            timer_past.configure(text=BENCH_TIMER_PAST_TEXT)
        else:
            timer_time.configure(fg=FG_TEXT)
            timer_past.configure(text="")

    def halt_timer_tick():
        if timer_after["id"] is not None:
            try:
                root.after_cancel(timer_after["id"])
            except Exception:
                pass
            timer_after["id"] = None

    def timer_tick():
        timer_after["id"] = None
        if not bench_timer.running:
            return
        render_timer()
        timer_after["id"] = root.after(100, timer_tick)

    def do_timer_toggle():
        if bench_timer.running:
            bench_timer.stop()
            halt_timer_tick()
            timer_btn.configure(text="START")
            render_timer()
            ride = watch_ride["current"]
            if ride is not None and not ride["applied"]:
                # STOP ends the watch too: signal it, and its
                # verdict lands through the result queue within a
                # poll cycle.
                ride["stop"].set()
                set_status(
                    "Count stopped — finishing the cure watch…")
            else:
                set_status("")
            return
        # Gate affordance only: the gate may start the count
        # part-way so the past-3-minutes flip is proven without a
        # real 3-minute sit. On the bench the variable is never set
        # and the count starts at 0:00.
        offset = 0.0
        raw = os.environ.get(
            "PANIC_READER_TIMER_START_OFFSET_SECONDS")
        if raw:
            try:
                offset = max(0.0, float(raw))
            except ValueError:
                offset = 0.0
        bench_timer.start(offset=offset)
        timer_btn.configure(text="STOP")
        render_timer()
        halt_timer_tick()
        timer_after["id"] = root.after(100, timer_tick)
        # The cure watch rides the count when a repair case has
        # been saved — the same precondition the old START WATCH
        # had (there is nothing to prove without a recorded
        # repair). Without a case the count is the plain bench
        # timer and no cure verdict is produced.
        case = state["case"]
        if case is not None:
            ride = {"case": case, "stop": threading.Event(),
                    "applied": False}
            watch_ride["current"] = ride

            def watch_worker(ride=ride):
                result = live_watch(
                    WATCH_RIDE_MAX_SECONDS,
                    poll_s=WATCH_RIDE_POLL_SECONDS,
                    should_stop=ride["stop"].is_set)
                work.put(("watch", result, ride))
            threading.Thread(target=watch_worker, daemon=True).start()
            set_status(
                "Count running — the cure watch is riding the "
                "timer. STOP ends both.")
        else:
            watch_ride["current"] = None
            set_status(
                "Count running — timer only. No saved repair "
                "case, so no cure watch is riding.")

    timer_btn.configure(command=do_timer_toggle)

    ai_row = tk.Frame(panel, bg=BG_PANEL)
    ai_row.pack(fill="x", padx=PAD_PANEL, pady=(GAP_CONTROL, 0))
    ask_ai_btn = tk.Button(ai_row, text="ASK THE AI", bg=BTN_FACE,
                           fg=BTN_TEXT, activebackground=BTN_FACE,
                           activeforeground=BTN_TEXT,
                           disabledforeground=BTN_TEXT_DISABLED,
                           font=FONT_CTRL, relief="flat",
                           highlightbackground=BORDER_COLOR,
                           highlightthickness=1,
                           cursor="hand2", state="disabled")
    ask_ai_btn.pack(side="left", padx=(0, GAP_CONTROL), ipady=5)
    explain_btn = tk.Button(ai_row, text="EXPLAIN THIS LOG",
                            bg=BTN_FACE, fg=BTN_TEXT,
                            activebackground=BTN_FACE,
                            activeforeground=BTN_TEXT,
                            disabledforeground=BTN_TEXT_DISABLED,
                            font=FONT_CTRL, relief="flat",
                            highlightbackground=BORDER_COLOR,
                            highlightthickness=1,
                            cursor="hand2", state="disabled")
    explain_btn.pack(side="left", padx=(0, GAP_CONTROL), ipady=5)
    draft_btn = tk.Button(ai_row, text="SAVE AI ANSWER AS DRAFT",
                          bg=BTN_FACE, fg=BTN_TEXT,
                          activebackground=BTN_FACE,
                          activeforeground=BTN_TEXT,
                          disabledforeground=BTN_TEXT_DISABLED,
                          font=FONT_CTRL, relief="flat",
                          highlightbackground=BORDER_COLOR,
                          highlightthickness=1,
                          cursor="hand2", state="disabled")
    draft_btn.pack(side="left", ipady=5)
    # The honesty badge rides on its own line under the AI buttons:
    # at the plain spec's control size the three buttons plus the
    # badge no longer fit one row, and the badge must never be the
    # thing that gets clipped. Same words, same place in the order.
    tk.Label(panel, text="AI answers are unproven.", bg=BG_PANEL,
             fg=FG_DIM, font=FONT_META, anchor="w").pack(
        fill="x", padx=PAD_PANEL, pady=(2, 0))

    # The big status line (v0.9): the result area's first strip,
    # directly under the AI row inside the panel. Every door's
    # result is announced here, and the timer's own lines land
    # here too. It is packed here only so the result-area block
    # at the end of main() can record its place — that block
    # unmaps it at rest and maps it whenever it has something
    # to say.
    status = tk.Label(panel, text="", bg=BG_PANEL, fg=WARN,
                      font=FONT_BODY_BOLD, wraplength=960,
                      justify="center")
    status.pack(fill="x", padx=PAD_PANEL, pady=(GAP_SECTION, 0))

    # Verdict row: the part's picture on the left, the verdict words
    # on the right.
    verdict_row = tk.Frame(panel, bg=BG_PANEL)
    verdict_row.pack(fill="x", padx=PAD_PANEL, pady=(PAD_PANEL, 0))
    pic_frame = tk.Frame(verdict_row, bg=BG_RAISED, width=PIC_AREA,
                         height=PIC_AREA,
                         highlightbackground=BORDER_COLOR,
                         highlightthickness=1)
    pic_frame.pack(side="left", padx=(0, PAD_PANEL))
    pic_frame.pack_propagate(False)
    pic_label = tk.Label(pic_frame, bg=BG_RAISED, fg=FG_DIM,
                         text="The part's picture shows here once a "
                              "log names a part",
                         font=FONT_BODY_BOLD, wraplength=308,
                         justify="center")
    pic_label.place(relx=0.5, rely=0.5, anchor="center")
    verdict_col = tk.Frame(verdict_row, bg=BG_PANEL)
    verdict_col.pack(side="left", fill="both", expand=True)
    verdict_label = tk.Label(verdict_col, text="No log read yet",
                             bg=BG_PANEL, fg=FG_TEXT,
                             font=FONT_PART,
                             wraplength=600, justify="left", anchor="w")
    verdict_label.pack(pady=(6, 4), fill="x")
    conf_label = tk.Label(verdict_col, text="", bg=BG_PANEL, fg=FG_TEXT,
                          font=FONT_META,
                          wraplength=560, justify="left", anchor="w")
    conf_label.pack(fill="x")
    tally_label = tk.Label(verdict_col, text="", bg=BG_PANEL, fg=FG_DIM,
                           font=FONT_META, wraplength=560,
                           justify="left", anchor="w")
    tally_label.pack(pady=(2, 4), fill="x")
    pic_credit = tk.Label(verdict_col, text="", bg=BG_PANEL, fg=FG_DIM,
                          font=FONT_META, wraplength=560,
                          justify="left", anchor="w")
    pic_credit.pack(fill="x")

    prove_head = tk.Label(panel, text="", bg=BG_PANEL, fg=ACCENT,
                          font=FONT_HEAD, anchor="w")
    prove_head.pack(fill="x", padx=PAD_PANEL, pady=(GAP_SECTION, 0))
    prove_text = tk.Label(panel, text="", bg=BG_PANEL, fg=FG_TEXT,
                          font=FONT_BODY, wraplength=920,
                          justify="left", anchor="w")
    prove_text.pack(fill="x", padx=PAD_PANEL, pady=(2, 0))

    also_head = tk.Label(panel, text="", bg=BG_PANEL, fg=ACCENT,
                         font=FONT_HEAD, anchor="w")
    also_head.pack(fill="x", padx=PAD_PANEL, pady=(GAP_SECTION, 0))
    also_text = tk.Label(panel, text="", bg=BG_PANEL, fg=FG_TEXT,
                         font=FONT_BODY, wraplength=920,
                         justify="left", anchor="w")
    also_text.pack(fill="x", padx=PAD_PANEL, pady=(2, 0))

    fix_head = tk.Label(panel, text="", bg=BG_PANEL, fg=ACCENT,
                        font=FONT_HEAD, anchor="w", wraplength=920,
                        justify="left")
    fix_head.pack(fill="x", padx=PAD_PANEL, pady=(GAP_SECTION, 0))
    fix_box = tk.Frame(panel, bg=BG_PANEL)
    fix_box.pack(fill="x", padx=PAD_PANEL, pady=(4, 0))
    fix_status = tk.Label(panel, text="", bg=BG_PANEL, fg=GOOD,
                          font=FONT_BODY_BOLD, wraplength=920,
                          justify="left", anchor="w")
    fix_status.pack(fill="x", padx=PAD_PANEL, pady=(4, 0))

    cure_head = tk.Label(panel, text="Cure check", bg=BG_PANEL,
                         fg=ACCENT, font=FONT_HEAD,
                         anchor="w")
    cure_head.pack(fill="x", padx=PAD_PANEL, pady=(GAP_SECTION, 0))
    # The cure section's two standing texts (construction and
    # startup both use these, word for word as the face has
    # always carried them).
    CURE_TEXT_DEFAULT = (
        "After a repair: tap WHAT FIXED IT on the verdict, plug "
        "the phone back in, and run CURE CHECK (top). Then "
        "start the 3-MINUTE TEST below — the cure watch rides "
        "the count, and a clean count earns the printable cure "
        "proof.")

    def saved_case_text(case):
        return ("A saved repair is on the book: %s on %s. Plug "
                "that phone in and run CURE CHECK (top), then "
                "start the 3-MINUTE TEST — the cure watch rides "
                "the count."
                % (case.get("winning_part", ""),
                   case.get("model_name", "")))

    cure_text = tk.Label(
        panel, text=CURE_TEXT_DEFAULT,
        bg=BG_PANEL, fg=FG_TEXT, font=FONT_BODY, wraplength=920,
        justify="left", anchor="w")
    cure_text.pack(fill="x", padx=PAD_PANEL, pady=(2, 0))
    # This row holds only PRINT CURE PROOF now. The live watch has
    # no controls of its own anymore (owner's simplification,
    # 2026-10-31: "No 3 different timers") — the 5/12/30 length
    # radios and the START WATCH button are gone; the watch rides
    # the one 3-MINUTE TEST timer above (front page, v0.8).
    watch_row = tk.Frame(panel, bg=BG_PANEL)
    watch_row.pack(fill="x", padx=PAD_PANEL, pady=(GAP_CONTROL, 0))
    print_btn = tk.Button(watch_row, text="PRINT CURE PROOF",
                          bg=BTN_FACE, fg=BTN_TEXT,
                          activebackground=BTN_FACE,
                          activeforeground=BTN_TEXT,
                          disabledforeground=BTN_TEXT_DISABLED,
                          font=FONT_CTRL, relief="flat",
                          highlightbackground=BORDER_COLOR,
                          highlightthickness=1,
                          cursor="hand2", state="disabled")
    print_btn.pack(side="left", ipady=5)

    facts_head = tk.Label(panel, text="What the log says", bg=BG_PANEL,
                          fg=ACCENT, font=FONT_HEAD,
                          anchor="w")
    facts_head.pack(fill="x", padx=PAD_PANEL, pady=(GAP_SECTION, 0))
    facts_box = scrolledtext.ScrolledText(
        panel, height=LOG_LINES, bg=BG_APP, fg=FG_DIM, font=FONT_LOG,
        wrap="word", relief="flat", highlightbackground=BORDER_COLOR,
        highlightthickness=1, insertbackground=FG_TEXT)
    # Fixed modest height (v0.6), the same in every state, with
    # its scrollbar for longer logs. It used to expand to fill
    # whatever height the window had going spare — the cavern.
    facts_box.pack(fill="x", padx=PAD_PANEL, pady=(4, PAD_PANEL))
    facts_box.configure(state="disabled")

    def fit_to_content():
        """Grow the window if the page's content outgrew it (v0.6).

        The page opens at its measured idle fit. A verdict — or a
        cure result landing in the cure text — can make it
        genuinely taller; when it does, the window grows to the
        content's requested height plus a margin rather than
        clipping the bottom or scrolling the column. It never
        shrinks the window, and a size the owner dragged by hand
        is left alone unless the content outgrows it.
        """
        root.update_idletasks()
        need = root.winfo_reqheight()
        if need > root.winfo_height():
            root.geometry("%dx%d" % (root.winfo_width(),
                                     need + WIN_FIT_MARGIN))

    def set_facts(lines):
        facts_box.configure(state="normal")
        facts_box.delete("1.0", "end")
        facts_box.insert("end", "\n".join(lines))
        facts_box.configure(state="disabled")

    def set_picture(part_name, empty_text=None):
        entry = part_image_entry(part_name, part_map) if part_name \
            else None
        if entry is not None:
            try:
                photo = tk.PhotoImage(file=entry["path"])
            except tk.TclError:
                photo = None
            if photo is not None:
                state["photo"] = photo
                pic_label.configure(image=photo, text="")
                pic_credit.configure(
                    text="%s\n%s" % (entry.get("label", ""),
                                      entry.get("credit", "")))
                return
        state["photo"] = None
        pic_label.configure(image="", text=empty_text or NO_PICTURE_TEXT)
        pic_credit.configure(text="")

    def set_busy(busy):
        mode = "disabled" if busy else "normal"
        for btn in (read_btn, file_btn, cure_btn, web_btn):
            btn.configure(state=mode)
        # The bottom status line's right side mirrors the doors:
        # amber "Working…" while a door is working, the board's
        # green dot and "Ready." whenever the app is idle.
        if busy:
            state_dot.configure(fg=WARN)
            state_text.configure(text="Working…")
        else:
            state_dot.configure(fg=GOOD)
            state_text.configure(text="Ready.")

    def rebuild_fix_buttons(parts):
        for child in fix_box.winfo_children():
            child.destroy()
        if state["verdict"] is None or not state["verdict"].parsed.ok:
            return
        fix_head.configure(
            text="WHAT FIXED IT?  (tap the part that cured it — "
                 "this teaches the book)")
        seen = []
        for part in parts:
            if part and part not in seen:
                seen.append(part)
        labels = []
        for part in seen[:4]:
            label = part if len(part) <= 36 else part[:35] + "\u2026"
            labels.append((label, part))
        labels.append(("Something else…", None))
        # At the spec's control size the row can be wider than the
        # panel; flow the buttons onto a second row rather than
        # clipping the last one. Measured with the real font, so it
        # wraps only when the face genuinely runs out of room.
        from tkinter import font as tkfont
        measure = tkfont.Font(font=FONT_CTRL)
        avail = 946  # panel inner width at the default window size
        row = tk.Frame(fix_box, bg=BG_PANEL)
        row.pack(fill="x")
        used = 0
        for label, part in labels:
            width = measure.measure(label) + 28 + GAP_CONTROL
            if used and used + width > avail:
                row = tk.Frame(fix_box, bg=BG_PANEL)
                row.pack(fill="x", pady=(4, 0))
                used = 0
            used += width
            if part is None:
                btn = tk.Button(row, text=label,
                                bg=BTN_FACE, fg=BTN_TEXT,
                                activebackground=BTN_FACE,
                                activeforeground=BTN_TEXT,
                                font=FONT_CTRL, relief="flat",
                                highlightbackground=BORDER_COLOR,
                                highlightthickness=1,
                                cursor="hand2", command=open_part_picker)
            else:
                btn = tk.Button(row, text=label, bg=BTN_FACE,
                                fg=BTN_TEXT, activebackground=BTN_FACE,
                                activeforeground=BTN_TEXT,
                                font=FONT_CTRL, relief="flat",
                                highlightbackground=BORDER_COLOR,
                                highlightthickness=1,
                                cursor="hand2",
                                command=lambda p=part: do_save_fix(p))
            btn.pack(side="left", padx=(0, GAP_CONTROL), pady=2, ipady=4)

    def do_save_fix(part):
        verdict = state["verdict"]
        if verdict is None or not verdict.parsed.ok:
            return
        if part == "Not fixed yet":
            fix_status.configure(
                text="Noted — no case saved. The book only learns "
                     "from cures.")
            return
        case = save_case(casebook, verdict, part)
        save_casebook(casebook)
        state["case"] = case
        summary = pattern_summary(casebook, pattern_of(verdict))
        fix_status.configure(text="Case saved: %s. %s"
                             % (part, summary["text"]))
        cure_text.configure(
            text="Case saved for %s. Plug the phone back in and run "
                 "CURE CHECK (top), then start the 3-MINUTE TEST — "
                 "the cure watch rides the count."
                 % case.get("model_name", "this phone"))
        print_btn.configure(state="disabled")
        fit_to_content()

    def open_part_picker():
        top = tk.Toplevel(root)
        top.title("What fixed it?")
        top.configure(bg=BG_APP)
        tk.Label(top, text="Pick the part that cured the phone:",
                 bg=BG_APP, fg=FG_TEXT,
                 font=FONT_BODY_BOLD).pack(padx=PAD_PANEL, pady=12)
        listbox = tk.Listbox(top, height=12, width=52, bg=BG_PANEL,
                             fg=FG_TEXT, font=FONT_CTRL,
                             selectbackground=ACCENT,
                             selectforeground=FG_ON_ACCENT,
                             highlightbackground=BORDER_COLOR,
                             highlightthickness=1)
        for part in PART_LIST:
            listbox.insert("end", part)
        listbox.pack(padx=PAD_PANEL)
        entry = tk.Entry(top, width=52, bg=BG_PANEL, fg=FG_TEXT,
                         font=FONT_CTRL,
                         insertbackground=FG_TEXT,
                         highlightbackground=BORDER_COLOR,
                         highlightthickness=1)
        entry.pack(padx=PAD_PANEL, pady=10)
        tk.Label(top, text="…or type the part here, then tap Use it.",
                 bg=BG_APP, fg=FG_DIM,
                 font=FONT_META).pack(padx=PAD_PANEL)

        def use_it():
            typed = entry.get().strip()
            chosen = typed
            if not chosen:
                sel = listbox.curselection()
                if sel:
                    chosen = listbox.get(sel[0])
            top.destroy()
            if chosen:
                do_save_fix(chosen)
        tk.Button(top, text="Use it", command=use_it, bg=BTN_FACE,
                  fg=BTN_TEXT, activebackground=BTN_FACE,
                  activeforeground=BTN_TEXT,
                  font=FONT_CTRL, relief="flat",
                  highlightbackground=BORDER_COLOR,
                  highlightthickness=1).pack(pady=12, ipady=5)

    def show_verdict(verdict, tally=""):
        # A verdict exists: the result area goes on the page —
        # the verdict block, followed by the Cure check block
        # and the What-the-log-says box (v0.9).
        result_shown["verdict"] = True
        result_shown["cure"] = True
        result_shown["facts"] = True
        apply_result_area()
        state["verdict"] = verdict
        state["case"] = None
        state["ai_text"] = ""
        draft_btn.configure(state="disabled")
        print_btn.configure(state="disabled")
        parsed = verdict.parsed
        if not parsed.ok:
            verdict_label.configure(text="That file could not be read",
                                    fg=BAD)
            conf_label.configure(text="")
            tally_label.configure(text="")
            prove_head.configure(text="")
            prove_text.configure(text=parsed.error)
            also_head.configure(text="")
            also_text.configure(text="")
            fix_head.configure(text="")
            rebuild_fix_buttons([])
            ask_ai_btn.configure(state="disabled")
            explain_btn.configure(state="disabled")
            set_picture(None, "No picture — nothing could be read")
            set_facts([])
            fit_to_content()
            return
        head = verdict.headline
        if head is None:
            verdict_label.configure(
                text="No known match — don't guess", fg=WARN)
            conf_label.configure(
                text="Nothing in the rule book fits this log. "
                     "Here is what the log does say:")
            tally_label.configure(text=tally)
            prove_head.configure(text="")
            prove_text.configure(
                text="Start from the facts below, and the general "
                     "rule: on a phone that restarts every few "
                     "minutes, test with known-good parts in this "
                     "order — charging-port flex, battery, front "
                     "sensor flex — before any board work. Or tap "
                     "ASK THE AI for an unproven second reading.")
            also_head.configure(text="")
            also_text.configure(text="")
            ask_ai_btn.configure(state="normal")
            explain_btn.configure(state="normal")
            set_picture(None, "No part named — no picture")
            rebuild_fix_buttons([])
            set_facts(facts_lines(parsed, book))
            fit_to_content()
            return
        rule = head.rule
        # The board draws the part name in primary text white; the
        # owner pointed at the board, so white it is (v0.5). Green
        # stays reserved for cure outcomes and the timer's flip.
        verdict_label.configure(text=rule["part"], fg=FG_TEXT)
        bits = ["How sure: %s" % rule["confidence"]]
        if parsed.model_name:
            bits.append("Phone: %s" % parsed.model_name)
        bits.append("Matched by: %s" % head.via)
        conf_label.configure(text="  •  ".join(bits))
        tally_label.configure(text=tally)
        prove_head.configure(text="How to prove it")
        prove_text.configure(text=rule["test"])
        others = verdict.matches[1:5]
        if others:
            also_head.configure(text="Also check, in this order")
            lines = []
            for match in others:
                lines.append("• %s (%s sure)"
                             % (match.rule["part"],
                                match.rule["confidence"]))
            if verdict.uncovered_bits:
                lines.append("• The code also carries a part this book "
                             "does not know yet (extra bits 0x%x)."
                             % verdict.uncovered_bits)
            also_text.configure(text="\n".join(lines))
        else:
            also_head.configure(text="")
            also_text.configure(text="")
        ask_ai_btn.configure(state="disabled")
        explain_btn.configure(state="normal")
        set_picture(rule["part"])
        rebuild_fix_buttons([m.rule["part"] for m in verdict.matches])
        notes = []
        if rule.get("also"):
            notes.append("Note: %s" % rule["also"])
        notes.append("Rule source: %s" % rule["source"])
        if not rule.get("bench_verified"):
            notes.append("This rule has not been confirmed on this "
                         "shop's bench yet.")
        set_facts(facts_lines(parsed, book) + ["", *notes])
        fit_to_content()

    def on_result(item):
        kind = item[0]
        if kind == "update_ready":
            # The update door found a newer build on the shelf
            # (v1.2): offer it — the install itself is gated by
            # download_update's size + SHA-256 verification.
            update_state["checking"] = False
            offer_update(item[1])
            return
        if kind == "update_none":
            # The update door's plain answer: already current, or
            # no manifest on the shelf yet — said out loud on the
            # big status line, never silent.
            update_state["checking"] = False
            set_busy(False)
            set_status(item[1])
            return
        if kind == "update_error":
            update_state["checking"] = False
            set_busy(False)
            set_status(item[1])
            return
        if kind == "message":
            # Every message result is a door's result (the phone
            # read or the web watch), announced on the status
            # line — the result area's strip below the AI row.
            set_busy(False)
            set_status(item[1])
            return
        if kind == "verdict":
            set_busy(False)
            set_status("")
            show_verdict(item[1], item[2])
            return
        if kind == "ai":
            set_busy(False)
            set_status("")
            # The AI answer lands in the log box (v0.9: make
            # sure the box is on the page).
            result_shown["facts"] = True
            apply_result_area()
            text = item[1]
            state["ai_text"] = text if text.startswith(AI_BADGE) else ""
            draft_btn.configure(
                state="normal" if state["ai_text"] else "disabled")
            set_facts(text.splitlines())
            fit_to_content()
            return
        if kind == "cure":
            set_busy(False)
            set_status("")
            # A cure result exists: the Cure check block (+ the
            # log box) goes on the page (v0.9).
            result_shown["cure"] = True
            result_shown["facts"] = True
            apply_result_area()
            result = item[1]
            state["cure"] = result
            cure_text.configure(text="\n".join(result.lines))
            print_btn.configure(state="disabled")
            fit_to_content()
            return
        if kind == "watch":
            # A cure watch that rode the timer has ended — either it
            # saw a new panic / a vanished phone on its own, or STOP
            # ended it clean. Stale rides (superseded by a newer
            # count) are ignored.
            set_busy(False)
            result, ride = item[1], item[2]
            if ride is not watch_ride["current"] or ride["applied"]:
                return
            ride["applied"] = True
            set_status("")
            # The watch's cure verdict lands in the Cure check
            # block (+ the log box) on the page (v0.9).
            result_shown["cure"] = True
            result_shown["facts"] = True
            apply_result_area()
            state["cure"] = result
            state["watch_minutes"] = bench_timer.elapsed() / 60.0
            cure_text.configure(text="\n".join(result.lines))
            print_btn.configure(
                state="normal" if result.status == "proven"
                else "disabled")
            fit_to_content()
            return

    def poll():
        try:
            while True:
                on_result(work.get_nowait())
        except queue.Empty:
            pass
        root.after(150, poll)

    def do_read_phone():
        if book is None:
            set_status(book_error)
            return
        # A fresh read starts: the previous result content
        # clears back to the at-rest inventory until the new
        # result lands (v0.9).
        clear_result_area()
        set_status("Reading the phone…")
        set_busy(True)

        def worker():
            message, verdict, tally = read_phone(
                book, list(casebook.get("promoted_rules", [])))
            if verdict is None:
                work.put(("message", message))
            else:
                if message:
                    work.put(("message", message))
                work.put(("verdict", verdict, tally))
        threading.Thread(target=worker, daemon=True).start()

    def do_open_file():
        if book is None:
            set_status(book_error)
            return
        path = filedialog.askopenfilename(
            title="Open a panic log file",
            filetypes=[("Panic logs", "*.ips *.txt *.log"),
                       ("All files", "*.*")])
        if not path:
            return
        # A fresh read starts: the previous result content
        # clears back to the at-rest inventory until the new
        # result lands (v0.9).
        clear_result_area()
        try:
            verdict = analyze_file(
                path, book, list(casebook.get("promoted_rules", [])))
        except OSError as exc:
            set_status("That file could not be opened: %s" % exc)
            return
        set_status("")
        show_verdict(verdict)

    def do_cure_check():
        case = state["case"]
        if case is None:
            set_status(
                "No saved repair to check yet. Read a verdict, "
                "tap WHAT FIXED IT after the repair, then run "
                "the cure check.")
            return
        set_status("Checking the phone against the "
                   "repair time…")
        set_busy(True)

        def worker():
            work.put(("cure", cure_check(case)))
        threading.Thread(target=worker, daemon=True).start()

    def do_print_proof():
        case = state["case"]
        result = state["cure"]
        if case is None or result is None or book is None:
            return
        slip = cure_proof_text(case, book, state["watch_minutes"],
                               result.status == "proven")
        top = tk.Toplevel(root)
        top.title("Cure proof")
        top.configure(bg=BG_APP)
        box = scrolledtext.ScrolledText(
            top, width=64, height=16, bg=BG_PANEL, fg=FG_TEXT,
            font=FONT_LOG, wrap="word", relief="flat",
            highlightbackground=BORDER_COLOR, highlightthickness=1)
        box.pack(padx=PAD_PANEL, pady=12)
        box.insert("end", slip)
        box.configure(state="disabled")
        note = tk.Label(top, text="", bg=BG_APP, fg=FG_DIM,
                        font=FONT_META)
        note.pack(padx=PAD_PANEL)

        def print_it():
            path, printed = print_slip(slip)
            note.configure(
                text="Slip saved to %s%s" % (
                    path, " — sent to the printer." if printed else
                    ". Print it from that file."))
        tk.Button(top, text="PRINT / SAVE SLIP", command=print_it,
                  bg=BTN_FACE, fg=BTN_TEXT, activebackground=BTN_FACE,
                  activeforeground=BTN_TEXT,
                  font=FONT_CTRL, relief="flat",
                  highlightbackground=BORDER_COLOR,
                  highlightthickness=1).pack(pady=12, ipady=5)

    def do_ai(kind):
        verdict = state["verdict"]
        if verdict is None or not verdict.parsed.ok or book is None:
            return
        set_status("Asking the AI… (identifiers are "
                   "stripped before anything is sent)")
        set_busy(True)

        def worker():
            work.put(("ai", ask_ai(kind, verdict.parsed, verdict)))
        threading.Thread(target=worker, daemon=True).start()

    def do_save_ai_draft():
        verdict = state["verdict"]
        if verdict is None or not state["ai_text"]:
            return
        draft = ai_draft_from_answer(verdict.parsed, state["ai_text"])
        save_draft(drafts_data, draft)
        save_drafts(drafts_data)
        draft_btn.configure(state="disabled")
        set_status(
            "Saved as a draft rule in drafts.json — unproven. "
            "Drafts never promote themselves; the case book "
            "decides.")

    def do_web_watch():
        if book is None:
            set_status(book_error)
            return
        set_status("Watching Repair Wiki and iFixit for "
                   "new codes…")
        set_busy(True)

        def worker():
            message, new_drafts = check_for_new_codes(book, drafts_data)
            if new_drafts:
                save_drafts(drafts_data)
            work.put(("message", message))
        threading.Thread(target=worker, daemon=True).start()

    def make_door(row, label, subline, command, fill, fg, cap_fg,
                  font, padx):
        """One door as the board draws it (v0.5): a flat colored
        block carrying the big label AND its small sub-line inside
        it. The label line is still a real tk.Button — busy state,
        keyboard focus and the gate's button census behave exactly
        as before — and the block and the sub-line forward their
        clicks to it (invoke() on a disabled door does nothing,
        which is the correct busy behavior)."""
        cell = tk.Frame(row, bg=fill,
                        highlightbackground=BORDER_COLOR,
                        highlightthickness=1)
        cell.pack(side="left", fill="x", expand=True, padx=padx)
        btn = tk.Button(cell, text=label, command=command, bg=BTN_FACE,
                        fg=fg, activebackground=BTN_FACE,
                        activeforeground=fg,
                        disabledforeground=BTN_TEXT_DISABLED, font=font,
                        relief="flat", cursor="hand2")
        btn.pack(fill="x", ipady=5)
        cap = tk.Label(cell, text=subline, bg=fill, fg=cap_fg,
                       font=FONT_META, justify="center")
        cap.pack(fill="x", pady=(0, 7))
        cap.bind("<Button-1>", lambda _e: btn.invoke())
        cell.bind("<Button-1>", lambda _e: btn.invoke())
        return btn

    read_btn = make_door(btn_row, "READ THE PHONE",
                         "Plug in an iPhone and read its panic log",
                         do_read_phone, ACCENT, BTN_TEXT, FG_TEXT,
                         FONT_MAIN_BTN, (0, GAP_CONTROL // 2))
    file_btn = make_door(btn_row, "OPEN A PANIC FILE",
                         "Open a saved panic log file from this computer",
                         do_open_file, WARN, BTN_TEXT, FG_ON_AMBER,
                         FONT_MAIN_BTN, (GAP_CONTROL // 2, 0))
    cure_btn = make_door(btn_row2, "CURE CHECK",
                         "Run a live watch after a repair",
                         do_cure_check, BG_RAISED, BTN_TEXT, FG_DIM,
                         FONT_CTRL, (0, GAP_CONTROL // 2))
    web_btn = make_door(btn_row2, "CHECK FOR NEW CODES",
                        "Update the known codes database",
                        do_web_watch, BG_RAISED, BTN_TEXT, FG_DIM,
                        FONT_CTRL, (GAP_CONTROL // 2, 0))
    print_btn.configure(command=do_print_proof)
    ask_ai_btn.configure(command=lambda: do_ai("ask"))
    explain_btn.configure(command=lambda: do_ai("explain"))
    draft_btn.configure(command=do_save_ai_draft)

    # The honesty footer + copyright close the panel's work on
    # the one page (v0.8).
    footer = tk.Label(page,
                      text="%s\n%s" % (CLUE_LINE, COPYRIGHT_LINE),
                      bg=BG_APP, fg=FG_DIM, font=FONT_META,
                      justify="center")
    footer.pack(pady=(0, 8))

    # The bottom status line closes the page, as the board draws
    # it: the version on the left (the REAL version, never the
    # board's), the app's state on the right — a green dot and
    # "Ready." at idle; set_busy flips the pair to an amber dot
    # and "Working…" while a door is working.
    statebar = tk.Frame(page, bg=BG_APP)
    statebar.pack(fill="x", padx=PAD_WINDOW, pady=(0, 8))
    tk.Label(statebar, text="%s v%s" % (WORKING_TITLE, VERSION),
             bg=BG_APP, fg=FG_DIM, font=FONT_META).pack(side="left")
    # v1.2: the update door — a real, labeled CHECK FOR UPDATES
    # button on the bottom status line, right beside the version
    # it updates (the owner's rule: every app ships a labeled,
    # findable update door). Its command is wired further down,
    # with the update handlers, the way the print/AI buttons are
    # wired after their creation.
    update_btn = tk.Button(statebar, text="CHECK FOR UPDATES",
                           bg=BTN_FACE, fg=BTN_TEXT,
                           activebackground=BTN_FACE,
                           activeforeground=BTN_TEXT,
                           disabledforeground=BTN_TEXT_DISABLED,
                           font=FONT_META, relief="flat",
                           highlightbackground=BORDER_COLOR,
                           highlightthickness=1,
                           cursor="hand2")
    update_btn.pack(side="left", padx=(16, 0), ipady=2)
    state_text = tk.Label(statebar, text="Ready.", bg=BG_APP,
                          fg=FG_TEXT, font=FONT_META)
    state_text.pack(side="right")
    state_dot = tk.Label(statebar, text="●", bg=BG_APP, fg=GOOD,
                         font=FONT_META)
    state_dot.pack(side="right", padx=(0, 6))

    # ==========================================================
    # v0.9 — THE RESULT AREA. The owner's words, to the letter:
    # at rest the front page is the title, the caps subtitle,
    # the four doors, the 3-MINUTE TEST, the AI row and the
    # bottom status line — and NOTHING else. Everything a result
    # needs (the big status strip, the verdict block with the
    # picture spot, the Cure check block, the What-the-log-says
    # box) plus the honesty footer lives here, OFF the page,
    # until a result exists; then it maps below the AI row on
    # this same page and the window grows to fit it. A fresh
    # read clears it back to the at-rest inventory until the
    # new result lands. The widgets were all built above and
    # packed in their places; their pack options are recorded
    # here and this block owns their mapping from now on.
    # ==========================================================
    result_sections = [
        ("status", [status]),
        ("verdict", [verdict_row, prove_head, prove_text,
                     also_head, also_text, fix_head, fix_box,
                     fix_status]),
        ("cure", [cure_head, cure_text, watch_row]),
        ("facts", [facts_head, facts_box]),
    ]
    result_pack = {}
    for _section, _widgets in result_sections:
        for _widget in _widgets:
            _info = _widget.pack_info()
            _info.pop("in", None)
            result_pack[_widget] = _info
    result_shown = {"verdict": False, "cure": False, "facts": False}
    _area_state = {"shown": None}

    def apply_result_area():
        """Map exactly the result sections that currently hold
        a result, in their standing order, and the honesty
        footer with them; unmap the rest."""
        wanted = (bool(status.cget("text")),
                  result_shown["verdict"], result_shown["cure"],
                  result_shown["facts"])
        if _area_state["shown"] == wanted:
            return
        _area_state["shown"] = wanted
        for _section, _widgets in result_sections:
            for _widget in _widgets:
                _widget.pack_forget()
        for (_section, _widgets), _want in zip(result_sections,
                                               wanted):
            if _want:
                for _widget in _widgets:
                    _widget.pack(**result_pack[_widget])
        if any(wanted):
            if footer.winfo_manager() != "pack":
                footer.pack(pady=(0, 8), before=statebar)
        elif footer.winfo_manager() == "pack":
            footer.pack_forget()

    def set_status(text):
        """The one way the big status line is written: the words
        land, the result area re-maps around them, and the
        window re-fits."""
        status.configure(text=text)
        apply_result_area()
        fit_to_content()

    def clear_result_area():
        """A fresh read starts: the previous result content
        clears back to the at-rest inventory (and the window
        returns to the at-rest fit) until the new result
        lands."""
        result_shown["verdict"] = False
        result_shown["cure"] = False
        result_shown["facts"] = False
        status.configure(text="")
        apply_result_area()
        root.update_idletasks()
        root.geometry("%dx%d" % (root.winfo_width(),
                                 root.winfo_reqheight()
                                 + WIN_FIT_MARGIN))

    # ==========================================================
    # v1.2 — THE UPDATE DOOR handlers. CHECK FOR UPDATES reads
    # the shelf manifest in a worker thread; results land through
    # the same queue as every other door (see on_result). An
    # offered update installs only after the download's size AND
    # SHA-256 match the manifest (download_update), and the swap
    # itself is handed to the helper, which rolls back if the
    # new build does not stay alive. A silent check also runs at
    # startup, like the donor's — it only ever offers; it never
    # installs on its own.
    # ==========================================================
    update_state = {"checking": False, "offering": False}

    def offer_update(info):
        if update_state["offering"]:
            return
        update_state["offering"] = True
        try:
            ok = messagebox.askyesno(
                WORKING_TITLE,
                "Analyze That Part v%s is available (you have "
                "v%s).\n\n%s\n\nInstall it now? The app will "
                "restart." % (info["version"], VERSION,
                              info.get("notes", "")))
        finally:
            update_state["offering"] = False
        if not ok:
            set_status("Update to v%s is available — tap CHECK "
                       "FOR UPDATES when you're ready to install "
                       "it." % info["version"])
            return
        set_busy(True)
        set_status("Downloading Analyze That Part v%s…"
                   % info["version"])

        def download_worker():
            path, err = download_update(info, SCRIPT_DIR)
            if err:
                work.put(("update_error",
                          "Update not installed: %s. You're still "
                          "on v%s." % (err, VERSION)))
                return
            try:
                begin_update(_current_program_path(), path,
                             info["version"], VERSION)
            except Exception as exc:
                work.put(("update_error",
                          "Update could not start (%s). You're "
                          "still on v%s." % (exc, VERSION)))
                return
            root.after(400, root.destroy)
        threading.Thread(target=download_worker,
                         daemon=True).start()

    def do_update_check():
        if update_state["checking"]:
            return
        update_state["checking"] = True
        set_status("Checking for updates…")

        def check_worker():
            info = fetch_update_info()
            if info is None:
                work.put(("update_none",
                          "No update information yet — the update "
                          "feed (analyze-that-part-version.json) "
                          "is not on the shelf. You're on v%s."
                          % VERSION))
            elif update_available(info):
                work.put(("update_ready", info))
            else:
                work.put(("update_none",
                          "You're on the latest version (v%s)."
                          % VERSION))
        threading.Thread(target=check_worker, daemon=True).start()

    update_btn.configure(command=do_update_check)

    def silent_update_check():
        info = fetch_update_info()
        if update_available(info):
            work.put(("update_ready", info))
    threading.Thread(target=silent_update_check,
                     daemon=True).start()

    # At rest the result area is OFF the page (v0.9): the front
    # page is the at-rest inventory alone.
    apply_result_area()
    if book is None:
        set_status(book_error)
    if state["case"] is not None:
        cure_text.configure(text=saved_case_text(state["case"]))
    # Open at the page's measured fit — of the AT-REST inventory
    # alone (v0.9): set the width first so wrapped text measures
    # at the real width, then set the height to the content's
    # requested height plus the fit margin — the whole front
    # page visible, nothing clipped, no void. The minimum
    # window height is that same fit, so the front page can
    # never be dragged smaller than whole.
    root.geometry("%dx%d" % (WIN_WIDTH, root.winfo_height()))
    root.update_idletasks()
    idle_height = root.winfo_reqheight() + WIN_FIT_MARGIN
    root.minsize(960, idle_height)
    root.geometry("%dx%d" % (WIN_WIDTH, idle_height))
    poll()
    root.mainloop()

if __name__ == "__main__":
    main()
