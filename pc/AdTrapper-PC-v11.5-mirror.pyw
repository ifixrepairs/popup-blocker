#!/usr/bin/env python3
"""
AdTrapper -- Malware & Adware Scanner
Copyright (c) 2026 iFixx Repairs, Englewood, Florida. All rights reserved.
Adware/malware detector and remover for Android phones.

Just double-click this file.
  1. Plug the customer's phone into the computer with USB.
  2. On the phone: enable Developer options > USB debugging, then tap
     "Allow" on the USB debugging prompt.
  3. Click SCAN. Tick what to remove, or hit REMOVE ALL. Done.

Detection: weighted red-flag scoring (sideloaded apps, device admins,
accessibility abuse, popup permission, hidden icons, never-opened apps,
junk-name patterns, known junk, boot autostart) plus a browser-notification
site list for the cases where no app is behind the popups.
Extras: privacy audit (SMS/contacts/location/mic/camera access), APK backup
before every removal, one-tap UNDO, BLOCK POPUPS (revoke overlay permission
without uninstalling), disable-app fallback when uninstall is blocked.

Needs: Python 3 + the platform-tools folder downloaded (this script finds
adb by itself in the usual spots).
"""

import os
import uuid
import hmac
import hashlib
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk

if os.name == "nt":
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(
            ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass
from tkinter import messagebox, ttk
from datetime import datetime, timedelta, date
from math import cos, sin, pi
from pathlib import Path
import json
import urllib.request

# --- hide the black console window on Windows; the GUI is the interface ---
if sys.platform == "win32":
    try:
        import ctypes
        _hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if _hwnd:
            ctypes.windll.user32.ShowWindow(_hwnd, 0)
    except Exception:
        pass

# ------------------------------------------------------------------ core ---

# App NAMES confirmed as junk in shop testing (exact label match, any
# package) -- for offenders whose package id hides or varies by variant.
# Both shop-tested on Duncan's A16, 2026-10-12.
KNOWN_BAD_LABELS = {"chore focus"}
KNOWN_BAD_LABEL_PREFIXES = ("phone clear", "phone cleaner")

# Packages confirmed as junk in shop testing -- always flagged.
# Bundled baseline synchronized with server/blocklist.json (125 entries).
KNOWN_BAD = {
    "antivirus.anti.virus.applock.protection.vpn",
    "antivirus.virus.cleaner.clean.vpn.booster",
    "app.luckymoneygames",
    "appicon.diy.tools.prop",
    "call.recorder.automatic.acr",
    "casinoplus.pindo3",
    "cleaner.clean.booster",
    "com.MoneyBingo.LuckyRewards.CashGame.BigWinner",
    "com.Solitaire.Card.MoneyGame.CashRewards",
    "com.againstvirus.flux",
    "com.androidneonkeyboard.app",
    "com.anti.virus.security",
    "com.antivirus.cleaner.supersecurity",  # Super Security (PC-caught, shop-filmed 2026-10-13)
    "com.antivi.shield.loish",
    "com.applabstudios.ai.mail.homescreen.inbox",  # Easy Mail (gauntlet test app)
    "com.arcfolio.pdf.mrrmfo",  # Arcfolio PDF (Duncan pen-test)
    "com.aviator.aviatorgamejamantech2",
    "com.bat.batsaver",
    "com.benjaminone.client",
    "com.bingo.games.bingo.offline.win.cash",
    "com.blue.deep.cleaner",
    "com.boost.clean",
    "com.burakgon.gamebooster3",
    "com.cachecleanereasytool.app",
    "com.caller.theme.slow",
    "com.callercallwallpaper.app",
    "com.callertheme.firstref",
    "com.capcut.capvideoeditorapp58",
    "com.chorefocus.app",  # Chore Focus (shop-tested 2026-10-12)
    "com.clea.mas.pro",
    "com.clean.maestro.security.speed.booster",
    "com.clean.mix.junk",
    "com.cleaner.phone.junk.files",
    "com.dl.guard.lock",
    "com.dmstudio.weather",
    "com.fancyanimatedbattery.app",
    "com.fastcleanercashecleaner.app",
    "com.flash.booster.Cleaner",
    "com.flintos.capcut2",
    "com.funnycallercustomtheme.app",
    "com.funnywallpapaerslive.app",
    "com.g19mobile.gamebooster",
    "com.godwin.applehealth2",
    "com.godwin.applepay3",
    "com.grouprx.pureanti",
    "com.hello.miheapp.secretspace",
    "com.hld.anzenbokusucal",
    "com.intelli.clean",
    "com.intelligent.heimlich.tool",
    "com.junkeraser.clean",
    "com.keli.imessage3",
    "com.keli.siriapp1",
    "com.lagofast.mobile.acclerater",
    "com.learned.guard.jido",  # MiraClean (gauntlet test app)
    "com.lionmobi.powerclean",
    "com.m24apps.acr",
    "com.mbkristine8.cleanmaster",
    "com.mhd.zelleapp2",
    "com.mobile.applock.en",
    "com.mobile.applock.wt",
    "com.mycallcallpersonalization.app",
    "com.mycallcustomcallscrean.app",
    "com.neonthemekeyboard.app",
    "com.newscrean4dwallpapers.app",
    "com.notesreminderslists.app",
    "com.novabrain.tool.cleanboost",
    "com.papaya.bingocash.play",
    "com.papaya.solitairecash.play",
    "com.paypal.wallawalled11",
    "com.pdfsprint.viewer.vertigerdig",
    "com.phcleanquickly.cleanplus",  # Quick Clean Plus (gauntlet test app)
    "com.planb.cleaner",
    "com.premkumar.zelleapp2",
    "com.premkumar.zelleapp5",
    "com.procleaner.clean",
    "com.react.fallguysgame1",
    "com.react.gta6game1",
    "com.rockskinthemes.app",
    "com.sas.virus.cleaner.antivirus.unusedapps",
    "com.sec.reclean",  # SecureClean variant (USB-cable verified 2026-10-13)
    "com.second.space",
    "com.shahdi.imessage2",
    "com.shahdi.siri1",
    "com.shahdi.siri2",
    "com.sitaram.robloxgame1",
    "com.sitaram.robloxgame3",
    "com.smartnettools.studio.easyclean",
    "com.sp.protector.free",
    "com.spaceclean.quickcleaner",
    "com.sr.clear2.jb",  # Phone Clear / AI Clean Storage cleaner (Galaxy Store, shop-tested 2026-10-12)
    "com.stg.plus.win.real.money.cash.app",
    "com.storage.androidcleaner",
    "com.tf.phonecleaner.booster",
    "com.trpz.travel",
    "com.ultimate.cleanerpro.ucp",
    "com.westhorizont.appsforge.filehorizon_explorereaddocuments",
    "com.winde.apex",
    "com.winrgames.solitaire",
    "com.works.amazing.colour",
    "com.zelleapp.devnexus2",
    "de.andromo.ssfiftylivesixcc",
    "de.fiftyninecamera.rollredactor",
    "de.hitopgop.sixtyeightgx",
    "de.instgang.fiftyggfife",
    "de.nineergysh.quickarttwo",
    "de.photoground.twentysixshot",
    "de.sixtyonecollice.cameraroll",
    "de.stockeighty.onewallpapers",
    "de.xnano.photoexifeditornine",
    "gb.artfilter.tenvarnist",
    "gb.crazykey.sevenboard",
    "gb.painnt.moonlightingnine",
    "gb.twentynine.redaktoridea",
    "helectronsoft.com.grubl.live.wallpapers3d",
    "huwaei.health1",
    "il.co.smedia.callrecorder.yoni",
    "live.weather.vitality.studio.forecast.widget",
    "mtr.cpumonitor.temperature",
    "myfiles.filemanager.fileexplorer.cleaner",
    "netflixgamecontroller.uzair1",
    "netflixgamecontroller.uzair2",
    "picturetranslate.extractor.text.lite",
    "vault.gallery.lock",
    "ws.clockthevault",
    "xboxgame.abdul2",
}

# Installers that count as legitimate app stores.
STORES = {
    "com.android.vending": "Play Store",
    "com.sec.android.app.samsungapps": "Galaxy Store",
    "com.amazon.venezia": "Amazon Appstore",
    "com.huawei.appmarket": "AppGallery",
}
TRANSFER = {
    "com.sec.android.easyMover": "Smart Switch transfer",
    "com.google.android.apps.restore": "Google restore",
}
CARRIER = re.compile(r"^com\.(dti|att|tmobile|verizon|vzw|sprint|uscellular|motricity|ironsrc\.aura)\b")

# Junk-name pattern (cleaner/booster/shield-type utility disguises).
# ------------------------- licensing -------------------------
# Hardware-locked license keys. Duncan generates keys with keygen.py.
# !!! CHANGE THIS SECRET BEFORE SELLING - keep it private !!!
_LICENSE_SECRET = b"deceptacon-licensing-v1-d5e9fd4b5e59153fa82022f985378404"

def get_hwid():
    """Stable hardware ID for this PC (12 hex chars, grouped)."""
    raw = "%s-%s-%s" % (uuid.getnode(), platform.node(), platform.machine())
    digest = hashlib.sha256(raw.encode()).hexdigest().upper()
    h = digest[:12]
    return "%s-%s-%s" % (h[0:4], h[4:8], h[8:12])

def _b32_noconfuse(data):
    """Base32 without confusing chars (0/O, 1/I/L)."""
    import base64
    s = base64.b32encode(data).decode().rstrip("=")
    return s.replace("0", "X").replace("1", "Y")

def make_license_key(hwid, days_valid=365):
    """Duncan's keygen logic (mirrored in keygen.py)."""
    import time
    expiry = int(time.time()) + days_valid * 86400 if days_valid > 0 else 0
    payload = "%s|%d" % (hwid.replace("-", ""), expiry)
    sig = hmac.new(_LICENSE_SECRET, payload.encode(),
                   hashlib.sha256).digest()
    key = _b32_noconfuse(sig)[:16]
    return "%s-%s-%s-%s" % (key[0:4], key[4:8], key[8:12], key[12:16]), expiry

def validate_license_key(hwid, key):
    """Returns (valid, expiry_timestamp). Checks all reasonable expiries."""
    import time
    clean = key.replace("-", "").replace(" ", "").upper()
    if len(clean) != 16:
        return False, 0
    # Try perpetual (expiry=0) and day-boundary expiries (keygen uses midnight UTC)
    now = int(time.time())
    day_start = now - (now % 86400)
    hwid_c = hwid.replace("-", "")
    candidates = [0] + [day_start + d * 86400 for d in range(1, 1826)]
    for expiry in candidates:
        payload = "%s|%d" % (hwid_c, expiry)
        sig = hmac.new(_LICENSE_SECRET, payload.encode(),
                       hashlib.sha256).digest()
        expect = _b32_noconfuse(sig)[:16]
        if hmac.compare_digest(expect, clean):
            return True, expiry
    return False, 0

def _license_path():
    return _script_dir_path() / "popup_defender_license.json"

def load_license():
    try:
        with open(_license_path()) as f:
            d = json.load(f)
        ok, exp = validate_license_key(get_hwid(), d.get("key", ""))
        if ok:
            return d["key"], exp
    except Exception:
        pass
    return None, 0

def save_license(key):
    try:
        with open(_license_path(), "w") as f:
            json.dump({"key": key}, f)
    except Exception:
        pass
# ----------------------- end licensing -----------------------

# --------------------------------- removal history + disclaimer (2026-10-21)
# Removal History + in-app Disclaimer (owner order 2026-10-21; see
# builds/adtrapper/REMOVAL-HISTORY-SPEC.md and DISCLAIMER-SPEC.md).
# Every CONFIRMED removal -- Guided Clean and REMOVE ALL both funnel
# through PopupBlockerApp._do_remove -- appends one JSON line to
# removal-history.json beside the app's other state files, so a
# customer who comes back can be shown exactly what came off their
# phone, and the shop can put a liked app back from the Play Store.
# A logging failure must NEVER block or fail a removal: every helper
# in this section swallows its own errors and reports by return value.

DISCLAIMER_TITLE = "PLEASE READ BEFORE WE CLEAN YOUR PHONE"

# Disclaimer text v3.1 (DISCLAIMER-SPEC.md) -- verbatim, do not reword.
DISCLAIMER_PARAGRAPHS = [
    "You asked us to remove the bad apps and malware from this phone.",
    "AdTrapper checks every app. The check decides what is bad. We do not choose and pick what stays and what goes \u2014 and neither does this software pick your personal apps or games on its own.",
    "Before anything is removed, we will go through every flagged app with you. If there is an app or a game you want to keep, tell us then.",
    "If the check marks an app bad and you do not ask us to keep it, that app will be deleted. That is the cleanup you asked for.",
    "Deleted apps cannot be brought back by us, and we are not responsible for a deleted app or game when it was deleted under this rule. We are not liable for games, or for the points and scores saved in them, when you came in for this service.",
]

DISCLAIMER_TEXT = "\n\n".join([DISCLAIMER_TITLE] + DISCLAIMER_PARAGRAPHS)


def _removal_history_path():
    return _script_dir_path() / "removal-history.json"


def _app_state_path():
    return _script_dir_path() / "adtrapper_app_state.json"


def make_removal_record(when, ticket, customer, model, app_name,
                        package, verdict, reason):
    """One removal-history record (a plain dict, JSON-ready)."""
    return {
        "datetime": when or "",
        "ticket": ticket or "",
        "customer": customer or "",
        "model": model or "",
        "app": app_name or "",
        "package": package or "",
        "verdict": verdict or "",
        "reason": reason or "",
    }


def append_removal_record(record, path=None):
    """Append one record to the history file as a JSON line.
    Returns True on success. NEVER raises: a history-write failure
    must not block or fail the removal it describes."""
    try:
        p = Path(path) if path else _removal_history_path()
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return True
    except Exception:
        return False


def load_removal_history(path=None):
    """All history records, NEWEST first. Unparseable lines are
    skipped; a missing or unreadable file reads as empty history."""
    try:
        p = Path(path) if path else _removal_history_path()
        lines = p.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    out.reverse()
    return out


def filter_removal_history(records, date_text="", model_text="",
                           ticket_text=""):
    """Case-insensitive substring filters over the record fields;
    an empty filter passes everything. The date filter matches the
    record's datetime string, so fragments like "2026-10-21" work."""
    d = (date_text or "").strip().lower()
    m = (model_text or "").strip().lower()
    t = (ticket_text or "").strip().lower()
    out = []
    for rec in records or []:
        if d and d not in str(rec.get("datetime", "")).lower():
            continue
        if m and m not in str(rec.get("model", "")).lower():
            continue
        if t and t not in str(rec.get("ticket", "")).lower():
            continue
        out.append(rec)
    return out


def removal_restore_url(package):
    """Where RESTORE sends the operator: the app's Play Store page,
    where it can be re-installed onto the customer's phone."""
    return ("https://play.google.com/store/apps/details?id=%s"
            % (package or ""))


def _load_app_state(path=None):
    try:
        p = Path(path) if path else _app_state_path()
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_app_state(state, path=None):
    try:
        p = Path(path) if path else _app_state_path()
        with open(p, "w", encoding="utf-8") as f:
            json.dump(state, f)
        return True
    except Exception:
        return False


def disclaimer_acknowledged(path=None):
    """True once the operator has tapped I UNDERSTAND on the
    first-run disclaimer (persisted in the app state file)."""
    return bool(_load_app_state(path).get("disclaimer_ack"))


def set_disclaimer_acknowledged(path=None):
    state = _load_app_state(path)
    state["disclaimer_ack"] = True
    return _save_app_state(state, path)
# --------------------- end removal history + disclaimer ------

# ------------------------------------------------- shop / report branding ---
SHOP_NAME = "iFixx Repairs"
SHOP_TAGLINE = "PHONE & DEVICE REPAIR"
SHOP_ADDRESS = "2828 S McCall Rd Unit 346, Englewood, FL 34224"
SHOP_PHONE = "(941) 875-7511"
SHOP_WEB = "ifixxrepairs.com"
APP_NAME = "AdTrapper"
VERSION = "11.5"
REPORT_TITLE = "AdTrapper \u2014 Malware & Adware Cleanup Report"
REPORT_SUBTITLE = "Android Device Scan & Cleanup Results"
# Pinned printed-report shop header line (boss addendum + AT-8 ruling):
SHOP_HEADER_LINE = ("iFixx Repairs \u2014 2828 S McCall Rd Unit 346, "
                    "Englewood, FL 34224 \u2014 (941) 875-7511")
# Section 11.10 disclaimer (AT-10, decided with the AT-8 table ruling):
REPORT_DISCLAIMER = ("This report documents the scan findings and "
                     "cleanup actions recorded by AdTrapper at the "
                     "stated date and time. Results reflect the "
                     "information available during this scan and do "
                     "not guarantee that the device is free of all "
                     "security threats.")

# Known remote-access / screen-sharing apps. After a bank fraud, this is
# the row the bank looks for: could a stranger see or drive this phone?
REMOTE_ACCESS_PACKAGES = {
    "com.anydesk.anydeskandroid", "com.teamviewer.remote",
    "com.teamviewer.host", "com.teamviewer.quicksupport.market",
    "com.logmein.rescue", "com.splashtop.remote", "com.realvnc.viewer",
    "com.microsoft.rdc.androidx", "com.google.chromeremotedesktop",
    "com.zoho.assist", "com.getscreen.me", "com.ammyy.admin",
    "com.rustdesk.rustdesk", "com.duowan.kiwi", "air.net.aisaac.app",
}


def report_remote_access(threats):
    """Remote-access / screen-sharing verdict for the cleanup report.

    Clean -> "" (the checked table prints "None found - normal").
    Found -> names the app(s): a flagged row when one of the threats is
    a remote-access package, otherwise an accessibility-abuse fallback
    (screen-sharing scams ride accessibility when no known package is
    present).
    """
    hits = []
    for label, pkg, reasons, verdict in threats:
        if str(pkg or "").lower() in REMOTE_ACCESS_PACKAGES:
            hits.append(str(label or pkg))
    if hits:
        return "Found: " + ", ".join(hits[:3])
    if any("accessibility" in _reasons_str(r).lower()
           for _l, _p, r, _v in threats):
        return ("An app abused accessibility - see above (can be used "
                "to watch this screen)")
    return ""


# What the scanner checks, in plain customer English.
SCAN_FEATURES = (
    ("Every installed app",
     "scored for adware signals: fake cleaner, booster and PDF names; "
     "hidden app icons; pop-up (overlay) permission; device-admin abuse; "
     "accessibility abuse; auto-start on boot; sideloaded from outside "
     "the Play Store; apps never opened."),
    ("Known-malware blocklist",
     "%d threat packages from our daily threat-intel feed, plus anything "
     "this shop has flagged before."),
    ("Browser notification senders",
     "websites allowed to pop up notifications in Chrome, Samsung "
     "Internet and Firefox."),
    ("Privacy audit",
     "apps that can read your SMS, contacts, location, microphone "
     "or camera."),
    ("App sources",
     "where each app came from: Play Store, Galaxy Store, sideloaded, "
     "or preinstalled."),
)

STAY_SAFE_TIPS = (
    'If a website asks to "Allow notifications", tap Block or Don\'t allow.',
    'Never install a "cleaner", "booster", or "PDF" app from a pop-up ad.',
    "In free games, close ads with the small X \u2014 don't tap the ad itself.",
    "Pop-ups again? Don't tap anything in them \u2014 call us and we'll take a look.",
)

# (Fix round, tester note N1: the legacy base64 shop logo that
# used to sit here, ~85 KB of dead data, is deleted -- together
# with its only reader, the report-logo path helper, which had
# zero callers since the AT-7 clean-mark redesign and whose
# image appeared in no generated report -- so no future code
# path can quietly reintroduce the legacy logo art beside the
# report title.)


# ---- report icon strip (v10.17; v11.0: spec 11.4) ------------------
# Page 1 of the cleanup report carries a small strip of the REAL app
# icons of the scan's findings -- the same pictures the main list
# shows -- with each icon's original scan number beneath it.
# Every step here is best-effort: any failure just means a plainer
# report, never a missing one.

def _png_decode_rgb(data):
    """Decode a PNG to (w, h, rgb_bytes) with the stdlib only, or None.

    Non-interlaced, 8/16-bit, gray / RGB / palette / gray+alpha / RGBA.
    Alpha is composited onto white; the result is capped at 144 px on
    its long side (nearest neighbour) so a 512 px store face cannot
    bloat the report. Interlaced PNGs and anything unexpected return
    None -- that icon is simply skipped."""
    import struct as _st
    import zlib as _zl
    try:
        if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        pos = 8
        idat = bytearray()
        plte = None
        w = h = bd = ct = inter = None
        while pos + 8 <= len(data):
            ln = _st.unpack(">I", data[pos:pos + 4])[0]
            typ = data[pos + 4:pos + 8]
            chunk = data[pos + 8:pos + 8 + ln]
            if typ == b"IHDR":
                (w, h, bd, ct, _comp, _filt,
                 inter) = _st.unpack(">IIBBBBB", chunk)
            elif typ == b"PLTE":
                plte = chunk
            elif typ == b"IDAT":
                idat += chunk
            elif typ == b"IEND":
                break
            pos += 12 + ln
        if not w or not h or inter != 0 or bd not in (8, 16):
            return None
        chans = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ct)
        if chans is None or (ct == 3 and not plte):
            return None
        raw = _zl.decompress(bytes(idat))
        step = 2 if bd == 16 else 1
        bpp = chans * step
        stride = w * bpp
        if len(raw) < h * (stride + 1):
            return None
        rows = []
        prev = bytearray(stride)
        i = 0
        for _yy in range(h):
            f = raw[i]
            i += 1
            line = bytearray(raw[i:i + stride])
            i += stride
            if f == 1:
                for x in range(bpp, stride):
                    line[x] = (line[x] + line[x - bpp]) & 0xFF
            elif f == 2:
                for x in range(stride):
                    line[x] = (line[x] + prev[x]) & 0xFF
            elif f == 3:
                for x in range(stride):
                    a = line[x - bpp] if x >= bpp else 0
                    line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
            elif f == 4:
                for x in range(stride):
                    a = line[x - bpp] if x >= bpp else 0
                    b = prev[x]
                    c = prev[x - bpp] if x >= bpp else 0
                    p = a + b - c
                    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                    pr = a if (pa <= pb and pa <= pc) else \
                        (b if pb <= pc else c)
                    line[x] = (line[x] + pr) & 0xFF
            elif f != 0:
                return None
            rows.append(line)
            prev = line
        cap = 144
        big = max(w, h)
        step_xy = max(1, (big + cap - 1) // cap)
        ow = (w + step_xy - 1) // step_xy
        oh = (h + step_xy - 1) // step_xy
        rgb = bytearray(ow * oh * 3)
        for oy in range(oh):
            line = rows[oy * step_xy]
            for ox in range(ow):
                sx = ox * step_xy
                if bd == 16:
                    px = [line[(sx * chans + k) * 2]
                          for k in range(chans)]
                else:
                    px = [line[sx * chans + k] for k in range(chans)]
                o = (oy * ow + ox) * 3
                if ct == 0 or ct == 4:
                    v = px[0]
                    if ct == 4:
                        a = px[1]
                        v = (v * a + 255 * (255 - a)) // 255
                    rgb[o] = rgb[o + 1] = rgb[o + 2] = v
                elif ct == 3:
                    j = px[0] * 3
                    rgb[o] = plte[j]
                    rgb[o + 1] = plte[j + 1]
                    rgb[o + 2] = plte[j + 2]
                elif ct == 2:
                    rgb[o], rgb[o + 1], rgb[o + 2] = px
                else:  # 6 RGBA
                    r, g, b, a = px
                    if a < 255:
                        r = (r * a + 255 * (255 - a)) // 255
                        g = (g * a + 255 * (255 - a)) // 255
                        b = (b * a + 255 * (255 - a)) // 255
                    rgb[o], rgb[o + 1], rgb[o + 2] = r, g, b
        return ow, oh, bytes(rgb)
    except Exception:
        return None


def _jpeg_info(data):
    """(w, h, components) from a JPEG's SOF marker, or None."""
    try:
        if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
            return None
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            ln = (data[i + 2] << 8) | data[i + 3]
            if marker in (0xC0, 0xC1, 0xC2):
                hh = (data[i + 5] << 8) | data[i + 6]
                ww = (data[i + 7] << 8) | data[i + 8]
                return ww, hh, data[i + 9]
            i += 2 + ln
    except Exception:
        pass
    return None


def _pdf_image_load(path):
    """Image dict for PDF embedding, or None. Never raises.

    PNG -> decoded to RGB (stdlib) for FlateDecode; JPEG -> passed
    through for DCTDecode. Anything else is not embeddable here."""
    import zlib as _zl
    try:
        data = Path(path).read_bytes()
    except Exception:
        return None
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            dec = _png_decode_rgb(data)
            if dec is None:
                return None
            w, h, rgb = dec
            return {"w": w, "h": h, "filter": "FlateDecode",
                    "cs": "/DeviceRGB", "data": _zl.compress(rgb, 6)}
        if data[:2] == b"\xff\xd8":
            info = _jpeg_info(data)
            if not info:
                return None
            w, h, comps = info
            if comps == 3:
                cs = "/DeviceRGB"
            elif comps == 1:
                cs = "/DeviceGray"
            else:
                return None
            return {"w": w, "h": h, "filter": "DCTDecode",
                    "cs": cs, "data": data}
    except Exception:
        return None
    return None


def _pdf_safe_image_path(p):
    """p as a PNG/JPEG file path (a cached WebP is converted first,
    exactly like the main list's ensure path), or None."""
    try:
        p = Path(p)
        if not p.is_file() or p.stat().st_size <= 0:
            return None
        suf = p.suffix.lower()
        if suf in (".png", ".jpg", ".jpeg"):
            return p
        if suf == ".webp":
            return _icon_convert_cached_webp(p)
    except Exception:
        pass
    return None


def _cached_face_entries(cache_dir, fname):
    """{package: entry} from a cached faces manifest (no network --
    a report must never wait on, or fail because of, a download)."""
    try:
        raw = (cache_dir / fname).read_bytes()
        data = json.loads(raw.decode("utf-8"))
        out = {}
        for e in data.get("faces", []):
            if isinstance(e, dict) and e.get("package"):
                out[str(e["package"])] = e
        return out
    except Exception:
        return {}


def _report_bytes_path(name, data):
    """Write embedded PNG bytes to a temp file for PDF embedding."""
    import tempfile as _tf
    try:
        p = os.path.join(_tf.gettempdir(), name)
        if not os.path.isfile(p):
            with open(p, "wb") as f:
                f.write(data)
        return _pdf_safe_image_path(p)
    except Exception:
        return None


def _report_icon_file(pkg):
    """The icon file the main list would show for pkg, or None --
    same resolution order (spec 6.10 / 11.4): (0) the companion
    phone-helper PNG when one is cached, (1) the icon pulled off
    the phone (icon cache), (2) the known-faces pack, (3) the Face
    Book store face, (4) a verified maker badge, (5) the generic
    APP chip -- so a report strip entry is never blank."""
    try:
        p = _resolved_icon_file(pkg)   # companion -> extracted face
        if p is not None:
            q = _pdf_safe_image_path(p)
            if q is not None:
                return q
    except Exception:
        pass
    for cache_dir, fname in ((_appfaces_cache_dir(), "appfaces.json"),
                             (_faces_cache_dir(), "faces.json")):
        try:
            e = _cached_face_entries(cache_dir, fname).get(pkg) or {}
            if e.get("status") == "found" and e.get("icon"):
                q = _pdf_safe_image_path(cache_dir / str(e["icon"]))
                if q is not None:
                    return q
        except Exception:
            pass
    try:
        _key = _maker_for(pkg)
        _data = _maker_chip_png(_key) if _key else None
        if _data:
            q = _report_bytes_path("adt_report_maker_%s.png" % _key,
                                   _data)
            if q is not None:
                return q
    except Exception:
        pass
    try:
        _data = _generic_chip_png()
        if _data:
            q = _report_bytes_path("adt_report_app_chip.png", _data)
            if q is not None:
                return q
    except Exception:
        pass
    return None


def _report_strip_resolved(threats, limit=8, numbers=None):
    """[(path, image_dict, original_number)] for findings in scan
    order (deduplicated by package), for the page-1 icon strip
    (spec 11.4: ~0.32-0.38in icons, original number beneath each).
    Every verdict is eligible; the fallback order in
    _report_icon_file ends at the maker badge / APP chip, so an
    entry is only missing when nothing at all can be embedded.
    Best-effort: returns whatever resolved, never raises."""
    out = []
    seen = set()
    try:
        for _idx, item in enumerate(threats or []):
            if len(out) >= limit:
                break
            _label, pkg, _reasons, _verdict = (list(item) + [""] * 4)[:4]
            pkg = str(pkg or "")
            if not pkg or pkg in seen:
                continue
            seen.add(pkg)
            p = _report_icon_file(pkg)
            if p is None:
                continue
            img = _pdf_image_load(p)
            if img is not None:
                if isinstance(numbers, dict) and pkg in numbers:
                    num = numbers[pkg]
                else:
                    num = _idx + 1
                out.append((p, img, num))
    except Exception:
        pass
    return out


def verdict_word(verdict):
    """User-facing verdict word for an internal verdict code
    (spec 3.2 vocabulary: REMOVE / KEEP / ASK FIRST)."""
    v = str(verdict or "").strip().lower()
    return {"remove": "REMOVE", "review": "ASK FIRST",
            "ask": "ASK FIRST", "clean": "KEEP", "ok": "KEEP",
            "keep": "KEEP"}.get(v, v.upper() or "KEEP")


def _cleanup_result(action, is_kept):
    """Cleanup-result column text for the findings table (11.7)."""
    if is_kept:
        return "Reviewed and kept"
    a = str(action or "").strip()
    if not a:
        return "Cleanup not performed"
    low = a.lower()
    if "could not" in low:
        return "Could not remove - needs manual step"
    if "device admin stripped" in low:
        return "Removed (admin stripped)"
    if "uninstall" in low or "removed" in low:
        return "Removed"
    if "disabl" in low:
        return "Disabled"
    if "block" in low:
        return "Blocked"
    if "kept" in low:
        return "Reviewed and kept"
    return a[:60]


def _report_findings(threats, actions_taken, kept=None, numbers=None):
    """Findings-table rows (spec 11.7):
    [(original_number, application, package, verdict_word,
      cleanup_result, full_reason)] -- threats first, then kept
    apps not already listed, deduplicated by package. The reason
    is the FULL scanner reason, never truncated."""
    rows = []
    seen = set()
    amap = {}
    for _lbl, _act in (actions_taken or []):
        amap[str(_lbl)] = _act
    kept_pkgs = set()
    kept_lbls = set()
    for _k in (kept or []):
        if len(_k) > 1:
            kept_pkgs.add(str(_k[1]))
        if len(_k) > 0:
            kept_lbls.add(str(_k[0]))
    for item in list(threats or []) + list(kept or []):
        label, pkg, reasons, verdict = (list(item) + [""] * 4)[:4]
        pkg = str(pkg or "")
        label = str(label or pkg)
        key = pkg or label
        if not key or key in seen:
            continue
        seen.add(key)
        act = amap.get(label, amap.get(pkg))
        is_kept = act is None and (pkg in kept_pkgs or label in kept_lbls)
        if isinstance(numbers, dict) and pkg in numbers:
            num = numbers[pkg]
        else:
            num = len(rows) + 1
        rows.append((num, label, pkg, verdict_word(verdict),
                     _cleanup_result(act, is_kept),
                     _reasons_str(reasons)))
    return rows


def _critical_span(reason, vword):
    """(start, end) of the ONE critical phrase inside a printed
    findings reason, or None -- the first loud boom segment, the
    same phrase the screen renderer bolds (spec 6.11 / 11.7 /
    15.4: exactly one). KEEP rows and phrase-less reasons get
    None. Render-time only, like the screen's segmentation."""
    internal = {"REMOVE": "remove", "ASK FIRST": "review"}.get(vword)
    if not internal or not reason:
        return None
    pos = 0
    for seg, loud in boom_segments(str(reason), internal):
        if loud:
            return (pos, pos + len(seg))
        pos += len(seg)
    return None


def _report_times(device_info, blank=False):
    """(scan_line, cleanup_line) -- SEPARATE Scan and Cleanup
    date/time lines (spec 11.5/11.6, AT-21 ruled with AT-8)."""
    if blank:
        return ("__________________", "__________________")
    scan = str((device_info or {}).get("scan_time") or "").strip()
    cleanup = str((device_info or {}).get("cleanup_time") or "").strip()
    if not scan:
        scan = time.strftime("%B %d, %Y - %I:%M %p")
    if not cleanup:
        cleanup = "Not performed as of this report."
    return (scan, cleanup)


def _reasons_str(r):
    if isinstance(r, (list, tuple)):
        return "; ".join(str(x) for x in r)
    return str(r or "")


def _t(s):
    """Make text safe for the PDF's core (latin-1) fonts.

    Em/en dashes are NOT flattened to hyphens (fix round D3):
    they ride as their WinAnsi/cp1252 byte values (0x97 / 0x96,
    carried here as the matching latin-1 code points), so the
    pinned shop header line and the 11.11 footer print REAL
    dashes -- the latin-1 encode below emits exactly those
    bytes, and WinAnsiEncoding (the core-font encoding both
    writers produce) renders them as dashes. Everything else
    unsafe flattens exactly as before."""
    t = str(s or "")
    t = (t.replace("\u2022", "-").replace("\u2192", "->")
          .replace("\u2014", "\u0097").replace("\u2013", "\u0096")
          .replace("\u2018", "'").replace("\u2019", "'")
          .replace("\u201c", '"').replace("\u201d", '"')
          .replace("\u2026", "...").replace("\u26a0", "!"))
    return t.encode("latin-1", "replace").decode("latin-1")


def _pdf_escape(t):
    return (_t(t).replace("\\", "\\\\").replace("(", "\\(")
            .replace(")", "\\)"))


def _write_simple_pdf(path, lines, strip_images=None, strip_after=-1,
                      strip_labels=None):
    """Minimal stdlib PDF writer (core Helvetica only).

    lines: [(text, bold, size, gap_after)] -- wrapped and paginated
    onto US Letter pages (612x792 pt), each carrying the spec 11.11
    footer ("AdTrapper \\u2014 iFixx Phone Repairs" / "Page X of Y").
    Used only by the emergency fallback report.

    Two entry extensions serve the findings table (fix round D1/D4):
    an entry may carry a 5th element, a tag -- "thead" marks the
    findings-table header entry and "trow" a findings row. When the
    table spans a page break the header repeats at the top of the
    next page (spec 11.12), and a row that does not fit in the
    remaining space moves whole to the next page instead of
    splitting mid-row. And an entry's text may be a list of
    (chunk, bold) spans instead of a plain string: the spans wrap
    word-by-word with the bold chunks preserved, so the Reason
    column's one critical phrase prints in Helvetica-Bold (11.7).

    strip_images: optional [_pdf_image_load dicts] drawn as one row
    on page 1 right after the lines entry at index strip_after
    (icon strip); any problem with them and the report is
    written without the strip -- a report ALWAYS comes out."""
    import textwrap

    def _visual_lines(content, bold, size):
        """One entry -> its wrapped visual lines, each a list of
        (chunk, bold) spans. Plain text wraps by character count,
        exactly as the shipped writer did."""
        maxc = max(24, int(500.0 / (size * 0.50)))
        if not isinstance(content, list):
            return [[(wl, bold)] for wl in
                    (textwrap.wrap(str(content), maxc) or [""])]
        # Rich spans: word tokens keep their bold flag, and the
        # space before a word rides inside that word's chunk.
        # Bold glyphs are wider than regular ones, so they count
        # 1.12 chars against the measure -- a bold-heavy line
        # cannot overflow it.
        pieces = []
        for txt, b in content:
            for w in str(txt).split(" "):
                if not w:
                    continue
                b = bool(b)
                step = max(1, int(maxc / (1.12 if b else 1.0)))
                while len(w) * (1.12 if b else 1.0) > maxc \
                        and len(w) > 1:
                    pieces.append((w[:step], b))
                    w = w[step:]
                pieces.append((w, b))
        wrapped, cur, cur_len = [], [], 0.0
        for w, b in pieces:
            wl = len(w) * (1.12 if b else 1.0)
            add = wl if not cur else wl + 1.0
            if cur and cur_len + add > maxc:
                wrapped.append(cur)
                cur, cur_len = [(w, b)], wl
            else:
                cur.append((w, b))
                cur_len += add
        if cur or not wrapped:
            wrapped.append(cur)
        out = []
        for line in wrapped:
            chunks = []
            for i, (w, b) in enumerate(line):
                piece = w if i == 0 else " " + w
                if chunks and chunks[-1][1] == b:
                    chunks[-1] = (chunks[-1][0] + piece, b)
                else:
                    chunks.append((piece, b))
            out.append(chunks or [("", False)])
        return out

    pages, cur, y = [], [], 742.0
    placements = []  # (img_idx, x, y_bottom, w_pt, h_pt) for page 1
    # Strip band: icons (top-inset 9) + the number row beneath them
    # + clear space under the numbers, so the numbers never share
    # the next line's baseline (micro fix: strip number overlap).
    strip_h = 54.0
    header = None    # (visual lines, size, gap) of the thead entry

    def _break_page(repeat_header):
        nonlocal cur, y
        pages.append(cur)
        cur, y = [], 742.0
        if repeat_header and header:
            hv, hs, hg = header
            for spans in hv:
                cur.append((42, y, spans, hs))
                y -= hs * 1.5
            y -= hg

    for li, entry in enumerate(lines):
        content = entry[0]
        bold = entry[1] if len(entry) > 1 else False
        size = entry[2]
        gap = entry[3] if len(entry) > 3 else 0
        tag = entry[4] if len(entry) > 4 else None
        vis = _visual_lines(content, bold, size)
        h = size * 1.5
        if tag == "thead":
            header = (vis, size, gap)
        moved = False
        if tag == "trow" and header:
            # Spec 11.12: keep the row together -- if it does not
            # fit in the remaining space but fits on a fresh page
            # under the repeated header, move it there whole.
            need = len(vis) * h
            if y - need < 48:
                hv, hs, hg = header
                fresh = 742.0 - len(hv) * (hs * 1.5) - hg
                if fresh - need >= 48:
                    _break_page(True)
                    for spans in vis:
                        cur.append((42, y, spans, size))
                        y -= h
                    y -= gap
                    moved = True
        if not moved:
            for spans in vis:
                if y - h < 48:
                    _break_page(tag == "trow")
                cur.append((42, y, spans, size))
                y -= h
            y -= gap
        if strip_images and li == strip_after and not pages:
            try:
                ih = 24.0   # ~0.33in icons (spec 11.4), number beneath
                widths = [ih * (im["w"] / float(im["h"]))
                          for im in strip_images]
                total = sum(widths) + 16.0 * (len(widths) - 1)
                if total > 511.0:
                    s = 511.0 / total
                    ih *= s
                    widths = [w_ * s for w_ in widths]
                    total = 511.0
                if y - strip_h >= 48:
                    x = 42.0 + (511.0 - total) / 2.0
                    y -= strip_h
                    # Icons keep their 9 pt top inset from the band
                    # top; the number row rides 8 pt under them and
                    # the rest of the band is clear space, so the
                    # numbers stand clear of the next text line.
                    iy = y + strip_h - 9.0 - ih
                    for k, wpt in enumerate(widths):
                        placements.append((k, x, iy, wpt, ih))
                        x += wpt + 16.0
            except Exception:
                placements = []
    if cur or not pages:
        pages.append(cur)
    objs = []  # (num, bytes)

    def obj(num, body):
        objs.append((num, body if isinstance(body, bytes)
                     else body.encode("latin-1", "replace")))

    page_nums = [4 + 2 * i for i in range(len(pages))]
    obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, "<< /Type /Pages /Kids [%s] /Count %d >>"
        % (" ".join("%d 0 R" % n for n in page_nums), len(pages)))
    obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    obj(4 + 2 * len(pages),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    bold_num = 4 + 2 * len(pages)
    img_nums = []
    if placements and strip_images:
        try:
            for k, im in enumerate(strip_images):
                num = bold_num + 1 + k
                img_nums.append(num)
                hdr = ("<< /Type /XObject /Subtype /Image /Width %d "
                       "/Height %d /ColorSpace %s /BitsPerComponent 8 "
                       "/Filter /%s /Length %d >>\nstream\n"
                       % (im["w"], im["h"], im["cs"], im["filter"],
                          len(im["data"])))
                obj(num, hdr.encode("latin-1") + im["data"]
                    + b"\nendstream")
        except Exception:
            img_nums = []
            placements = []
    for i, pg in enumerate(pages):
        content = []
        if i == 0 and placements:
            for k, x, iy, wpt, ih in placements:
                content.append("q %.1f 0 0 %.1f %.1f %.1f cm /Im%d Do Q"
                               % (wpt, ih, x, iy, k))
            if strip_labels:
                for (k, x, iy, wpt, ih), _lab in zip(placements,
                                                     strip_labels):
                    if _lab is None or str(_lab) == "":
                        continue
                    _s = str(_lab)
                    content.append(
                        "BT /F1 7 Tf %.1f %.1f Td (%s) Tj ET"
                        % (x + wpt / 2.0 - 2.0 * len(_s), iy - 8.0,
                           _pdf_escape(_s)))
        for x, yy, spans, size in pg:
            ops = ["%.1f %.1f Td" % (x, yy)]
            for chunk, cbold in spans:
                ops.append("/F%d %d Tf (%s) Tj"
                           % (2 if cbold else 1, size,
                              _pdf_escape(chunk)))
            content.append("BT " + " ".join(ops) + " ET")
        # spec 11.11 footer on EVERY page
        content.append("BT /F1 8 Tf 42 24 Td (%s) Tj ET"
                       % _pdf_escape("AdTrapper \u2014 iFixx Phone Repairs"))
        _rt = "Page %d of %d" % (i + 1, len(pages))
        content.append("BT /F1 8 Tf %.1f 24 Td (%s) Tj ET"
                       % (570.0 - 4.4 * len(_rt), _pdf_escape(_rt)))
        stream = "\n".join(content).encode("latin-1", "replace")
        obj(5 + 2 * i, ("<< /Length %d >>\nstream\n" % len(stream)).encode(
            "latin-1") + stream + b"\nendstream")
        res = ("/Resources << /Font << /F1 3 0 R /F2 %d 0 R >>" % bold_num)
        if i == 0 and img_nums:
            res += (" /XObject << %s >>" % " ".join(
                "/Im%d %d 0 R" % (k, n) for k, n in enumerate(img_nums)))
        res += " >> "
        obj(4 + 2 * i,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            + res + "/Contents %d 0 R >>" % (5 + 2 * i))
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for num, body in sorted(objs):
        offsets[num] = len(out)
        out += ("%d 0 obj\n" % num).encode("latin-1") + body + b"\nendobj\n"
    xref = len(out)
    maxnum = max(offsets) if offsets else 0
    out += ("xref\n0 %d\n" % (maxnum + 1)).encode("latin-1")
    out += b"0000000000 65535 f \n"
    for n in range(1, maxnum + 1):
        out += ("%010d 00000 n \n" % offsets.get(n, 0)).encode("latin-1")
    out += ("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF"
            % (maxnum + 1, xref)).encode("latin-1")
    with open(path, "wb") as f:
        f.write(bytes(out))
    return path


def _fallback_customer_report(device_info, threats, actions_taken, sites,
                              scan_summary, save_dir, kept=None,
                              numbers=None):
    """Emergency report used ONLY when the fpdf library cannot be
    loaded on this PC. Same ruled format as the real report
    (v11.0, AT-8 TABLE ruling): pinned shop header line, separate
    Scan / Cleanup date-time lines, page-1 icon strip with the
    original number beneath each icon, the section 11.7
    six-column findings table, the section 11.10 disclaimer, and
    per-page footers (in _write_simple_pdf). Plain layout, so a
    report is ALWAYS produced; empty customer / ticket /
    technician details print as hand-fill lines."""
    import time

    n_found = len(threats or []) + len(kept or [])
    n_sites = len(sites or [])
    n_removed = sum(1 for _, a in (actions_taken or [])
                    if "could not" not in str(a).lower()
                    and "kept" not in str(a).lower())
    n_kept = len(kept or [])
    findings = _report_findings(threats, actions_taken, kept=kept,
                                 numbers=numbers)
    if not (threats or kept) and n_sites == 0:
        result = ("No threats were found on this device. Your apps, "
                  "permissions and notification senders were all "
                  "reviewed.")
    elif (threats or kept) and n_removed == 0 and n_kept and n_sites == 0:
        result = ("We found %d app(s) that needed a closer look. "
                  "After review they were left on the phone - see "
                  "the findings table below. Nothing had to be "
                  "removed." % n_found)
    elif (threats or kept) and n_removed == n_found and n_sites == 0:
        result = ("The pop-ups have been stopped. We found and "
                  "removed %d unwanted app(s) that were causing them."
                  % n_found)
    elif (threats or kept) and n_removed and n_kept and n_sites == 0:
        result = ("We found and removed %d unwanted app(s). %d app(s) "
                  "were reviewed and kept on the phone."
                  % (n_removed, n_kept))
    elif (threats or kept) and n_sites == 0:
        result = ("We found %d unwanted app(s). %d were removed; the "
                  "rest need a manual step (see below)."
                  % (n_found, n_removed))
    elif not (threats or kept):
        result = ("No bad apps were found, but %d website(s) were "
                  "allowed to send pop-up notifications." % n_sites)
    else:
        result = ("We found and removed %d unwanted app(s), and "
                  "found %d website(s) allowed to send pop-up "
                  "notifications." % (n_removed, n_sites))

    def _blank(v):
        v = str(v or "").strip()
        return v if v else "__________________"

    scan_s, cleanup_s = _report_times(device_info)
    L = []
    L.append((SHOP_NAME, True, 20, 2))
    L.append((REPORT_TITLE, True, 13, 2))
    L.append((REPORT_SUBTITLE, False, 10, 0))
    L.append((SHOP_HEADER_LINE, False, 10, 6))
    L.append(("Scan date/time: %s" % scan_s, False, 10, 2))
    L.append(("Cleanup date/time: %s" % cleanup_s, False, 10, 6))
    L.append(("DEVICE: %s    ANDROID: %s    SERIAL: %s"
              % (_blank(device_info.get("model")),
                 _blank(device_info.get("android")),
                 _blank(device_info.get("serial"))), False, 10, 2))
    L.append(("CUSTOMER: %s    TICKET NO.: %s"
              % (_blank(device_info.get("customer")),
                 _blank(device_info.get("ticket"))), False, 10, 8))
    strip_after = len(L) - 1
    if str(device_info.get("ticket", "") or "").strip():
        # Removal History (2026-10-21): the customer leaves holding
        # the same key the shop searches the removal log by.
        L.append(("Removals from this job are logged under this "
                  "ticket.", False, 9, 6))
    L.append(("RESULT", True, 11, 2))
    L.append((result, False, 10, 4))
    L.append((REPORT_DISCLAIMER, False, 9, 2))
    L.append(("Privacy: we did not open, copy, or access your "
              "messages, photos, or accounts. This inspection checks "
              "apps and permissions only.", False, 9, 2))
    L.append(("Scope: this report covers the inspection on the date "
              "shown. It is not a guarantee against future infections.",
              False, 9, 8))
    ss = scan_summary or {}
    L.append(("SCAN SUMMARY", True, 11, 3))
    L.append(("Total apps scanned: %s" % ss.get("apps", 0), False, 9, 2))
    L.append(("REMOVE findings: %d"
              % sum(1 for f in findings if f[3] == "REMOVE"),
              False, 9, 2))
    L.append(("ASK FIRST findings: %d"
              % sum(1 for f in findings if f[3] == "ASK FIRST"),
              False, 9, 2))
    L.append(("Successfully removed: %d" % n_removed, False, 9, 2))
    L.append(("Reviewed and kept: %d" % n_kept, False, 9, 8))
    L.append(("SCAN FINDINGS", True, 11, 3))
    L.append(("# | APPLICATION | PACKAGE | VERDICT | CLEANUP RESULT "
              "| REASON", True, 9, 3, "thead"))
    if findings:
        for num, label, pkg, vword, clean_res, reason in findings:
            _pre = ("%s | %s | %s | %s | %s | "
                    % (num, label, pkg, vword, clean_res))
            _sp = _critical_span(reason, vword)
            if _sp:
                _spans = [(_pre + reason[:_sp[0]], False),
                          (reason[_sp[0]:_sp[1]], True),
                          (reason[_sp[1]:], False)]
                _spans = [(t_, b_) for t_, b_ in _spans if t_]
            else:
                _spans = [(_pre + reason, False)]
            L.append((_spans, False, 9, 2, "trow"))
    else:
        L.append(("No findings - no applications were flagged in "
                  "this scan.", False, 9, 2))
    L.append(("", False, 9, 6))
    L.append(("CLEANUP RESULTS", True, 11, 3))
    if not actions_taken:
        # Section 11.8 (fix round D2): the sentence keys on whether
        # a cleanup was performed -- a review-only job (kept rows,
        # no actions) prints it too.
        L.append(("Cleanup not performed as of this report.",
                  False, 9, 6))
    else:
        L.append(("Applications successfully removed: %d" % n_removed,
                  False, 9, 2))
        L.append(("Applications not removed: %d"
                  % max(0, len(findings) - n_removed - n_kept),
                  False, 9, 2))
        L.append(("Applications requiring customer review: %d"
                  % n_kept, False, 9, 6))
    if sites:
        L.append(("WEBSITES ALLOWED TO SEND POP-UPS", True, 11, 3))
        for dstr, host in sites[:20]:
            L.append(("%s (allowed since %s)" % (host, dstr),
                      False, 9, 2))
        L.append(("", False, 9, 6))
    L.append(("CHECKED - NO PROBLEMS FOUND", True, 11, 3))

    def _res(n):
        return ("%d flagged - see above" % n) if n else "None found - normal"
    L.append(("Apps with pop-up (overlay) permission: %s"
              % _res(ss.get("overlay", 0)), False, 9, 2))
    L.append(("Device administrator apps: %s"
              % _res(ss.get("admin", 0)), False, 9, 2))
    L.append(("Accessibility services in use: %s"
              % _res(ss.get("a11y", 0)), False, 9, 2))
    L.append(("Websites allowed to send notifications: %s"
              % _res(len(sites or [])), False, 9, 8))
    L.append(("HOW TO STAY SAFE", True, 11, 3))
    for t in STAY_SAFE_TIPS:
        L.append(("- " + t, False, 9, 3))
    L.append(("", False, 9, 6))
    L.append((SHOP_HEADER_LINE, False, 9, 2))
    _tech = str(device_info.get("technician", "") or "").strip()
    L.append(("Technician: %s" % (_tech[:28] if _tech
                                   else "____________________"),
              False, 10, 2))
    L.append(("Customer: ____________________", False, 10, 2))
    L.append(("Date: ____________________", False, 10, 0))

    os.makedirs(save_dir, exist_ok=True)
    _tickf = re.sub(r"[^A-Za-z0-9-]+", "",
                    str(device_info.get("ticket", "") or "").strip())
    if _tickf:
        fname = "cleanup-report-%s.pdf" % _tickf
    else:
        fname = "PhoneCleanup_%s.pdf" % time.strftime("%Y%m%d_%H%M%S")
    _strip = []
    _labels = []
    try:
        _all = list(threats or []) + list(kept or [])
        _res_strip = _report_strip_resolved(_all, numbers=numbers)
        _strip = [img for _p, img, _n in _res_strip]
        _labels = [_n for _p, img, _n in _res_strip]
    except Exception:
        _strip, _labels = [], []
    return _write_simple_pdf(os.path.join(save_dir, fname), L,
                             strip_images=_strip, strip_after=strip_after,
                             strip_labels=_labels)


def generate_customer_report(device_info, threats, actions_taken, sites,
                             scan_summary, save_dir, blank=False,
                             kept=None, numbers=None):
    """Build the iFixx Repairs AdTrapper cleanup report PDF (v11.0).

    Ruled format (AT-8 OWNER RULING 2026-10-17: TABLE): the
    section 11.7 six-column findings table is the findings format
    -- # (original scan number) / Application / Package / Verdict
    (REMOVE / KEEP / ASK FIRST) / Cleanup result / Reason (the
    FULL scanner reason, critical phrase untruncated). US Letter,
    pinned shop header line, clean phone/shield mark (no legacy
    characters art, AT-7), page-1 icon strip (11.4), separate
    Scan and Cleanup date/time lines, section 11.10 disclaimer,
    and a footer on every page (11.11). The shipped bank-edition
    identifier behavior stands for ticket jobs (device model /
    serial / customer / ticket / technician print as recorded).

    device_info: {"model", "android", "serial", ...}
    threats: [(label, pkg, reasons, verdict)] -- reasons list|str
    actions_taken: [(label, action_str)]
    sites: [(date_str, host)] notification senders found
    scan_summary: {"apps": N, "overlay": n, "admin": n, "a11y": n}
    blank: True -> printable hand-fillable template
    kept: [(label, pkg, reasons, verdict)] reviewed-and-kept apps;
    they appear in the findings table as ASK FIRST / Reviewed
    and kept. numbers: {pkg: original_number} from the scan
    snapshot (AT-2/AT-19); when absent, findings number in the
    order given. Returns the PDF path; if the PDF lib is missing
    on this PC, a stdlib fallback report is written instead of
    returning None."""
    try:
        from fpdf import FPDF
    except ImportError:
        return _fallback_customer_report(
            device_info, threats, actions_taken, sites, scan_summary,
            save_dir, kept=kept, numbers=numbers)
    import time

    X0 = 14.0          # left/right margins 0.55in on US Letter
    W = 188.0          # usable width (215.9 - 2*14)
    BOTTOM = 263.0     # last usable y (279.4 - ~16mm bottom margin)
    PCOL = {"REMOVE": (180, 35, 24), "KEEP": (23, 101, 52),
            "ASK FIRST": (128, 80, 0)}
    DARK = (24, 34, 48)

    class _ReportPDF(FPDF):
        def footer(self):
            try:
                self.set_y(-14)
                self.set_draw_color(205, 213, 223)
                self.set_line_width(0.2)
                self.line(X0, self.get_y(), X0 + W, self.get_y())
                self.set_font("Helvetica", "", 8)
                self.set_text_color(83, 98, 115)
                self.cell(W / 2, 8,
                          _t("AdTrapper \u2014 iFixx Phone Repairs"))
                self.cell(W / 2, 8, "Page %d of {nb}" % self.page_no(),
                          align="R")
                self.set_text_color(0, 0, 0)
            except Exception:
                pass

    pdf = _ReportPDF(orientation="P", unit="mm", format="Letter")
    try:
        pdf.alias_nb_pages("{nb}")
    except Exception:
        pass
    pdf.set_margins(X0, 13, X0)
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    def rule(w=0.6, color=(8, 127, 158)):
        pdf.set_draw_color(*color)
        pdf.set_line_width(w)
        pdf.line(X0, pdf.get_y(), X0 + W, pdf.get_y())
        pdf.ln(4)

    def section_title(t):
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 7, t.upper(), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

    def thin_line():
        pdf.set_draw_color(205, 213, 223)
        pdf.set_line_width(0.2)
        pdf.line(X0, pdf.get_y(), X0 + W, pdf.get_y())

    def wrap_lines(txt, width_mm, max_lines=99):
        toks = []
        for wd in str(txt).split(" "):
            while pdf.get_string_width(wd) > width_mm and len(wd) > 1:
                cut = -1
                for i, ch in enumerate(wd):
                    if pdf.get_string_width(wd[:i + 1]) > width_mm:
                        break
                    if ch == ".":
                        cut = i
                if cut < 0:
                    n = 1
                    while n < len(wd) and \
                            pdf.get_string_width(wd[:n + 1]) <= width_mm:
                        n += 1
                    cut = n - 1
                toks.append(wd[:cut + 1])
                wd = wd[cut + 1:]
            toks.append(wd)
        lines, cur = [], ""
        for wd in toks:
            trial = (cur + " " + wd) if cur else wd
            if pdf.get_string_width(trial) <= width_mm or not cur:
                cur = trial
            else:
                lines.append(cur)
                cur = wd
                if len(lines) >= max_lines:
                    return lines
        if cur:
            lines.append(cur)
        return lines[:max_lines] or [""]

    def wrap_segments(segs, width_mm):
        # Rich wrap for one cell (fix round D4): [(text, bold), ...]
        # -> wrapped lines of merged (chunk, bold) runs, each word
        # measured with its own font so bold text wraps at its true
        # width. Mirrors wrap_lines (space-split tokens, over-long
        # words cut); the space before a word rides inside that
        # word's chunk, and the first line carries the same leading
        # pad the plain path gets from its " " + text.
        words = []
        for txt, b in segs:
            for w in str(txt).split(" "):
                if w:
                    words.append((w, bool(b)))
        toks = []
        for w, b in words:
            pdf.set_font("Helvetica", "B" if b else "", 8.5)
            while pdf.get_string_width(w) > width_mm and len(w) > 1:
                cut = -1
                for i, ch in enumerate(w):
                    if pdf.get_string_width(w[:i + 1]) > width_mm:
                        break
                    if ch == ".":
                        cut = i
                if cut < 0:
                    n = 1
                    while n < len(w) and \
                            pdf.get_string_width(w[:n + 1]) <= width_mm:
                        n += 1
                    cut = n - 1
                toks.append((w[:cut + 1], b))
                w = w[cut + 1:]
            toks.append((w, b))
        pdf.set_font("Helvetica", "", 8.5)
        space_w = pdf.get_string_width(" ")

        def _tok_w(tok):
            pdf.set_font("Helvetica", "B" if tok[1] else "", 8.5)
            return pdf.get_string_width(tok[0])

        wrapped, cur, cur_w = [], [], 0.0
        for tok in toks:
            tw = _tok_w(tok)
            add = tw if not cur else tw + space_w
            if cur and cur_w + add > width_mm:
                wrapped.append(cur)
                cur, cur_w = [tok], tw
            else:
                cur.append(tok)
                cur_w += add
        if cur:
            wrapped.append(cur)
        if not wrapped:
            return [[(" ", False)]]
        out = []
        for li, line in enumerate(wrapped):
            chunks = []
            for i, (w, b) in enumerate(line):
                piece = w if i == 0 else " " + w
                if chunks and chunks[-1][1] == b:
                    chunks[-1] = (chunks[-1][0] + piece, b)
                else:
                    chunks.append((piece, b))
            if li == 0:
                if chunks and not chunks[0][1]:
                    chunks[0] = (" " + chunks[0][0], False)
                else:
                    chunks.insert(0, (" ", False))
            out.append(chunks)
        return out

    def table_header(cols):
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(238, 242, 247)
        pdf.set_text_color(*DARK)
        for w_, txt in cols:
            pdf.cell(w_, 6, " " + txt, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln()
        thin_line()

    def draw_row(cells, lh=5.5, header_cols=None):
        # cells: [(width_mm, text, bold, color-or-None)] at 8.5pt;
        # full text, wrapped -- never truncated. A cell may carry
        # a 5th element, rich segments [(text, bold), ...]: the
        # bold chunks then print in Helvetica-Bold inside the same
        # wrapped flow (the findings Reason column, 11.7 / D4).
        parts = []
        n = 1
        for cell_ in cells:
            w_, txt, bold, _c = cell_[:4]
            segs = cell_[4] if len(cell_) > 4 else None
            pdf.set_font("Helvetica", "B" if bold else "", 8.5)
            if segs:
                ls = wrap_segments(segs, w_ - 2)
            else:
                ls = wrap_lines(" " + str(txt), w_ - 2)
            parts.append((w_, ls, bold, _c, bool(segs)))
            n = max(n, len(ls))
        if pdf.get_y() + lh * n > BOTTOM:
            pdf.add_page()
            if header_cols:
                table_header(header_cols)
        y0 = pdf.get_y()
        x = X0
        for w_, ls, bold, col, rich in parts:
            pdf.set_font("Helvetica", "B" if bold else "", 8.5)
            if col:
                pdf.set_text_color(*col)
            for i, ln in enumerate(ls):
                if rich:
                    cx = x
                    for chunk, cb in ln:
                        if not chunk:
                            continue
                        pdf.set_font("Helvetica", "B" if cb else "",
                                     8.5)
                        cw = pdf.get_string_width(chunk)
                        pdf.set_xy(cx, y0 + i * lh)
                        pdf.cell(cw + 0.3, lh, _t(chunk))
                        cx += cw
                else:
                    pdf.set_xy(x, y0 + i * lh)
                    pdf.cell(w_, lh, _t(ln))
            pdf.set_text_color(0, 0, 0)
            x += w_
        pdf.set_xy(X0, y0 + lh * n)
        thin_line()

    def short_action(act):
        return _cleanup_result(act, False)

    findings = _report_findings(threats, actions_taken, kept=kept,
                                 numbers=numbers)
    scan_s, cleanup_s = _report_times(device_info, blank=blank)

    # ---- header: clean phone/shield mark + wordmark (AT-6/AT-7) ----
    y_top = pdf.get_y()
    try:
        pdf.set_fill_color(13, 22, 38)
        pdf.set_draw_color(40, 199, 232)
        pdf.set_line_width(0.5)
        pdf.rect(X0, y_top, 11, 16, style="DF")
        pdf.set_fill_color(245, 248, 252)
        pdf.rect(X0 + 1.5, y_top + 1.5, 8, 11, style="F")
        try:
            pdf.set_fill_color(40, 199, 232)
            pdf.polygon([(X0 + 5.5, y_top + 3.6),
                         (X0 + 8.6, y_top + 4.8),
                         (X0 + 8.6, y_top + 7.8),
                         (X0 + 5.5, y_top + 10.8),
                         (X0 + 2.4, y_top + 7.8),
                         (X0 + 2.4, y_top + 4.8)], style="F")
        except Exception:
            pass
        pdf.set_draw_color(255, 255, 255)
        pdf.set_line_width(0.5)
        pdf.line(X0 + 3.9, y_top + 7.2, X0 + 5.2, y_top + 8.6)
        pdf.line(X0 + 5.2, y_top + 8.6, X0 + 7.3, y_top + 5.6)
    except Exception:
        pass
    tx = X0 + 17
    pdf.set_xy(tx, y_top)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*DARK)
    pdf.cell(80, 9, SHOP_NAME)
    pdf.set_xy(tx, y_top + 9)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(83, 98, 115)
    pdf.cell(80, 5, SHOP_TAGLINE)
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(104, y_top + 1)
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*DARK)
    pdf.cell(98, 7, "AdTrapper", align="R")
    pdf.set_xy(104, y_top + 8)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(98, 6, "Malware & Adware Cleanup Report", align="R")
    pdf.set_xy(104, y_top + 13)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(83, 98, 115)
    pdf.cell(98, 5, _t(REPORT_SUBTITLE), align="R")
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(X0, y_top + 19)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(W, 5, _t(SHOP_HEADER_LINE))
    pdf.set_y(y_top + 26)
    rule(0.6)

    # ---- page-1 icon strip (11.4): ~0.35in, number beneath each ----
    if not blank:
        _strip = []
        try:
            _all = list(threats or []) + list(kept or [])
            _strip = _report_strip_resolved(_all, numbers=numbers)
        except Exception:
            _strip = []
        if _strip:
            _sh = 9.0
            _widths = [_sh * (img["w"] / float(img["h"]))
                       for _p, img, _n in _strip]
            _total = sum(_widths) + 6.0 * (len(_widths) - 1)
            if _total > W:
                _sc = W / _total
                _sh *= _sc
                _widths = [w_ * _sc for w_ in _widths]
                _total = W
            _x = X0 + (W - _total) / 2.0
            _y = pdf.get_y()
            _drew = False
            for (_p, _img, _num), _iw in zip(_strip, _widths):
                try:
                    pdf.image(str(_p), x=_x, y=_y, w=_iw, h=_sh)
                    _drew = True
                    pdf.set_xy(_x - 2, _y + _sh + 0.5)
                    pdf.set_font("Helvetica", "", 7)
                    pdf.set_text_color(83, 98, 115)
                    pdf.cell(_iw + 4, 3.5, str(_num), align="C")
                    pdf.set_text_color(0, 0, 0)
                except Exception:
                    pass
                _x += _iw + 6.0
            if _drew:
                pdf.set_y(_y + _sh + 6)

    # ---- device / customer / ticket grid (identifiers as shipped) ----
    cols = ("DEVICE", "ANDROID", "SERIAL", "CUSTOMER", "TICKET NO.")
    col_w = W / 5
    pdf.set_draw_color(205, 213, 223)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*DARK)
    for i, c in enumerate(cols):
        pdf.cell(col_w, 5, c, border="LTR",
                 new_x="RIGHT" if i < 4 else "LMARGIN", new_y="TOP")
    pdf.ln()
    vals = [device_info.get("model", ""),
            device_info.get("android", ""),
            device_info.get("serial", ""),
            device_info.get("customer", ""),
            device_info.get("ticket", "")]
    if blank:
        vals = ["", "", "", "", ""]
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(0, 0, 0)
    for i, v in enumerate(vals):
        txt = (v or "")[:19]
        if i in (3, 4) and not txt:
            txt = "__________________"
        pdf.cell(col_w, 7, _t(txt), border="LBR",
                 new_x="RIGHT" if i < 4 else "LMARGIN", new_y="TOP")
    pdf.ln()
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(W, 5.5, "Scan date/time: %s" % scan_s,
             new_x="LMARGIN", new_y="NEXT")
    pdf.cell(W, 5.5, "Cleanup date/time: %s" % cleanup_s,
             new_x="LMARGIN", new_y="NEXT")
    if not blank and str(device_info.get("ticket", "") or "").strip():
        # Removal History (2026-10-21): the customer leaves holding
        # the same key the shop searches the removal log by.
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(W, 5.5,
                 "Removals from this job are logged under this ticket.",
                 new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # ---- result box (no black band: bordered, dark text) ----
    def result_text():
        n_found = len(threats or []) + len(kept or [])
        n_sites = len(sites or [])
        n_removed = sum(1 for _, a in (actions_taken or [])
                        if "could not" not in str(a).lower()
                        and "kept" not in str(a).lower())
        n_kept = len(kept or [])
        if n_found == 0 and n_sites == 0:
            return ("No threats were found on this device. Your apps, "
                    "permissions and notification senders were all "
                    "reviewed.")
        if n_found and n_removed == 0 and n_kept and n_sites == 0:
            return ("We found %d app(s) that needed a closer look. "
                    "After review they were left on the phone - see "
                    "the findings table below. Nothing had to be "
                    "removed." % n_found)
        if n_found and n_removed == n_found and n_sites == 0:
            return ("The pop-ups have been stopped. We found and removed "
                    "%d unwanted app(s) that were causing them." % n_found)
        if n_found and n_removed and n_kept and n_sites == 0:
            return ("We found and removed %d unwanted app(s). %d app(s) "
                    "were reviewed and kept on the phone."
                    % (n_removed, n_kept))
        if n_found and n_sites == 0:
            return ("We found %d unwanted app(s). %d were removed; the rest "
                    "need a manual step (see below)." % (n_found, n_removed))
        if n_found == 0:
            return ("No bad apps were found, but %d website(s) were allowed "
                    "to send pop-up notifications. Follow the cleanup steps "
                    "below to remove them." % n_sites)
        return ("We found and removed %d unwanted app(s), and found %d "
                "website(s) allowed to send pop-up notifications "
                "(cleanup steps below)." % (n_removed, n_sites))

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*DARK)
    pdf.cell(25, 6, "RESULT", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    x0, y0 = pdf.get_x(), pdf.get_y()
    pdf.set_xy(x0 + 2, y0 + 2)
    if blank:
        pdf.set_font("Helvetica", "", 10)
        for _ in range(3):
            pdf.cell(W - 4, 7, "_" * 88, new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(x0 + 2)
    else:
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(W - 4, 6, _t(result_text()))
    y1 = pdf.get_y() + 2
    pdf.set_draw_color(205, 213, 223)
    pdf.rect(X0, y0, W, y1 - y0)
    pdf.set_xy(X0, y1)
    pdf.ln(4)

    # ---- disclaimer (11.10) + privacy / scope facts (as shipped) ----
    if not blank:
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(W, 5.5, _t(REPORT_DISCLAIMER))
        pdf.ln(1)
        pdf.multi_cell(W, 5.5, _t(
            "Privacy: we did not open, copy, or access your messages, "
            "photos, or accounts. This inspection checks apps and "
            "permissions only."))
        pdf.ln(1)
        pdf.multi_cell(W, 5.5, _t(
            "Scope: this report covers the inspection on the date "
            "shown. It is not a guarantee against future infections."))
        pdf.ln(2)

    # ---- what it scanned for ----
    section_title("What it scanned for")
    pdf.set_font("Helvetica", "", 9)
    feats = []
    _threat_n = (scan_summary or {}).get("threat_count") or len(KNOWN_BAD)
    for lead, desc in SCAN_FEATURES:
        if "%d" in desc:
            try:
                desc = desc % int(_threat_n)
            except Exception:
                pass
        feats.append((lead, desc))
    for lead, desc in feats:
        pdf.cell(5, 5.5, "-")
        pdf.set_font("Helvetica", "B", 9)
        pdf.write(5.5, lead + " - ")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5.5, _t(desc))
        pdf.set_x(X0)
    n_apps = (scan_summary or {}).get("apps", 0)
    if n_apps and not blank:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "%d apps on this phone were individually checked."
                 % n_apps, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # ---- scan summary (11.6, one finalized count set) ----
    if not blank:
        section_title("Scan summary")
        pdf.set_font("Helvetica", "", 9)
        n_removed = sum(1 for _, a in (actions_taken or [])
                        if "could not" not in str(a).lower()
                        and "kept" not in str(a).lower())
        n_failed = sum(1 for _, a in (actions_taken or [])
                       if "could not" in str(a).lower())
        sum_lines = [
            "Total apps scanned: %d" % int(n_apps or 0),
            "REMOVE findings: %d"
            % sum(1 for f in findings if f[3] == "REMOVE"),
            "ASK FIRST findings: %d"
            % sum(1 for f in findings if f[3] == "ASK FIRST"),
            "KEEP findings: %d"
            % max(0, int(n_apps or 0) - len(findings)),
            "Successfully removed: %d" % n_removed,
            "Removal failures: %d" % n_failed,
            "Customer-review items: %d" % len(kept or []),
        ]
        for _sl in sum_lines:
            pdf.cell(W, 5.5, _sl, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # ---- findings table (11.7): the ruled findings format ----
    section_title("Scan findings")
    fcols = [(10, "#"), (32, "APPLICATION"), (40, "PACKAGE"),
             (20, "VERDICT"), (30, "CLEANUP RESULT"), (56, "REASON")]
    table_header(fcols)
    if blank:
        for _ in range(5):
            draw_row([(10, "", False, None), (32, "", False, None),
                      (40, "", False, None), (20, "", False, None),
                      (30, "", False, None), (56, "", False, None)],
                     lh=6.5, header_cols=fcols)
    elif findings:
        for num, label, pkg, vword, clean_res, reason in findings:
            _rcell = (56, reason, False, None)
            _sp = _critical_span(reason, vword)
            if _sp:
                _rcell = (56, reason, False, None,
                          [(reason[:_sp[0]], False),
                           (reason[_sp[0]:_sp[1]], True),
                           (reason[_sp[1]:], False)])
            draw_row([(10, str(num), True, None),
                      (32, label, True, None),
                      (40, pkg, False, None),
                      (20, vword, True, PCOL.get(vword)),
                      (30, clean_res, False, None),
                      _rcell],
                     header_cols=fcols)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(W, 6, "No findings - no applications were flagged "
                       "in this scan.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # ---- cleanup results (11.8) ----
    if not blank:
        section_title("Cleanup results")
        pdf.set_font("Helvetica", "", 9)
        if not actions_taken:
            # Section 11.8 (fix round D2): keys on cleanup performed,
            # not on the kept list -- review-only jobs print it too.
            pdf.multi_cell(W, 5.5, "Cleanup not performed as of this "
                                   "report.")
        else:
            n_removed = sum(1 for _, a in (actions_taken or [])
                            if "could not" not in str(a).lower()
                            and "kept" not in str(a).lower())
            pdf.cell(W, 5.5, "Applications successfully removed: %d"
                     % n_removed, new_x="LMARGIN", new_y="NEXT")
            pdf.cell(W, 5.5, "Applications not removed: %d"
                     % max(0, len(findings) - n_removed - len(kept or [])),
                     new_x="LMARGIN", new_y="NEXT")
            pdf.cell(W, 5.5, "Applications requiring customer review: %d"
                     % len(kept or []), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # ---- notification senders ----
    if not blank and sites:
        section_title("Websites allowed to send pop-ups")
        table_header([(120, "WEBSITE"), (68, "ALLOWED SINCE")])
        for dstr, host in sites[:20]:
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(120, 6, _t(" " + str(host)[:60]))
            pdf.cell(68, 6, " " + str(dstr),
                     new_x="LMARGIN", new_y="NEXT")
            thin_line()
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(0, 5.5, "These were listed in the app with cleanup "
                               "steps - remove them in your browser's "
                               "notification settings.")
        pdf.ln(3)

    # ---- checked, no problems ----
    section_title("Checked - no problems found")
    ccols = [(70, "CHECK"), (118, "RESULT")]
    table_header(ccols)
    if blank:
        checks = [("Apps with pop-up (overlay) permission", ""),
                  ("Device administrator apps", ""),
                  ("Accessibility services in use", ""),
                  ("Websites allowed to send notifications", ""),
                  ("Remote-access / screen-sharing apps", "")]
    else:
        def res(n, noun):
            return ("%d flagged - see above" % n) if n else \
                ("None found - normal")
        checks = [
            ("Apps with pop-up (overlay) permission",
             res((scan_summary or {}).get("overlay", 0), "overlay")),
            ("Device administrator apps",
             res((scan_summary or {}).get("admin", 0), "admin")),
            ("Accessibility services in use",
             res((scan_summary or {}).get("a11y", 0), "a11y")),
            ("Websites allowed to send notifications",
             res(len(sites or []), "sites")),
            ("Remote-access / screen-sharing apps",
             report_remote_access(threats) or "None found - normal"),
        ]
    for chk, r in checks:
        draw_row([(70, chk, True, None), (118, r, False, None)],
                 header_cols=ccols)
    pdf.ln(4)

    # ---- how to stay safe ----
    if pdf.get_y() > 228:  # keep the whole box on one page
        pdf.add_page()
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*DARK)
    pdf.cell(45, 6, "HOW TO STAY SAFE", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    x0, y0 = pdf.get_x(), pdf.get_y()
    pdf.set_xy(x0 + 3, y0 + 2)
    pdf.set_font("Helvetica", "", 9)
    for t in STAY_SAFE_TIPS:
        pdf.cell(5, 6, "-")
        pdf.multi_cell(W - 13, 6, _t(t))
        pdf.set_x(x0 + 3)
    y1 = pdf.get_y() + 2
    pdf.set_draw_color(205, 213, 223)
    pdf.rect(X0, y0, W, y1 - y0)
    pdf.set_xy(X0, y1)
    pdf.ln(6)

    # ---- closing block: pinned shop line + signature lines (11.9) ----
    rule(0.4, color=(205, 213, 223))
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(W, 6, _t(SHOP_HEADER_LINE), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 4, "\u00a9 2026 iFixx Repairs. All rights reserved. "
                   "AdTrapper is a product of iFixx Repairs.",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10)
    _tech = str(device_info.get("technician", "") or "").strip()
    if blank or not _tech:
        pdf.cell(95, 6, "Technician: ____________________")
    else:
        pdf.cell(95, 6, _t("Technician: " + _tech[:28]))
    pdf.cell(93, 6, "Customer: ____________________",
             new_x="LMARGIN", new_y="NEXT")
    pdf.cell(95, 6, "Date: ____________________",
             new_x="LMARGIN", new_y="NEXT")

    os.makedirs(save_dir, exist_ok=True)
    _tickf = re.sub(r"[^A-Za-z0-9-]+", "",
                    str(device_info.get("ticket", "") or "").strip())
    if blank:
        fname = "PhoneCleanup_BLANK.pdf"
    elif _tickf:
        fname = "cleanup-report-%s.pdf" % _tickf
    else:
        fname = "PhoneCleanup_%s.pdf" % time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(save_dir, fname)
    pdf.output(path)
    return path

def _script_dir_path():
    return Path(sys.argv[0]).parent


# ------------------------------------------------- learned store ---
# v11.3 "Learned Guard": what this shop removed before is a MEMORY,
# not a conviction. Up to 11.2 the store was a bare set of package
# names and a learned-only hit was a REMOVE verdict -- so removing
# Facebook Messenger once (say, at a customer's request) sentenced
# Messenger on every phone after that, forever, on memory alone
# (owner's filmed case, 2026-10-19). The store now keeps one record
# per package -- {"date": ISO date or None, "ticket": str or None,
# "build": str or None} -- in the same learned_bad.json file beside
# the app, wrapped as {"format": 2, "entries": {pkg: record}}.
# Unknown facts stay None and are never rendered as if known.

# Famous verified-publisher packages (EXACT ids) the learned list can
# never convict -- or even flag: a learned-only hit on one of these is
# no flag at all (see _known_or_learned_verdict). Exact-id matching
# only: a clone wears a different id and gets no shelter. The guard
# originally governed the LEARNED path alone. UPDATE (owner ruling
# 2026-10-21): the guard ALSO gates the new ad-software-alone scan
# conviction in scan_core (a guard package is never convicted by
# 1-3 ad networks alone). The >= 4 census bar and blocklist paths
# are UNCHANGED -- they still convict guard packages on that
# evidence, exactly as before. UPDATE (owner ruling 2026-10-21,
# law section 14): the guard ALSO gates the fake-costume
# conviction on BOTH paths (the scan keyword class and the
# Background Check costume finding) -- a guard package is never
# convicted by its costume. com.cvs.launchers.cvs joins the
# guard with that ruling (26 ids).
KNOWN_LEGIT_GUARD = frozenset({
    "com.facebook.orca",                 # Facebook Messenger (Meta)
    "com.facebook.katana",               # Facebook (Meta)
    "com.instagram.android",              # Instagram (Meta)
    "com.instagram.barcelona",            # Threads (Meta) -- parity with the Android guard; standing law: Threads = KEEP
    "com.cvs.launchers.cvs",              # CVS Pharmacy (CVS Health) -- verified real app (Google Play, 10M+ downloads); "launchers" is its legacy package name, NOT a home-screen launcher: the fake-costume finding misfired on it (owner ruling 2026-10-21, law section 14)
    "com.whatsapp",                       # WhatsApp (Meta)
    "com.google.android.gm",              # Gmail (Google)
    "com.google.android.youtube",         # YouTube (Google)
    "com.google.android.apps.maps",       # Google Maps (Google)
    "com.google.android.apps.photos",     # Google Photos (Google)
    "com.spotify.music",                  # Spotify
    "com.amazon.mShop.android.shopping",  # Amazon Shopping
    "com.netflix.mediaclient",            # Netflix
    "com.snapchat.android",               # Snapchat
    "com.zhiliaoapp.musically",           # TikTok
    "com.twitter.android",                # X / Twitter
    "com.pinterest",                      # Pinterest
    "com.reddit.frontpage",               # Reddit (official app)
    "com.discord",                        # Discord
    "com.microsoft.office.outlook",       # Outlook (Microsoft)
    "net.zedge.android",                  # Zedge
    "com.samsung.android.messaging",      # Samsung Messages
    "com.paypal.android.p2pmobile",       # PayPal
    "com.venmo",                          # Venmo
    "com.squareup.cash",                  # Cash App
    "com.apple.android.music",            # Apple Music (Android)
})

# NEVER-REMOVE packages (EXACT ids) -- the PC mirror of Android's
# kNeverRemovePackages (issue #69; the guardrail case is
# com.piriform.ccleaner, CCleaner). Verified real apps whose names
# sit inside the junk-utility family: three carry the owner's
# CLEANER keyword in the package itself (com.piriform.ccleaner --
# "cleaner" hides inside "ccleaner" -- com.avg.cleaner,
# com.avast.android.cleaner) and a fourth (com.symantec.cleansweep,
# Norton) carries it in its title. The keyword dig of 2026-10-21
# flagged the gap: this set did not exist on PC, and CCleaner sat
# in NEITHER the guard above NOR TRUSTED_PKGS, so the section 14
# CLEANER keyword could convict it on sight. This set shields the
# section 14 fake-costume conviction ONLY (both teeth, via
# _fake_costume_shielded): a shielded package keeps exactly the
# treatment it had before section 14 (the junk-name ASK FIRST),
# mirroring Android, where a never-remove id is not convicted by
# the costume branch and keeps its heuristic ASK FIRST. No other
# rule consults this set -- the ad-software conviction, the
# census bar, the blocklist and the learned path are unchanged.
NEVER_REMOVE_PKGS = frozenset({
    "com.piriform.ccleaner",          # CCleaner (Piriform) -- the #69 guardrail case
    "com.avg.cleaner",                # AVG Cleaner
    "com.avast.android.cleaner",      # Avast Cleanup
    "com.symantec.cleansweep",        # Norton Clean
    "eu.thedarken.sdm",               # SD Maid
    "com.wsandroid.suite",            # McAfee Security
    "com.adobe.reader",               # Adobe Acrobat
    "com.adobe.scan.android",         # Adobe Scan
    "com.defianttech.diskdigger",     # DiskDigger
    "com.brave.browser",              # Brave
    "com.opera.browser",              # Opera
    "com.opera.mini.native",          # Opera Mini
    "com.sec.android.app.sbrowser",   # Samsung Internet
    "net.zedge.android",              # Zedge
    "com.samsung.android.lool",       # Samsung Device Care
    "com.luma.touch",                 # LumaFusion
})


def _fake_costume_shielded(pkg):
    """True when section 14 must not convict this package: it is
    on the known-legit guard OR on the never-remove list. Both
    shields stand in front of the fake keyword class on both
    teeth (scan and Background Check) -- law section 14, and the
    2026-10-21 keyword dig's shield rule: shields first, always,
    on both platforms, by exact ID."""
    return pkg in KNOWN_LEGIT_GUARD or pkg in NEVER_REMOVE_PKGS


def _learned_path():
    return _script_dir_path() / "learned_bad.json"


def _blank_learned_record():
    return {"date": None, "ticket": None, "build": None}


def _coerce_learned_record(raw):
    """One learned entry -> {date, ticket, build}; non-string or blank
    fields become None (unknown, and rendered as unknown)."""
    rec = _blank_learned_record()
    if isinstance(raw, dict):
        for key in ("date", "ticket", "build"):
            val = raw.get(key)
            if isinstance(val, str) and val.strip():
                rec[key] = val.strip()
    return rec


def _parse_learned_store(data):
    """(records, was_legacy) from parsed learned_bad.json content.

    Accepted shapes: the legacy (<= 11.2) bare list of package-name
    strings; the v11.3 {"format": 2, "entries": {...}} object; and,
    tolerated, a bare {pkg: record} mapping.
    """
    if isinstance(data, list):
        return ({str(p): _blank_learned_record() for p in data
                 if isinstance(p, str) and p}, True)
    if isinstance(data, dict):
        entries = data.get("entries") if "entries" in data else data
        if isinstance(entries, dict):
            return ({str(p): _coerce_learned_record(r)
                     for p, r in entries.items()}, False)
    return {}, False


def _save_learned_store(records):
    """Persist the learned store in the v11.3 record format. Guard
    packages are filtered out here too, so they can never be written
    back in by any path."""
    try:
        entries = {p: _coerce_learned_record(records[p])
                   for p in sorted(records)
                   if p not in KNOWN_LEGIT_GUARD}
        with open(_learned_path(), "w") as f:
            json.dump({"format": 2, "entries": entries}, f, indent=1)
    except Exception:
        pass


def _load_local_bad():
    """{pkg: {date, ticket, build}} -- packages this shop removed
    before, with whatever provenance the removal recorded.

    Loading MIGRATES a legacy bare-list file to the record format
    (dates unknown -> None, never invented) and PURGES guard-list
    packages; when either happened the cleaned store is written back
    immediately, so an old file cures itself on first run (Messenger
    strikes itself). Guard packages are likewise dropped from a
    current-format file that somehow carries them.
    """
    try:
        with open(_learned_path()) as f:
            data = json.load(f)
    except Exception:
        return {}
    records, was_legacy = _parse_learned_store(data)
    purged = [p for p in records if p in KNOWN_LEGIT_GUARD]
    for p in purged:
        del records[p]
    if was_legacy or purged:
        _save_learned_store(records)
    return records


def _save_local_bad(pkgs, ticket=None):
    """Record removals in the learned store, provenance attached
    (today's date, the POS ticket when one is on the session, and
    this build). Guard-list packages are never learned."""
    fresh = {p: {"date": date.today().isoformat(),
                 "ticket": (str(ticket).strip() or None)
                 if ticket else None,
                 "build": VERSION}
             for p in pkgs if p and p not in KNOWN_LEGIT_GUARD}
    if not fresh:
        return
    LEARNED_BAD.update(fresh)
    _save_learned_store(LEARNED_BAD)


def unlearn_package(pkg):
    """Strike pkg from the learned store (memory + disk, immediately).
    True when it was there. Powers the in-app UN-LEARN control."""
    if pkg not in LEARNED_BAD:
        return False
    del LEARNED_BAD[pkg]
    _save_learned_store(LEARNED_BAD)
    return True


def _learned_provenance_suffix(rec):
    """' -- Mar 3, 2026, ticket R-1406' from a learned record, or ''.

    Only facts the record actually carries are rendered: no date in
    the record -> no date in the reason (never invented)."""
    if not isinstance(rec, dict):
        return ""
    parts = []
    raw_date = rec.get("date")
    if isinstance(raw_date, str) and raw_date:
        try:
            d = date.fromisoformat(raw_date)
            parts.append("%s %d, %d"
                         % (d.strftime("%b"), d.day, d.year))
        except ValueError:
            parts.append(raw_date)
    ticket = rec.get("ticket")
    if isinstance(ticket, str) and ticket.strip():
        parts.append("ticket %s" % ticket.strip())
    return (" \u2014 " + ", ".join(parts)) if parts else ""

# ------------------------------------------------------- app pictures ---
# v10.12 (owner order, 2026-10-15): every scanned app shows its REAL
# launcher icon next to its row -- the same picture the phone app shows.
# Icons are pulled off the phone over adb (the app's base.apk), read out
# of the APK by the pure-stdlib extractor below (binary AndroidManifest +
# resources.arsc, no new dependencies), and cached next to this script in
# icon_cache/ so repeat scans are instant. Since v10.15 a failed
# extraction no longer leaves a blank tile: the row falls back to the
# known-faces pack, the Face Book store face, or a maker badge (see
# the v10.15 section below) -- and the scan never waits on pictures.
import struct as _struct
import zipfile as _zipfile

_ICON_BOX = 36                       # px, icon display size in the rows (spec 5.2)
_ICON_MAX_APK = 400 * 1024 * 1024    # v10.14: runaway guard ONLY. The old
                                     # 60MB skip killed exactly the big brands
                                     # (WhatsApp/Spotify/ChatGPT-size APKs) and
                                     # our own 81MB app -- a missing picture is
                                     # now a defect, not a fallback
_ICON_EXTS = (".png", ".webp", ".jpg", ".jpeg")
_TYPE_REF = 0x01
_TYPE_STR = 0x03


def _iu16(b, o):
    return _struct.unpack_from("<H", b, o)[0]


def _iu32(b, o):
    return _struct.unpack_from("<I", b, o)[0]


class _IconPool(object):
    """Minimal binary-XML / arsc string pool reader (UTF-8 + UTF-16)."""
    __slots__ = ("strings",)

    def __init__(self, data, off):
        self.strings = []
        try:
            if _iu16(data, off) != 0x0001:
                return
            count = _iu32(data, off + 8)
            flags = _iu32(data, off + 16)
            start = _iu32(data, off + 20)
            utf8 = bool(flags & 0x00000100)
            base = off + start
            for i in range(count):
                p = base + _iu32(data, off + 28 + 4 * i)
                try:
                    if utf8:
                        n = data[p]
                        p += 1
                        if n & 0x80:
                            p += 1
                        blen = data[p]
                        p += 1
                        if blen & 0x80:
                            blen = ((blen & 0x7F) << 8) | data[p]
                            p += 1
                        self.strings.append(
                            data[p:p + blen].decode("utf-8", "replace"))
                    else:
                        ln = _iu16(data, p)
                        p += 2
                        if ln & 0x8000:
                            ln = ((ln & 0x7FFF) << 16) | _iu16(data, p)
                            p += 2
                        self.strings.append(
                            data[p:p + 2 * ln].decode("utf-16-le", "replace"))
                except Exception:
                    self.strings.append("")
        except Exception:
            pass

    def get(self, idx):
        if idx is None or idx < 0 or idx >= len(self.strings):
            return None
        return self.strings[idx]


def _axml_elements(data):
    """[(name, {attr: (kind, value, ns)})] for a binary XML blob, or None.

    kind is "ref" (value = resource id), "str" (value = string) or "raw".
    """
    if len(data) < 8 or _iu16(data, 0) != 0x0003:
        return None
    pool = None
    elements = []
    off = _iu16(data, 2)
    total = len(data)
    while off + 8 <= total:
        ctype = _iu16(data, off)
        csize = _iu32(data, off + 4)
        if csize < 8:
            break
        if ctype == 0x0001:
            pool = _IconPool(data, off)
        elif ctype == 0x0102 and pool is not None:
            try:
                name = pool.get(_iu32(data, off + 20))
                attr_start = _iu16(data, off + 24)
                attr_size = _iu16(data, off + 26) or 20
                attr_count = _iu16(data, off + 28)
                abase = off + 16 + attr_start
                attrs = {}
                for i in range(attr_count):
                    a = abase + i * attr_size
                    if a + 20 > total:
                        break
                    ns = pool.get(_iu32(data, a))
                    aname = pool.get(_iu32(data, a + 4))
                    raw = _iu32(data, a + 8)
                    dtype = data[a + 15]
                    dval = _iu32(data, a + 16)
                    if aname is None:
                        continue
                    if dtype == _TYPE_REF:
                        attrs[aname] = ("ref", dval, ns)
                    elif dtype == _TYPE_STR:
                        attrs[aname] = ("str", pool.get(dval), ns)
                    elif raw != 0xFFFFFFFF and pool.get(raw) is not None:
                        attrs[aname] = ("str", pool.get(raw), ns)
                    else:
                        attrs[aname] = ("raw", (dtype, dval), ns)
                elements.append((name, attrs))
            except Exception:
                pass
        off += csize
    if pool is None:
        return None
    return pool, elements


def _arsc_icon_candidates(data, resid, depth=0):
    """[(density, path)] for a resource id in resources.arsc bytes.

    Follows reference aliases; only string (file path) values are kept.
    """
    if depth > 3 or len(data) < 16 or _iu16(data, 0) != 0x0002:
        return []
    hsize = _iu16(data, 2)
    pool = _IconPool(data, hsize)
    pkg_want = (resid >> 24) & 0xFF
    type_want = (resid >> 16) & 0xFF
    entry_want = resid & 0xFFFF
    results = []
    off = hsize + _iu32(data, hsize + 4)
    total = len(data)
    while off + 8 <= total:
        ctype = _iu16(data, off)
        csize = _iu32(data, off + 4)
        if csize < 8:
            break
        if ctype == 0x0200 and _iu32(data, off + 8) == pkg_want:
            sub = off + _iu16(data, off + 2)
            pend = off + csize
            while sub + 8 <= pend:
                stype = _iu16(data, sub)
                ssize = _iu32(data, sub + 4)
                if ssize < 8:
                    break
                if stype == 0x0201 and data[sub + 8] == type_want:
                    shsize = _iu16(data, sub + 2)
                    ecount = _iu32(data, sub + 12)
                    estart = _iu32(data, sub + 16)
                    density = _iu16(data, sub + 34)
                    if entry_want < ecount:
                        eo = _iu32(data, sub + shsize + 4 * entry_want)
                        if eo != 0xFFFFFFFF:
                            eoff = sub + estart + eo
                            try:
                                if not (_iu16(data, eoff + 2) & 0x0001):
                                    dtype = data[eoff + 11]
                                    dval = _iu32(data, eoff + 12)
                                    if dtype == _TYPE_STR:
                                        p = pool.get(dval)
                                        if p:
                                            results.append((density, p))
                                    elif dtype == _TYPE_REF:
                                        results.extend(
                                            _arsc_icon_candidates(
                                                data, dval, depth + 1))
                            except Exception:
                                pass
                sub += ssize
        off += csize
    return results


def _icon_pick_path(cands):
    """Best single (density, path) from a flat candidate list --
    kept for API stability; the real resolution lives in
    _icon_trial_paths (v10.14)."""
    if not cands:
        return None
    ordered = _icon_ordered_rasters(cands)
    return ordered[0][1] if ordered else None


# v10.14 -- PNG-preference resolution. The owner rule is "icons on every
# single thing": a plain tile is a defect. The old picker chose ONE
# path per resource id and gave up if that file would not read, and a
# WebP win was final even when a PNG sibling sat in the same APK (and a
# WebP cached by an older build shadowed everything). Now every
# density variant of the icon -- and of the adaptive-icon drawables
# behind it -- is enumerated and tried best-first: PNG before JPG
# before WebP (format beats density: a real face at 144px beats a
# tile), the icon's own files before the adaptive foreground before
# the background. WebP bytes are accepted only when no PNG/JPG variant
# exists anywhere in the icon's resource graph; packages that end up
# WebP-only are registered in _WEBP_ONLY_PKGS.
_ICON_FMT_RANK = {".png": 0, ".jpg": 1, ".jpeg": 1, ".webp": 2}
_WEBP_ONLY_PKGS = []
_WEBP_ONLY_SET = set()
_WEBP_RECHECKED = set()


def _icon_magic_ext(blob):
    """Real format of image bytes from their magic numbers, or None.
    The path in the APK can mislead (aapt renames crunched files);
    the bytes never lie."""
    if not blob:
        return None
    if blob[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if blob[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if len(blob) > 12 and blob[:4] == b"RIFF" and blob[8:12] == b"WEBP":
        return ".webp"
    return None


def _icon_dens(density):
    """Comparable density: any/no-dpi rasters count as top density,
    plain nodpi as baseline (as the old picker treated them)."""
    if density in (0xFFFE, 0xFFFF):
        return 640
    if density == 0:
        return 160
    return density


def _icon_ordered_rasters(cands):
    """(density, path) raster candidates, best first: PNG, then JPG,
    then WebP; largest density first within a format. Non-raster
    (XML) paths are dropped."""
    seen = set()
    out = []
    for density, path in cands or []:
        if not path or path in seen:
            continue
        seen.add(path)
        if path.lower().endswith(_ICON_EXTS):
            out.append((density, path))
    out.sort(key=lambda c: (_ICON_FMT_RANK.get(
        Path(c[1]).suffix.lower(), 3), -_icon_dens(c[0])))
    return out


def _icon_collect(zf, names, arsc, resid, branch, depth, out):
    """Append (branch, density, path) raster candidates reachable
    from a resource id, chasing adaptive-icon XML. branch: 0 = the
    icon resource itself, 1 = adaptive foreground, 2 = adaptive
    background, 3 = any other drawable element in an icon XML
    (layer-list items, monochrome)."""
    if depth > 3:
        return
    for density, path in _arsc_icon_candidates(arsc, resid):
        if path not in names:
            continue
        low = path.lower()
        if low.endswith(_ICON_EXTS):
            out.append((branch, density, path))
        elif low.endswith(".xml"):
            try:
                parsed = _axml_elements(zf.read(path))
            except Exception:
                parsed = None
            if not parsed:
                continue
            _pool, elements = parsed
            for el_name, attrs in elements:
                v = attrs.get("drawable")
                if not v or v[0] != "ref":
                    continue
                if branch:
                    sub_branch = branch
                elif el_name == "foreground":
                    sub_branch = 1
                elif el_name == "background":
                    sub_branch = 2
                else:
                    sub_branch = 3
                _icon_collect(zf, names, arsc, v[1], sub_branch,
                              depth + 1, out)


def _icon_trial_paths(zf, names, arsc, resid):
    """Every raster path worth trying for an icon resource, best
    first: format (PNG > JPG > WebP) beats everything, then the
    icon's own files before adaptive foreground before background,
    then density."""
    pool = []
    _icon_collect(zf, names, arsc, resid, 0, 0, pool)
    seen = set()
    uniq = []
    for branch, density, path in pool:
        if path in seen:
            continue
        seen.add(path)
        uniq.append((branch, density, path))
    uniq.sort(key=lambda t: (_ICON_FMT_RANK.get(
        Path(t[2]).suffix.lower(), 3), t[0], -_icon_dens(t[1])))
    return [p for _b, _d, p in uniq]


def _apk_icon_bytes(apk_path):
    """(inner_path, image_bytes) for an APK's launcher icon, or
    (None, None). Pure stdlib: zipfile + the parsers above. Tries
    every candidate path from _icon_trial_paths in order and returns
    the first file whose bytes are a real raster (magic-checked), so
    one unreadable or mislabeled entry never costs the icon."""
    _LAST_EXTRACT_WEBP["v"] = False
    try:
        zf = _zipfile.ZipFile(str(apk_path))
    except Exception:
        return None, None
    try:
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names or "resources.arsc" not in names:
            return None, None
        parsed = _axml_elements(zf.read("AndroidManifest.xml"))
        if not parsed:
            return None, None
        _pool, elements = parsed
        icon = round_icon = None
        for el_name, attrs in elements:
            if el_name == "application":
                for key in ("icon", "roundIcon"):
                    v = attrs.get(key)
                    if v and v[0] == "ref":
                        if key == "icon":
                            icon = v[1]
                        else:
                            round_icon = v[1]
        arsc = zf.read("resources.arsc")
        for resid in (icon, round_icon):
            if not resid:
                continue
            # v10.15: a true adaptive composite (the app's own
            # foreground over its own background) beats any single
            # raster; the raw-foreground fallback is used only when
            # the trial paths find nothing at all.
            comp = _adaptive_composite(zf, names, arsc, resid)
            if comp and comp[0] == "<adaptive-icon>":
                return comp
            for path in _icon_trial_paths(zf, names, arsc, resid):
                try:
                    blob = zf.read(path)
                except Exception:
                    continue
                if _icon_magic_ext(blob):
                    return path, blob
            if comp:
                return comp
        return None, None
    except Exception:
        return None, None
    finally:
        try:
            zf.close()
        except Exception:
            pass


def _icon_cache_dir():
    """Icon cache lives next to the script, like the license + history."""
    d = _script_dir_path() / "icon_cache"
    try:
        d.mkdir(exist_ok=True)
    except Exception:
        pass
    return d


def _icon_safe(pkg):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", pkg or "")


def _icon_cache_find(pkg):
    """Cached icon file for pkg (any version tag), or None.

    v10.14: prefers PNG over JPG over WebP among the hits -- a WebP
    cached by an older build (or an older APK version: the size tag is
    ignored here on purpose) must not shadow a PNG of the same app."""
    try:
        d = _icon_cache_dir()
        hits = []
        for h in sorted(d.glob(_icon_safe(pkg) + "__*")):
            if h.suffix.lower() in _ICON_EXTS:
                try:
                    if h.stat().st_size > 0:
                        hits.append(h)
                except Exception:
                    pass
        if not hits:
            return None
        hits.sort(key=lambda h: _ICON_FMT_RANK.get(h.suffix.lower(), 3))
        return hits[0]
    except Exception:
        pass
    return None


_DENSITY_BUCKETS = ("ldpi", "mdpi", "hdpi", "xhdpi", "xxhdpi",
                    "xxxhdpi", "tvdpi", "nodpi", "anydpi")


def _icon_density_split_paths(paths, base):
    """Density config splits among a package's `pm path` lines
    (consult F2): installed files other than the base whose name
    marks them as a density/config split (split_config.*.apk,
    *density*.apk). Order preserved; base excluded."""
    out = []
    for p in paths or []:
        if not p or p == base:
            continue
        name = p.rsplit("/", 1)[-1].lower()
        stem = name[:-4] if name.endswith(".apk") else name
        bucket = stem.rsplit(".", 1)[-1] if "." in stem else ""
        if "density" in name or (
                stem.startswith("split_config.")
                and bucket in _DENSITY_BUCKETS):
            out.append(p)
    return out


def _icon_ensure_cached_inner(pkg, launcher):
    """Make pkg's real icon available in the cache; return its Path.

    launcher: set of packages with a launcher entry, or None if that
    query was unsupported (then every package is attempted). Pulls the
    base.apk once per package+size; later calls hit the cache. Returns
    None on any failure -- the row just keeps its empty tile.
    """
    stale_webp = None
    try:
        if launcher is not None and pkg not in launcher:
            return None
        hit = _icon_cache_find(pkg)
        if hit and hit.suffix.lower() != ".webp":
            return hit
        if hit:
            # A WebP-only cache hit gets ONE recheck per run (v10.14):
            # the PNG-preference resolver may find a PNG this build's
            # older picker walked past. If the recheck finds nothing
            # better, the WebP below stays the icon.
            if pkg in _WEBP_RECHECKED:
                return hit
            _WEBP_RECHECKED.add(pkg)
            stale_webp = hit
        out = adb_cmd("shell", "pm", "path", pkg)
        base = None
        for line in (out or "").splitlines():
            line = line.strip()
            if line.startswith("package:"):
                p = line[len("package:"):]
                if base is None:
                    base = p
                if p.endswith("base.apk"):
                    base = p
                    break
        if not base:
            return stale_webp
        # v11.4 interim (consult F2, fallback half): the OTHER pm
        # path lines for this package -- a density config split is
        # where the device-density raster can live on split installs.
        _all_paths = []
        for line in (out or "").splitlines():
            line = line.strip()
            if line.startswith("package:"):
                _all_paths.append(line[len("package:"):])
        _splits = _icon_density_split_paths(_all_paths, base)
        size = 0
        st = adb_cmd("shell", "stat", "-c", "%s", base)
        if st and st.strip().isdigit():
            size = int(st.strip())
        if size > _ICON_MAX_APK:
            return stale_webp
        d = _icon_cache_dir()
        tmp = d / ("tmp_%d.apk" % os.getpid())
        try:
            adb_cmd("pull", base, str(tmp), timeout=120)
            if not tmp.is_file():
                return stale_webp
            if not size:
                size = tmp.stat().st_size
            if size > _ICON_MAX_APK:
                return stale_webp
            inner, blob = _apk_icon_bytes(tmp)
            if not blob and _splits:
                # Base had no usable icon: let the SAME trial logic
                # see the density split's rasters. Any split failure
                # degrades to the old base-only behavior, silently.
                for _sp in _splits:
                    try:
                        _ssize = 0
                        _st = adb_cmd("shell", "stat", "-c", "%s", _sp)
                        if _st and _st.strip().isdigit():
                            _ssize = int(_st.strip())
                        if _ssize > _ICON_MAX_APK:
                            continue
                        _stmp = d / ("tmp_split_%d.apk" % os.getpid())
                        try:
                            adb_cmd("pull", _sp, str(_stmp), timeout=120)
                            if not _stmp.is_file():
                                continue
                            _sinner, _sblob = _apk_icon_bytes(_stmp)
                            if _sblob:
                                inner, blob = _sinner, _sblob
                                size = _stmp.stat().st_size
                                break
                        finally:
                            try:
                                if _stmp.is_file():
                                    _stmp.unlink()
                            except Exception:
                                pass
                    except Exception:
                        continue
            if not blob:
                return stale_webp
            ext = _icon_magic_ext(blob) or Path(inner or "").suffix.lower()
            if ext not in _ICON_EXTS:
                ext = ".png"
            if (ext == ".webp" or _LAST_EXTRACT_WEBP["v"]) \
                    and pkg not in _WEBP_ONLY_SET:
                _WEBP_ONLY_SET.add(pkg)
                _WEBP_ONLY_PKGS.append(pkg)
            dest = d / ("%s__%d%s" % (_icon_safe(pkg), size, ext))
            with open(str(dest), "wb") as f:
                f.write(blob)
            hit = _icon_cache_find(pkg)
            return hit if hit else dest
        finally:
            try:
                if tmp.is_file():
                    tmp.unlink()
            except Exception:
                pass
    except Exception:
        return stale_webp



# ------------------------------------------------------- v10.15 ----
# Icons on EVERYTHING, computer-side only (owner: "Not on my phone,
# this is computer app"). v10.14's extractor finds most icons, but
# three gaps still showed blank tiles on the shop PC:
#   (a) WebP icons cannot DISPLAY there (Tk + no PIL) even when the
#       extractor succeeds -- fixed by converting WebP -> PNG once,
#       with the official dwebp.exe the updater drops beside the
#       program as a manifest "extra" (see download_extras).
#   (b) adaptive icons are COMPOSITED: the app's own foreground over
#       its own background (solid color / solid-fill vector /
#       raster) via the pure-stdlib PNG codec below; a complex
#       background gets a neutral dark plate. Only the app's own
#       layers -- never invented art.
#   (c) apps whose icon cannot come out of the base APK at all
#       (split APKs, vector-only) and system components with no
#       launcher icon anywhere -- the row falls back to the shelf
#       known-faces pack, then (for blocklisted apps) the Face Book
#       store face, then a MAKER BADGE chip. A badge is a label, not
#       a picture: it never counts in the Pictures line.
import zlib as _zlib

_ADAPTIVE_PLATE_RGB = (35, 38, 44)   # neutral dark plate
_LAST_EXTRACT_WEBP = {"v": False}    # set by _apk_icon_bytes when
                                     # the served icon derives from
                                     # WebP sources (registry truth)


# ---- tiny pure-stdlib PNG codec (decode to RGBA rows / encode) ----
def _png_rows(blob):
    """Decode PNG bytes -> (w, h, [bytearray RGBA rows]) or None.
    8/16-bit, color types 0/2/3/4/6, plain + Adam7 interlace."""
    try:
        if not blob or len(blob) < 8 or blob[:8] != b"\x89PNG\r\n\x1a\n":
            return None

        def be32(b, o):
            return int.from_bytes(b[o:o + 4], "big")

        pos = 8
        idat = bytearray()
        plte = trns = None
        w = h = depth = ctype = inter = None
        while pos + 12 <= len(blob):
            ln = be32(blob, pos)
            typ = blob[pos + 4:pos + 8]
            data = blob[pos + 8:pos + 8 + ln]
            if typ == b"IHDR":
                w, h = be32(data, 0), be32(data, 4)
                depth, ctype, inter = data[8], data[9], data[12]
            elif typ == b"PLTE":
                plte = data
            elif typ == b"tRNS":
                trns = data
            elif typ == b"IDAT":
                idat += data
            elif typ == b"IEND":
                break
            pos += 12 + ln
        if not w or depth not in (8, 16) or ctype not in (0, 2, 3, 4, 6):
            return None
        if ctype == 3 and (plte is None or depth != 8):
            return None
        ch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ctype]
        sb = 2 if depth == 16 else 1          # bytes per sample
        bpp = max(1, ch * sb)                  # bytes per pixel
        raw = _zlib.decompress(bytes(idat))
        rows = [bytearray(w * 4) for _ in range(h)]
        state = [0]

        def _read_pass(pw, ph):
            rb = pw * ch * sb
            if pw <= 0 or ph <= 0:
                return []
            out = []
            prev = bytearray(rb)
            for _ in range(ph):
                if state[0] + rb + 1 > len(raw):
                    return None
                ft = raw[state[0]]
                line = bytearray(raw[state[0] + 1: state[0] + 1 + rb])
                state[0] += rb + 1
                if ft == 1:
                    for i in range(bpp, rb):
                        line[i] = (line[i] + line[i - bpp]) & 0xFF
                elif ft == 2:
                    for i in range(rb):
                        line[i] = (line[i] + prev[i]) & 0xFF
                elif ft == 3:
                    for i in range(rb):
                        a = line[i - bpp] if i >= bpp else 0
                        line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
                elif ft == 4:
                    for i in range(rb):
                        a = line[i - bpp] if i >= bpp else 0
                        b = prev[i]
                        c = prev[i - bpp] if i >= bpp else 0
                        pp = a + b - c
                        pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                        pr = a if (pa <= pb and pa <= pc) else \
                            (b if pb <= pc else c)
                        line[i] = (line[i] + pr) & 0xFF
                elif ft != 0:
                    return None
                out.append(line)
                prev = line
            return out

        def _put(pass_rows, ox, oy, dx, dy):
            for y, line in enumerate(pass_rows):
                ty = oy + y * dy
                if ty >= h:
                    break
                trow = rows[ty]
                for x in range(len(line) // (ch * sb)):
                    tx = ox + x * dx
                    if tx >= w:
                        break
                    o = x * ch * sb
                    if depth == 16:
                        vals = [line[o + 2 * i] for i in range(ch)]
                    else:
                        vals = [line[o + i] for i in range(ch)]
                    d = bytearray(4)
                    if ctype == 6:
                        d[0], d[1], d[2], d[3] = vals
                    elif ctype == 2:
                        d[0], d[1], d[2], d[3] = vals[0], vals[1], vals[2], 255
                    elif ctype == 4:
                        d[0] = d[1] = d[2] = vals[0]
                        d[3] = vals[1]
                    elif ctype == 0:
                        d[0] = d[1] = d[2] = vals[0]
                        d[3] = 255
                    else:
                        idx = vals[0]
                        d[0] = plte[idx * 3]
                        d[1] = plte[idx * 3 + 1]
                        d[2] = plte[idx * 3 + 2]
                        d[3] = trns[idx] if trns and idx < len(trns) else 255
                    trow[tx * 4:tx * 4 + 4] = d

        if inter == 0:
            pr = _read_pass(w, h)
            if pr is None:
                return None
            _put(pr, 0, 0, 1, 1)
        elif inter == 1:
            for (ox, oy, dx, dy) in ((0, 0, 8, 8), (4, 0, 8, 8),
                                     (0, 4, 4, 8), (2, 0, 4, 4),
                                     (0, 2, 2, 4), (1, 0, 2, 2),
                                     (0, 1, 1, 2)):
                pw = (w - ox + dx - 1) // dx if w > ox else 0
                ph = (h - oy + dy - 1) // dy if h > oy else 0
                if pw <= 0 or ph <= 0:
                    continue
                pr = _read_pass(pw, ph)
                if pr is None:
                    return None
                _put(pr, ox, oy, dx, dy)
        else:
            return None
        return w, h, rows
    except Exception:
        return None


def _png_encode(w, h, rows):
    """RGBA rows -> PNG bytes (filter 0 rows, zlib)."""
    try:
        def _chunk(typ, data):
            c = typ + data
            return (len(data)).to_bytes(4, "big") + c + \
                (_zlib.crc32(c) & 0xFFFFFFFF).to_bytes(4, "big")

        raw = bytearray()
        for r in rows:
            raw.append(0)
            raw += r
        ihdr = w.to_bytes(4, "big") + h.to_bytes(4, "big") + \
            bytes([8, 6, 0, 0, 0])
        return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr)
                + _chunk(b"IDAT", _zlib.compress(bytes(raw), 6))
                + _chunk(b"IEND", b""))
    except Exception:
        return None


def _png_scale(rows, sw, sh, dw, dh):
    """Bilinear resample of RGBA rows."""
    if (sw, sh) == (dw, dh):
        return rows
    out = [bytearray(dw * 4) for _ in range(dh)]
    for y in range(dh):
        fy = min(max((y + 0.5) * sh / float(dh) - 0.5, 0.0), sh - 1.001)
        y0 = int(fy)
        y1 = min(y0 + 1, sh - 1)
        wy = fy - y0
        for x in range(dw):
            fx = min(max((x + 0.5) * sw / float(dw) - 0.5, 0.0),
                     sw - 1.001)
            x0 = int(fx)
            x1 = min(x0 + 1, sw - 1)
            wx = fx - x0
            o = x * 4
            for c in range(4):
                top = rows[y0][x0 * 4 + c] * (1 - wx) + \
                    rows[y0][x1 * 4 + c] * wx
                bot = rows[y1][x0 * 4 + c] * (1 - wx) + \
                    rows[y1][x1 * 4 + c] * wx
                out[y][o + c] = int(top * (1 - wy) + bot * wy + 0.5)
    return out


def _png_composite(fg_png, bg):
    """Foreground PNG bytes composited over a background -> PNG
    bytes, or None. bg is an (r, g, b) solid or PNG bytes (scaled to
    the foreground's size). Only the app's own layers are used."""
    try:
        dec = _png_rows(fg_png)
        if not dec:
            return None
        w, h, fg = dec
        if isinstance(bg, (bytes, bytearray)):
            bdec = _png_rows(bytes(bg))
            if not bdec:
                return None
            bw, bh, brows = bdec
            brows = _png_scale(brows, bw, bh, w, h)
        else:
            r, g, b = bg
            brows = [bytearray([r, g, b, 255] * w) for _ in range(h)]
        out = []
        for y in range(h):
            frow, brow = fg[y], brows[y]
            orow = bytearray(w * 4)
            for x in range(w):
                o = x * 4
                fa = frow[o + 3] / 255.0
                if fa >= 0.999:
                    orow[o:o + 4] = frow[o:o + 4]
                elif fa <= 0.001:
                    orow[o:o + 4] = brow[o:o + 4]
                else:
                    ba = brow[o + 3] / 255.0
                    oa = fa + ba * (1 - fa)
                    for c in range(3):
                        orow[o + c] = int(
                            (frow[o + c] * fa
                             + brow[o + c] * ba * (1 - fa)) / oa) \
                            if oa > 0 else 0
                    orow[o + 3] = int(oa * 255)
            out.append(orow)
        return _png_encode(w, h, out)
    except Exception:
        return None


# ---- the bundled WebP converter (an updater "extra") --------------
def _dwebp_path():
    """dwebp beside the program (dropped there by the updater as a
    manifest extra), or one on PATH; None when absent -- WebP then
    simply falls through to the next picture source, as before."""
    try:
        d = _script_dir_path()
        names = ("dwebp.exe", "dwebp") if os.name == "nt" else \
            ("dwebp", "dwebp.exe")
        for name in names:
            p = d / name
            if p.is_file():
                return p
        w = shutil.which("dwebp")
        if w:
            return Path(w)
    except Exception:
        pass
    return None


def _run_dwebp(src, dst):
    exe = _dwebp_path()
    if not exe:
        return False
    try:
        r = subprocess.run([str(exe), str(src), "-o", str(dst)],
                           timeout=30, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, **_no_console())
        return r.returncode == 0 and Path(dst).is_file() \
            and Path(dst).stat().st_size > 0
    except Exception:
        return False


def _webp_bytes_to_png(blob):
    """WebP bytes -> PNG bytes via the bundled converter, or None."""
    if not blob or not _dwebp_path():
        return None
    d = _icon_cache_dir()
    tin = d / ("tmpconv_%d.webp" % os.getpid())
    tout = d / ("tmpconv_%d.png" % os.getpid())
    try:
        tin.write_bytes(blob)
        if _run_dwebp(tin, tout):
            out = tout.read_bytes()
            if _icon_magic_ext(out) == ".png":
                return out
    except Exception:
        pass
    finally:
        for t in (tin, tout):
            try:
                if t.is_file():
                    t.unlink()
            except Exception:
                pass
    return None


def _icon_convert_cached_webp(path):
    """Convert a cached .webp icon file to a sibling .png (same stem,
    so the cache finder's PNG preference picks it up from then on).
    Returns the PNG Path, or None when no converter / it failed."""
    try:
        path = Path(path)
        if path.suffix.lower() != ".webp":
            return None
        png = path.with_suffix(".png")
        if png.is_file() and png.stat().st_size > 0:
            return png
        tmp = path.parent / (path.stem + ".conv.png")
        if _run_dwebp(path, tmp):
            try:
                tmp.replace(png)
            except Exception:
                return None
            return png
    except Exception:
        pass
    return None


# ---- adaptive icons ------------------------------------------------
def _arsc_resolve_value(data, resid, depth=0):
    """(dtype, dval, string) for a resource id's densest config, or
    None. Follows reference aliases. dtype 0x1C = a color (dval is
    ARGB); string values return the pool string."""
    if depth > 3 or len(data) < 16 or _iu16(data, 0) != 0x0002:
        return None
    hsize = _iu16(data, 2)
    pool = _IconPool(data, hsize)
    pkg_want = (resid >> 24) & 0xFF
    type_want = (resid >> 16) & 0xFF
    entry_want = resid & 0xFFFF
    best = None
    off = hsize + _iu32(data, hsize + 4)
    total = len(data)
    while off + 8 <= total:
        ctype = _iu16(data, off)
        csize = _iu32(data, off + 4)
        if csize < 8:
            break
        if ctype == 0x0200 and _iu32(data, off + 8) == pkg_want:
            sub = off + _iu16(data, off + 2)
            pend = off + csize
            while sub + 8 <= pend:
                stype = _iu16(data, sub)
                ssize = _iu32(data, sub + 4)
                if ssize < 8:
                    break
                if stype == 0x0201 and data[sub + 8] == type_want:
                    shsize = _iu16(data, sub + 2)
                    ecount = _iu32(data, sub + 12)
                    estart = _iu32(data, sub + 16)
                    density = _iu16(data, sub + 34)
                    if entry_want < ecount:
                        eo = _iu32(data, sub + shsize + 4 * entry_want)
                        if eo != 0xFFFFFFFF:
                            eoff = sub + estart + eo
                            try:
                                if not (_iu16(data, eoff + 2) & 0x0001):
                                    dtype = data[eoff + 11]
                                    dval = _iu32(data, eoff + 12)
                                    if best is None or _icon_dens(density) > _icon_dens(best[0]):
                                        best = (density, dtype, dval)
                            except Exception:
                                pass
                sub += ssize
        off += csize
    if best is None:
        return None
    _dens, dtype, dval = best
    if dtype == _TYPE_STR:
        return (dtype, dval, pool.get(dval))
    if dtype == _TYPE_REF:
        return _arsc_resolve_value(data, dval, depth + 1)
    return (dtype, dval, None)


def _argb_rgb(v):
    return ((int(v) >> 16) & 0xFF, (int(v) >> 8) & 0xFF, int(v) & 0xFF)


def _value_as_color(v, arsc):
    """A solid (r, g, b) from an XML attribute tuple -- ("raw",
    (0x1C, argb)), ("str", "#AARRGGBB") or ("ref", color id)
    resolved in the arsc -- or None."""
    try:
        if not v:
            return None
        kind, val = v[0], v[1]
        if kind == "raw":
            dtype, dval = val
            if dtype == 0x1C:
                return _argb_rgb(dval)
            return None
        if kind == "str":
            s = (val or "").strip()
            if s.startswith("#"):
                hx = s[1:]
                if len(hx) == 8:
                    hx = hx[2:]
                if len(hx) == 6:
                    return (int(hx[0:2], 16), int(hx[2:4], 16),
                            int(hx[4:6], 16))
            return None
        if kind == "ref":
            got = _arsc_resolve_value(arsc, val)
            if got and got[0] == 0x1C:
                return _argb_rgb(got[1])
    except Exception:
        pass
    return None


def _xml_solid_color(zf, names, arsc, path):
    """(r, g, b) when the drawable XML at path paints one solid
    color (a <shape><solid> or a vector path fillColor), the string
    "complex" when it paints a gradient, else None."""
    try:
        parsed = _axml_elements(zf.read(path))
    except Exception:
        return None
    if not parsed:
        return None
    _pool, elements = parsed
    for el_name, attrs in elements:
        if el_name == "gradient":
            return "complex"
        if el_name == "solid":
            c = _value_as_color(attrs.get("color"), arsc)
            if c:
                return c
        if el_name == "path":
            c = _value_as_color(attrs.get("fillColor"), arsc)
            if c:
                return c
    return None


def _adaptive_bg(zf, names, arsc, v):
    """The background of an adaptive icon: ("color", (r, g, b)) |
    ("png", bytes) | ("plate",)."""
    try:
        if v is not None:
            c = _value_as_color(v, arsc)
            if c:
                return ("color", c)
            if v[0] == "ref":
                got = _arsc_resolve_value(arsc, v[1])
                if got and got[0] == _TYPE_STR and got[2]:
                    path = got[2]
                    low = path.lower()
                    if path in names and low.endswith(_ICON_EXTS):
                        blob = zf.read(path)
                        ext = _icon_magic_ext(blob)
                        if ext == ".png":
                            return ("png", blob)
                        if ext == ".webp":
                            _LAST_EXTRACT_WEBP["v"] = True
                            png = _webp_bytes_to_png(blob)
                            if png:
                                return ("png", png)
                    elif path in names and low.endswith(".xml"):
                        sc = _xml_solid_color(zf, names, arsc, path)
                        if isinstance(sc, tuple):
                            return ("color", sc)
    except Exception:
        pass
    return ("plate",)


def _adaptive_composite(zf, names, arsc, resid):
    """(inner_path, PNG bytes) for an adaptive-icon resource: the
    app's own foreground composited over its own background (the
    neutral dark plate when the background is complex). Falls back
    to (fg_path, fg_bytes) -- the v10.14 outcome -- when the
    foreground is not a PNG-convertible raster; None when resid is
    not an adaptive icon or has no raster foreground at all."""
    try:
        xml_path = None
        for _density, path in _arsc_icon_candidates(arsc, resid):
            if path in names and path.lower().endswith(".xml"):
                xml_path = path
                break
        if not xml_path:
            return None
        parsed = _axml_elements(zf.read(xml_path))
        if not parsed:
            return None
        _pool, elements = parsed
        if not elements or elements[0][0] != "adaptive-icon":
            return None
        fg_v = bg_v = None
        for el_name, attrs in elements:
            v = attrs.get("drawable")
            if not v:
                continue
            if el_name == "foreground":
                fg_v = v
            elif el_name == "background":
                bg_v = v
        if not fg_v or fg_v[0] != "ref":
            return None
        fg_path = fg_blob = None
        for path in _icon_trial_paths(zf, names, arsc, fg_v[1]):
            try:
                blob = zf.read(path)
            except Exception:
                continue
            if _icon_magic_ext(blob):
                fg_path, fg_blob = path, blob
                break
        if not fg_blob:
            return None
        ext = _icon_magic_ext(fg_blob)
        if ext == ".webp":
            _LAST_EXTRACT_WEBP["v"] = True
        fg_png = None
        if ext == ".png":
            fg_png = fg_blob
        elif ext == ".webp":
            fg_png = _webp_bytes_to_png(fg_blob)
        if fg_png is None:
            return (fg_path, fg_blob)
        bg = _adaptive_bg(zf, names, arsc, bg_v)
        comp = _png_composite(
            fg_png, bg[1] if bg[0] in ("color", "png")
            else _ADAPTIVE_PLATE_RGB)
        if comp:
            return ("<adaptive-icon>", comp)
        return (fg_path, fg_blob)
    except Exception:
        return None


# ---- maker badges: a label, never a picture ------------------------
_MAKER_PREFIXES = (
    ("com.samsung.", "samsung"), ("com.sec.", "samsung"),
    ("com.google.", "google"),
    ("com.android.", "android"),
    ("com.xiaomi.", "xiaomi"), ("com.miui.", "xiaomi"),
    ("com.motorola.", "motorola"),
    ("com.huawei.", "huawei"),
    ("com.lge.", "lg"), ("com.lg.", "lg"),
    ("com.sony.", "sony"), ("com.sonymobile.", "sony"),
    ("com.oneplus.", "oneplus"),
    ("com.asus.", "asus"),
    ("com.lenovo.", "lenovo"),
    ("com.zte.", "zte"),
    ("com.hmdglobal.", "nokia"),
)

_MAKER_CHIPS_B64 = {
    "android": ("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"),
    "asus": ("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"),
    "google": ("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" "Am7BHZXiXIJOAAAAAElFTkSuQmCC"),
    "huawei": ("iVBORw0KGgoAAAANSUhEUgAAAKAAAABQCAYAAACeXX40AAAIsklEQVR4nO2dbWxT1xnH/7bj" "2Dg05AXbCSSEvBRKIC92CqglwAqhDJYwadPUrWXT+D5pk/Zlk4bGxtRKfKg2dWVdp23VJloN" "bR2r2jIobVfWLutLYpNkCSQEAqQ0dkwSyAuxje19CPfmXp9zr6/tRNcOz+8L3Ofcc+4l+eV5" "7jnnmgAEQRAEQeiAId0BYrHY0wtxI0R2YjAYXk2rfyqdSDqCRyoyJiUgT7w/1jWdSPaixNLh" "UHfHM/GxZETULKBUPpKO4CGVUauECQUk8YhkSUZEo1ojyUekgtSVRPMFVQF5AxKEFrQ6oyig" "YC7JR6SK4I5aFuQKSPIRC0UiCTWVYIJYLBgBKfsRC41aFqQMSOgKCUjoikxAKr/EYqFUhikD" "ErpCAhK6QgISukICErpCAhK6QgISukICErpCAhK6QgISukICErpCAhK6QgISupKTTueSzU3Y" "94eXmfhHR46i/2+nFPutbn4cT/7mBSZ+/seHMfjm22lfw2TJxXc+a2fi/a+fwkc/Pap4XwBg" "NJnw1PtnYC0s5La/3vY13B66xu9rNuNg+3mYLLmyePsvnsPFv/yV26d8RzNaXvwVE//w8M8w" "cOoNbp+1e3bjieePyWKxaBQnHt+J8PQMAOWvmxYioRD+1PQYE0/1+60GZcA4ynY0K8oHADUH" "WhXbouEwRnt6mLjT7VLs41Boczap9HE1MrGxS/2ifNkECRhHddtX1Ntb9wMG5Y9T+zu9TExN" "JidHJrU4AJRwxvNxrpsNkIAScvPzUb5zu+o5eaUlKN3yqGL7SKeH7eN0YvmqUiZuNJuxcmMt" "d5z8ijWwFhUxcbPNhsL165i4j3PdbCCtZ8ClRtW+J2HKzU14Xk1bK774+FNum997AbFoFAaj" "/Gfb6XZh6uYXstjKTbXM86K8TyOunXtPFrM31MFoMrHX9XgT3jeQ3vPaYkAZUALv+c5/oYuJ" "VezZhZxly7hjhKemMd4/wMSd7kY25pKX0nhBeWWY9zw5Ofw5ZkYD3PvJdEjA++RXVMBeX8fE" "//PzZxG8fUcWM9tsqGjZpTiWj5ONeOLES9nzyp9V25XGydbyC5CAIjUH2MnH+MBljPcPMGVQ" "6XwBXwcrREFVJSwFK+YDBgMcjQ3iYTQcxsDf/4HQ5KQYK9rwCHKsVvHYmJMDe/0m9noay28m" "QgICgMEwN7uN48rpM7I/pZRu2Yw8p5M7HDcjGQyyklpQXQXLinzxOPC/XtybnYXfO1/yjSYT" "7A3zWbm4Vi6kAG/mnS0syiRk25HD2Hbk8GIMvSiUbm7izlKHzrwDABj59DPMjo3JZqUGoxHV" "rfvQ9ftXmH4zowFMDn+Oh8pWy+JOtwvX3/9g7u9xz3fCMoqvoxNl27fN93E1ihMeXvkNTtzG" "xNWhhP9GAS3fm/ajz+HiSf7C+UJDGRBANWfycau3D3eu3wAwt8swdPZdTf0EeFlQ+kwX/3wn" "lNH4ZRypdLxnQp/HC8RiiveR6TzwAuZYrVjbspuJX/3nWdVjYO65Tmkdjydgce0GmCwWAHEy" "xWLiMkqgpxeRYEhsstfXiUs6jkZJn/toXX7JVB54AStadsGcZ2PiV++XXwGfx4sZ/yhzXs1X" "+VmQNxERJhE2hx3LV60S4xODV8SZdvx2njnPhqL161BQVQlrYQF7nSx+/gMW6Rkw1ZcReEiz" "gRRjjvKtm8z8xd3I7CwT4639jXZ1M2tyc2X4HGoPfksWr/zyXnxy7HlE792TxW8PXcPs+Diz" "r1zidmFZcbEsFj+L9Xd6UdLkFo+d7kbu1yESDCHQ28fE1ci0heiM3wmJX4MTsBQUKPaRLXdI" "x7ozKTu2ORwo3bqZOc9eX4dD3R2a7s9aWICyHc24/t6/mDZfpxcVu5+QxRxuF6zFRcx5UkY6" "PaiXHDvdLkSCQWb80Z4eRMNhTfeZqWR8CZ4eGWGyCwAUb3hEsY9S2+TwsOy4unU/s2WWCkpv" "yPDKo6OhHiWPNsWdJy/Xwnae2MfVyH2hIZuXXwQyXsBIMIhbnDJT1ryNu3QCAOu/8XVuPF6I" "mjZ27S8Vync0c7MubyJizrOh8OEa8Xja52PKfXhqGmOX5rfzbPaVsmfG+fG9adx1ZpDxAgLA" "4JunmZjJkou9Lx9H+c7tMC/Pg9FsRuG6h/GlY89i1WNbmfP9F7oweWM+A67cWIuCmuoFuT+j" "2YyqfXuZ+FjfRdy7e1e1r1IW83vUt9di0Sj83gua7zFTyfhnQGDuTeZN3/02k/HyK9ag5de/" "TDxALAbPiy/JQryttEgohNd2tiA8Na063IGTJ5gyX93Wir7XTspi0UgEo13dKN26RXEs3utb" "ADDS4cGGp7+p2G/i8iBCU1Oq98lD6ybBue/9ADc++HfS4ydLVmTASDCId7//w5Tf+PUc/y1u" "tn8sHhtzclDJyVjD5z9MKB8AXOVszdnrNmJF5VomnqhMKrUnesFgKZRfIEsEBICxi5fwxlPP" "cF+PUmJ2fALnf/QTeF/6nSxetp3/2j1vz5fHldNnuLsPvMnICGc9UCA0NYWJy4PctruBW+JO" "DI9sfgFBSlaUYIE7167jrYOH4GhswNo9u2Cvq8PystWw5D8Eg8mE8NQ07gYCCPT24eZ/P8HQ" "2Xe462e88huemdFccqZHfPB7u+BwNcji1a370fnCcdkMdrSrG9FIhP8SadxsNx5fpwf5a8oV" "25YCsg830H/RSywmwu+Qk/7+uKwpwcTShAQkdIUEJHSFBCR0hQQkdIUEJHSFBCR0hQQkdIUE" "JHSFBCR0hQQkdIUEJHRFJqCwSSxsGhPEQsF7EQGgDEjoDAlI6AojIJVhYqFRKr8AZUBCZ7gC" "UhYkFgq17AeoZECSkEiXRPIBGkswSUgki1ZnVAWUmksSElqRuqKW/YC4T8WpIXxiDqBPzRF8" "khFPPC+ZC0glFCAZH2x4lVGrfECSAgrwRCSIZMQT+6R7UZLxwSYV6QiCIAiC0J3/A3TpKPIL" "QfQMAAAAAElFTkSuQmCC"),
    "lenovo": ("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"),
    "lg": ("iVBORw0KGgoAAAANSUhEUgAAAKAAAABQCAYAAACeXX40AAAE20lEQVR4nO3cf0zUdRzH8dfB" "/YITiDRFyDi1qx0iCRiGpbNWKWtttlYxXG790TS3crn8p02Xs7U51lbO1h+1VmtaKeo/Ciat" "iTkL2lQu1tGgQWJgDi8R74AD+vZPx+667x3fX3cfvvB6/MV97r73ff/x3OdzMHYAERERCWDR" "+waSJNUZMQiZk8ViOaLrei0XMTqSoyVGVQHKhVfvrTms9qY0e+z2N235/5qaEBUHGB0foyM5" "0TEqjXDaABkeqaUmxIxkTzI+0iK6lel+X0gaoNwbEimhtJmEAUbKZXykVaSdZLugbICMj4wy" "XYSKjmCiVIkLkLsfGS3ZLsgdkIRigCRUTIA8filVEh3D3AFJKAZIQjFAEooBklAMkIRigCQU" "AyShGCAJxQBJKAZIQjFAEooBklBW0QOk25KqMtR+cSBu/ds9H8LXcMaQexSUeuBeW4GiihLk" "FxfBmZcDR64Lk+MTCAdDGB4YRKDnGgbaO3G1tR2D3X8Ycl8zmnMBptLyDWvwyLaXULjKK/t8" "RmYmbE4HXPPzUVDqQcmzjwMABrt6ceHgl+j67mI6x50RGKABbE4Hnnh7O8pe2KTp+gUeN5Zv" "qGKApF6G1YrNH+2Fe22F6FFMiQHq9OSeHQnjC/Rcw+WvTqGvzYfb/TcwPjIGZ64LOQX3oGDl" "A1i6bjWWrVuNTLstzVPPHAxQh0Ul9+OhBMdu66fH8MMHn0Oa/CdmPRQYQigwhL9+7Ub7N41w" "5LiwqvYZ2F1Z6Rh5xmGAOlTvqAMs8V+v4zt2Buff/0zRe4wNB9H6yVGjRzMN/h1QI6vDDvej" "8UdvODSCFoXxEQPUrLDcC5vTEbfe0/IzRoeGBUxkTgxQo9zFC2XX+32/pXkSc+NnQI2y786T" "XR8JDMmulz73FGre25X0PZv3HcKVr0/rns1MuANqJv/dnhKkNM9hbgxQo1Dglux6dr78zkjy" "GKBGtwduyK4vLnswzZOYGz8DatR/2Y+J0TCsTnvM+rL1D8M+LxvhO6GY9Y6Tzeg42Tz1+I22" "BjhyXGmZdSbjDqjRxFgYvRcvxa3b52XjsddfFjCROTFAHX78WP4L4Cu3bsaaV19M8zTmxAB1" "uN7RhV9OnJV9bv2uV7C14SBWPv808u8rhM3pQKbNiuz5d6G4uhyZtrn7DwjR+BnwPxv378TG" "/Tunfd2J197B7+dapx437zuE/OJC3FtZGvfaRSs82PTum4bOOdtwB9RpMjyO49v2wn/6nOhR" "TIk7oAHCwRGceusAur//CdXba7HA41Z+sSThzyt++I42obPpfMpmnKkYoIE6G1vQ2diCJVVl" "cFeXo6hyBXILFyIrLwe2LCfGR0YxdieIW33XcbP7Kvrb/ei9cAnBm3+LHl2YORdgX5sP9d6a" "lN+jr82X0nvMFvwMSEIxQBKKAZJQDJCEYoAkFAMkoRggCcUASSgGSEIxQBKKAZJQDJCEignQ" "YrEcAYDd/qYtYsah2SrSVKSxCO6AJBQDJKHiAuQxTEZLdPwC3AFJMNkAuQuSUZLtfkCSHZAR" "kl7TxQcoPIIZIamltJmkAUaXywhJqehWku1+QKJvWZQhSVJd5Od6b81hbaPRbKYmvKnXqblB" "dIQRjHFukzsZlcYHqAwwQi5EIjXhTV2j96aMcW7TEh0REREJ9y8R1XN1PnC2vwAAAABJRU5E" "rkJggg=="),
    "motorola": ("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"),
    "nokia": ("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" "OP8Fn9kasecUqiwAAAAASUVORK5CYII="),
    "oneplus": ("iVBORw0KGgoAAAANSUhEUgAAAKAAAABQCAYAAACeXX40AAAKR0lEQVR4nO2deVAUVx7HvzM4" "yDFcIgOKI4cawSjI4aoIGC9UEjRGY6zEMsmurhoNmtLdilayrms0xioriUeibnSziSZmPaIm" "2QQKNkRUTMkhEkBARcVB7gEGh+Ga2T8IhLZ7Zrp7gK7o7/OX/vq993vih1+/fq8HAIIgCIIg" "JEBm6wAmk+nF3pgI8ftEJpN9YVN/MZ1IOoILMTIKEpBLvH9NGHdMaFLi0eHVK3kvPRwTIiJv" "AXvKR9IRXPSUka+EVgUk8QihCBFRbukiyUeIoacr1p4XLArINSBB8IGvM2YF7DKX5CPE0uWO" "pSrIKSDJR/QW1iTkdQsmiL6CJSBVP6K3sVQFqQISkkICEpLCEJBuv0RfYe42TBWQkBQSkJAU" "EpCQFBKQkBQSkJAUEpCQFBKQkBQSkJAUEpCQFBKQkBQSkJAUEpCQFBKQkJQBvTWQ63A/BMbN" "hU94JFyH+2GgmztkMhkMDfVoKtegMicLpSnJqCu+bnGcKW9txRPzn2PEjG1tOL0oAbpyDav9" "0D9Mwuz9/2TELmx9CyXfnrU6rjUKT3yJy7t2CBrHZDSiTa+HvroKtYX5KE1Jwr2L6TAZjay2" "XGMlJ66GJuOC1bkJ6evmH4DnTpxjxDQZF5GcuIpz7IFu7hiV8CyGRUXDPXAE7F1cAZjQ0tiI" "Vp0OzTXV0N4sgfZGCSqys9BYdsfqfM1hs4ADXd0w6a+bETBrDmRydkF1VnnDWeUN7/HhCHl1" "BcounMelHVuhr67inUOuUCBs5Rqc37LZ1un2OTK5HPZKJeyVSrgHBGJEfAKq8nKRtmkjHlRW" "SD09q6ijYxHz9+0Y6ObOuuY02AtOg73gHhCIIRMmAuD+JhWCTbdgV7Uf5h39DwJnx3PKx4U6" "Ohbzj56AZ/AYQbkC5zwNjxEjxUxTclTjQjHn48MY4Ogo9VQs4hk8BtN3fcApX18hugLaK5WY" "+f4+KIcMZcSr8/OQc3A/qvNyYTIa4Rk0BuOXr+r+jgEAh0GDMHP3XnyzbAn0NdW88snkcoS/" "lojUDYlip8yC7+1OyDgOHh4YNiUWEze8CXulsruNq3o4nnxxGXIPH7Q5X18Rsfp1yBWK7r+3" "Nzfjyp7dKEv/CQZtHQY4OsE9MBDDomIw8ul5cPJS2ZxTdAUM/dNKuPn5M2IV2Zn474qXocm4" "iNamJrTp9ajIzkTS2j/jzo8pjLZOXipErF0vKOfw2GlQjQsVO+V+waDV4sa3Z5G5Zzfrmt+0" "GRLMiB9yhQJDIicyYrlHDuL6ya/woLICHa2taGmoR2VONrL2f4gTCXG4tGMrmmtrbcsrppPC" "WYmghS8wYiajERff2QJjWxurvcloxKWd29De3MyIj5j7DJx9hgjKHbFmnfAJS4Dm8iVWzMVX" "LcFM+OHoMYhR/QCgqeK+2fbGjg4UfX3S5oouSsAhkRNY65mK7Ew0lt0128dQV4ey9DRGTCaX" "Y9jkKVbzaTIudv/ZJ2ICfHn0IYTR0c4uHGNeeAmOgzz7NK+oNaAqZDwrVpWbY7Vf5bWrCIib" "yxqr6OuTFvtlffQhfCdFAbLOH+YV8dq6zgpjMvGfNAdxez62eP3LWbEw1GtFje07KYoV02nK" "RI3VHxjq6qCvrmKs67zGhuD5b5JQ/vNlVF7NRu31AtQU5qNVp+u1vKIEdPQczIpZKtfdbcrL" "eY31MNqSYtxK+h6Bc+IBAJ5BwQiYEYfSlCQes+1fHNw9MCw6FpGJG1jX7qalSjAj/hR8dQyR" "a99gxOzsB0IdMxXqmKkAOpdTdSVFuJ2SjKLTJ9DS2GBTTlEC2jsrWbEOg8Fqv3ZDMytmr3Th" "lTP7wF74z4yDfEDnlMNXv856sJEKa5UUAHSae8j/4vN+mI14fvn8U3gEjsSI+ASzbWRyOTxH" "B8NzdDDGLfsjzm/ZzFpaCUGUgK0PmlgxOwcH68kc2PtgrU38yrlOcw/FZ04haFHnw4/rcD+M" "TFiApvJ7vPpz0VvbMNaozs9D2qaNaNPr+zyXLZiMRpzfshmlKckYu/Rl+IRFdC97uLB3ccG0" "nbtxbuli1JfeFJVTlIDNtTWsmJLH06xy6FBWjGssc1z95ABGPjMfA36VffyKVcjYuY13/37B" "ZEJbsx766mrUFObjdkoSytJ/4jyKsy0P//FkHBKZLKyfy9LTUJaeBgcPD/iET4DX2BCoQkIx" "+MlxkNvZMdra2dsjePESZLy3nfd8eiJKwKprV1kxVWiY1X7eXA8vHGOZo7m2BgXHjyLkleUA" "Oo/5gp9fwrt/X9FflbQnrU3su5DCzEkL551H12g1h0Grxe3UZNxOTQbQeUYcuXY9nnh2IaPd" "oNHBfKbMiahtmPuZV9D+0JrPJzwSrurhZvs4eHhAHfMUI2YyGjn3yyyR99kRtDb+9sXznRwt" "qP+jAte5souae5/RheP/Rcy5dEtDPTJ2bkNHSwsj3rUuF4MoAdseNOH6yeOMmEwux5S3trI2" "M7uuRW36G2vv8NYP36HpPvvJ2BKtOh2ufXZY+KQfMSqys1gx/+mzONv6T5/JilXmsPvP+eiT" "zj1WC+s+OwdHyB4STl/F/8WShxF9FJd75BDrNRyf8EjEH/oUvpOioHByxgBHR/iERSBu70H4" "TWN+EfQ11cjc94Go3AXHjwl6m+ZRpK74Oqrz8xixwWPGIvrtf8BlmBpyOzs4q7wRsWYd/GfE" "Mdo13S9nbO53oQoNQ9yeA1h05ntErFkH38nRcPJSQa5QwN7FBT7hkZj1/n7WOrD85wzR/w7R" "tbNVp0PKG2sxe98hxnGa19gQxO21fDxjqNcidUOiaIk6WlqQe/ggJr/5tqj+XVjbPtHdK8PJ" "BfE25RCKkDllvPcO4g/9u/uhDABGzVuAUfMWmO1vMhpx6d1tMHZ0mG3jMtQXIa8s715rW5xP" "uQbF505bbWcOm17HarhzG2eXLkZpShLvpzxNxgWcW7oYNQW/2JIaxWdOWTz6exyoLSxAcuJK" "POBxCAB0fuP/7y/rzT4wtTcL2ybS3ryBpDUrWGtCIdj8QmpLQz3SNm2Em58/AmfH//ZGtKsb" "IANaGhrQdL8cFdlZuJ2ShNqiQltTAug8DM8+sA9Pbd/VK+P9XqnMycaphQnwnzEL6pip8AwK" "hoOHJxROTmg3NMOg1aKupAiajIu49cN3Fvcij8+dDu/QMKhCw+AZFAxXXzWcVCoonJwhs7P7" "9U3vStQVF+FOWiru/phqsZLygbHapB9QSfQlXb9BqedvT6IPJRGSQgISkkICEpJCAhKSQgIS" "kkICEpJCAhKSQgISkkICEpJCAhKSQgISkkICEpJCAhKSQgISksIQsOs1ma7XZgiit+B6FQug" "CkhIDAlISApLQLoNE72NudsvQBWQkBhOAakKEr2FpeoHWKiAJCFhK9bkA3jegklCQih8nbEo" "YE9zSUKCLz1dsVT9gIc+F2yJrs8MA/S5YYIbIeJ1txOSoKeEXZCMjzdcd0a+8gECBeyCS0SC" "ECJedx9bk5KMjzdipCMIgiAIQnL+D+vUqf/oNJKdAAAAAElFTkSuQmCC"),
    "samsung": ("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" "tuRk0uiuAAAAAElFTkSuQmCC"),
    "sony": ("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" "/g+tlK1Y6uJrawAAAABJRU5ErkJggg=="),
    "xiaomi": ("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" "SUVORK5CYII="),
    "zte": ("iVBORw0KGgoAAAANSUhEUgAAAKAAAABQCAYAAACeXX40AAAEB0lEQVR4nO3dTWgUdxjH8d/m" "hahBrJqqJbT1oNhqPahIbEJbTUTQg3ioqK2KHsSXpqiQQxEJoXpSVIK09gVU1FQUFXopPdQE" "8SVUkaLBFxRbsBSLfVN8a7LZxNPKZmcyO7OZ5DEz389xZmf2CXz5T3Y2m5UAAICBRF9P0N3d" "/VEYg2BwSiQS3/Xp+HwOIjq4ySfGQAG6hTd1zYGmoE+K6Gj7dvXH2duChOg7wMz4iA5uMmP0" "G2HOAAkPQQUJscBrJ/EhH5mt5Hq94Bmg2wkBP/w202uA6XKJD/lKt+O1CroGSHwIS64IfV2C" "gf7iCJDVD2HzWgVZAWGKAGGqR4BcftFfersMswLCFAHCFAHCFAHCFAHCFAHCFAHCFAHCFAHC" "FAHCFAHCFAHCVJH1AGGpnvaGGjfUhHKuyo1NOrZ1oV5/dXgo55Ok2r0/6czV3yVJMyeN0/66" "+Xmdp6MzpRnrD4U2lzVWQJgiQJgiwCwPHrerI5myHiM2IvM7YPMvdzV1zQFfj503Y7x2rZvj" "2J7q6lLd1y1qT6a0YMuJXo+vX16pxR9McmyvqD2ip+1J/0NnaTh0XifP3sr7+MEodivgxPKR" "2r76Pdd9O49f0s837w3wRPEWqwBHlJZob22NhpY4F/7vL9xW0+nrBlPFW2wCLChIaNfaOSov" "c95aafvtL31+uNVgKsQmwLrFM1Xx9muO7X8/fKZNXzaro5MXHhYi8yLEy8J3J2jF3CmO7cnO" "Lm3a16z7D54aTOXUsLJKDSurPB+z7Uirjp+5OUAT9b/Ir4DvjC9T/YpK133bm1p15c79AZ4I" "mSIdYNmIoWr8pEYlxYWOfUdbbujUuXjd8ngZRTbA4qIC7V5XrTGvDHPsu3zrT+04dtFgKmSL" "7O+AW5bN0rQJYxzb7/37RJu/alFnqstgKm/ciI6IJbPf0ofvO9+paE+mtPGL0/rv0f8GU8FN" "5AKcPnGsPlta4bqv/uA53bj7zwBPBC+RCnDcqFLtWV+tokLnj7X/xzb9cPFXg6ngJTIBlhQX" "qnFDjUYNH+LYd/7aH2o8ddlgKuQSmRchny6arslvjnbdVzWlXFe+WeX7XFY3e/3ciJZ6/nX1" "YBeZFXDsyFLrEZCHyASIwYkAYarHd8XxL3rRn9LfIZf5/XGsgDBFgDBFgDBFgDBFgDBFgDBF" "gDBFgDBFgDBFgDBFgDBFgDDVI8D0m8TpN42BsLj9IYLECghjBAhTjgC5DCNsvV1+JVZAGHMN" "kFUQYfFa/SSPFZAI0Ve54pN8XoKJEEH5bcYzwMxyiRB+ZbbitfpJWZ+K85L+xJzEp+bgLkh4" "Lx4X5AkyI0wjxnhzuzL6jU8KGGCaW4hAkPBeHNPXJyXGeMsnOgAAYO45Tow5JoQdmbMAAAAA" "SUVORK5CYII="),
}


def _maker_for(pkg):
    """Maker-chip key for a package (longest-prefix table order),
    or None when the maker is not one we badge."""
    if not pkg:
        return None
    for pre, key in _MAKER_PREFIXES:
        if pkg.startswith(pre):
            return key
    return None


def _maker_chip_png(key):
    """PNG bytes of a maker chip (embedded, drawn at build time --
    white caps on a muted brand-toned rounded rect), or None."""
    b64 = _MAKER_CHIPS_B64.get(key or "")
    if not b64:
        return None
    try:
        import base64 as _b64c
        return _b64c.b64decode(b64)
    except Exception:
        return None


# ---- generic chip: the floor under every row (v10.16) --------------
# A neutral "APP" chip in the maker-chip style, drawn at build time.
# It claims NOTHING about maker or identity: it is the last resort
# for a row whose resolution chain produced no real picture and no
# maker badge, so no row ever renders blank. Like a maker chip it
# lives in _badge_imgs and counts on the badge line, never as a
# real picture.
_GENERIC_CHIP_B64 = (
    "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")


def _generic_chip_png():
    """PNG bytes of the generic APP chip, or None."""
    try:
        import base64 as _b64g
        return _b64g.b64decode(_GENERIC_CHIP_B64)
    except Exception:
        return None


def _icon_ensure_cached(pkg, launcher):
    """v10.15 wrapper over the v10.14 ensure path: a WebP result is
    converted to PNG on the spot (the bundled dwebp extra) so it can
    actually DISPLAY on a PC without PIL; the converted PNG then
    wins every later cache find."""
    got = _icon_ensure_cached_inner(pkg, launcher)
    if got and Path(got).suffix.lower() == ".webp":
        conv = _icon_convert_cached_webp(got)
        if conv:
            return conv
    return got




# ------------------------------------------------------- v11.4 ----
# COMPANION ICON SERVICE -- PC client (ICON-CONSULT §4.2).
# When the phone carries our own Android app, the PC stops
# re-assembling icons from APK spare parts and asks the phone app
# for finished PNGs (PackageManager renders on-device: vectors,
# splits, WebP and adaptive layers all compose correctly there).
# The extractor below remains the fallback for phones without the
# helper. Protocol: line-delimited JSON over an ADB-forwarded
# socket bound to 127.0.0.1 on the phone; ops ping / icons / stop;
# every op carries the per-session token.
import base64 as _b64comp
import random as _random
import socket as _socket

COMPANION_PACKAGE = "com.ifixxrepairs.popup_blocker"
COMPANION_ACTION = "com.ifixxrepairs.popup_blocker.ICON_SERVICE"
COMPANION_ICON_SIZE = 192
COMPANION_CHUNK = 100
COMPANION_APK_NAMES = ("adtrapper-companion.apk", "companion.apk",
                       "AdTrapper-Android.apk")

# Session state (module-level so the worker thread and the UI agree).
_COMPANION = {"session": None, "status": "not checked"}
# Packages the phone itself says have NO icon of their own
# (state=default): never used as a face, only counted honestly.
_COMPANION_NO_OWN_ICON = set()
# pkg -> {"file": name, "versionCode": int, "lastUpdateTime": str}
_COMPANION_INDEX = {"loaded": False, "entries": {}}


def companion_status_text():
    """The honest one-line helper state for the status bar."""
    return "Phone helper: %s" % _COMPANION["status"]


def _companion_set_status(text):
    _COMPANION["status"] = text
    return companion_status_text()


def companion_detect(adb=None):
    """True when the companion app is installed on the phone."""
    adb = adb or adb_cmd
    try:
        out = adb("shell", "pm", "list", "packages", COMPANION_PACKAGE)
    except Exception:
        out = ""
    return COMPANION_PACKAGE in (out or "")


def companion_apk_beside_program(script_dir=None):
    """Path of a companion APK sitting beside the program, or None.
    Only these names count -- an arbitrary .apk is never installed."""
    try:
        d = Path(script_dir) if script_dir else _script_dir_path()
        for name in COMPANION_APK_NAMES:
            p = d / name
            if p.is_file() and p.stat().st_size > 0:
                return p
        for p in sorted(d.glob("*-companion.apk")):
            if p.is_file() and p.stat().st_size > 0:
                return p
    except Exception:
        pass
    return None


def companion_offer(adb=None, script_dir=None):
    """Install-offer state: {'present', 'apk', 'can_offer'}.
    The one-click offer exists ONLY when the helper is absent AND
    an APK sits beside the program (consult §4.2 PC-1)."""
    present = companion_detect(adb)
    apk = None if present else companion_apk_beside_program(script_dir)
    return {"present": present, "apk": apk,
            "can_offer": bool(not present and apk)}


def companion_install_helper(adb=None, script_dir=None):
    """One-click install of the beside-the-program companion APK.
    Returns (ok, honest_reason). Failure never blocks a scan."""
    adb = adb or adb_cmd
    apk = companion_apk_beside_program(script_dir)
    if apk is None:
        return (False, "no companion APK beside the program")
    try:
        out = adb("install", "-r", str(apk), timeout=180) or ""
    except Exception as e:
        return (False, "install failed (%s)" % e)
    if "Success" in out:
        return (True, "installed")
    return (False, "install refused by the phone (%s)"
            % (out.strip().splitlines()[-1] if out.strip()
               else "no answer"))


def companion_package_meta(pkg, adb=None):
    """(versionCode:int, lastUpdateTime-token:str) for the cache key.
    Both come from the same `dumpsys package` output the scan already
    reads; failures degrade to (0, "0") -- the key stays stable for
    this build of the app, it just cannot prove freshness."""
    adb = adb or adb_cmd
    vc, lu = 0, "0"
    try:
        out = adb("shell", "dumpsys", "package", pkg) or ""
        m = re.search(r"versionCode=(\d+)", out)
        if m:
            vc = int(m.group(1))
        m = re.search(r"lastUpdateTime=(\d{4}-\d{2}-\d{2})"
                      r"(?:\s+(\d{2}:\d{2}:\d{2}))?", out)
        if m:
            lu = re.sub(r"[^A-Za-z0-9_.-]", "_",
                        m.group(1) + (" " + m.group(2)
                                      if m.group(2) else ""))
    except Exception:
        pass
    return (vc, lu)


def companion_cache_key(pkg, version_code, last_update):
    """Cache filename: pkg__<versionCode>_<lastUpdateTime>.png --
    an app update changes the key, so its old icon is invalidated."""
    return "%s__%s_%s.png" % (_icon_safe(pkg), version_code, last_update)


def _companion_index_path():
    return _icon_cache_dir() / "companion_index.json"


def _companion_index_load():
    if _COMPANION_INDEX["loaded"]:
        return _COMPANION_INDEX["entries"]
    _COMPANION_INDEX["loaded"] = True
    try:
        data = json.loads(_companion_index_path().read_text(
            encoding="utf-8"))
        if isinstance(data, dict):
            _COMPANION_INDEX["entries"] = {
                str(k): v for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        _COMPANION_INDEX["entries"] = {}
    return _COMPANION_INDEX["entries"]


def _companion_index_save():
    try:
        _companion_index_path().write_text(
            json.dumps(_COMPANION_INDEX["entries"]), encoding="utf-8")
    except Exception:
        pass


def companion_cache_find(pkg):
    """The companion PNG file for pkg (current index entry), or None.
    This is step 1 of the amended resolution order; the index is
    re-pointed by every fetch, so an updated app serves its new face
    and the stale file is simply no longer referenced."""
    try:
        e = _companion_index_load().get(pkg) or {}
        name = e.get("file")
        if name:
            p = _icon_cache_dir() / str(name)
            if p.is_file() and p.stat().st_size > 0:
                return p
    except Exception:
        pass
    return None


def _resolved_icon_file(pkg):
    """File-based resolution chain, amended at the top only
    (owner's law): companion PNG -> extracted face (icon cache).
    Used by the report and the guide so every surface resolves a
    package the SAME way the rows do -- no forked chain."""
    p = companion_cache_find(pkg)
    if p is not None:
        return p
    return _icon_cache_find(pkg)


class _CompanionSession(object):
    """One live icon-service session: socket + token + port."""
    def __init__(self, sock, token, port):
        self.sock = sock
        self.token = token
        self.port = port
        self.rfile = sock.makefile("rb")
        self.wfile = sock.makefile("wb")

    def _send(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))
        self.wfile.flush()

    def _read_obj(self):
        line = self.rfile.readline()
        if not line:
            raise IOError("companion closed the session")
        return json.loads(line.decode("utf-8"))

    def ping(self):
        self._send({"op": "ping", "token": self.token})
        resp = self._read_obj()
        return bool(resp.get("ok")) and resp.get("app") == "adtrapper"

    def fetch_icons(self, metas, size=COMPANION_ICON_SIZE):
        """metas: [(pkg, versionCode, lastUpdateToken), ...].
        Returns {pkg: Path|None}. state=real PNGs are stored under
        the version-tagged cache key; state=default is recorded in
        _COMPANION_NO_OWN_ICON and NEVER stored as a face; a wrong
        token / refusal raises and the caller falls back."""
        out = {}
        metas = list(metas or [])
        for i in range(0, len(metas), COMPANION_CHUNK):
            chunk = metas[i:i + COMPANION_CHUNK]
            self._send({"op": "icons", "token": self.token,
                        "size": int(size),
                        "packages": [m[0] for m in chunk]})
            by_pkg = {}
            for _ in chunk:
                resp = self._read_obj()
                if isinstance(resp, dict) and resp.get("ok") is False:
                    raise IOError("companion refused the icons "
                                  "request (%s)"
                                  % resp.get("error", "no reason"))
                if isinstance(resp, dict) and resp.get("package"):
                    by_pkg[str(resp["package"])] = resp
            for pkg, vc, lu in chunk:
                resp = by_pkg.get(pkg) or {}
                state = resp.get("state")
                if state == "default":
                    _COMPANION_NO_OWN_ICON.add(pkg)
                    out[pkg] = None
                    continue
                if state == "real" and resp.get("png"):
                    try:
                        blob = _b64comp.b64decode(resp["png"])
                    except Exception:
                        blob = b""
                    if blob[:8] == b"\x89PNG\r\n\x1a\n":
                        name = companion_cache_key(pkg, vc, lu)
                        dest = _icon_cache_dir() / name
                        try:
                            dest.write_bytes(blob)
                            entries = _companion_index_load()
                            entries[pkg] = {
                                "file": name, "versionCode": vc,
                                "lastUpdateTime": lu}
                            _companion_index_save()
                            out[pkg] = dest
                            continue
                        except Exception:
                            pass
                    out[pkg] = None
                    continue
                out[pkg] = None     # state=none or malformed line
        return out

    def stop(self):
        try:
            self._send({"op": "stop", "token": self.token})
            try:
                self._read_obj()
            except Exception:
                pass
        except Exception:
            pass
        self.close()

    def close(self):
        for f in (getattr(self, "wfile", None),
                  getattr(self, "rfile", None)):
            try:
                if f:
                    f.close()
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass


def companion_open_session(port, token, host="127.0.0.1",
                           sock_factory=None, timeout=10):
    """Connect + ping-verify a session on an already-forwarded port.
    Returns the session, or None (refusal/timeout = fallback, never
    a crash -- a wrong token lands here too: ping fails)."""
    factory = sock_factory or _socket.create_connection
    try:
        sock = factory((host, int(port)), timeout=timeout)
        sess = _CompanionSession(sock, token, int(port))
        if not sess.ping():
            sess.close()
            return None
        return sess
    except Exception:
        return None


def companion_start_session(adb=None, sock_factory=None,
                            port_picker=None, retries=3):
    """Full session bring-up (consult §4.2 PC-2): random token,
    `am start` the trampoline, `adb forward` an ephemeral-range
    port (retry x3 on collision), ping to verify. On success the
    status reads 'connected'; every failure names its fallback
    state and returns None -- the scan is never blocked."""
    adb = adb or adb_cmd
    if _COMPANION["session"] is not None:
        return _COMPANION["session"]
    if not companion_detect(adb):
        _companion_set_status("not installed -- using the built-in "
                              "picture finder")
        return None
    picker = port_picker or (lambda: _random.randint(49152, 65535))
    token = uuid.uuid4().hex + uuid.uuid4().hex
    for _attempt in range(max(1, retries)):
        port = int(picker())
        try:
            adb("shell", "am", "start", "-a", COMPANION_ACTION,
                "--es", "token", token, "--ei", "port", str(port),
                timeout=30)
            fwd = adb("forward", "tcp:%d" % port, "tcp:%d" % port,
                      timeout=30) or ""
            if "cannot" in fwd.lower() or "error" in fwd.lower():
                continue            # port collision: next attempt
        except Exception:
            continue
        sess = companion_open_session(port, token,
                                      sock_factory=sock_factory)
        if sess is not None:
            _COMPANION["session"] = sess
            _companion_set_status("connected")
            return sess
        try:
            adb("forward", "--remove", "tcp:%d" % port, timeout=15)
        except Exception:
            pass
    _companion_set_status("installed but not answering -- using the "
                          "built-in picture finder")
    return None


def companion_stop_session(adb=None):
    """Teardown: stop op + forward removal. Nothing left running."""
    adb = adb or adb_cmd
    sess = _COMPANION["session"]
    _COMPANION["session"] = None
    if sess is None:
        return
    port = sess.port
    sess.stop()
    try:
        adb("forward", "--remove", "tcp:%d" % port, timeout=15)
    except Exception:
        pass
    if _COMPANION["status"] == "connected":
        _companion_set_status("installed (session ended)")


def companion_fetch_for_packages(pkgs, adb=None, sock_factory=None,
                                 port_picker=None):
    """Ensure a session and fetch every listed package whose CURRENT
    companion cache entry is missing/stale. Returns {pkg: Path|None}
    for the packages fetched this call ({} when no session -- the
    caller simply proceeds on the extractor fallback)."""
    sess = companion_start_session(adb, sock_factory=sock_factory,
                                   port_picker=port_picker)
    if sess is None:
        return {}
    adb = adb or adb_cmd
    entries = _companion_index_load()
    todo = []
    for pkg in pkgs or []:
        vc, lu = companion_package_meta(pkg, adb)
        e = entries.get(pkg) or {}
        if e.get("file") == companion_cache_key(pkg, vc, lu) and \
                companion_cache_find(pkg) is not None:
            continue                # current face already cached
        todo.append((pkg, vc, lu))
    if not todo:
        return {}
    try:
        return sess.fetch_icons(todo)
    except Exception:
        # Refusal / broken pipe mid-fetch: honest fallback state.
        _companion_set_status("installed but the session failed -- "
                              "using the built-in picture finder")
        return {}


def companion_no_own_icon_count(pkgs=None):
    """How many (of pkgs, or overall) the phone says have no icon
    of their own -- the honest Pictures/coverage number."""
    if pkgs is None:
        return len(_COMPANION_NO_OWN_ICON)
    return sum(1 for p in pkgs if p in _COMPANION_NO_OWN_ICON)


LEARNED_BAD = _load_local_bad()

def _load_blocklist_feed():
    """Load threat feed from local blocklist.json or cached feed if present,
    merging into KNOWN_BAD so PC scanner stays in sync with server/blocklist.json."""
    candidates = [
        _script_dir_path() / "blocklist.json",
        _script_dir_path().parent / "server" / "blocklist.json",
    ]
    for c in candidates:
        if c.is_file():
            try:
                with open(c, encoding="utf-8") as f:
                    data = json.load(f)
                pkgs = data.get("packages", [])
                if pkgs:
                    return set(pkgs)
            except Exception:
                pass
    return set()

# The feed set loaded at import is the silent refresher's shrink
# baseline: a fetched feed must never hold FEWER packages than
# what this PC already knew when the app started.
_FEED_BASELINE = _load_blocklist_feed()
KNOWN_BAD.update(_FEED_BASELINE)

# --------------------------------------------------------- face book --
# The Bad List face view (v10.13): every blocklist package with the
# store name + face picture hunted from the Play Store listing
# (faces.json / faces.zip on the same shelf as the threat feed).
# Packages the store has delisted get the owner's no-face badge:
# a circle-with-a-cross plus the words REMOVED FROM PLAY STORE.
SHELF_BASE = ("https://raw.githubusercontent.com/ifixrepairs/"
              "popup-blocker/main/")
FACES_BADGE_TEXT = "REMOVED FROM PLAY STORE"


def _faces_cache_dir():
    """Face-book cache lives next to the script, like the icon cache."""
    d = _script_dir_path() / "faces_cache"
    try:
        d.mkdir(exist_ok=True)
    except Exception:
        pass
    return d


def _faces_fetch(url, timeout=20):
    try:
        return _default_fetch_bytes(url, timeout=timeout)
    except Exception:
        return None


def _load_faces_feed():
    """(order, entries, ok_faces) for the Bad List face view.

    Downloads blocklist.json + faces.json from the shelf and caches
    them next to the script; faces.zip (every store face picture) is
    downloaded ONCE and extracted into faces_cache/faces/. Falls
    back to the cached copies, then to the bundled blocklist, so
    the view still lists names when the PC is offline.
    """
    cache = _faces_cache_dir()
    order, entries, faces_list = [], {}, []
    raw = _faces_fetch(SHELF_BASE + "blocklist.json", timeout=15)
    if raw:
        try:
            (cache / "blocklist.json").write_bytes(raw)
        except Exception:
            pass
    if not raw:
        try:
            raw = (cache / "blocklist.json").read_bytes()
        except Exception:
            raw = None
    if raw:
        try:
            order = [str(x) for x in
                     json.loads(raw.decode("utf-8")).get("packages", [])]
        except Exception:
            order = []
    rawf = _faces_fetch(SHELF_BASE + "faces.json", timeout=15)
    if rawf:
        try:
            (cache / "faces.json").write_bytes(rawf)
        except Exception:
            pass
    if not rawf:
        try:
            rawf = (cache / "faces.json").read_bytes()
        except Exception:
            rawf = None
    if rawf:
        try:
            faces_list = json.loads(
                rawf.decode("utf-8")).get("faces", [])
            for e in faces_list:
                if isinstance(e, dict) and e.get("package"):
                    entries[str(e["package"])] = e
        except Exception:
            faces_list, entries = [], {}
    ok_faces = bool(entries)
    if not order:
        order = [str(e["package"]) for e in faces_list
                 if isinstance(e, dict) and e.get("package")]
    if not order:
        order = sorted(KNOWN_BAD)
    # v10.15 gate fix: the downloaded shelf blocklist is the LIVE
    # conviction list; the built-in KNOWN_BAD is only the offline
    # floor and goes stale between releases (125 built in vs 155 on
    # the shelf). Merge the shelf order into KNOWN_BAD IN PLACE so
    # every reader -- scan_core convictions, the guided piles, and
    # the icon resolution's store-face step -- sees the same list.
    # The built-in entries are never removed: offline, the floor
    # still convicts.
    if order:
        try:
            KNOWN_BAD.update(order)
        except Exception:
            pass
    if ok_faces and not (cache / "faces").is_dir():
        rawz = _faces_fetch(SHELF_BASE + "faces.zip", timeout=180)
        if rawz:
            try:
                import io as _iof
                zf = _zipfile.ZipFile(_iof.BytesIO(rawz))
                for name in zf.namelist():
                    if (name.startswith("faces/")
                            and not name.endswith("/")):
                        target = cache / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(zf.read(name))
            except Exception:
                pass
    return order, entries, ok_faces


# -------------------------------------------------- silent feed -----
# SILENT FEED (owner-approved 2026-10-17): the threat list keeps
# itself current QUIETLY. On app startup and at the start of every
# scan, a background thread re-fetches the shelf blocklist.json --
# the same raw URL the face-book feed uses -- and, if the accept
# rule passes, merges it into KNOWN_BAD on the spot. No button,
# no wait, no popup: the tech just finds the list longer than he
# left it, with one line in the Activity log saying so. Feature
# updates still travel the manual UPDATE road (manifest + hash +
# verified swap); only the DATA flows silently.
_SILENT_FEED_TIMEOUT = 8          # seconds; the UI never waits

_FEED_LOCK = threading.Lock()
_FEED_STATE = {"current": None,   # last accepted shelf feed (set)
               "previous": None,  # the feed it replaced (rollback)
               "busy": False}     # a refresh is already in flight


def _feed_accepts(new_pkgs, old_pkgs):
    """THE accept rule for a fetched threat feed -- the one gate,
    kept in a single named function so the per-shop license /
    watermark layer can hook it later. A feed is accepted only
    when it is a real, non-empty package set that does not SHRINK
    what we already know: the list only grows or holds. A feed
    that arrives smaller is rejected as suspicious -- if the
    owner ever needs the list smaller, the manual UPDATE button
    (manifest-verified) is the deliberate road for that."""
    if not isinstance(new_pkgs, (set, frozenset)) or not new_pkgs:
        return False
    if old_pkgs and len(new_pkgs) < len(old_pkgs):
        return False
    return True


def _fetch_shelf_feed(fetch_bytes=None, timeout=None):
    """The shelf blocklist as a package set, or None on ANY
    failure -- offline, timeout, malformed JSON, or a shape that
    is not {packages: [str, ...]}. Reuses the exact raw shelf URL
    and byte fetcher the face-book feed already uses."""
    fetch = fetch_bytes or _default_fetch_bytes
    try:
        raw = fetch(SHELF_BASE + "blocklist.json",
                    timeout=timeout or _SILENT_FEED_TIMEOUT)
        if not raw:
            return None
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            return None
        pkgs = data.get("packages")
        if not isinstance(pkgs, list):
            return None
        return {str(p) for p in pkgs if isinstance(p, str) and p}
    except Exception:
        return None


def _silent_feed_once(fetch_bytes=None):
    """One silent threat-feed refresh attempt. Returns the log
    line to show when a fetched feed was accepted AND grew what
    we know; returns None (and changes NOTHING) when the fetch
    failed, the feed was rejected, or nothing was new. Never
    raises. Runs in a background thread -- the merge itself is
    one quick set union under the feed lock, so the in-memory
    feed swaps atomically while the previous feed is kept in
    _FEED_STATE for the session's rollback."""
    try:
        with _FEED_LOCK:
            if _FEED_STATE["busy"]:
                return None
            _FEED_STATE["busy"] = True
    except Exception:
        return None
    try:
        new = _fetch_shelf_feed(fetch_bytes)
        if new is None:
            return None
        with _FEED_LOCK:
            old = _FEED_STATE["current"]
            if old is None:
                old = _FEED_BASELINE
            if not _feed_accepts(new, old):
                return None
            before = len(KNOWN_BAD)
            _FEED_STATE["previous"] = set(old) if old else None
            _FEED_STATE["current"] = set(new)
            KNOWN_BAD.update(new)
            added = len(KNOWN_BAD) - before
            total = len(KNOWN_BAD)
        if added > 0:
            return ("Threat list updated silently \u2014 %d bad "
                    "apps known (+%d new)." % (total, added))
        return None
    except Exception:
        return None
    finally:
        try:
            with _FEED_LOCK:
                _FEED_STATE["busy"] = False
        except Exception:
            pass


# -------------------------------------------------- known faces -----
# v10.15: the KNOWN-FACES pack (appfaces.json / appfaces.zip on the
# same shelf): a store name + face for the apps a counter sees every
# day, hunted from their Play listings exactly like the Face Book.
# It is a FALLBACK for rows the extractor could not face (split
# APKs, vector-only icons) -- a face scanned off the phone wins.
def _appfaces_cache_dir():
    """Known-faces cache lives next to the script, like the others."""
    d = _script_dir_path() / "appfaces_cache"
    try:
        d.mkdir(exist_ok=True)
    except Exception:
        pass
    return d


def _load_appfaces_feed():
    """(entries, ok) for the known-faces pack.

    Downloads appfaces.json from the shelf and caches it next to the
    script; appfaces.zip (every pack face picture) is downloaded
    when the manifest's zip hash differs from the extracted copy's
    stamp -- or there is no extracted copy -- and extracted into
    appfaces_cache/. Falls back to the cached copies, so the pack
    still works when the PC is offline. Never raises.
    """
    cache = _appfaces_cache_dir()
    entries = {}
    raw = _faces_fetch(SHELF_BASE + "appfaces.json", timeout=15)
    if raw:
        try:
            (cache / "appfaces.json").write_bytes(raw)
        except Exception:
            pass
    if not raw:
        try:
            raw = (cache / "appfaces.json").read_bytes()
        except Exception:
            raw = None
    manifest = None
    if raw:
        try:
            manifest = json.loads(raw.decode("utf-8"))
            for e in manifest.get("faces", []):
                if isinstance(e, dict) and e.get("package"):
                    entries[str(e["package"])] = e
        except Exception:
            entries, manifest = {}, None
    ok = bool(entries)
    if ok:
        want = str((manifest or {}).get("zip_sha256") or "")
        stamp = ""
        try:
            stamp = (cache / "appfaces_zip.sha").read_text().strip()
        except Exception:
            stamp = ""
        have = (cache / "appfaces").is_dir()
        if not have or (want and stamp != want):
            rawz = _faces_fetch(SHELF_BASE + "appfaces.zip",
                                timeout=180)
            if rawz and want:
                try:
                    if hashlib.sha256(rawz).hexdigest() != want:
                        rawz = None
                except Exception:
                    rawz = None
            if rawz:
                try:
                    import io as _ioa
                    zf = _zipfile.ZipFile(_ioa.BytesIO(rawz))
                    for name in zf.namelist():
                        if (name.startswith("appfaces/")
                                and not name.endswith("/")):
                            target = cache / name
                            target.parent.mkdir(parents=True,
                                                exist_ok=True)
                            target.write_bytes(zf.read(name))
                    (cache / "appfaces_zip.sha").write_text(
                        want or hashlib.sha256(rawz).hexdigest())
                except Exception:
                    pass
    return entries, ok

# Legitimate home apps (system launchers) - never flagged as hijackers
TRUSTED_LAUNCHERS = {
    "com.sec.android.app.launcher",      # Samsung One UI Home
    "com.google.android.apps.nexuslauncher",  # Pixel Launcher
    "com.android.launcher3",             # AOSP Launcher
    "com.mi.android.globallauncher",     # MIUI
}

# First-party package prefixes whose apps are never flagged by heuristics.
# Matches lib/services/app_scanner.dart in the Android app (Hard Rule #3).
FIRST_PARTY_PREFIXES = (
    "com.google.",
    "com.samsung.",
    "com.sec.",
    "com.adobe.",
    "com.amazon.",
    "com.microsoft.",
    "com.miui.",
    "com.oneplus.",
    "com.motorola.",
    "com.android.",
    "android.",
    "com.qualcomm.",
    "com.mediatek.",
    "org.chromium.",
    "com.skms.",
)
WEBAPK_PREFIX = "org.chromium.webapk."

# Legitimate apps never flagged, even if the name looks "junky"
TRUSTED_PKGS = {
    "com.adobe.reader",              # Adobe Acrobat Reader
    "com.foxit.mobile.pdf.lite",     # Foxit PDF Reader
    "com.google.android.apps.docs",  # Google Drive (PDF viewer)
}

JUNK_RE = re.compile(
    r"clean|boost|junk|cooler|antivirus|virus|shield|guard|battery|flashlight|torch|"
    r"applock|qrcode|qrscan|wallpaper|weather|launcher|optimi[sz]|speed|phonemaster|"
    r"vpn|antispy|phonecare|ramclean|cpucool|"
    r"pdfreader|pdfviewer|pdfupdate|clarifypdf|pdf|adblock|adremov|"
    r"adblocker|ad\s*remov|doc\s*reader|document\s*reader", re.I)

# === BEGIN FAKE-KEYWORD TABLE (law section 14) =====================
# THE KEYWORD SOURCE OF TRUTH for the section 14 conviction.
# Owner ruling 2026-10-21 (~11:59 EDT): NO NARROWING -- the
# owner ordered a full web harvest of every keyword that makes
# up fake cleaner / junk app names ("Add all the keywords that
# make up fake cleaners. The keywords are the flags."), and the
# harvested table replaces the old question of whether section
# 14 should consult all of JUNK_RE: section 14 consults THIS
# TABLE ONLY, on both paths (scan_core's costume block and the
# Background Check's fake_utility fact). JUNK_RE above keeps
# its older heuristic jobs (combos, ASK FIRST reasons) and is
# no longer the section 14 source.
#
# HARVEST LANDED 2026-10-21: the rows below are the harvested
# set from builds/verdict-law-2026-10-21/fake-keywords.json
# (+ FAKE-KEYWORD-HARVEST.md) -- 91 keywords/phrases in 14
# families -- plus ONE owner-ruled row the harvest does not
# carry: the word FAKE itself (owner ruling ~11:35, Keyword
# fake), which started this section and stays. BOOSTER and
# CLEANER, the other two owner-ruled words, are among the
# harvested rows.
#
# Rows are (keyword, match_target, family). match_target is
# "package+label", "package" or "label" -- the JSON's
# "name_or_package" / "package" / "name" adapted to this
# file's target names; matching is a case-insensitive substring
# test, the same style the old alternation used. Brand
# impersonation (the harvest's family 15) carries NO bare
# keywords by design -- it is a pattern check, not a word
# match -- so it has no rows here.
FAKE_KEYWORD_TABLE = (
    # Owner-ruled (2026-10-21 ~11:35): the word FAKE itself.
    ("fake", "package+label", "owner-ruled"),
    # Harvested rows (fake-keywords.json, in file order).
    # family: cleaner_booster
    ("cleaner", "package+label", "cleaner_booster"),
    ("phone cleaner", "label", "cleaner_booster"),
    ("junk cleaner", "package+label", "cleaner_booster"),
    ("smart clean", "package+label", "cleaner_booster"),
    ("clean master", "package+label", "cleaner_booster"),
    ("super clean", "label", "cleaner_booster"),
    ("super cleaner", "label", "cleaner_booster"),
    ("fast cleaner", "label", "cleaner_booster"),
    ("useful cleaner", "label", "cleaner_booster"),
    ("rubbish cleaner", "label", "cleaner_booster"),
    ("clean boost", "label", "cleaner_booster"),
    ("powerful cleaner", "label", "cleaner_booster"),
    ("total cleaner", "package+label", "cleaner_booster"),
    ("booster", "package+label", "cleaner_booster"),
    ("ram booster", "package+label", "cleaner_booster"),
    ("ramclean", "package", "cleaner_booster"),
    ("speed booster", "label", "cleaner_booster"),
    ("optimizer", "package+label", "cleaner_booster"),
    ("junk", "label", "cleaner_booster"),
    ("phone master", "label", "cleaner_booster"),
    # family: antivirus_security
    ("antivirus", "package+label", "antivirus_security"),
    ("virus cleaner", "label", "antivirus_security"),
    ("cleaner antivirus", "label", "antivirus_security"),
    ("app lock", "label", "antivirus_security"),
    ("applock", "package", "antivirus_security"),
    ("ad blocker", "package+label", "antivirus_security"),
    ("internet security", "label", "antivirus_security"),
    # family: vpn_proxy
    ("vpn", "package+label", "vpn_proxy"),
    ("free vpn", "label", "vpn_proxy"),
    ("super vpn", "label", "vpn_proxy"),
    ("vpn pro", "label", "vpn_proxy"),
    ("turbo vpn", "label", "vpn_proxy"),
    ("unblock", "package", "vpn_proxy"),
    # family: battery_cooler_ram
    ("battery saver", "package+label", "battery_cooler_ram"),
    ("battery doctor", "label", "battery_cooler_ram"),
    ("phone cooler", "package+label", "battery_cooler_ram"),
    ("cpu cooler", "label", "battery_cooler_ram"),
    ("charging animation", "label", "battery_cooler_ram"),
    # family: pdf_scanner_document
    ("pdfreader", "package", "pdf_scanner_document"),
    ("pdfviewer", "package", "pdf_scanner_document"),
    ("pdfupdate", "package", "pdf_scanner_document"),
    ("clarifypdf", "package", "pdf_scanner_document"),
    ("pdf scanner", "label", "pdf_scanner_document"),
    ("doc scanner", "label", "pdf_scanner_document"),
    ("pdf converter", "label", "pdf_scanner_document"),
    ("file converter", "label", "pdf_scanner_document"),
    ("qr code", "package+label", "pdf_scanner_document"),
    ("barcode scanner", "label", "pdf_scanner_document"),
    # family: wallpaper_flashlight
    ("wallpaper", "package+label", "wallpaper_flashlight"),
    ("live wallpaper", "label", "wallpaper_flashlight"),
    ("wallpaper 4d", "label", "wallpaper_flashlight"),
    ("emoji wallpaper", "label", "wallpaper_flashlight"),
    ("flashlight", "package+label", "wallpaper_flashlight"),
    ("flash on call", "label", "wallpaper_flashlight"),
    ("flash alert", "label", "wallpaper_flashlight"),
    # family: cash_reward_bait
    ("real cash", "label", "cash_reward_bait"),
    ("real money", "label", "cash_reward_bait"),
    ("win real cash", "label", "cash_reward_bait"),
    ("win cash", "label", "cash_reward_bait"),
    ("lucky money", "label", "cash_reward_bait"),
    ("jackpot", "label", "cash_reward_bait"),
    # family: call_screen_communication
    ("call screen", "package+label", "call_screen_communication"),
    ("call screen theme", "label", "call_screen_communication"),
    ("color call", "label", "call_screen_communication"),
    ("color phone", "label", "call_screen_communication"),
    ("call flash", "label", "call_screen_communication"),
    ("private sms", "label", "call_screen_communication"),
    ("private message", "label", "call_screen_communication"),
    ("direct messenger", "label", "call_screen_communication"),
    ("color message", "label", "call_screen_communication"),
    ("emoji messenger", "label", "call_screen_communication"),
    # family: fortune_horoscope
    ("horoscope", "package+label", "fortune_horoscope"),
    ("palmistry", "package+label", "fortune_horoscope"),
    ("palm reader", "label", "fortune_horoscope"),
    ("fortune", "label", "fortune_horoscope"),
    ("zodiac", "label", "fortune_horoscope"),
    ("future seer", "label", "fortune_horoscope"),
    # family: photo_camera_bait
    ("beauty camera", "label", "photo_camera_bait"),
    ("selfie camera", "label", "photo_camera_bait"),
    ("magic camera", "label", "photo_camera_bait"),
    ("background cut out", "label", "photo_camera_bait"),
    # family: keyboard_fonts
    ("fancy fonts", "label", "keyboard_fonts"),
    ("emoji keyboard", "label", "keyboard_fonts"),
    # family: system_disguise
    ("system update", "label", "system_disguise"),
    ("software update", "label", "system_disguise"),
    ("find your phone", "label", "system_disguise"),
    # family: file_recovery_bait
    ("file manager", "label", "file_recovery_bait"),
    ("photo recovery", "label", "file_recovery_bait"),
    ("recover deleted", "label", "file_recovery_bait"),
    ("file recovery", "package+label", "file_recovery_bait"),
    # family: weather_disguise
    ("weather", "package+label", "weather_disguise"),
)
# === END FAKE-KEYWORD TABLE ========================================


def _compile_fake_keyword_res():
    """Compile the table into one regex per match target. The
    keywords are DATA (plain words/phrases from the harvest), so
    they are escaped before compilation -- a keyword can never
    act as a pattern."""
    by_target = {}
    for keyword, target, _family in FAKE_KEYWORD_TABLE:
        by_target.setdefault(target, []).append(re.escape(keyword))
    return {target: re.compile("|".join(parts), re.I)
            for target, parts in by_target.items() if parts}


_FAKE_KEYWORD_RES = _compile_fake_keyword_res()


def _fake_keyword_match(pkg, label):
    """Pure section 14 keyword-table match (no shields, no
    exceptions): True when any table row hits its target field.
    This is the determination BOTH section 14 teeth consult --
    the Background Check's fake_utility fact is exactly this."""
    pkg = pkg or ""
    label = label or ""
    for target, rx in _FAKE_KEYWORD_RES.items():
        if target in ("package+label", "package") \
                and rx.search(pkg):
            return True
        if target in ("package+label", "label") \
                and rx.search(label):
            return True
    return False


def _fake_keyword_hit(pkg, label):
    """The scan-side section 14 determination: the table match,
    with the TRUSTED_PKGS exception the scan's junk_hit always
    carried (verified PDF readers are not convicted on name
    evidence). Shields (guard / never-remove) are applied by the
    caller via _fake_costume_shielded, as before."""
    return _fake_keyword_match(pkg, label) and pkg not in TRUSTED_PKGS

PKG_RE = r"[a-zA-Z][\w]*(?:\.[\w]+)+"

# Permissions worth flagging in the privacy audit.
# Ad / tracking networks whose components are declared inside an app's
# manifest (visible in dumpsys). One network in a free app is normal
# monetization; a stack of them - or an aggressive one - is how "free"
# games and tools hide pop-up machines. AGGRESSIVE = repeatedly caught
# serving ads OUTSIDE their host app.
AD_SDKS = {
    "Google Ads": ("com.google.android.gms.ads", "com.google.ads"),
    "AppLovin": ("com.applovin",),
    "Unity Ads": ("com.unity3d.ads", "com.unity3d.services"),
    "ironSource": ("com.ironsource",),
    "Mintegral": ("com.mbridge", "com.mintegral"),
    "Vungle": ("com.vungle",),
    "Chartboost": ("com.chartboost",),
    "Meta Audience Network": ("com.facebook.ads",),
    "Pangle": ("com.bytedance.sdk", "com.pangle"),
    "StartApp": ("com.startapp",),
    "Fyber": ("com.fyber",),
    "InMobi": ("com.inmobi",),
    "Tapjoy": ("com.tapjoy",),
    "AdColony": ("com.adcolony",),
    "Ogury": ("com.ogury",),
    "Amazon Ads": ("com.amazon.device.ads",),
    "Moloco": ("com.moloco",),
    "BidMachine": ("io.bidmachine",),
    "Yandex Ads": ("com.yandex.mobile.ads",),
}
AGGRESSIVE_SDKS = ("Mintegral", "StartApp")


SENSITIVE_PERMS = {
    "texts": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
              "android.permission.SEND_SMS"],
    "contacts": ["android.permission.READ_CONTACTS"],
    "call log": ["android.permission.READ_CALL_LOG"],
    "location": ["android.permission.ACCESS_FINE_LOCATION",
                 "android.permission.ACCESS_COARSE_LOCATION",
                 "android.permission.ACCESS_BACKGROUND_LOCATION"],
    "microphone": ["android.permission.RECORD_AUDIO"],
    "camera": ["android.permission.CAMERA"],
}

# Score at which an app is auto-flagged (pre-checked) for removal.
FLAG_SCORE = 3

# v11.2 owner ruling (2026-10-19): the Background Check conviction bar
# applies to the plain scan too. An app whose inline scan finds this
# many or more DISTINCT ad networks is REMOVE on the scan itself --
# "stuffed with 9 ad networks should have been a red flag from the
# jump" -- instead of waiting for a one-tap Background Check to
# convict it. The bar VALUE is 4 (owner amendment 2026-10-19 10:48
# EDT: "I want four ads not 5"; it was 5 in the first 11.2 build).
# (The Background Check's own bar lives in score_background_check: a
# COMPLETE code census at >= 5 networks confirms. That bar is NOT
# changed by the amendment, which was about the scan verdict. The
# scan's count is the inline manifest count, n_sdk.)
CONVICT_NETWORK_COUNT = 4

# Photo bar (owner ruling 2026-10-21): a photo-vault app is
# convicted by ad evidence only at this many distinct ad networks
# or more; under it, ad evidence caps the vault at ASK FIRST.
PHOTO_VAULT_CONVICT_NETWORKS = 3

ADB = None  # resolved at startup


def find_adb():
    """Locate adb.exe: PATH first, then the usual download spots."""
    found = shutil.which("adb")
    if found:
        return found
    home = Path.home()
    candidates = [
        Path(sys.argv[0]).parent / "platform-tools" / "adb.exe",
        Path.cwd() / "platform-tools" / "adb.exe",
        home / "Downloads" / "platform-tools-latest-windows"
             / "platform-tools" / "adb.exe",
        home / "Downloads" / "platform-tools" / "adb.exe",
        home / "platform-tools" / "adb.exe",
        Path("C:/platform-tools/adb.exe"),
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def _no_console():
    """Windows: keep subprocess calls from flashing a console window."""
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return {"startupinfo": si}
    return {}


def run(cmd, timeout=60):
    """Run an adb command, return stdout text ('' on failure)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, **_no_console())
        return out.stdout.strip()
    except Exception:
        return ""


def adb_cmd(*args, timeout=60):
    return run([ADB, *args], timeout=timeout)


def check_device():
    """Returns (ok, message)."""
    global ADB
    ADB = find_adb()
    if not ADB:
        return (False, "ADB_NOT_FOUND")
    out = adb_cmd("devices")
    devices = [l for l in out.splitlines()[1:] if l.strip().endswith("device")]
    if not devices:
        return (False, "NO_PHONE")
    if len(devices) > 1:
        return (False, "MULTI_PHONE")
    return (True, "")




def packages_in(text):
    """Extract package names from adb output text."""
    return set(re.findall(PKG_RE + r"(?=/|:|\s|$)", text or ""))


def third_party_with_installers():
    """Returns {pkg: installer_pkg} for third-party apps."""
    out = adb_cmd("shell", "pm", "list", "packages", "-3", "-i")
    result = {}
    for line in out.splitlines():
        m = re.match(r"package:(\S+)\s+installer=(\S+)", line.strip())
        if m:
            result[m.group(1)] = m.group(2)
    return result


def install_source(installer):
    """(label, sideloaded?) for an installer package name."""
    if installer in STORES:
        return STORES[installer], False
    if installer in TRANSFER:
        return TRANSFER[installer], False
    if CARRIER.match(installer or ""):
        return "carrier preload", False
    if installer in ("null", "", None):
        return "sideloaded (no installer)", True
    return "sideloaded via " + installer, True


def parse_pkg_dump(out):
    """(first_install, last_update, label, granted_perms) from dumpsys output."""
    first = last = None
    for key, var in (("firstInstallTime", "first"), ("lastUpdateTime", "last")):
        m = re.search(key + r"=(\S+)", out)
        if m:
            try:
                val = datetime.strptime(m.group(1)[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                try:
                    val = datetime.strptime(m.group(1)[:10], "%Y-%m-%d")
                except ValueError:
                    val = None
            if var == "first":
                first = val
            else:
                last = val
    label = None
    m = re.search(r"application-label:'([^']+)'", out)
    if not m:
        m = re.search(r'application-label:"([^"]+)"', out)
    if m:
        label = m.group(1)
    perms = set(re.findall(r"\s*([\w.]+): granted=true", out))
    return first, last, label, perms


def usage_map():
    """{pkg: (last_used_str, launch_count)} from usage stats."""
    out = adb_cmd("shell", "dumpsys", "usagestats", timeout=90)
    result = {}
    for m in re.finditer(r'package=(\S+) totalTimeUsed="[^"]*" lastTimeUsed="([^"]+)"(.*)', out):
        pkg, last, rest = m.group(1), m.group(2), m.group(3)
        lm = re.search(r"appLaunchCount=(\d+)", rest)
        launches = int(lm.group(1)) if lm else 0
        prev_last, prev_launch = result.get(pkg, ("", 0))
        clean_last = last if not last.startswith("19") else ""
        result[pkg] = (max(prev_last, clean_last), max(prev_launch, launches))
    return result


def site_channels():
    """Browser site-notification grants as [(date_str, host)], newest first."""
    out = adb_cmd("shell", "dumpsys", "notification", "--noredact", timeout=90)
    rows = []
    for host, stamp in set(re.findall(r"mId='web:https?://([^;']*);(\d+)'", out)):
        try:
            # Chrome stores grant time as microseconds since 1601-01-01.
            when = datetime.fromtimestamp(int(stamp) / 1_000_000 - 11644473600)
            rows.append((when.strftime("%Y-%m-%d"), host))
        except (ValueError, OSError):
            pass
    return sorted(rows, reverse=True)


def phone_today():
    d = adb_cmd("shell", "date", "+%F").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
        return date.fromisoformat(d)
    return date.today()


# Issue #36: manufacturer namespaces for the learned-list rule. A package
# whose ONLY hit is the shop's learned list, living in one of these
# namespaces, is OEM software the shop once removed - a REVIEW item
# ("shop history"), not a REMOVE conviction.
OEM_LEARNED_PREFIXES = ("com.samsung.", "com.sec.android.",
                        "com.google.android.", "com.android.")


# Packages that ARE part of the phone itself (OS / maker system
# components). The namespaces below are the ones BOTH views of this
# app already treat as the phone's own system: the scanner's core
# prefixes (scan_core) and Guided Clean's shield (SHIELD_PREFIXES).
# A shop-history hit on one of these is an ECHO, not a finding: the
# component lives on the system image, so "removing" it only strips
# its updates and it comes right back -- flagging it forever made the
# main list call it REVIEW while Guided Clean called the same app
# GREEN. System components are never flagged for shop history.
SHOP_HISTORY_SYSTEM_PKGS = frozenset({
    "com.google.android.contactkeys",   # contact-key verifier (system)
    "com.google.android.safetycore",    # Android System SafetyCore
})
SHOP_HISTORY_SYSTEM_PREFIXES = (
    "com.google.android.", "com.android.", "android.",
    "com.samsung.", "com.sec.android.",
    "com.qualcomm.", "com.mediatek.", "org.chromium.", "com.skms.",
)


def _is_system_component(pkg):
    """True for OS / maker system components (see note above)."""
    return (pkg in SHOP_HISTORY_SYSTEM_PKGS
            or pkg.startswith(SHOP_HISTORY_SYSTEM_PREFIXES))


# --------------------------------------------------------- house trust --
# v10.14 (owner order, after he filmed v10.13 flagging the shop's own
# beta app as its ONLY hit): packages under the shop's own namespace
# are OUR OWN apps -- AdTrapper itself, PrintMyTexts, and whatever
# ships next under it. The scanner must never flag its own tools: a
# house package skips the sideload flag and every heuristic and comes
# out OK, labeled "(our app)" so the counter can see it is ours at a
# glance. In scan_core this exemption sits AFTER the conviction inputs
# are computed: KNOWN_BAD membership or a known-bad label still routes
# the package into _known_or_learned_verdict and still shows REMOVE --
# house trust never whitewashes a conviction.
HOUSE_PREFIX = "com.ifixxrepairs."


def _known_or_learned_verdict(pkg, in_known_bad, label_bad, learned_rec):
    """(verdict, reason) for list-based hits, or None if no list hit.

    Convictions (KNOWN_BAD or a known-bad label) are always REMOVE -
    including OEM-namespace mimics like com.sec.reclean, which is not a
    manufacturer package at all; the learned guard below never shelters
    a conviction. Learned-only hits are shop MEMORY, never a
    conviction (v11.3 Learned Guard -- removal-by-memory-alone is
    abolished):
      * a guard-list package (famous verified app, exact id) is no
        flag at all -- one customer's housekeeping removal is not the
        next customer's crime;
      * a system component is no flag at all (unchanged: the component
        lives on the system image and only "came back", v10.13);
      * a manufacturer package is REVIEW, "shop history" (Issue #36);
      * anything else is REVIEW, "learned".
    A recorded removal date / ticket rides along in the reason; an
    unknown date is omitted, never invented.
    """
    if in_known_bad or label_bad:
        return ("remove", "known junk app (confirmed in shop testing)")
    if learned_rec is not None:
        if pkg in KNOWN_LEGIT_GUARD:
            return None
        if _is_system_component(pkg):
            return None
        suffix = _learned_provenance_suffix(learned_rec)
        if pkg.startswith(OEM_LEARNED_PREFIXES):
            return ("review",
                    "removed by this shop before (shop history)" + suffix)
        return ("review",
                "removed by this shop before (learned)" + suffix)
    return None


# ------------------------------------------------- factory-app cap ---
# Owner amendment (2026-10-21): "put all the factory apps on phone
# no removable". An app whose copy ON THIS PHONE is a factory /
# preinstalled install is NEVER removable on that device: its
# verdict caps at ASK FIRST (review) no matter what the evidence
# says -- blocklist match and ad-software conviction included. The
# evidence lines still display, plus the factory line below. The
# cap is PER-DEVICE (this phone's copy), never per-package: the
# same package installed from a store on another phone follows the
# normal rules, and KNOWN_BAD contents are untouched by this rule.
# scan_core decides factory-ness per package from THIS device's
# own data only: (1) membership in PRELOAD_EXTRA (not a third-party
# -3 install on this phone, yet it has a launcher icon), which
# scan_core itself resolves to source "preinstalled
# (carrier/maker)"; (2) its own source resolution landing on
# "factory preinstalled"; (3) the package's dumpsys text declaring
# a system-image copy (pkgFlags/flags containing SYSTEM, or a
# codePath under /system, /product, /vendor, /oem, /system_ext).
FACTORY_APP_REASON = ("factory app: came preinstalled on this phone "
                      "-- cannot be removed from this phone "
                      "(it can only be disabled)")


def _row_is_factory(reasons):
    """True when a scan row's reasons carry the factory-app line
    (scan_core is the only writer of that exact line, so rows --
    whose 9-tuple shape must not change -- carry their own
    per-device factory mark for Guided Clean / checkbox /
    stored-verdict consumers)."""
    for r in reasons or []:
        if str(r).lower().startswith("factory app: came preinstalled"):
            return True
    return False


def _dump_is_factory(out):
    """True when one package's dumpsys text declares a
    system-image (factory) copy on THIS device."""
    text = out or ""
    if re.search(r"(?:pkgFlags|flags)=\[[^\]]*\bSYSTEM\b", text):
        return True
    if re.search(r"codePath=/(?:system|product|vendor|oem|system_ext)/",
                 text):
        return True
    return False


# ------------------------------------------------------- guided clean ---
# Guided Clean (beginner mode) sorts each flagged row into one of three
# piles: "remove" (junk -- safe to take off), "keep" (the customer's own
# stuff -- Guided Clean NEVER removes it), "ask" (left on the phone for a
# human to decide). System/manufacturer namespaces and famous consumer
# apps are always "keep" -- UNLESS the package is a feed conviction
# (KNOWN_BAD): a shield never overrides a conviction (com.sec.reclean
# wears a Samsung-style namespace but is confirmed junk).
SHIELD_PREFIXES = ("com.google.android.", "com.android.",
                   "com.samsung.", "com.sec.android.")

POPULAR_KEEP = {
    "com.facebook.katana", "com.facebook.orca", "com.instagram.android",
    "com.whatsapp", "com.zhiliaoapp.musically", "com.snapchat.android",
    "com.amazon.mShop.android.shopping", "com.netflix.mediaclient",
    "com.spotify.music", "net.zedge.android",
}
POPULAR_KEEP_PREFIXES = ("com.zynga.", "net.peakgames.",
                         "com.peoplefun.", "com.easybrain.")


def guided_pile(pkg, verdict, convicted=False, factory=False):
    """Which Guided Clean pile a flagged row belongs to.

    "keep"   -- shielded/famous app (unless convicted), or clean verdict
    "remove" -- REMOVE verdict on a non-shielded app, or any conviction
    "ask"    -- REVIEW verdict: a human decides

    factory=True (owner amendment 2026-10-21) outranks even a
    conviction: a factory app lands in "ask" -- shown with its
    evidence, never in a removal set.
    """
    if factory and verdict in ("remove", "review"):
        return "ask"
    shielded = (pkg.startswith(SHIELD_PREFIXES)
                or pkg in POPULAR_KEEP
                or pkg.startswith(POPULAR_KEEP_PREFIXES))
    if shielded and not convicted:
        return "keep"
    if verdict == "remove" or convicted:
        return "remove"
    if verdict == "review":
        return "ask"
    return "keep"


def original_numbers(scan_data):
    """{pkg: original_number} -- the stable scan numbers (AT-2).

    Assigned ONCE, in scan order over every row of the scan, at
    the presentation layer (scan_core's 9-tuple MUST NOT change,
    AT-19). Because the number comes from this one mapping -- not
    from a row's position in whatever view is on screen -- it
    survives filter / sort / view changes and is the same number
    in the main list, Guided Clean, and the printed report."""
    nums = {}
    for i, r in enumerate(scan_data or [], 1):
        try:
            if r[0] not in nums:
                nums[r[0]] = i
        except Exception:
            continue
    return nums


def scan_numbers(scan_data):
    """Original scan numbers (kept name for existing callers).

    v11.0: this is the AT-2 original-number mapping over ALL scan
    rows in scan order -- NOT a renumbering of the flagged subset,
    so a flagged app keeps its number in every view."""
    return original_numbers(scan_data)


GUIDE_PILE_STYLE = {
    # Midnight Dark verdict tokens (spec 3.2, AT-23 single swap):
    "remove": "#FF4D4D",   # RED text    = take it off
    "keep":   "#35D05A",   # GREEN text  = it stays
    "ask":    "#FFCF40",   # YELLOW text = ask first
}

GUIDE_HEADERS = {
    "remove": "JUNK -- will be removed (%d):",
    "keep":   "YOUR STUFF -- kept, never touched (%d):",
    "ask":    "NOT SURE -- left on the phone for a human to decide (%d):",
}


def guided_sections(scan_data):
    """Guided Clean guide sections (issues #46 + #49).

    Returns [(pile, header, [(number, name, row), ...]), ...] in
    remove / keep / ask order. Every flagged row appears exactly once,
    carrying its main-list scan number (issue #46), and NOTHING is
    truncated: the guide is what staff and customers follow, so no app
    may hide behind a '+ N more' line. The dialog WRITES each line in
    its pile color (GUIDE_PILE_STYLE) -- RED = remove, GREEN = keep,
    YELLOW = ask first -- on the guide's normal background, so the
    guide can be followed by color alone (issue #49)."""
    piles = {"remove": [], "keep": [], "ask": []}
    for r in scan_data:
        if r[4] not in ("remove", "review"):
            continue
        piles[guided_pile(r[0], r[4],
                          convicted=r[0] in KNOWN_BAD,
                          factory=_row_is_factory(r[3]))].append(r)
    nums = scan_numbers(scan_data)
    return [(k, GUIDE_HEADERS[k] % len(piles[k]),
             [(nums[r[0]], r[1] or r[0], r) for r in piles[k]])
            for k in ("remove", "keep", "ask")]


STABLE_NAME = "AdTrapper-PC.pyw"


def ensure_stable_alias(src=None):
    """Keep a stable-named copy of the running build next to it.

    Every update installs a NEW versioned filename (…-v10.8.pyw), which
    breaks any desktop shortcut pointing at the old name. This alias
    (AdTrapper-PC.pyw, no version in the name) is refreshed to the
    running build at every startup, so a shortcut pointed at it works
    forever — updates included. Returns the alias path, or None.
    """
    try:
        src = os.path.abspath(src or __file__)
        dst = os.path.join(os.path.dirname(src), STABLE_NAME)
        if os.path.normcase(src) == os.path.normcase(dst):
            return dst
        if os.path.exists(dst) \
                and os.path.getsize(dst) == os.path.getsize(src):
            with open(src, "rb") as a, open(dst, "rb") as b:
                if a.read() == b.read():
                    return dst
        shutil.copyfile(src, dst)
        return dst
    except Exception:
        return None


def row_default_checked(pkg, verdict, reasons=None):
    """Initial checkbox state for a results-list row.

    A row starts checked only if it is flagged (remove/review) AND
    Guided Clean would not keep it. Shielded rows (Facebook, Google
    system apps) still show their verdict badge, but start UNCHECKED --
    after a removal pass the app auto re-scans and rebuilds this list,
    and one stray REMOVE ALL click must never take a keeper with it.
    (convicted=False here on purpose: the shield namespaces are exact
    prefixes -- com.sec.android. is shielded, com.sec.<junk> is not.)
    Factory rows (reasons carries the factory-app line; owner
    amendment 2026-10-21) NEVER start checked.
    """
    if _row_is_factory(reasons):
        return False
    return (verdict in ("remove", "review")
            and guided_pile(pkg, verdict) != "keep")


def scan_core(progress_cb=None):
    """Returns (results, sites).
    results: [(pkg, label, score, reasons, verdict, source_cat, privacy,
               threat_type, boot_hit)] for every third-party app.
    verdict is "remove" (high-confidence junk, pre-checked), "review"
    (suspicious, needs a human look) or "clean". threat_type is one of
    Malware/Adware/Spyware/Tracking/Suspicious/Clean.
    sites: [(date_str, host)] allowed to send browser notifications.
    """
    installers = third_party_with_installers()
    today = phone_today()
    boot_pkgs = packages_in(adb_cmd("shell", "pm", "queryreceivers", "--components",
                                    "-a", "android.intent.action.BOOT_COMPLETED"))

    overlays = packages_in(adb_cmd("shell", "appops", "query-op",
                                   "SYSTEM_ALERT_WINDOW", "allow"))
    admins = packages_in(" ".join(
        re.findall(r"ComponentInfo\{[^}]+\}", adb_cmd("shell", "dumpsys", "device_policy"))))
    a11y = packages_in(adb_cmd("shell", "settings", "get", "secure",
                               "enabled_accessibility_services"))
    can_install = packages_in(adb_cmd("shell", "appops", "query-op",
                                      "REQUEST_INSTALL_PACKAGES", "allow"))
    listeners = packages_in(adb_cmd("shell", "settings", "get", "secure",
                                    "enabled_notification_listeners"))
    usage_access = packages_in(adb_cmd("shell", "appops", "query-op",
                                       "GET_USAGE_STATS", "allow"))
    launcher_raw = adb_cmd("shell", "cmd", "package", "query-activities", "--brief",
                           "-a", "android.intent.action.MAIN",
                           "-c", "android.intent.category.LAUNCHER")
    launcher = packages_in(launcher_raw)
    if len(launcher) < 5:
        launcher = None  # unsupported on this Android version: skip hidden-icon check
    # HOME apps: who can be the device's home screen? A "cleaner" or "PDF"
    # app registered as HOME is a launcher hijack - massive red flag.
    home_raw = adb_cmd("shell", "cmd", "package", "query-activities", "--brief",
                       "-a", "android.intent.action.MAIN",
                       "-c", "android.intent.category.HOME")
    home_apps = packages_in(home_raw)
    # Preloaded apps with a launcher icon that are NOT core system parts:
    # carrier/maker junk (cleaners, ad apps) hides here because the
    # third-party list (-3) never includes it.
    ALL_PKGS = packages_in(adb_cmd("shell", "pm", "list", "packages"))
    PRELOAD_EXTRA = set()
    if launcher:
        CORE_PREFIXES = ("com.samsung.", "com.sec.", "com.google.",
                         "com.android.", "android.", "com.qualcomm.",
                         "com.mediatek.", "org.chromium.", "com.skms.")
        for p in ALL_PKGS:
            if (p not in installers and p in launcher
                    and not p.startswith(CORE_PREFIXES)):
                PRELOAD_EXTRA.add(p)
                installers[p] = None

    used = usage_map()

    recent_cutoff = datetime.now() - timedelta(days=30)
    results = []
    pkgs = sorted(installers)
    total = len(pkgs)
    for i, pkg in enumerate(pkgs):
        installer = installers[pkg]
        out = adb_cmd("shell", "dumpsys", "package", pkg)
        first, last, label, perms = parse_pkg_dump(out)
        if not label:
            label = pkg

        source, sideloaded = install_source(installer)
        if pkg in PRELOAD_EXTRA:
            source, sideloaded = "preinstalled (carrier/maker)", False
        if sideloaded and (not first or first.year < 2010 or
                           pkg.startswith(("com.samsung.", "com.sec."))):
            source, sideloaded = "factory preinstalled", False

        # Factory-app signal for THIS phone's copy (owner
        # amendment 2026-10-21; see the factory-cap block above
        # scan_core for why these three are the per-device truth).
        _is_factory = (pkg in PRELOAD_EXTRA
                       or source in ("preinstalled (carrier/maker)",
                                     "factory preinstalled")
                       or _dump_is_factory(out))

        if sideloaded:
            source_cat = "Sideloaded"
        elif source in STORES.values():
            source_cat = source  # "Play Store", "Galaxy Store", ...
        else:
            source_cat = "Preinstalled"

        score, reasons = 0, []
        _lab = (label or "").strip().lower()
        _label_bad = (_lab in KNOWN_BAD_LABELS
                      or _lab.startswith(KNOWN_BAD_LABEL_PREFIXES))
        if (pkg.startswith(HOUSE_PREFIX) and pkg not in KNOWN_BAD
                and not _label_bad):
            # House trust (v10.14): our own app -- OK, "(our app)",
            # no sideload flag, no heuristics. Convictions were NOT
            # exempted: KNOWN_BAD / known-bad-label packages fall
            # through to _known_or_learned_verdict and stay REMOVE.
            boot_hit = pkg in boot_pkgs
            privacy = [cat for cat, plist in SENSITIVE_PERMS.items()
                       if any(pr in perms for pr in plist)]
            if progress_cb:
                try:
                    progress_cb(i + 1, total, pkg)
                except Exception:
                    pass
            results.append((pkg, label + " (our app)", 0, [], "clean",
                            source_cat, privacy, "Clean", boot_hit))
            continue
        _kl = _known_or_learned_verdict(pkg, pkg in KNOWN_BAD,
                                        _label_bad, LEARNED_BAD.get(pkg))
        if _kl is not None:
            verdict, _kl_reason = _kl
            score = 99
            reasons = [_kl_reason]
            if _is_factory:
                # Factory cap (owner amendment 2026-10-21) catches
                # the blocklist short-circuit too: a blocklisted
                # factory copy is ASK FIRST, its known-junk
                # evidence line still shown, plus the factory line.
                if verdict == "remove":
                    verdict = "review"
                reasons = reasons + [FACTORY_APP_REASON]
            threat_type = "Malware"
            boot_hit = pkg in boot_pkgs
            privacy = [cat for cat, plist in SENSITIVE_PERMS.items()
                       if any(pr in perms for pr in plist)]
            if progress_cb:
                try:
                    progress_cb(i + 1, total, pkg)
                except Exception:
                    pass
            results.append((pkg, label, score, reasons, verdict, source_cat,
                            privacy, threat_type, boot_hit))
            continue

        if (pkg.startswith(FIRST_PARTY_PREFIXES)
                and not pkg.startswith(WEBAPK_PREFIX)):
            # First-party shield: vendor apps are never flagged by heuristics.
            # (Matches lib/services/app_scanner.dart - Hard Rule #3).
            boot_hit = pkg in boot_pkgs
            privacy = [cat for cat, plist in SENSITIVE_PERMS.items()
                       if any(pr in perms for pr in plist)]
            if progress_cb:
                try:
                    progress_cb(i + 1, total, pkg)
                except Exception:
                    pass
            results.append((pkg, label, 0, [], "clean", source_cat,
                            privacy, "Clean", boot_hit))
            continue

        webapk_hit = pkg.startswith(WEBAPK_PREFIX)
        admin_hit = pkg in admins
        a11y_hit = pkg in a11y
        hidden_hit = launcher is not None and pkg not in launcher
        overlay_hit = pkg in overlays
        home_hit = pkg in home_apps and pkg not in TRUSTED_LAUNCHERS
        installer_hit = ("android.permission.REQUEST_INSTALL_PACKAGES" in perms
                         or pkg in can_install)
        if webapk_hit:
            score += 2
            reasons.append("a website installed as an app (WebAPK)")
        if sideloaded:
            score += 4
            reasons.append("not from an app store (%s)" % source)
        if admin_hit:
            score += 3
            reasons.append("device admin (can resist uninstall)")
        if a11y_hit:
            score += 3
            reasons.append("uses accessibility service")
        if hidden_hit:
            score += 2
            reasons.append("no app icon (hidden from app drawer)")
        if overlay_hit:
            score += 2
            reasons.append("can draw over other apps (POPUP CAPABLE)")
        if home_hit:
            score += 5
            reasons.append("registers as a HOME app (launcher hijack!)")
        if installer_hit:
            score += 1
            reasons.append("can install other apps")

        never_hit = recent_hit = abandoned_hit = False
        age = (today - first.date()).days if first else None
        if age is not None:
            last_used, launches = used.get(pkg, ("", 0))
            if age > 3 and not last_used and launches == 0:
                never_hit = True
                score += 1
                reasons.append("never opened")
            if age <= 30:
                recent_hit = True
                score += 1
                reasons.append("installed recently (%s)" % first.date())
        if last and (today - last.date()).days > 730:
            abandoned_hit = True
            score += 1
            reasons.append("not updated since %s (abandoned)" % last.date())
        junk_hit = bool(
            pkg not in TRUSTED_PKGS
            and (JUNK_RE.search(pkg) or JUNK_RE.search(label or "")))
        if junk_hit:
            score += 1
            reasons.append("cleaner/booster/PDF-type name (common adware disguise)")
        # Inside the app: ad networks declared in its manifest.
        _low = out.lower()
        sdk_hits = sorted({nm for nm, prefs in AD_SDKS.items()
                           if any(pf in _low for pf in prefs)})
        n_sdk = len(sdk_hits)
        aggressive_hit = any(nm in AGGRESSIVE_SDKS for nm in sdk_hits)
        listener_hit = pkg in listeners
        usage_hit = pkg in usage_access
        if n_sdk >= CONVICT_NETWORK_COUNT:
            # v11.2: over the conviction line -- the reason itself
            # carries the count and the network names (boom rule:
            # "stuffed with N ad networks" renders loud + bold).
            score += 2
            _shown = ", ".join(sdk_hits[:6])
            if n_sdk > 6:
                _shown += " +%d more" % (n_sdk - 6)
            reasons.append("Stuffed with %d ad networks (%s)"
                           % (n_sdk, _shown))
        elif n_sdk >= 3:
            score += 2
            reasons.append("stuffed with %d ad networks (%s)"
                           % (n_sdk, ", ".join(sdk_hits[:4])))
        elif aggressive_hit:
            score += 2
            reasons.append("runs aggressive ad network %s (known for "
                           "pop-up ads outside the app)"
                           % ", ".join(nm for nm in sdk_hits
                                       if nm in AGGRESSIVE_SDKS))
        if listener_hit:
            score += 4
            reasons.append("can READ all notifications "
                           "(notification listener access)")
        if usage_hit and n_sdk:
            score += 1
            reasons.append("can track which apps you use (usage access)")
        # Sideloaded "PDF" app: classic scareware (legit readers use Play Store)
        if sideloaded and "pdf" in (pkg + " " + (label or "")).lower():
            score += 2
            reasons.append("sideloaded PDF app (common scareware disguise)")
        # Name mimicry: pretends to be "Google Play", "Settings", etc. (McAfee HiddenAds)
        _mimic_labels = {"google play", "settings", "google settings", "play store",
                         "google home", "system update", "android system"}
        _genuine_pkgs = {"com.android.vending", "com.google.android.gms",
                         "com.android.settings", "com.google.android.apps.home"}
        _mimic_hit = False
        if (label or "").strip().lower() in _mimic_labels and pkg not in _genuine_pkgs:
            score += 4
            reasons.append('pretends to be "%s" (name mimicry - review required)' % label.strip())
            _mimic_hit = True
        boot_hit = pkg in boot_pkgs
        if boot_hit:
            score += 2
            reasons.append("starts at boot (survives restart)")
        privacy = [cat for cat, plist in SENSITIVE_PERMS.items()
                   if any(pr in perms for pr in plist)]
        if privacy and (junk_hit or sideloaded or len(privacy) >= 2):
            score += 1
            reasons.append("can access your " + ", ".join(privacy))

        # Verdict: "remove" = high-confidence junk, pre-checked.
        # "review" = suspicious, shown for a human decision. "clean" = leave alone.
        if (webapk_hit
              or home_hit
              or (sideloaded and (junk_hit or overlay_hit or admin_hit))
              or (junk_hit and (recent_hit or overlay_hit or abandoned_hit))
              or (overlay_hit and junk_hit)
              or (overlay_hit and n_sdk >= 1)
              or (listener_hit and n_sdk >= 1)
              or (aggressive_hit and recent_hit)
              or (admin_hit and junk_hit)):
            verdict = "remove"
        elif score >= FLAG_SCORE:
            verdict = "review"
        elif _mimic_hit:
            verdict = "review"
        elif junk_hit:
            verdict = "review"
            reasons.append("cleaner/booster-type: never trusted blind "
                           "(common adware disguise)")
        elif n_sdk >= 3 or listener_hit:
            verdict = "review"
        elif overlay_hit or admin_hit or a11y_hit:
            verdict = "review"
        else:
            verdict = "clean"

        # v11.2 owner ruling (2026-10-19): the Background Check
        # conviction bar applies to the plain scan. >=
        # CONVICT_NETWORK_COUNT distinct ad networks found inline is
        # a REMOVE on the scan itself. The bar value is 4 (owner
        # amendment 2026-10-19 10:48 EDT: "I want four ads not 5").
        # Precedence:
        #   * an existing REMOVE stays REMOVE (nothing to outrank --
        #     this only ever promotes);
        #   * it outranks every softer outcome above (review /
        #     clean), including the junk-name ASK FIRST and the
        #     n_sdk >= 3 review branch;
        #   * photo vaults: the total exemption that stood here
        #     (owner rail, scan rulings 2026-10-15) was replaced
        #     by the PHOTO BAR (owner ruling 2026-10-21): a
        #     vault is convicted by ad evidence at >= 3 distinct
        #     ad networks -- at this >= 4 bar, and at exactly 3
        #     in the ad-software block below; under 3 the vault
        #     sits at ASK FIRST with its ad evidence shown;
        #   * the bar outranks the name-mimicry downgrade below:
        #     a stuffed fake clone app is REMOVE (owner ruling
        #     2026-10-19 10:44 EDT, "Yes remove fake clone app").
        #     The mimicry downgrade still demotes removals that
        #     came from the name/score path with NO census
        #     conviction, exactly as in 11.1.
        _bar_convicted = False
        if n_sdk >= CONVICT_NETWORK_COUNT:
            verdict = "remove"
            _bar_convicted = True

        # Owner ruling (2026-10-21): "if it says contains ad
        # software, flag it immediately onto the list" -- the
        # "Contains ad software" evidence (>= 1 known ad SDK found
        # by this scan's existing inline manifest census) convicts
        # BY ITSELF: verdict REMOVE. No fake-name clue needed, no
        # network-count threshold, no Background Check trip. This
        # block is promotion-only (it never demotes a REMOVE) and
        # sits after the >= 4 bar, before the mimicry downgrade --
        # and, like a bar conviction, it is NOT demoted by the
        # mimicry downgrade (census convictions are not demoted by
        # costume; fake-clone ruling 2026-10-19). Exemptions:
        # KNOWN_LEGIT_GUARD packages (the guard previously governed
        # the learned path alone; it now also gates THIS path --
        # the >= 4 bar above and the blocklist paths are unchanged
        # and still convict guard packages). Photo vaults follow
        # the PHOTO BAR in this block (owner ruling 2026-10-21):
        # ASK FIRST under 3 distinct ad networks, convicted at 3
        # or more. First-party-shield and house-trust
        # packages returned earlier and never reach here.
        # Reason wording: for 1-2 networks (which previously got no
        # SDK reason line, or only an aggressive-network line) the
        # row gains the "Contains ad software" line naming the
        # network(s); for >= 3 networks the existing "stuffed with
        # N ad networks" line already carries the same fact and
        # renders loud, so no duplicate line is appended.
        _adsw_convicted = False
        _photo_vault = is_photo_vault(pkg, label)
        if n_sdk >= 1 and pkg not in KNOWN_LEGIT_GUARD:
            if _photo_vault and n_sdk < PHOTO_VAULT_CONVICT_NETWORKS:
                # PHOTO BAR (owner ruling 2026-10-21 ~09:18 EDT;
                # the owner set the bar at 3, ~09:20 EDT): under 3
                # distinct ad networks a photo vault is NOT
                # convicted by ad evidence -- it sits at ASK FIRST
                # with the ad evidence shown and the photo reason
                # noted, so a customer's photos are never deleted
                # on thin ad evidence. The floor only ever raises a
                # softer verdict to review; harder verdicts from
                # the non-census paths above are shipped law and
                # are not demoted here.
                if verdict in ("clean", "review"):
                    verdict = "review"
                    reasons.append(
                        "Contains ad software \u2014 %s (photo app "
                        "\u2014 kept for asking: photos are never "
                        "deleted on ad evidence under %d networks)"
                        % (", ".join(sdk_hits),
                           PHOTO_VAULT_CONVICT_NETWORKS))
            elif _photo_vault and n_sdk < CONVICT_NETWORK_COUNT:
                # A vault at exactly PHOTO_VAULT_CONVICT_NETWORKS
                # (3): convicted by ad evidence in this block (the
                # >= 4 bar block above takes 4 and up). The
                # "stuffed with 3 ad networks" line appended above
                # already carries the fact and renders loud, so --
                # as for every >= 3 conviction -- no second line.
                verdict = "remove"
                _adsw_convicted = True
            elif not _photo_vault:
                if n_sdk < 3 and not any(
                        "contains ad software" in r.lower()
                        for r in reasons):
                    reasons.append("Contains ad software \u2014 %s"
                                   % ", ".join(sdk_hits))
                verdict = "remove"
                _adsw_convicted = True

        # Owner ruling (2026-10-21, law section 14): the FAKE
        # keyword class convicts INSTANTLY at scan. The keywords
        # are owner-named -- FAKE, BOOSTER, CLEANER -- and the
        # class is the scan's EXISTING fake-name determination
        # (junk_hit: the JUNK_RE name test on package or label,
        # whose tokens already carry the class -- "clean" matches
        # cleaner, "boost" matches booster, and the costume words
        # cleaner / flashlight / wallpaper / launcher / pdf /
        # antivirus ... are the fake-utility disguise family). No
        # new name heuristic is invented here; no Background Check
        # trip, no points threshold, no network count. This
        # supersedes the older line "fake-name alone stays ASK
        # FIRST" for this class (section 14 records the
        # supersession). Promotion-only: it never demotes a
        # REMOVE earned another way. Exemptions mirror the
        # ad-software block above: the KNOWN_LEGIT GUARD wins (a
        # guard package is never convicted by its costume --
        # com.cvs.launchers.cvs, the verified CVS Pharmacy app,
        # joins the guard with this very ruling because this
        # finding misfired on its legacy "launchers" package
        # name); the factory cap below still caps the verdict at
        # review; first-party-shield and house-trust packages
        # returned earlier and never reach here. Photo vaults:
        # the section 13 photo bar governs AD-EVIDENCE
        # convictions only -- the costume conviction is not an
        # ad-network count, so a vault wearing the costume
        # convicts here like any other app (unless guarded or
        # factory); report-up still never reports a vault. The
        # NEVER-REMOVE list shields this conviction the same way
        # (via _fake_costume_shielded): CCleaner & co. are never
        # convicted by the cleaner keyword, on either tooth.
        _fake_convicted = False
        if _fake_keyword_hit(pkg, label) \
                and not _fake_costume_shielded(pkg):
            _fake_convicted = True
            if verdict != "remove":
                verdict = "remove"
                reasons.append(
                    "FAKE-UTILITY COSTUME \u2014 cleaner / "
                    "flashlight / wallpaper-type disguise: flagged "
                    "fake on sight (owner keyword rule)")

        if _mimic_hit and verdict == "remove" and not _bar_convicted \
                and not _adsw_convicted and not _fake_convicted:
            # Owner rule: name mimicry is review-only, never
            # auto-remove -- for name/score-path removals only.
            # A census conviction (bar fired above) is NOT demoted:
            # owner ruling 2026-10-19 10:44 EDT ("Yes remove fake
            # clone app") -- the bar wins over the costume. A
            # section 14 costume conviction is likewise NOT
            # demoted: the costume is itself a conviction-grade
            # finding, not a mimicry-only removal.
            verdict = "review"

        if verdict in ("remove", "review"):
            if admin_hit:
                threat_type = "Malware"
            elif _mimic_hit:
                threat_type = "Suspicious"
            elif privacy and (sideloaded or junk_hit):
                threat_type = "Spyware"
            elif "location" in privacy:
                threat_type = "Tracking"
            elif junk_hit or overlay_hit or n_sdk >= 2 or _adsw_convicted:
                threat_type = "Adware"
            else:
                threat_type = "Suspicious"
        else:
            threat_type = "Clean"

        # Factory cap (owner amendment 2026-10-21): a factory copy
        # is NEVER removable on this device -- the verdict caps at
        # review, the evidence lines stay, and the factory line is
        # appended. A ceiling, not a floor: a clean factory row is
        # untouched (this block only ever demotes a REMOVE).
        if _is_factory and verdict == "remove":
            verdict = "review"
            reasons = reasons + [FACTORY_APP_REASON]

        # Report-up for the NEW ad-software path (report-up section
        # below): a conviction produced by ad software ALONE (not
        # the >= 4 bar -- bar convictions follow the existing
        # Background Check report path unchanged) queues a tagged
        # scan conviction report into the same outbox. A
        # factory-capped row queues NOTHING: the evidence is real
        # but no conviction stands on this device. Never raises; a
        # failed queue changes no verdict. version_code is parsed
        # from the same dumpsys text this scan already read; when
        # it cannot be read (> 0 required by the contract) the
        # builder declines and nothing is queued.
        if _adsw_convicted and not _bar_convicted and not _is_factory:
            try:
                _vc_m = re.search(r"versionCode=(\d+)", out or "")
                _vc = int(_vc_m.group(1)) if _vc_m else 0
                queue_scan_conviction_report(
                    pkg, label, sdk_hits, reasons, _vc,
                    vault=is_photo_vault(pkg, label))
            except Exception:
                pass

        # Report-up for the section 14 keyword path: a costume
        # conviction the ad-software rule did NOT also claim
        # queues ONE report tagged "scan_fake_costume" into the
        # same outbox (one report per row per scan -- when both
        # rules convict, the ad report above is the row's report:
        # the census evidence is the stronger exhibit). A
        # factory-capped row queues NOTHING, exactly as on the
        # ad path. The builder declines vaults and >= 4-network
        # (bar-class) rows. PIPE POLICY (owner ruling 2026-10-21):
        # a scan_fake_costume report is a KEYWORD-CLASS
        # conviction -- on the pipe side it promotes to the bad
        # list IMMEDIATELY (it counts at once; it does not wait
        # in quarantine for the double-check). The automatic
        # double-check still runs afterward as an AUDIT, and an
        # audit-cleared package is struck via the removal-manifest
        # path. That policy lives in the pipe processor, not in
        # this file; this hook's only job is the tag.
        if _fake_convicted and not _adsw_convicted \
                and not _bar_convicted and not _is_factory:
            try:
                _vc_f = re.search(r"versionCode=(\d+)", out or "")
                _vcfv = int(_vc_f.group(1)) if _vc_f else 0
                queue_scan_costume_report(
                    pkg, label, sdk_hits, reasons, _vcfv,
                    vault=is_photo_vault(pkg, label))
            except Exception:
                pass

        if progress_cb:
            try:
                progress_cb(i + 1, total, pkg)
            except Exception:
                pass
        results.append((pkg, label, score, reasons, verdict, source_cat,
                        privacy, threat_type, boot_hit))

    # Fake copies: several apps sharing one system-app name.
    _COMMON = {"messages", "messenger", "phone", "camera", "gallery",
               "settings", "play store", "calculator", "clock",
               "calendar", "contacts", "weather", "browser", "email"}
    _counts = {}
    for r in results:
        if len(r) == 9:
            k = (r[1] or "").strip().lower()
            _counts[k] = _counts.get(k, 0) + 1
    _fixed = []
    for r in results:
        if len(r) == 9 and r[4] == "clean":
            pkg, label, score, reasons, verdict, sc, priv, tt, bt = r
            lab = (label or "").strip().lower()
            if lab in _COMMON and _counts.get(lab, 0) >= 2:
                if pkg.startswith(FIRST_PARTY_PREFIXES):
                    _fixed.append(r)
                    continue
                score += 3
                reasons = reasons + ["multiple apps named '%s' - fake copy (review required)"
                                     % label]
                verdict = "review"  # Owner rule: review-only, never auto-remove
                if tt == "Clean":
                    tt = "Suspicious"
                r = (pkg, label, score, reasons, verdict, sc, priv, tt, bt)
        _fixed.append(r)
    results = _fixed

    # Tripwire: any app with a drawer icon that the scan did NOT process
    # gets flagged REVIEW - a silent miss becomes a loud one.
    if launcher:
        _scanned = {r[0] for r in results}
        for p in sorted(launcher):
            if (p not in _scanned and p in ALL_PKGS
                    and not p.startswith(CORE_PREFIXES)):
                results.append(
                    (p, p, 3,
                     ["has an app-drawer icon but was NOT in the scan "
                      "list (hiding from the scan)"],
                     "review", "Unknown", [], "Suspicious", False))

    results.sort(key=lambda r: (-r[2], r[1].lower()))
    return results, site_channels()


def backup_apk(pkg, backup_dir):
    """Pull the app's APK(s) into backup_dir/pkg/. Returns base apk path or None."""
    paths = [l.replace("package:", "") for l in
             adb_cmd("shell", "pm", "path", pkg).splitlines()
             if l.startswith("package:")]
    if not paths:
        return None
    dest = Path(backup_dir) / pkg
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None
    saved = None
    for ap in paths:
        local = dest / Path(ap).name
        try:
            subprocess.run([ADB, "pull", ap, str(local)],
                           capture_output=True, text=True, timeout=120,
                           **_no_console())
        except Exception:
            pass
        if local.is_file() and saved is None:
            saved = str(local)
    return saved


def strip_device_admin(pkg):
    """Revoke device-admin via dpm so the app can be uninstalled.
    Returns True if an admin was found and verified removed."""
    out = adb_cmd("shell", "dumpsys", "device_policy")
    for m in re.finditer(r"ComponentInfo\{([^}]+)\}", out):
        comp = m.group(1)  # e.g. "com.pkg/.AdminReceiver"
        if comp.split("/")[0] == pkg:
            r = adb_cmd("shell", "dpm", "remove-active-admin",
                        "--user", "0", comp)
            # Re-check dumpsys to verify active admin was actually stripped
            post = adb_cmd("shell", "dumpsys", "device_policy")
            if comp not in post:
                return True
            if "Success" in r or "removed" in r.lower():
                return True
    return False


def uninstall_core(pkg):
    """Returns a short result message. Three methods, strongest last."""
    out = adb_cmd("uninstall", pkg)
    if "Success" in out:
        return "uninstalled"
    out = adb_cmd("shell", "pm", "uninstall", "--user", "0", pkg)
    if "Success" in out:
        return "uninstalled (stubborn-app method)"
    # Brick-wall breaker: strip device admin, then retry uninstall
    if strip_device_admin(pkg):
        out = adb_cmd("shell", "pm", "uninstall", "--user", "0", pkg)
        if "Success" in out:
            return "uninstalled (device admin stripped first)"
    out = adb_cmd("shell", "pm", "disable-user", "--user", "0", pkg)
    if "disabled" in out.lower():
        return "disabled (can't run or show popups)"
    return ("COULD NOT REMOVE - on the phone go to Settings > Security and privacy > "
            "Device admin apps, turn it off there, then uninstall from Settings > Apps")


# ------------------------------------------- background check (v11.1) --
# BACKGROUND CHECK (owner's feature, researched 2026-10-17 -- see
# builds/adtrapper/background-check-RESEARCH-v1.md and issue #82):
# a REVIEW row ("ASK FIRST") gets a BACKGROUND CHECK button. The check
# digs into that one app OFFLINE, over the same ADB cable the scan
# used: it reads the app's declared tells out of dumpsys (pop-up
# permission, full-screen intent, install-others, installer, target
# SDK), pulls the app's APK(s) off the phone and runs a DEX census --
# every class name inside the code matched against the ad-SDK
# signature book -- then scores the evidence by the research law:
#
#   * Store words alone can never confirm; a CONFIRMED verdict
#     REQUIRES the code census (an eyes-on-the-code source).
#   * >= 5 distinct ad networks in the census = CONFIRMED on its own.
#   * Points: census 3-4 networks +3, census 2 networks +2,
#     pop-up + stays-alive combo in a fake-utility app +2,
#     sideloaded +1, ancient target SDK (<= 28) under a recent
#     update +1. Confirm at >= 7 points WITH the census present.
#   * Clearing also requires the census: a completed census at
#     0-1 networks (a -3 clearing weight) at <= 2 net points =
#     CLEARED BY CODE CENSUS. No census = STILL NOT SURE, never
#     "clean" -- "no evidence found" is not the same as clean.
#     "Completed" means COMPLETE: if any part of the app could not
#     be read (a split that would not pull, an unopenable APK, an
#     unreadable DEX), the verdict caps at STILL NOT SURE -- a
#     partial census can still CONFIRM (presence is proven) but
#     can never clear, and the dialog says the app was NOT FULLY
#     CHECKED.
#   * The check NEVER removes anything. It recolors and explains;
#     the tech still taps Remove (or Keep) in the result dialog.
#   * Photo vaults can be CHECKED but never removed from the dialog:
#     the customer's hidden photos may live inside (standing rail).
# Every completed check appends its evidence bundle as one JSON line
# to background-check-results.jsonl beside this app -- the staging
# file that feeds the blocklist pipeline (research Angle 3, rail 4).
import struct as _bg_struct
import tempfile as _bg_tempfile
import zipfile as _bg_zipfile

_BG_SIG_FILENAME = "ad-sdk-signatures.json"
_BG_RESULTS_FILENAME = "background-check-results.jsonl"
_BG_STORE_FILENAME = "background-check-store.json"

# Embedded fallback copy of the signature book (name -> class/package
# prefixes), generated from builds/shared/ad-sdk-signatures.json --
# the file beside the .pyw wins when present (see load_signature_book).
_BG_EMBEDDED_BOOK = {'360Dialog': ['com.threesixtydialog.sdk'], 'AD(X)': ['com.adxcorp.ads', 'com.adxcorp.nativead'], 'Aarki': ['com.aarki'], 'Actv8me': ['me.actv8'], 'Ad Generation': ['com.socdm.d.adgeneration'], 'Ad4Screen': ['com.ad4screen.sdk'], 'AdAdapted': ['com.adadapted.android.sdk'], 'AdBuddiz': ['com.purplebrain.adbuddiz.sdk'], 'AdColony': ['com.adcolony', 'com.jirbo.adcolony'], 'AdFalcon': ['com.noqoush.adfalcon.android.sdk'], 'AdGateMedia': ['com.adgatemedia'], 'AdGem': ['com.adgem.android'], 'AdLocus': ['com.adlocus'], 'AdMarvel': ['com.admarvel'], 'AdMob': ['com.google.ads', 'com.google.android.ads', 'com.google.android.gms.admob', 'com.google.android.gms.ads', 'com.google.android.gms.ads.AdActivity', 'com.google.android.gms.ads.AdRequest', 'com.google.android.gms.ads.AdView', 'com.google.android.gms.ads.doubleclick', 'com.google.android.gms.ads.mediation', 'com.google.firebase.firebase_ads', 'com.google.unity.ads'], 'AdMuing': ['com.admuing.danmaku'], 'AdTiming': ['com.adtiming', 'com.aiming.mdt'], 'AdTrial': ['com.adtrial.sdk'], 'Adcash': ['com.adcash.mobileads'], 'Adcenix': ['com.adcenix'], 'Adfurikun': ['com.glossomads.sdk', 'jp.tjkapp.adfurikunsdk'], 'Adjoe': ['io.adjoe.protection', 'io.adjoe.sdk'], 'Admitad': ['ru.tachos.admitadstatisticsdk'], 'Admixer': ['com.admixer', 'net.admixer.sdk'], 'Admost': ['admost.adserver', 'admost.sdk'], 'AerServ': ['com.aerserv.sdk'], 'Airpush': ['com.airpush'], 'Alimama (formerly AdsMogo)': ['com.adsmogo', 'com.alimama'], 'Altamob': ['com.altamob.sdk'], 'Amazon Ads': ['com.amazon.device.ads'], 'Anvato (A Google Company)': ['com.anvato.androidsdk'], 'AnySDK': ['com.anysdk.framework.AdsWrapper', 'com.anysdk.framework.AnalyticsWrapper'], 'AppLovin': ['com.applovin'], 'AppVador': ['com.appvador.ads'], 'Appodeal Stack': ['com.explorestack'], 'AppsGeyser': ['com.appsgeyser.multiTabApp.VideoPlayerActivity', 'com.appsgeyser.sdk'], 'Apsalar': ['com.apsalar.sdk'], 'Beintoo': ['com.beintoo.nucleon'], 'BidMachine': ['io.bidmachine'], 'Braze (formerly Appboy)': ['com.appboy'], 'BuzzAd Benefit': ['com.buzzvil'], 'CallDorado': ['com.calldorado.android'], 'Carto (formerly Nutiteq)': ['com.carto', 'com.nutiteq'], 'Cauly': ['com.cauly.android.ad', 'com.fsn.cauly', 'com.trid.tridad'], 'Chartboost': ['com.chartboost.sdk'], 'Cifrasoft': ['com.cifrasoft'], 'ComScore': ['com.comscore'], 'Coulus Coelib': ['coelib.c.couluslibrary'], 'DOV-E': ['com.dv.DVSDK'], 'Flurry': ['com.flurry'], 'FreeWheel': ['tv.freewheel.ad'], 'Fyber': ['com.fyber'], 'GOM Factory AdPie': ['com.gomfactory.adpie'], 'Geniee': ['jp.co.geniee.gnadsdk'], 'Huawei Mobile Services (HMS) Core': ['com.huawei.agconnect', 'com.huawei.hms.analytics', 'com.huawei.hms.flutter.analytics', 'com.huawei.hms.location', 'com.huawei.hms.plugin.ads', 'com.huawei.hms.plugin.analytics', 'com.huawei.hms.support.api.push', 'com.huawei.updatesdk'], 'HyprMX': ['com.hyprmx.android.sdk'], 'IAB Open Measurement': ['com.iab.omid.library', 'com.prime31.IAB', 'com.prime31.util.IabHelperImpl'], 'IBM Mobile Marketing (Acoustic)': ['co.acoustic.mobile.push.sdk', 'com.ibm.mce.sdk', 'com.xtify.android.sdk', 'com.xtify.mce.sdk'], 'IQzone': ['com.iqzone'], 'InMobi': ['com.inmobi', 'in.inmobi'], 'Inneractive': ['com.inneractive.api.ads'], 'Instreamatic (Adman)': ['com.instreamatic'], 'JumpTap': ['com.jumptap.adtag'], 'KIDOZ': ['com.kidoz.sdk'], 'Kiip': ['me.kiip.sdk'], 'Kochava': ['com.kochava.android.tracker', 'com.kochava.base'], 'LoopMe': ['com.loopme'], 'MDOTM': ['com.mdotm.android'], 'Magnite (Rubicon Project)': ['com.magnite', 'com.rfm.sdk', 'com.rubiconproject'], 'Meta Audience Network': ['com.facebook.ads', 'com.facebook.audiencenetwork'], 'Metaps': ['com.metaps'], 'Mintegral': ['com.mbridge', 'com.mbridge.msdk', 'com.mintegral'], 'MoPub': ['com.mopub'], 'Moat': ['com.moat.analytics.mobile'], 'MobFox': ['com.adsdk.sdk', 'com.mobfox'], 'MobPower': ['com.mobpower'], 'Moloco': ['com.moloco'], 'Moodmedia': ['com.moodmedia'], 'OfferToro': ['com.offertoro.sdk'], 'Ogury': ['com.ogury', 'io.presage'], 'Ooyala': ['com.ooyala'], 'OpenX': ['com.openx.android_sdk_openx', 'com.openx.view.plugplay'], 'POKKT': ['com.pokkt.sdk'], 'Pangle': ['com.bytedance', 'com.bytedance.sdk', 'com.pangle', 'com.pangle.global', 'com.pgl'], 'Pincrux': ['com.pincrux'], 'PingStart': ['com.pingstart.adsdk'], 'Prebid Mobile': ['org.prebid.mobile'], 'PredicIO': ['com.telescope.android', 'io.predic.tracker'], 'PubMatic': ['com.pubmatic', 'com.pubmatic.sdk'], 'PubNative': ['net.pubnative'], 'Receptiv (formerly Mediabrix)': ['com.mediabrix.android'], 'Revmob': ['com.revmob.ads'], 'RjFun': ['com.rjfun.cordova.ad', 'com.rjfun.cordova.admob'], 'SK planet Tad': ['com.skplanet.tad'], 'Smaato': ['com.smaato'], 'Snap Ad Kit': ['com.snap.adkit', 'com.snap.appadskit'], 'Solar2D (Corona)': ['com.ansca.corona'], 'Start.io (StartApp)': ['com.startapp'], 'SuperAwesome': ['tv.superawesome.lib', 'tv.superawesome.sdk'], 'Synerise': ['com.synerise.sdk'], 'TNK Factory': ['com.tnkfactory.ad'], 'TalkingData': ['com.apptalkingdata.push', 'com.gametalkingdata.push', 'com.talkingdata.adtracking', 'com.talkingdata.appanalytics', 'com.talkingdata.sdk', 'com.tendcloud.appcpa', 'com.tendcloud.tenddata'], 'Tapdaq': ['com.tapdaq.adapters', 'com.tapdaq.sdk'], 'Tapjoy': ['com.tapjoy'], 'Taplytics': ['com.taplytics.sdk'], 'Tappx': ['com.tappx.sdk.android'], 'Teads': ['teads.tv', 'tv.teads'], 'Unity Ads': ['com.unity3d.ads', 'com.unity3d.services'], 'Upsight': ['com.upsight.android'], 'Vdopia': ['com.vdopia.ads', 'com.vdopia.client.android'], 'Veloxity': ['net.veloxity'], 'Verizon Ads': ['com.oath.mobile', 'com.verizon.ads', 'com.verizondigitalmedia.mobile'], 'Verve': ['com.vervewireless.advert'], 'Virgo Mobile': ['com.virgo.ads'], 'Vpon': ['com.vpadn.ads', 'com.vpadn.analytics', 'com.vpadn.widget', 'com.vpon.ads'], 'Vungle': ['com.vungle', 'com.vungle.publisher', 'com.vungle.warren'], 'YOC VIS.X': ['com.yoc.visx'], 'Yandex Ads': ['com.yandex.mobile.ads'], 'Yinzcam Sobek': ['com.yinzcam.sobek'], 'Yoadx': ['com.yoadx.yoadx'], 'YuMe': ['com.yume.android'], 'Zapr': ['com.redbricklane.zapr'], 'adPOPcorn': ['com.igaworks.adpopcorn', 'com.igaworks.ssp'], 'fineboost': ['com.fineboost'], 'ironSource': ['com.ironsource'], 'mediba': ['com.mediba.jp', 'mediba.ad.sdk.android.openx'], 'myTarget': ['com.my.target'], 'nend': ['net.nend.android', 'net.nend.unity']}

_BG_BOOK_CACHE = {"book": None}


def load_signature_book():
    """{network_name: [prefix, ...]} -- the ad-SDK signature book.

    ad-sdk-signatures.json beside the .pyw wins when present (so the
    book can be refreshed without a new build); otherwise the embedded
    copy is used and the single-file .pyw still works alone. Seeded
    from the Exodus Privacy tracker database (ETIP, CC BY-SA),
    fetched 2026-10-17: every Advertisement-category tracker plus
    curated ad networks -- builds/shared/ad-sdk-signatures.json.
    A dotted class name N matches prefix P iff N == P, or N starts
    with P + ".", or N starts with P + "$" (inner classes).
    """
    if _BG_BOOK_CACHE["book"] is not None:
        return _BG_BOOK_CACHE["book"]
    book = None
    try:
        p = _script_dir_path() / _BG_SIG_FILENAME
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            nets = {}
            for n in data.get("networks", []):
                prefs = [str(x).rstrip(".")
                         for x in n.get("prefixes", [])]
                if n.get("name") and prefs:
                    nets[str(n["name"])] = prefs
            if nets:
                book = nets
    except Exception:
        book = None
    if book is None:
        book = {k: list(v) for k, v in _BG_EMBEDDED_BOOK.items()}
    _BG_BOOK_CACHE["book"] = book
    return book


# ---- photo-vault rail -------------------------------------------------
# Standing owner rule (scan rulings, 2026-10-15): a photo vault holds
# the customer's hidden photos; it is NEVER removed without asking the
# customer first -- regardless of what any check finds inside it.
# NOTE: v11.0 carried this rule as doctrine only (no named list); the
# rail is implemented here as named package/label pattern constants.
PHOTO_VAULT_PKG_HINTS = ("vault", "photovault", "hidephoto",
                         "hidephotos", "hidepictures", "gallerylock",
                         "photolock", "secretphoto", "privatephoto")
PHOTO_VAULT_LABEL_HINTS = ("vault", "hide photos", "hidden photos",
                           "hide pictures", "photo lock",
                           "gallery lock", "secret photos")
# Exact-match known vaults whose package names carry no hint at all:
# com.kii.safe is Keepsafe Photo Vault (blind spot caught by Android
# CI, 2026-10-17). Exact equality only -- lookalike packages such as
# com.kii.safety must NOT be swept in by this list.
PHOTO_VAULT_KNOWN_PKGS = ("com.kii.safe",)


def is_photo_vault(pkg, label=""):
    """True if the package/label pattern-matches a photo vault."""
    p = (pkg or "").lower()
    if p in PHOTO_VAULT_KNOWN_PKGS:
        return True
    if any(h in p for h in PHOTO_VAULT_PKG_HINTS):
        return True
    lab = (label or "").lower()
    return any(h in lab for h in PHOTO_VAULT_LABEL_HINTS)


_BG_PERM_OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"
_BG_PERM_FULLSCREEN = "android.permission.USE_FULL_SCREEN_INTENT"
_BG_PERM_INSTALL = "android.permission.REQUEST_INSTALL_PACKAGES"
_BG_PERM_BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
_BG_PERM_FG_SERVICE = "android.permission.FOREGROUND_SERVICE"


def parse_bg_dump(out):
    """Extended per-package facts from one `dumpsys package` dump:
    requested permissions (the DECLARED tells), target SDK, installer
    package name, and whether a boot receiver is declared."""
    requested = set()
    in_req = False
    for line in (out or "").splitlines():
        if "requested permissions:" in line:
            in_req = True
            continue
        if in_req:
            m = re.match(r"\s+(android\.permission\.[\w.]+)", line)
            if m:
                requested.add(m.group(1))
            elif re.match(r"\s+\S.*:\s*$", line) or \
                    (line.strip() and not line.startswith((" ", "\t"))):
                in_req = False
    if not requested:
        requested = set(re.findall(
            r"(android\.permission\.[\w.]+): granted=", out or ""))
    target_sdk = None
    m = re.search(r"targetSdk=(\d+)", out or "")
    if m:
        target_sdk = int(m.group(1))
    installer = None
    m = re.search(r"installerPackageName=(\S+)", out or "")
    if m:
        installer = m.group(1)
    return {"requested_perms": requested,
            "target_sdk": target_sdk,
            "installer": installer,
            "boot_receiver":
                "android.intent.action.BOOT_COMPLETED" in (out or "")}


def _dex_class_names_strict(data):
    """(names, complete) -- the DEX string-table read with an
    honesty verdict. Name extraction stays best-effort, exactly
    like _dex_class_names, but `complete` is False whenever the
    blob was NOT read end-to-end:

      * the declared string_ids table (count at 0x38) reaches past
        the end of the blob -- a truncated table whose overflow the
        old swallow-and-continue parser turned into a silent short
        read (tester finding F-1: such a DEX counted as a complete
        clean read and could earn a CLEARED);
      * any entry's string data starts outside the blob, its
        uleb128 length never terminates inside the blob, or no
        NUL terminator exists before the end of the blob;
      * a NONZERO declared string count yields ZERO names -- a
        silent short read must never pose as a complete one.

    A normal classes.dex declares thousands of strings and always
    yields names, so the strict verdict costs real files nothing."""
    names = set()
    try:
        if len(data) < 0x70 or data[:4] != b"dex\n":
            return names, False
        count, off = _bg_struct.unpack_from("<II", data, 0x38)
        if count == 0:
            return names, True
        if off + 4 * count > len(data):
            return names, False
        for i in range(count):
            (soff,) = _bg_struct.unpack_from("<I", data, off + 4 * i)
            if soff >= len(data):
                return names, False
            p = soff
            while True:                     # skip the uleb128 length
                if p >= len(data):
                    return names, False
                b = data[p]
                p += 1
                if not (b & 0x80):
                    break
            end = data.find(b"\x00", p)
            if end < 0:
                return names, False
            s = data[p:end].decode("utf-8", "replace")
            if s.startswith("L") and s.endswith(";") and "/" in s:
                names.add(s[1:-1].replace("/", "."))
            elif re.fullmatch(r"[a-z][\w]*(\.[\w$]+)+", s or ""):
                names.add(s)
        if not names:
            return names, False
        return names, True
    except Exception:
        return names, False


def _dex_class_names(data):
    """Dotted class names from one .dex blob's string table.

    Class descriptors (Lcom/foo/Bar;) become com.foo.Bar; plain
    dotted strings are kept too -- the signature-prefix match keeps
    noise harmless. Returns an empty set for a non-DEX blob.
    (Best-effort view of _dex_class_names_strict; the census uses
    the strict verdict so a short read can never pose as a read.)"""
    names, _complete = _dex_class_names_strict(data)
    return names


def census_apk_networks(apk_paths, book=None):
    """({network: class_hits}, stats) -- scan every classes*.dex
    entry of the pulled APK(s) against the signature book.

    stats counts files as well as DEX blobs: files_total attempted,
    files_read opened and read end-to-end, files_failed that could
    not be opened or had an unreadable / non-DEX classes entry --
    "unreadable" includes a DEX whose string table cannot be
    walked whole (strict verdict from _dex_class_names_strict).
    census_complete is True only when at least one file was
    attempted and NONE failed -- a partial census (say, a corrupt
    split beside a clean base) must never pose as a full read:
    clearing requires the complete census (research Angle 3)."""
    book = book or load_signature_book()
    by_head = {}
    for name, prefs in book.items():
        for p in prefs:
            head = ".".join(p.split(".")[:2])
            by_head.setdefault(head, []).append((p, name))
    found = {}
    n_dex = 0
    n_names = 0
    files_total = 0
    files_read = 0
    files_failed = 0
    for ap in apk_paths or []:
        files_total += 1
        zf = None
        ok = True
        try:
            zf = _bg_zipfile.ZipFile(ap)
            for entry in zf.namelist():
                base = entry.rsplit("/", 1)[-1]
                if not (base.startswith("classes")
                        and base.endswith(".dex")):
                    continue
                try:
                    data = zf.read(entry)
                except Exception:
                    ok = False
                    continue
                names, dex_ok = _dex_class_names_strict(data)
                if not dex_ok:
                    # A classes entry that is not a DEX, or a DEX
                    # that cannot be read end-to-end (truncated
                    # string table / short read -- F-1), fails
                    # its whole file: the census stays incomplete
                    # and the scoring cap does the rest.
                    ok = False
                    continue
                n_dex += 1
                n_names += len(names)
                for dotted in names:
                    head = ".".join(dotted.split(".")[:2])
                    for p, net in by_head.get(head, ()):
                        if (dotted == p or dotted.startswith(p + ".")
                                or dotted.startswith(p + "$")):
                            found[net] = found.get(net, 0) + 1
        except Exception:
            ok = False
        finally:
            if zf is not None:
                try:
                    zf.close()
                except Exception:
                    pass
        if ok:
            files_read += 1
        else:
            files_failed += 1
    stats = {"dex_files": n_dex, "class_names": n_names,
             "files_total": files_total, "files_read": files_read,
             "files_failed": files_failed,
             "census_complete": bool(files_total
                                     and files_failed == 0)}
    return found, stats


def _bg_pull_apks(pkg, dest_dir):
    """Pull the base APK and every split (pm path order) into
    dest_dir. Returns (local_paths, n_failed): n_failed counts the
    pm-path entries that could not be pulled (or landed empty) --
    the caller folds them into the census file counts, because an
    unpulled split is app code nobody read (partial census)."""
    paths = [l[len("package:"):] for l in
             adb_cmd("shell", "pm", "path", pkg).splitlines()
             if l.startswith("package:")]
    local = []
    failed = 0
    for i, rp in enumerate(paths):
        lp = Path(dest_dir) / ("part%d.apk" % i)
        try:
            subprocess.run([ADB, "pull", rp, str(lp)],
                           capture_output=True, text=True, timeout=180,
                           **_no_console())
        except Exception:
            pass
        if lp.is_file() and lp.stat().st_size > 0:
            local.append(str(lp))
        else:
            failed += 1
    return local, failed


def score_background_check(facts):
    """Score one app's evidence bundle by the research law (Angle 3).

    facts keys: census_done, networks ({name: hits}), overlay_declared,
    overlay_on, fullscreen_intent, install_packages, boot_persistence,
    fake_utility, sideloaded, source_label, target_sdk, stale_target.
    Optional key (2026-10-21, law section 14): guarded -- True when
    the package sits on the known-legit guard; the guard stands in
    front of the section 14 costume conviction below.
    Completeness keys (census_complete, files_read, files_total,
    files_failed): when the census RAN but is incomplete (a split
    would not pull, an APK would not open, a DEX would not read),
    CLEARED is forbidden -- the verdict caps at STILL NOT SURE and
    the evidence says the app was NOT FULLY CHECKED. A partial
    census can still CONFIRM: the networks it did read are proven
    present. Returns {outcome, points, evidence} -- outcome is "confirmed",
    "not_sure" or "cleared"; evidence is [(line, is_loud), ...] in
    plain words, the damning phrase first (boom rule)."""
    nets = sorted(facts.get("networks") or {})
    n = len(nets)
    census_done = bool(facts.get("census_done"))
    points = 0
    ev = []
    if census_done:
        if n >= 5:
            tail = (", ".join(nets[:6])
                    + (" +%d more" % (n - 6) if n > 6 else ""))
            ev.append(("STUFFED WITH %d AD NETWORKS: %s" % (n, tail),
                       True))
        elif n >= 3:
            points += 3
            ev.append(("%d AD NETWORKS INSIDE ITS CODE: %s"
                       % (n, ", ".join(nets)), True))
        elif n == 2:
            points += 2
            ev.append(("2 AD NETWORKS INSIDE ITS CODE: %s"
                       % ", ".join(nets), True))
        elif n == 1:
            ev.append(("ONLY 1 AD NETWORK INSIDE ITS CODE: %s"
                       % nets[0], False))
        else:
            ev.append(("CODE CENSUS FOUND NO AD NETWORKS INSIDE",
                       False))
    else:
        ev.append(("NOBODY HAS LOOKED INSIDE THIS ONE -- the code "
                   "census could not run, so there is no code proof "
                   "either way", True))
    if facts.get("overlay_declared"):
        line = "CAN DRAW ADS OVER YOUR OTHER APPS (pop-up permission)"
        if facts.get("overlay_on"):
            line += " -- AND THAT SWITCH IS ON"
        ev.append((line, True))
    if facts.get("fullscreen_intent"):
        ev.append(("CAN TAKE OVER THE WHOLE SCREEN "
                   "(full-screen ads)", True))
    if facts.get("install_packages"):
        ev.append(("CAN INSTALL OTHER APPS", False))
    if facts.get("boot_persistence"):
        ev.append(("ARRANGES TO STAY ALIVE: starts at boot and "
                   "re-starts itself", False))
    if (facts.get("overlay_declared") and facts.get("boot_persistence")
            and facts.get("fake_utility")):
        points += 2
        ev.append(("POP-UP POWER + STAYS-ALIVE + FAKE-UTILITY "
                   "COSTUME (cleaner / flashlight / wallpaper type)",
                   True))
    elif facts.get("fake_utility"):
        # Law section 14 (2026-10-21): this finding CONVICTS on
        # its own (see the outcome block below), so on an
        # unguarded app the line renders loud like every other
        # conviction-grade line. On a GUARDED app the finding is
        # still shown -- the evidence is never hidden -- but it
        # convicts nothing and stays quiet.
        ev.append(("FAKE-UTILITY COSTUME: cleaner / flashlight / "
                   "wallpaper-type app (common adware disguise)",
                   not facts.get("guarded")))
    if facts.get("sideloaded"):
        points += 1
        ev.append(("SIDELOADED -- IT CAME FROM A DOWNLOADED FILE, "
                   "NOT A STORE (%s)" % facts.get("source_label", ""),
                   True))
    if facts.get("stale_target"):
        points += 1
        ev.append(("TARGETS AN ANCIENT ANDROID (target SDK %s) EVEN "
                   "THOUGH IT WAS UPDATED RECENTLY -- hiding from "
                   "the modern rules" % facts.get("target_sdk"), False))
    net = points - (3 if (census_done and n <= 1) else 0)
    if census_done and n >= 5:
        outcome = "confirmed"
    elif census_done and points >= 7:
        outcome = "confirmed"
    elif census_done and n <= 1 and net <= 2:
        outcome = "cleared"
    else:
        outcome = "not_sure"
    if census_done and not facts.get("census_complete", True):
        failed = facts.get("files_failed")
        total = facts.get("files_total")
        if failed is not None and total is not None:
            unread_line = ("PART OF THIS APP COULD NOT BE READ "
                           "— %d of %d files unread "
                           "— NOT FULLY CHECKED" % (failed, total))
        else:
            unread_line = ("PART OF THIS APP COULD NOT BE READ "
                           "— NOT FULLY CHECKED")
        ev.insert(1, (unread_line, True))
        if outcome == "cleared":
            outcome = "not_sure"
    # Owner ruling (2026-10-21, law section 14): the FAKE-UTILITY
    # COSTUME finding convicts ON ITS OWN. When the check's
    # evidence establishes the costume (facts["fake_utility"] --
    # the same existing name determination that produced the
    # costume evidence line above; no new heuristic), the outcome
    # is "confirmed" with no points threshold, no network count
    # and no census requirement: the keyword class is the
    # evidence. It therefore stands even over a census that
    # would have cleared, and even when the census could not run
    # -- exactly as a partial census can confirm. The one rail in
    # front of it is the known-legit guard: on a guarded package
    # (facts["guarded"]) the costume convicts nothing and the
    # scored outcome stands -- the trigger case for this ruling,
    # com.cvs.launchers.cvs (the verified CVS Pharmacy app),
    # joins the guard with the ruling itself. The factory cap is
    # NOT applied here: it already lands where it always lands --
    # a stored confirmed verdict never flips a factory scan row
    # (apply_stored_check_verdicts rule c2), and the scan applies
    # its own cap. Points are reported unchanged: the score stays
    # the honest sum of the scored evidence; the outcome no
    # longer derives from it when the costume speaks.
    if facts.get("fake_utility") and not facts.get("guarded"):
        outcome = "confirmed"
    return {"outcome": outcome, "points": points, "evidence": ev}


def _bg_results_path():
    return _script_dir_path() / _BG_RESULTS_FILENAME


def _bg_append_result(res):
    """Append one completed check's evidence bundle to the JSONL
    staging file (feeds the blocklist pipeline later)."""
    try:
        rec = {"ts": res.get("ts"), "pkg": res.get("pkg"),
               "label": res.get("label"),
               "verdict": res.get("outcome"),
               "points": res.get("points"),
               "networks": res.get("networks"),
               "network_count": res.get("network_count"),
               "census_done": res.get("census_done"),
               "census_complete": res.get("census_complete"),
               "files_read": res.get("files_read"),
               "files_total": res.get("files_total"),
               "vault": res.get("vault"),
               "signals": res.get("signals", {})}
        with open(_bg_results_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


# ------------------------------------------- report-up pipe ---
# Conviction report emission (Report-Up Pipe, PC side): a
# confirmed Background Check also queues a contract conviction
# report into report-up-outbox/ beside this program, where the
# pipe's transport picks it up (drop folder -> intake pull ->
# boss inbox). Best-effort and never raises, exactly like the
# durable store save it hangs off. Section source of truth:
# report-up-pipe/pc-sender/conviction_report_pc.py (the pipe's
# tests prove this copy produces identical reports).
# === BEGIN REPORT-UP SECTION ===
# Everything between the BEGIN/END markers is inserted verbatim
# into the PC app (.pyw) candidate build. It relies only on names
# the app already has in scope (json, os, time, datetime, Path)
# plus its own definitions.

REPORT_UP_NETWORK_BAR = 4  # the pipe's bar (owner, 2026-10-18: 5 -> 4)
REPORT_UP_OWNER_LICENSE_ID = "OWNER"
REPORT_UP_OUTBOX_NAME = "report-up-outbox"


def _report_up_distinct_networks(networks):
    """Distinct, non-empty network names, sorted (the census dict's
    keys are already distinct; a list input is deduped). The wire
    invariant network_count == distinct count holds by
    construction here."""
    out = []
    seen = set()
    for name in networks or []:
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            out.append(name)
    return sorted(out)


def _report_up_evidence_lines(evidence):
    """Flatten the check's evidence to plain strings. The app
    carries evidence as (line, is_loud) tuples; plain strings pass
    through. Empty lines are dropped (the contract rejects a report
    whose evidence is empty after dropping empties)."""
    lines = []
    for item in evidence or []:
        if isinstance(item, (tuple, list)):
            text = item[0] if item else ""
        else:
            text = item
        if isinstance(text, str) and text.strip():
            lines.append(text)
    return lines


def _report_up_checked_at_ms(res):
    """Epoch milliseconds of the check. The result's ts is a local
    ISO string (datetime.now().isoformat(timespec="seconds"));
    anything unparseable falls back to now."""
    ts = res.get("ts")
    if isinstance(ts, str) and ts:
        try:
            return int(datetime.fromisoformat(ts).timestamp() * 1000)
        except Exception:
            pass
    return int(time.time() * 1000)


def build_conviction_report(res, license_id=REPORT_UP_OWNER_LICENSE_ID):
    """One contract conviction report (dict) from a completed
    run_background_check() result, or None when ANY eligibility
    rule fails. Pure: no I/O. Keys are exactly the contract's --
    report_version, package, outcome, network_count, networks,
    census_complete, evidence, version_code, checked_at_ms,
    license_id, plus app_name only when the check learned a real
    display name (the result's label, when it is not just the
    package repeated back)."""
    if not isinstance(res, dict):
        return None
    pkg = res.get("pkg")
    if not isinstance(pkg, str) or not pkg:
        return None
    if res.get("outcome") != "confirmed":
        return None
    if not res.get("census_complete"):
        return None
    # VAULT RAIL: a photo vault is never reported for
    # auto-promotion, no matter how bad it looks.
    if res.get("vault"):
        return None
    version_code = res.get("version_code")
    if (not isinstance(version_code, int)
            or isinstance(version_code, bool) or version_code <= 0):
        return None
    networks = _report_up_distinct_networks(res.get("networks"))
    if len(networks) < REPORT_UP_NETWORK_BAR:
        return None
    evidence = _report_up_evidence_lines(res.get("evidence"))
    if not evidence:
        return None
    report = {
        "report_version": 1,
        "package": pkg,
        "outcome": "confirmed_bad",
        "network_count": len(networks),
        "networks": networks,
        "census_complete": True,
        "evidence": evidence,
        "version_code": version_code,
        "checked_at_ms": _report_up_checked_at_ms(res),
        "license_id": license_id,
    }
    label = res.get("label")
    if isinstance(label, str) and label and label != pkg:
        report["app_name"] = label
    return report


def _report_up_filename(report):
    pkg = "".join(ch if (ch.isalnum() or ch in "._-") else "_"
                  for ch in report["package"])
    return "conviction-%s-%d.json" % (pkg, report["version_code"])


def _report_up_outbox_dir():
    """The outbox folder: report-up-outbox beside the running
    program (resolved through the app's _script_dir_path() when
    this section runs inside the app). Standalone fallback:
    $ADTRAPPER_REPORT_OUTBOX, else ./report-up-outbox."""
    fn = globals().get("_script_dir_path")
    if callable(fn):
        try:
            return Path(fn()) / REPORT_UP_OUTBOX_NAME
        except Exception:
            pass
    env = os.environ.get("ADTRAPPER_REPORT_OUTBOX")
    if env:
        return Path(env)
    return Path.cwd() / REPORT_UP_OUTBOX_NAME


def queue_conviction_report(res, outbox_dir=None,
                            license_id=REPORT_UP_OWNER_LICENSE_ID):
    """Build the report for one completed check and write it into
    the outbox as one JSON file. Returns the written Path, or None
    when the check is not eligible or the write failed.

    Dedupe mirrors the Android queue: the filename keys on
    (package, version_code), so a re-check of the same build
    REPLACES the older queued report for that pair; a different
    build queues alongside it. The write is atomic (temp file in
    the same folder + os.replace). NEVER raises."""
    try:
        report = build_conviction_report(res, license_id=license_id)
        if report is None:
            return None
        outbox = Path(outbox_dir) if outbox_dir else _report_up_outbox_dir()
        outbox.mkdir(parents=True, exist_ok=True)
        target = outbox / _report_up_filename(report)
        tmp = outbox / (target.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(str(tmp), str(target))
        return target
    except Exception:
        return None


REPORT_UP_SCAN_TAG = "scan_ad_software"


def build_scan_conviction_report(pkg, label, networks, evidence,
                                 version_code, vault=False,
                                 checked_at_ms=None,
                                 license_id=REPORT_UP_OWNER_LICENSE_ID):
    """One contract conviction report (dict) from a PLAIN SCAN
    ad-software conviction (owner ruling 2026-10-21: "Contains ad
    software" convicts by itself), or None when ANY eligibility
    rule fails. Pure: no I/O.

    This is a DISTINCT report class from the Background Check
    builder above, and it deviates from that builder's eligibility
    on purpose (documented in the build report):
      * network bar: 1..REPORT_UP_NETWORK_BAR-1 DISTINCT networks
        (the new scan law convicts at >= 1; at >= 4 the older
        census bar produced the conviction, and those convictions
        keep following the existing Background Check report path
        -- this builder declines them so no report double-counts
        a bar conviction as a scan conviction);
      * census_complete is True: the scan's inline manifest census
        really happened for this package (its dumpsys components
        were read against the app's AD_SDKS signature table). It
        is NOT the Background Check file census;
      * evidence[0] is exactly the tag "scan_ad_software" (the
        contract carries no tag field, so the tag rides as the
        first evidence line), followed by the scan row's reason
        lines;
      * the VAULT RAIL and the version rule are unchanged: a photo
        vault is never reported, and version_code must be a real
        int > 0 (scan queues only when it could parse one).
    Because these reports carry 1-3 networks, the pipe processor
    routes them to its review pile (below_pipe_bar); shelf
    promotion remains the processor's quarantine -> automatic
    double-check, exactly as for every other report class.
    No customer data: only the checked app and the shop identity.
    """
    if not isinstance(pkg, str) or not pkg:
        return None
    # VAULT RAIL: a photo vault is never reported for
    # auto-promotion, no matter how bad it looks.
    if vault:
        return None
    if (not isinstance(version_code, int)
            or isinstance(version_code, bool) or version_code <= 0):
        return None
    nets = _report_up_distinct_networks(networks)
    if not 1 <= len(nets) < REPORT_UP_NETWORK_BAR:
        return None
    lines = [REPORT_UP_SCAN_TAG]
    for line in _report_up_evidence_lines(evidence):
        if line != REPORT_UP_SCAN_TAG and line not in lines:
            lines.append(line)
    try:
        stamp = int(checked_at_ms) if checked_at_ms else 0
    except Exception:
        stamp = 0
    if stamp <= 0:
        stamp = int(time.time() * 1000)
    report = {
        "report_version": 1,
        "package": pkg,
        "outcome": "confirmed_bad",
        "network_count": len(nets),
        "networks": nets,
        "census_complete": True,
        "evidence": lines,
        "version_code": version_code,
        "checked_at_ms": stamp,
        "license_id": license_id,
    }
    if isinstance(label, str) and label and label != pkg:
        report["app_name"] = label
    return report


def queue_scan_conviction_report(pkg, label, networks, evidence,
                                 version_code, vault=False,
                                 checked_at_ms=None, outbox_dir=None,
                                 license_id=REPORT_UP_OWNER_LICENSE_ID):
    """Build the scan ad-software report for one package and write
    it into the SAME report-up outbox as Background Check reports.

    Queue discipline mirrors queue_conviction_report exactly: the
    filename keys on (package, version_code), so a re-scan of the
    same build REPLACES the older queued report for that pair; a
    different build queues alongside it. The write is atomic
    (temp file in the same folder + os.replace). Returns the
    written Path, or None when not eligible or the write failed.
    NEVER raises."""
    try:
        report = build_scan_conviction_report(
            pkg, label, networks, evidence, version_code,
            vault=vault, checked_at_ms=checked_at_ms,
            license_id=license_id)
        if report is None:
            return None
        outbox = Path(outbox_dir) if outbox_dir else _report_up_outbox_dir()
        outbox.mkdir(parents=True, exist_ok=True)
        target = outbox / _report_up_filename(report)
        tmp = outbox / (target.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(str(tmp), str(target))
        return target
    except Exception:
        return None


REPORT_UP_SCAN_COSTUME_TAG = "scan_fake_costume"


def build_scan_costume_report(pkg, label, networks, evidence,
                              version_code, vault=False,
                              checked_at_ms=None,
                              license_id=REPORT_UP_OWNER_LICENSE_ID):
    """One contract conviction report (dict) from a PLAIN SCAN
    fake-costume conviction (owner ruling 2026-10-21, law
    section 14: the fake keyword class -- the scan's existing
    fake-name / fake-utility determination -- convicts on sight),
    or None when ANY eligibility rule fails. Pure: no I/O.

    This is a DISTINCT report class from the two builders above,
    and it mirrors the scan ad-software builder's eligibility
    with ONE documented difference:
      * network range: 0..REPORT_UP_NETWORK_BAR-1 DISTINCT
        networks. The ad-software builder's floor of 1 exists
        because ITS conviction evidence IS the census. Here the
        conviction evidence is the keyword class itself, so a
        0-network report is legitimate: census_complete is True
        because the scan's inline manifest census really ran for
        this package and found no ad networks -- a completed
        census with an empty result, not a missing one. At >=
        REPORT_UP_NETWORK_BAR the census bar produced (or would
        produce) the conviction, so this builder declines, as
        the ad builder does, to keep bar convictions on their
        existing Background Check report path;
      * evidence[0] is exactly the tag "scan_fake_costume" (the
        contract carries no tag field, so the tag rides as the
        first evidence line), followed by the scan row's reason
        lines; a report whose only line would be the tag itself
        carries no exhibit and is declined;
      * the VAULT RAIL and the version rule are unchanged: a
        photo vault is never reported (a vault CAN be convicted
        by the costume under section 14 -- the section 13 photo
        bar governs ad evidence only -- but it is still never
        reported for auto-promotion), and version_code must be a
        real int > 0.
    When the ad-software rule convicts the same row in the same
    scan, scan_core queues the ad-software report INSTEAD (one
    report per row per scan; the census evidence is the stronger
    exhibit), so in practice this class carries the pure keyword
    convictions -- costume rows the ad rule did not claim.
    Because these reports carry 0-3 networks, the pipe processor
    routes them to its review pile (below_pipe_bar); shelf
    promotion remains the processor's quarantine -> automatic
    double-check, exactly as for every other report class.
    No customer data: only the checked app and the shop identity.
    """
    if not isinstance(pkg, str) or not pkg:
        return None
    # VAULT RAIL: a photo vault is never reported for
    # auto-promotion, no matter how bad it looks.
    if vault:
        return None
    if (not isinstance(version_code, int)
            or isinstance(version_code, bool) or version_code <= 0):
        return None
    nets = _report_up_distinct_networks(networks)
    if len(nets) >= REPORT_UP_NETWORK_BAR:
        return None
    lines = [REPORT_UP_SCAN_COSTUME_TAG]
    for line in _report_up_evidence_lines(evidence):
        if line != REPORT_UP_SCAN_COSTUME_TAG and line not in lines:
            lines.append(line)
    if len(lines) < 2:
        # The contract rejects empty evidence; a costume report
        # whose only line is the tag itself carries no exhibit.
        return None
    try:
        stamp = int(checked_at_ms) if checked_at_ms else 0
    except Exception:
        stamp = 0
    if stamp <= 0:
        stamp = int(time.time() * 1000)
    report = {
        "report_version": 1,
        "package": pkg,
        "outcome": "confirmed_bad",
        "network_count": len(nets),
        "networks": nets,
        "census_complete": True,
        "evidence": lines,
        "version_code": version_code,
        "checked_at_ms": stamp,
        "license_id": license_id,
    }
    if isinstance(label, str) and label and label != pkg:
        report["app_name"] = label
    return report


def queue_scan_costume_report(pkg, label, networks, evidence,
                              version_code, vault=False,
                              checked_at_ms=None, outbox_dir=None,
                              license_id=REPORT_UP_OWNER_LICENSE_ID):
    """Build the scan fake-costume report for one package and
    write it into the SAME report-up outbox as every other
    report class.

    Queue discipline mirrors queue_scan_conviction_report
    exactly: the filename keys on (package, version_code), so a
    re-scan of the same build REPLACES the older queued report
    for that pair; a different build queues alongside it. The
    write is atomic (temp file in the same folder + os.replace).
    Returns the written Path, or None when not eligible or the
    write failed. NEVER raises."""
    try:
        report = build_scan_costume_report(
            pkg, label, networks, evidence, version_code,
            vault=vault, checked_at_ms=checked_at_ms,
            license_id=license_id)
        if report is None:
            return None
        outbox = Path(outbox_dir) if outbox_dir else _report_up_outbox_dir()
        outbox.mkdir(parents=True, exist_ok=True)
        target = outbox / _report_up_filename(report)
        tmp = outbox / (target.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(str(tmp), str(target))
        return target
    except Exception:
        return None

# === END REPORT-UP SECTION ===


# === BEGIN CONVICTION COUNTER SECTION ===
# CONVICTION COUNTER (owner idea 2026-10-20: "a conviction
# counter, right on the home screen"). The tallies derive from
# values the app already holds: the live bad-list size
# (len(KNOWN_BAD) -- the same number the Activity log reports)
# and the local Background Check store (load_bg_store()):
# "contributed" counts this shop's own confirmed_bad records --
# the very records the report-up sender turns into pipe reports;
# "parked" counts its not_sure records, the local mirror of the
# pipe's quarantine box. Source of truth:
# report-up-pipe/pc-sender/conviction_counter_pc.py (this section
# is that module's two functions, verbatim); the App glue (label +
# refresh) lives with the App class, like the report-up hook.

def conviction_tallies(bad_count, bg_records):
    """{"bad_list": int, "contributed": int, "parked": int} from a
    bad-list count and a load_bg_store()-shaped {pkg: record}."""
    contributed = 0
    parked = 0
    for record in (bg_records or {}).values():
        if not isinstance(record, dict):
            continue
        outcome = record.get("outcome")
        if outcome == "confirmed_bad":
            contributed += 1
        elif outcome == "not_sure":
            parked += 1
    try:
        bad = int(bad_count)
    except Exception:
        bad = 0
    return {"bad_list": bad, "contributed": contributed,
            "parked": parked}


def conviction_counter_text(bad_count, bg_records):
    """The one-line home-screen text for the tallies."""
    tallies = conviction_tallies(bad_count, bg_records)
    return ("Bad list: %d  \u00b7  Convictions from this shop: %d  "
            "\u00b7  Suspects parked: %d"
            % (tallies["bad_list"], tallies["contributed"],
               tallies["parked"]))

# === END CONVICTION COUNTER SECTION ===


# === BEGIN FACE SELF-AUDIT SECTION ===
# FACE SELF-AUDIT (owner idea 2026-10-20: "the app tests its
# face -- every start-up; no blank rows"). After the UI is built,
# and after every render, the app walks its own results and guide
# widget trees and checks the CONFIGURATION it can honestly
# check:
#   * every verdict word (REMOVE / KEEP / ASK FIRST) riding
#     directly on a results row is a Label whose foreground IS
#     this build's verdict token color -- colored TEXT;
#   * no verdict word rides on a verdict-colored BACKGROUND
#     (the banned color band);
#   * every row frame carries at least one Label with non-empty
#     text (a truly blank row is a defect, never a silent state);
#   * the Guided Clean guide's pile tags carry the pile colors.
# Problems are written to face-self-check.log beside the program
# and raised as a plain visible banner -- never a silent blank.
# HONEST LIMIT: this proves configuration (text present, colors
# right), not pixels on glass. A render-layer paint failure (the
# Mac Aqua canvas defect) can still hide configured text; that is
# what the on-Mac probe work is for, and this audit does not
# pretend to replace it.

def _face_norm_color(value):
    try:
        return str(value).strip().lower()
    except Exception:
        return ""


def _face_verdict_word_colors():
    """{word: token color} from this build's own verdict maps --
    the single source the renderers take their colors from."""
    out = {}
    for key, word in VERDICT_WORDS.items():
        color = VERDICT_COLORS.get(key)
        if color:
            out[word] = color
    return out


def _face_descendants(widget):
    out = []
    try:
        stack = list(widget.winfo_children())
    except Exception:
        return out
    while stack:
        w = stack.pop()
        out.append(w)
        try:
            stack.extend(w.winfo_children())
        except Exception:
            pass
    return out


def face_audit_labels(container):
    """Problem strings for a widget subtree (the results tree or
    a dialog). [] means the face is configured honestly. Row rule:
    each direct-child Frame is a row; if it has Labels at all, at
    least one must carry non-empty text. Verdict rule: a Label
    sitting directly on a row whose text is exactly a verdict
    word must wear the token color as its FOREGROUND and must
    not wear any verdict color as its BACKGROUND."""
    problems = []
    if container is None:
        return problems
    word_colors = _face_verdict_word_colors()
    law = {_face_norm_color(c) for c in word_colors.values()}
    try:
        children = container.winfo_children()
    except Exception:
        children = []
    for child in children:
        if not isinstance(child, tk.Frame):
            continue
        labels = [w for w in _face_descendants(child)
                  if isinstance(w, tk.Label)]
        if labels:
            texts = []
            for w in labels:
                try:
                    texts.append(str(w.cget("text") or ""))
                except Exception:
                    texts.append("")
            if not any(t.strip() for t in texts):
                problems.append(
                    "blank row: a row's labels are all empty")
        try:
            direct = child.winfo_children()
        except Exception:
            direct = []
        for w in direct:
            if not isinstance(w, tk.Label):
                continue
            try:
                text = str(w.cget("text") or "")
            except Exception:
                continue
            if text not in word_colors:
                continue
            expected = _face_norm_color(word_colors[text])
            try:
                fg = _face_norm_color(w.cget("foreground"))
                bg = _face_norm_color(w.cget("background"))
            except Exception:
                continue
            if fg != expected:
                problems.append(
                    "verdict %s has foreground %s, expected %s"
                    % (text, fg or "(none)", expected))
            if bg in law:
                problems.append(
                    "verdict %s rides on a verdict-color background "
                    "(bands are banned; verdicts are colored text)"
                    % text)
    return problems


def face_audit_text(text_widget):
    """Problem strings for a Guided Clean guide Text: each pile
    tag that exists must carry its pile color."""
    problems = []
    if text_widget is None:
        return problems
    try:
        names = text_widget.tag_names()
    except Exception:
        return problems
    for key, color in GUIDE_PILE_STYLE.items():
        for tag in (key, "hdr_" + key):
            if tag in names:
                try:
                    fg = _face_norm_color(
                        text_widget.tag_cget(tag, "foreground"))
                except Exception:
                    fg = ""
                if fg != _face_norm_color(color):
                    problems.append(
                        "guide pile %s tag %s has foreground %s, "
                        "expected %s"
                        % (key, tag, fg or "(none)",
                           _face_norm_color(color)))
    return problems


def _face_audit_log(message):
    """One line in face-self-check.log beside the program. Never
    raises -- the audit must not be able to break the app."""
    try:
        path = _script_dir_path() / "face-self-check.log"
        line = "%s %s\n" % (datetime.now().isoformat(
            timespec="seconds"), message)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
    except Exception:
        pass

# === END FACE SELF-AUDIT SECTION ===


def run_background_check(pkg, label=""):
    """The full offline check for one package, over the ADB cable:
    dumpsys tells + app-ops overlay state + pulled-APK DEX census,
    scored by the research law. Returns the result dict (also
    appended to background-check-results.jsonl)."""
    global ADB
    res = {"pkg": pkg, "label": label or pkg,
           "ts": datetime.now().isoformat(timespec="seconds"),
           "version_code": None,
           "outcome": "not_sure", "points": 0, "networks": [],
           "network_count": 0, "census_done": False,
           "census_complete": False, "files_read": 0, "files_total": 0,
           "evidence": [],
           "vault": is_photo_vault(pkg, label), "signals": {},
           "error": ""}
    try:
        if not ADB:
            ADB = find_adb()
        if not ADB:
            res["error"] = "ADB not found"
            res["evidence"] = [("THE CHECK COULD NOT RUN -- no ADB "
                                 "on this computer", True)]
            _bg_append_result(res)
            return res
        out = adb_cmd("shell", "dumpsys", "package", pkg, timeout=90)
        _vcm = re.search(r"versionCode=(\d+)", out or "")
        res["version_code"] = int(_vcm.group(1)) if _vcm else None
        first, last, dlabel, _granted = parse_pkg_dump(out)
        if dlabel:
            res["label"] = dlabel
        res["vault"] = is_photo_vault(pkg, res["label"])
        bg = parse_bg_dump(out)
        req = bg["requested_perms"]
        inst_map = third_party_with_installers()
        installer = inst_map.get(pkg) or bg["installer"]
        if installer in (None, "", "null"):
            src_label, sideloaded = "preinstalled (no store " \
                                    "installer)", False
        else:
            src_label, sideloaded = install_source(installer)
        overlay_on = False
        try:
            ao = adb_cmd("shell", "appops", "get", pkg, timeout=30)
            overlay_on = bool(re.search(
                r"SYSTEM_ALERT_WINDOW:\s*allow", ao or ""))
        except Exception:
            overlay_on = False
        networks = {}
        census_done = False
        census_complete = False
        files_read = 0
        files_total = 0
        files_failed = 0
        with _bg_tempfile.TemporaryDirectory() as td:
            apks, pull_failed = _bg_pull_apks(pkg, td)
            files_total = len(apks) + pull_failed
            files_failed = pull_failed
            if apks:
                networks, stats = census_apk_networks(apks)
                census_done = stats.get("dex_files", 0) > 0
                files_read = stats.get("files_read", 0)
                files_failed += stats.get("files_failed", 0)
                census_complete = bool(
                    stats.get("census_complete") and pull_failed == 0)
        stale = (bg["target_sdk"] is not None
                 and bg["target_sdk"] <= 28 and last is not None
                 and (datetime.now() - last).days <= 400)
        facts = {
            "census_done": census_done,
            "census_complete": census_complete,
            "files_read": files_read,
            "files_total": files_total,
            "files_failed": files_failed,
            "networks": networks,
            "overlay_declared": _BG_PERM_OVERLAY in req,
            "overlay_on": overlay_on,
            "fullscreen_intent": _BG_PERM_FULLSCREEN in req,
            "install_packages": _BG_PERM_INSTALL in req,
            "boot_persistence": bool(bg["boot_receiver"]
                                     or _BG_PERM_BOOT in req
                                     or _BG_PERM_FG_SERVICE in req),
            # Section 14's keyword determination is the
            # FAKE-KEYWORD TABLE above (owner ruling 2026-10-21:
            # the harvested table is the source of truth) -- NOT
            # JUNK_RE, which the fact used before the table
            # existed. Same no-exceptions shape as before: the
            # shields ride in "guarded", not in the fact.
            "fake_utility": _fake_keyword_match(pkg, res["label"]),
            "guarded": _fake_costume_shielded(pkg),
            "sideloaded": sideloaded,
            "source_label": src_label,
            "target_sdk": bg["target_sdk"],
            "stale_target": stale,
        }
        scored = score_background_check(facts)
        res.update(scored)
        res["networks"] = sorted(networks)
        res["network_count"] = len(networks)
        res["census_done"] = census_done
        res["census_complete"] = census_complete
        res["files_read"] = files_read
        res["files_total"] = files_total
        res["signals"] = {
            "overlay_declared": facts["overlay_declared"],
            "overlay_on": overlay_on,
            "fullscreen_intent": facts["fullscreen_intent"],
            "install_packages": facts["install_packages"],
            "boot_persistence": facts["boot_persistence"],
            "fake_utility": facts["fake_utility"],
            "guarded": facts["guarded"],
            "sideloaded": sideloaded,
            "installer": installer,
            "source_label": src_label,
            "target_sdk": bg["target_sdk"],
            "stale_target": stale,
        }
    except Exception as e:
        res["error"] = str(e)
        if not res["evidence"]:
            res["evidence"] = [("THE CHECK COULD NOT FINISH: %s" % e,
                                True)]
    _bg_append_result(res)
    return res


# ------------------------------------------- durable check store ---
# Verdict persistence (mirror of the Android fix): a background check
# used to live only in self._bg_results for the session, so the next
# scan forgot it and the app went back to ASK FIRST. Completed checks
# are now ALSO saved durably in background-check-store.json, resolved
# in _script_dir_path() -- i.e. the folder beside the running .pyw,
# the same place as ad-sdk-signatures.json, learned_bad.json and
# background-check-results.jsonl (_bg_store_path() below). At scan
# time the stored verdicts are re-applied onto the fresh scan rows by
# apply_stored_check_verdicts(), but ONLY while the installed app is
# still the exact version that was checked (versionCode match): an
# updated app is a new unknown and its stored verdict expires.
_BG_OUTCOME_TO_STORE = {"confirmed": "confirmed_bad",
                        "cleared": "cleared",
                        "not_sure": "not_sure"}
_BG_OUTCOME_FROM_STORE = {"confirmed_bad": "confirmed",
                          "cleared": "cleared",
                          "not_sure": "not_sure"}


def _bg_store_path():
    """Resolved durable store path: background-check-store.json in
    _script_dir_path() (beside the running .pyw)."""
    return _script_dir_path() / _BG_STORE_FILENAME


def _bg_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def load_bg_store():
    """{pkg: record} from the durable store. Tolerant by law: a
    missing or corrupt file (or any error at all) returns {} -- a
    broken store must never break a scan."""
    try:
        data = json.loads(_bg_store_path().read_text(encoding="utf-8"))
        pkgs = data.get("packages") if isinstance(data, dict) else None
        if isinstance(pkgs, dict):
            return {str(k): v for k, v in pkgs.items()
                    if isinstance(v, dict)}
    except Exception:
        pass
    return {}


def save_bg_record(res, version_code):
    """Persist one run_background_check() result dict as a store
    record (outcome "confirmed" -> "confirmed_bad"). Atomic: the
    document is written to a temp file in the SAME directory and
    os.replace()d over the store. Never raises into the caller."""
    try:
        if not res or not res.get("pkg"):
            return
        evidence = []
        for item in (res.get("evidence") or []):
            try:
                evidence.append([str(item[0]), bool(item[1])])
            except Exception:
                continue
        record = {
            "package": res.get("pkg"),
            "outcome": _BG_OUTCOME_TO_STORE.get(res.get("outcome"),
                                                "not_sure"),
            "network_count": _bg_int(res.get("network_count")),
            "networks": [str(n) for n in (res.get("networks") or [])],
            "evidence": evidence,
            "points": _bg_int(res.get("points")),
            "checked_at": (res.get("ts") or res.get("checked_at")
                           or datetime.now().isoformat(
                               timespec="seconds")),
            "version_code": (None if version_code is None
                             else _bg_int(version_code, None)),
            "vault": bool(res.get("vault")),
            "census_done": bool(res.get("census_done")),
            "census_complete": bool(res.get("census_complete")),
            "label": res.get("label") or res.get("pkg"),
        }
        packages = load_bg_store()
        packages[record["package"]] = record
        doc = {"version": 1, "packages": packages}
        path = _bg_store_path()
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        os.replace(tmp, path)
    except Exception:
        pass


def bg_record_to_result(record):
    """Convert a store record back into a run_background_check()-shaped
    result dict (outcome "confirmed_bad" -> "confirmed") so the
    existing GUI rendering and dialog code consume stored records
    unchanged. Carries "stored": True and "checked_at"."""
    rec = record if isinstance(record, dict) else {}
    evidence = []
    for item in (rec.get("evidence") or []):
        try:
            evidence.append((str(item[0]), bool(item[1])))
        except Exception:
            continue
    pkg = rec.get("package") or ""
    return {"pkg": pkg,
            "label": rec.get("label") or pkg,
            "ts": rec.get("checked_at") or "",
            "checked_at": rec.get("checked_at") or "",
            "version_code": rec.get("version_code"),
            "outcome": _BG_OUTCOME_FROM_STORE.get(rec.get("outcome"),
                                                  "not_sure"),
            "points": _bg_int(rec.get("points")),
            "networks": [str(n) for n in (rec.get("networks") or [])],
            "network_count": _bg_int(rec.get("network_count")),
            "census_done": bool(rec.get("census_done")),
            "census_complete": bool(rec.get("census_complete")),
            "files_read": 0, "files_total": 0,
            "evidence": evidence,
            "vault": bool(rec.get("vault")),
            "signals": {},
            "error": "",
            "stored": True}


def installed_version_codes(pkgs):
    """{pkg: int|None} -- the CURRENT installed versionCode of each
    package, read from the `dumpsys package` output the check already
    uses. Any failure yields None (which expires the stored record).
    Only ever called for packages that have stored records."""
    out_map = {}
    for pkg in (pkgs or []):
        vc = None
        try:
            out = adb_cmd("shell", "dumpsys", "package", pkg)
            m = re.search(r"versionCode=(\d+)", out or "")
            if m:
                vc = int(m.group(1))
        except Exception:
            vc = None
        out_map[pkg] = vc
    return out_map


def apply_stored_check_verdicts(scan_data, records, version_codes):
    """Re-apply durable background-check verdicts onto fresh scan rows.

    Pure (no GUI, no ADB): scan_data rows are scan_core 9-tuples,
    records is {pkg: record} from load_bg_store(), version_codes is
    {pkg: int|None} of CURRENT installed versions. Returns
    (new_rows, flips); input rows and their reasons lists are never
    mutated -- flipped rows are NEW tuples. Only a "review" row may
    flip. Rules, in order:
      a. no record for the package -> unchanged;
      b. EXPIRY: record.version_code is None, or the current version
         is None, or they differ -> record ignored, row unchanged;
      c. BLOCKLIST FIRST: pkg in KNOWN_BAD -> unchanged (a stored
         "cleared" never resurrects a convicted app);
      c2. FACTORY CAP: a factory-capped row (its reasons carry the
          factory-app line) -> unchanged in BOTH directions: a
          stored "confirmed_bad" must not flip it to "remove", and
          a stored "cleared" does not erase the factory ask. The
          cap is per-device and current; the stored record was a
          verdict about a checked build, and it still surfaces in
          the Background Check dialog via _bg_results;
      d. VAULT RAIL: a photo vault's "confirmed_bad" record must NOT
         flip it to remove (stays "review"); a "cleared" record MAY
         flip a vault to "clean";
      e. "confirmed_bad" -> "remove" + a boom reason line;
      f. "cleared" -> "clean" + a cleared reason line;
      g. "not_sure" -> unchanged (the GUI still surfaces the stored
         record in _bg_results for the banner/dialog).
    """
    records = records or {}
    version_codes = version_codes or {}
    new_rows = []
    flips = {}
    for row in (scan_data or []):
        try:
            (pkg, label, score, reasons, verdict, source_cat,
             privacy, threat_type, boot_hit) = row
        except Exception:
            new_rows.append(row)
            continue
        if verdict != "review":
            new_rows.append(row)
            continue
        rec = records.get(pkg)
        if not rec:                                        # rule a
            new_rows.append(row)
            continue
        rec_vc = rec.get("version_code")                   # rule b
        cur_vc = version_codes.get(pkg)
        if rec_vc is None or cur_vc is None or rec_vc != cur_vc:
            new_rows.append(row)
            continue
        if pkg in KNOWN_BAD:                               # rule c
            new_rows.append(row)
            continue
        if _row_is_factory(reasons):                       # rule c2
            new_rows.append(row)
            continue
        outcome = rec.get("outcome")
        checked_date = str(rec.get("checked_at") or "")[:10]
        new_verdict = None
        boom = None
        if outcome == "confirmed_bad":
            if is_photo_vault(pkg, label):                 # rule d
                new_rows.append(row)
                continue
            detail = None
            for item in (rec.get("evidence") or []):
                try:
                    if item[1]:
                        detail = str(item[0])
                        break
                except Exception:
                    continue
            if not detail:
                detail = ("STUFFED WITH %d AD NETWORKS"
                          % _bg_int(rec.get("network_count")))
            boom = ("BACKGROUND CHECK: CONFIRMED BAD -- %s "
                    "(checked %s)" % (detail, checked_date))
            new_verdict = "remove"                         # rule e
        elif outcome == "cleared":
            boom = ("BACKGROUND CHECK: CLEARED -- code census found "
                    "%d ad network(s) (checked %s)"
                    % (_bg_int(rec.get("network_count")), checked_date))
            new_verdict = "clean"                          # rule f
        else:                                              # rule g
            new_rows.append(row)
            continue
        new_reasons = list(reasons or []) + [boom]
        new_rows.append((pkg, label, score, new_reasons, new_verdict,
                         source_cat, privacy, threat_type, boot_hit))
        flips[pkg] = {"from": verdict, "to": new_verdict,
                      "outcome": outcome,
                      "checked_at": rec.get("checked_at")}
    return new_rows, flips



# ------------------------------------------------- original GUI ---

# Original Pop-Up Blocker look (from the first build):
#   dark window, red POP-UP BLOCKER header, teal ADWARE SCANNER subhead,
#   green-dot status bar, cyan SCAN PHONE, filter radios, purple-gray
#   results pane, red REMOVE ALL, Activity log. Single window.

# ---- Midnight Dark design tokens (v11.0, spec 3 / AT-17) ----------
# ONE embedded canonical token block inside this single file (AT-17:
# no design_tokens.json ships). Every screen, dialog, the Guided
# Clean guide, boom text and verdict rendering take colors from
# here -- the AT-23 swap happens once, in this block, everywhere.
BG_APP = "#080F1B"            # 3.1 main application background
BG_PANEL = "#0D1626"          # 3.1 primary content panels
BG_PANEL_DEEP = "#0A1220"     # 3.1 recessed panels, logs, inputs
BORDER = "#1B2A44"            # 3.1 dividers / panel outlines
ACCENT_CYAN = "#28C7E8"       # 3.1 branding / informational emphasis
ACTION_BLUE = "#168EF2"       # 3.1 / 3.3 primary scan action
ACTION_BLUE_HOVER = "#36A7FF"
TEXT_PRIMARY = "#F5F8FC"      # 3.1 headings and main content
TEXT_SECONDARY = "#B4C2D2"    # 3.1 descriptions / supporting content
TEXT_MUTED = "#879AB0"        # 3.1 package metadata / low priority
VERDICT_REMOVE = "#FF4D4D"    # 3.2 REMOVE
VERDICT_KEEP = "#35D05A"      # 3.2 KEEP
VERDICT_ASK = "#FFCF40"       # 3.2 ASK FIRST
CRITICAL_REMOVE = "#FF6B74"   # 3.2 critical phrase, REMOVE
CRITICAL_KEEP = "#7BF5A8"     # 3.2 critical phrase, KEEP
CRITICAL_ASK = "#FFE47D"      # 3.2 critical phrase, ASK FIRST
ACTION_REMOVE = "#D92D38"     # 3.3 REMOVE ALL button
ACTION_REMOVE_HOVER = "#EF404B"
ACTION_CLEAN = "#169B4B"      # 3.3 GUIDED CLEAN action
ACTION_CLEAN_HOVER = "#20B85B"
ACTION_NEUTRAL = "#24364C"    # 3.3 secondary buttons
ACTION_NEUTRAL_HOVER = "#30465F"
FOCUS_RING = "#69DDF4"        # 3.3 keyboard focus outline
SELECTION_BG = "#234562"      # 3.3 neutral selected controls
DISABLED_BG = "#172334"       # 3.3 disabled button background
DISABLED_TEXT = "#879AB0"     # 3.3 disabled labels
PRINT_BG = "#FFFFFF"          # 3.4 printed report (light theme)
PRINT_PRIMARY = "#182230"
PRINT_SECONDARY = "#536273"
PRINT_BORDER = "#CDD5DF"
PRINT_ACCENT = "#087F9E"
PRINT_REMOVE = "#B42318"
PRINT_KEEP = "#176534"
PRINT_ASK = "#805000"
VERDICT_WORDS = {"remove": "REMOVE", "review": "ASK FIRST",
                 "clean": "KEEP"}
VERDICT_COLORS = {"remove": VERDICT_REMOVE, "review": VERDICT_ASK,
                  "clean": VERDICT_KEEP}
CRITICAL_COLORS = {"remove": CRITICAL_REMOVE, "review": CRITICAL_ASK,
                   "clean": CRITICAL_KEEP}

# ---- Honest Shelf tokens (v11.4 mirror, owner order 2026-10-19) ----
# The scan-results view, the all-apps list, the detail (Background
# Check) view and the Guided Clean guide render on the clean WHITE
# shelf face, mirroring the phone's Honest Shelf (SHELF-SPEC §1).
# ONE token block: every shelf surface takes its colors from here,
# never from scattered literals. Verdicts stay colored TEXT, never
# blocks/bands (owner law). The verdict hexes are the PC's spec-3.2
# token set above (REMOVE #FF4D4D / KEEP #35D05A / ASK #FFCF40) --
# the phone shelf ships the briefed set (#FF4D4D/#35D05A/#FFCF40,
# SHELF-SPEC §7.1); that fork is recorded in RELEASE-RECORD.md as a
# boss landing decision, and SHELF_VERDICT_COLORS below is the one
# place a future unification changes.
SHELF_BG = "#FFFFFF"               # shelf face background
SHELF_INK = PRINT_PRIMARY          # #182230 dark ink (body text)
SHELF_SECONDARY = PRINT_SECONDARY  # #536273 supporting text on white
SHELF_MUTED = "#6B7A8D"            # package metadata on white
SHELF_BORDER = PRINT_BORDER        # #CDD5DF dividers on white
SHELF_SELECTION = "#DCE6F0"        # checkbox selectcolor on white
SHELF_VERDICT_COLORS = {"remove": VERDICT_REMOVE,
                        "review": VERDICT_ASK,
                        "clean": VERDICT_KEEP}
# Boom on white (SHELF-SPEC §7.3): the reason BODY renders in dark
# ink; only the single loud phrase takes the verdict color.
SHELF_BOOM_BODY = SHELF_INK
# Legacy constant names (kept for the existing code, now token-driven):
DBG = BG_APP
DBAR = BG_PANEL
DRED = ACTION_REMOVE
DTEAL = ACCENT_CYAN
DCYAN = ACTION_BLUE
DPANE = BG_PANEL
DTEXT = TEXT_PRIMARY
DGRAY = TEXT_MUTED

DGREEN = VERDICT_KEEP   # token (spec 3.2)
DFONT = "Segoe UI"
DMONO = "Consolas"


# ------------------------------------------------------------ self-update --
# Issue #37: one-click self-update, the way the phone app does it.
# The program checks a small manifest on OUR feed repo only:
#   pc-version.json  {version, url, sha256, size, notes}
# A download is installed only after its size AND SHA-256 match the
# manifest; a helper script performs the file swap after this process
# exits and rolls back to the backup copy if the new version fails to
# start. Updates are never offered or applied while a scan/removal
# (phone session) is in progress, and never applied automatically.
UPDATE_MANIFEST_URL = ("https://raw.githubusercontent.com/ifixrepairs/"
                       "popup-blocker/main/pc-version.json")
UPDATE_ALIVE_SECONDS = 10  # new version must stay alive this long

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


def _version_tuple(v):
    parts = []
    for piece in str(v).strip().split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_newer(remote, local):
    r, l = _version_tuple(remote), _version_tuple(local)
    n = max(len(r), len(l))
    r += (0,) * (n - len(r))
    l += (0,) * (n - len(l))
    return r > l


def _default_fetch_bytes(url, timeout=20):
    req = urllib.request.Request(
        url, headers={"User-Agent": "AdTrapper-PC-Updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_update_manifest(raw):
    """Validate manifest bytes -> dict, or None if malformed."""
    try:
        data = json.loads(raw.decode("utf-8"))
        version = str(data["version"]).strip()
        url = str(data["url"]).strip()
        sha = str(data["sha256"]).strip().lower()
        size = int(data["size"])
        notes = str(data.get("notes", ""))
    except Exception:
        return None
    if not version or not url or len(sha) != 64 or size <= 0:
        return None
    extras = []
    if isinstance(data.get("extras"), list):
        for e in data["extras"]:
            try:
                nm = str(e["name"]).strip()
                eu = str(e["url"]).strip()
                es = str(e["sha256"]).strip().lower()
                ez = int(e["size"])
            except Exception:
                continue
            if (not nm or "/" in nm or "\\" in nm or nm in (".", "..")
                    or not eu or len(es) != 64 or ez <= 0):
                continue
            extras.append({"name": nm, "url": eu, "sha256": es,
                           "size": ez})
    return {"version": version, "url": url, "sha256": sha,
            "size": size, "notes": notes, "extras": extras}


def check_for_update(fetch_bytes=None):
    """Manifest dict if the feed offers a NEWER version, else None.
    Any network or parse problem returns None quietly - offline is a
    normal state for a shop PC, never an error."""
    fetch = fetch_bytes or _default_fetch_bytes
    try:
        info = parse_update_manifest(fetch(UPDATE_MANIFEST_URL))
    except Exception:
        return None
    if info and _version_newer(info["version"], VERSION):
        return info
    return None


def verify_update_file(path, expected_size, expected_sha256):
    """True only if the file's size and SHA-256 both match the manifest."""
    try:
        p = Path(path)
        if p.stat().st_size != int(expected_size):
            return False
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower() == str(expected_sha256).lower()
    except Exception:
        return False


def download_update(manifest, dest_dir, fetch_bytes=None):
    """Download the update into dest_dir and verify it.
    Returns (path, None) on success, (None, reason) on failure. A failed
    or unverifiable download is always deleted, never installed."""
    fetch = fetch_bytes or _default_fetch_bytes
    dest = Path(dest_dir) / ("AdTrapper-PC-v%s.download"
                             % manifest["version"])
    try:
        data = fetch(manifest["url"], timeout=120)
        dest.write_bytes(data)
    except Exception as e:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        return (None, "download failed (%s)" % e)
    if not verify_update_file(dest, manifest["size"], manifest["sha256"]):
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass
        return (None, "the downloaded file failed its safety check "
                      "(size/hash mismatch) and was discarded")
    return (dest, None)



def download_extras(manifest, dest_dir, fetch_bytes=None):
    """Download + verify the manifest's optional "extras" (v10.15:
    bundled helper files like dwebp.exe, dropped beside the
    program). Returns [(name, ok, reason)]. NEVER raises and NEVER
    blocks the app update: an extra is an enhancement, not a
    requirement -- a failed extra is discarded and reported."""
    out = []
    fetch = fetch_bytes or _default_fetch_bytes
    for e in (manifest or {}).get("extras") or []:
        name = e.get("name") or "extra"
        dest = Path(dest_dir) / name
        tmp = Path(dest_dir) / (name + ".download")
        try:
            data = fetch(e["url"], timeout=120)
            tmp.write_bytes(data)
            if verify_update_file(tmp, e["size"], e["sha256"]):
                tmp.replace(dest)
                out.append((name, True, None))
            else:
                tmp.unlink(missing_ok=True)
                out.append((name, False,
                            "failed its safety check (size/hash "
                            "mismatch) and was discarded"))
        except Exception as ex:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            out.append((name, False, "download failed (%s)" % ex))
    return out


def ensure_own_extras(fetch_bytes=None):
    """Self-heal: when the shelf manifest describes THIS version,
    fetch any of its extras that are missing (or fail verification)
    beside the program. A PC that updated from a pre-extras build
    lands without dwebp.exe; this closes that gap at startup.
    Quiet on every failure -- extras are optional."""
    fetch = fetch_bytes or _default_fetch_bytes
    try:
        info = parse_update_manifest(fetch(UPDATE_MANIFEST_URL))
    except Exception:
        return []
    if not info or _version_tuple(info["version"]) != _version_tuple(VERSION):
        return []
    todo = []
    for e in info.get("extras") or []:
        p = _script_dir_path() / e["name"]
        try:
            good = p.is_file() and verify_update_file(
                p, e["size"], e["sha256"])
        except Exception:
            good = False
        if not good:
            todo.append(e)
    if not todo:
        return []
    return download_extras({"extras": todo}, _script_dir_path(), fetch)


def updater_guard_reason(busy):
    """Self-update is refused while a scan/removal (a phone session) is
    running. Returns a plain reason string, or None if update may go on."""
    if busy:
        return ("a scan or removal is in progress - finish it "
                "before updating")
    return None


def begin_update(current_path, downloaded_path, new_version, from_version,
                 wait_pid=None, alive_seconds=UPDATE_ALIVE_SECONDS):
    """Write the swap helper next to the program, launch it detached,
    and return its process handle. The CALLER exits right after this;
    the helper waits for that exit, renames the current file to
    AdTrapper-PC-v<old>-backup.pyw, moves the verified download in as
    AdTrapper-PC-v<new>.pyw, relaunches it, and - if it does not stay
    alive - restores the backup and relaunches that instead. Either way
    it leaves update_result.json for the relaunched program to report."""
    current_path = Path(current_path)
    folder = current_path.parent
    target = folder / ("AdTrapper-PC-v%s.pyw" % new_version)
    backup = folder / ("AdTrapper-PC-v%s-backup.pyw" % from_version)
    result_path = folder / "update_result.json"
    helper = folder / "adtrapper_update_helper.py"
    helper.write_text(UPDATE_HELPER_SRC, encoding="utf-8")
    if wait_pid is None:
        wait_pid = os.getpid()
    args = [sys.executable, str(helper), str(wait_pid), str(current_path),
            str(downloaded_path), str(target), str(backup),
            str(result_path), sys.executable, str(alive_seconds),
            str(from_version), str(new_version)]
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(args, **kwargs)



# ------------------------------------------------------------ boom text --
# Boom text (v10.13, owner spec): in the results list, the GUILT
# PHRASES inside a row's reason line render loudly -- bold and hot
# colored -- inline, while the rest of the reason stays the normal
# muted color. Colored TEXT only: no circles, boxes, pills, or
# background blocks. Max 2 loud spans per row. "Removed by this shop
# before" is history, not guilt, and never goes loud; a known-bad
# blocklist hit IS guilt. Reasons stay plain strings at the data
# layer (scan_core, the PDF report); segmentation is render-time.
BOOM_COLORS = {"remove": CRITICAL_REMOVE, "review": CRITICAL_ASK}  # 3.2 critical tokens (AT-23)

_BOOM_RULES = (
    re.compile(r"stuffed with \d+ ad networks", re.I),
    re.compile(r"contains ad software", re.I),
    re.compile(r"fake-utility costume", re.I),
    re.compile(r"known-bad blocklist", re.I),
    re.compile(r"known junk app", re.I),
    re.compile(r"never opened", re.I),
    re.compile(r"not from an app store", re.I),
    re.compile(r"can access your [\w, ]+?(?=;|$)", re.I),
    re.compile(r"sideloaded", re.I),
)


def boom_segments(text, verdict):
    """Split a reason string into [(segment, is_loud), ...].

    Only REMOVE / REVIEW rows get loud spans, at most 2; overlapping
    hits merge into one span. A "sideloaded" hit inside the same
    reason segment as a "not from an app store" hit is the same
    signal said twice (the scanner writes "not from an app store
    (sideloaded via ...)") and does not eat the second loud slot.
    """
    if not text:
        return []
    if verdict not in BOOM_COLORS:
        return [(text, False)]
    hits = []
    for rx in _BOOM_RULES:
        for mt in rx.finditer(text):
            hits.append((mt.start(), mt.end(), mt.group(0).lower()))
    keep = []
    for st, en, g in hits:
        if g == "sideloaded":
            seg_start = text.rfind(";", 0, st) + 1
            if "not from an app store" in text[seg_start:st].lower():
                continue
        keep.append((st, en))
    keep.sort()
    merged = []
    for st, en in keep:
        if merged and st < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], en))
        else:
            merged.append((st, en))
    merged = merged[:2]
    if not merged:
        return [(text, False)]
    out, pos = [], 0
    for st, en in merged:
        if st > pos:
            out.append((text[pos:st], False))
        out.append((text[st:en], True))
        pos = en
    if pos < len(text):
        out.append((text[pos:], False))
    return out


class PopupBlockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AdTrapper v%s -- Malware & Adware Scanner" % VERSION)
        self.root.minsize(640, 620)
        self.root.configure(bg=DBG)
        try:
            self.root.iconbitmap("popup_blocker.ico")
        except Exception:
            pass

        self.q = queue.Queue()
        self.busy = False
        self.scan_data = []      # full scan_core results
        self._original_numbers = {}  # pkg -> original_number (AT-2)
        self._scan_time_str = ""     # scan completion time (report)
        self._cleanup_time_str = ""  # cleanup completion time (report)
        self.sites = []          # [(date, host)]
        self._guided_pending = False  # guided clean awaiting its re-scan
        self._guided_ask = []         # names left for a human decision
        self._bg_results = {}       # pkg -> background-check result (v11.1)
        self._bg_keep = set()       # pkgs kept after a background check
        self.last_report_path = None
        self.report_customer = ""   # customer name for the cleanup report
        self.report_ticket = ""     # POS ticket no. (bank-proof reports)
        self.report_technician = ""  # technician printed on the report
        self._details_asked = False
        self._scan_completed = False
        self.row_vars = []       # [(BooleanVar, pkg, label)]
        self._icon_imgs = {}        # pkg -> PhotoImage (UI thread)
        self._row_icon_labels = {}  # pkg -> icon Label in live rows
        self._icon_wanted = set()   # pkgs the icon worker still owes
        self._icon_lock = threading.Lock()
        self._scan_gen = 0            # bumps per completed scan (v10.14)
        self._icon_token = 0          # gen the icon worker reports for
        self._icons_logged_gen = -1   # gen whose Pictures line is out
        self._current_icon_rows = []  # pkgs in the app rows on screen
        self._icon_worker_on = False
        # v10.16 settle gate for the Pictures/badge lines: per scan,
        # the lines print ONCE, only after the icon worker drained
        # the latest kick AND every async icon source (appfaces pack,
        # faces/blocklist feed, dwebp extras) has settled -- loaded,
        # failed, or timed out (20 s deadline armed per scan).
        self._pass_seq = 0            # bumps per _kick_icons feed
        self._icons_done_seq = 0      # newest kick seq fully drained
        self._pass_deadline = False   # settle deadline passed (gen)
        self._src_settled = {"pack": False, "faces": False,
                             "extras": False}
        self._generic_photo_img = None  # shared APP-chip PhotoImage
        self._face_imgs = {}          # pkg -> PhotoImage (bad list)
        self._row_face_labels = {}    # pkg -> face Label in bad-list rows
        self._faces_order = []        # bad-list pkgs, blocklist order
        self._faces_entries = None    # pkg -> faces.json entry
        self._faces_ok = False        # faces.json data available
        self._faces_loading = False
        self._faces_fail_logged = False
        self._guide_imgs = {}         # pkg -> 32px PhotoImage (guide)
        self._badge_imgs = {}       # pkg -> maker-chip PhotoImage (v10.15)
        self._icon_fallback = set() # rows currently showing a chip/none
        self._appfaces_entries = None  # pkg -> appfaces.json entry
        self._appfaces_ok = False      # known-faces pack available
        self._appfaces_loading = False
        self._companion_state = "not checked"  # v11.4 icon service
        self._companion_offer = False          # install button live?
        self.show_var = tk.StringVar(value="sites")   # flagged | all | sites
        self.source_var = tk.StringVar(value="All sources")

        # ---------- header ----------
        # v11.0 (AT-6, spec 6.3/2.3): clean phone/shield mark drawn
        # with Tk canvas shapes (no external art files, no cartoon
        # characters) + the two-tone "AdTrapper" wordmark as TEXT
        # ("Ad" TEXT_PRIMARY, "Trapper" ACCENT_CYAN) + descriptor
        # + shop identification. Slim: the results list keeps the
        # height. (The 2.4 brand asset files / window .ico do not
        # exist yet -- open dependency, noted in the change summary;
        # the shipped iconbitmap attempt below is unchanged.)
        head = tk.Frame(root, bg=DBG)
        head.pack(fill="x", padx=22, pady=(8, 0))
        _mark = tk.Canvas(head, width=30, height=40, bg=DBG,
                          highlightthickness=0, bd=0)
        _mark.create_rectangle(4, 2, 26, 38, outline=ACCENT_CYAN,
                               width=2)
        _mark.create_rectangle(7, 6, 23, 30, outline=BORDER, width=1)
        _mark.create_polygon(15, 10, 21, 12.5, 21, 18, 15, 24,
                             9, 18, 9, 12.5, fill=ACCENT_CYAN,
                             outline=ACCENT_CYAN)
        _mark.create_line(11.8, 16.8, 14.2, 19.4, fill=BG_APP, width=2)
        _mark.create_line(14.2, 19.4, 18.4, 13.8, fill=BG_APP, width=2)
        _mark.pack(side="left", padx=(0, 10))
        _htxt = tk.Frame(head, bg=DBG)
        _htxt.pack(side="left")
        _wm = tk.Frame(_htxt, bg=DBG)
        _wm.pack(fill="x")
        tk.Label(_wm, text="Ad", font=(DFONT, 17, "bold"),
                 fg=TEXT_PRIMARY, bg=DBG).pack(side="left")
        tk.Label(_wm, text="Trapper", font=(DFONT, 17, "bold"),
                 fg=ACCENT_CYAN, bg=DBG).pack(side="left")
        tk.Label(_htxt, text="MALWARE & ADWARE SCANNER",
                 font=(DFONT, 9, "bold"), fg=TEXT_SECONDARY, bg=DBG,
                 anchor="w").pack(fill="x")
        tk.Label(_htxt, text="iFixx Repairs \u2014 Englewood, Florida",
                 font=(DFONT, 9), fg=DGRAY, bg=DBG,
                 anchor="w").pack(fill="x")
        tk.Label(head, text="v%s" % VERSION, font=(DFONT, 10),
                 fg=DGRAY, bg=DBG).pack(side="right")

        # ---------- status bar ----------
        sbar = tk.Frame(root, bg=DBAR)
        sbar.pack(fill="x", padx=22, pady=(6, 10))
        self.dot = tk.Label(sbar, text="●", font=(DFONT, 12), fg=DGRAY,
                            bg=DBAR)
        self.dot.pack(side="left", padx=(14, 6), pady=10)
        self.status = tk.Label(sbar, text="Checking for phone …",
                               font=(DFONT, 11), fg=DTEXT, bg=DBAR)
        self.status.pack(side="left", pady=10)
        # v11.4 companion icon service: honest helper state, always
        # visible next to the phone state (consult §4.2 PC-2).
        self.helper_status = tk.Label(sbar, text="Phone helper: not checked",
                                      font=(DFONT, 11), fg=DGRAY, bg=DBAR)
        self.helper_status.pack(side="left", padx=(18, 0), pady=10)
        self.helper_btn = tk.Button(
            sbar, text="INSTALL PHONE HELPER", font=(DFONT, 10, "bold"),
            fg=DTEXT, bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=12, pady=6, cursor="hand2", state="disabled",
            command=self.on_helper_install)
        # packed only when an install offer actually exists
        # (companion absent AND a companion APK beside the program).

        # ---------- conviction counter ----------
        # Owner idea 2026-10-20: the tallies on the home screen --
        # live bad-list count, this shop's own convictions, and
        # the suspects this machine has parked undecided.
        # Refreshed at startup and after every render.
        self.counter = tk.Label(root, text="", font=(DFONT, 10),
                                fg=DGRAY, bg=DBG, anchor="w")
        self.counter.pack(fill="x", padx=22, pady=(0, 2))
        # Face self-audit banner: empty while the face is honest;
        # turns red with plain words when a startup/render audit
        # finds a problem (see run_face_self_audit).
        self._face_banner = tk.Label(root, text="",
                                     font=(DFONT, 10, "bold"),
                                     fg="white", bg=DBG, anchor="w")
        self._face_banner.pack(fill="x", padx=22, pady=(0, 2))

        # ---------- scan button ----------
        bwrap = tk.Frame(root, bg=DBG)
        bwrap.pack(fill="x", padx=22, pady=(0, 12))
        btnrow = tk.Frame(bwrap, bg=DBG)
        btnrow.pack()
        self.scan_btn = tk.Button(
            btnrow, text="SCAN PHONE", font=(DFONT, 13, "bold"),
            fg="white", bg=DCYAN, activebackground=ACTION_BLUE_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=34, pady=12, cursor="hand2", command=self.start_scan)
        self.scan_btn.pack(side="left")
        self.usb_btn = tk.Button(
            btnrow, text="USB GUIDE", font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.show_usb_guide)
        self.usb_btn.pack(side="left", padx=(12, 0))
        self.update_btn = tk.Button(
            btnrow, text="CHECK FOR UPDATES", font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.on_update_click)
        self.update_btn.pack(side="left", padx=(12, 0))
        self.guided_btn = tk.Button(
            btnrow, text="GUIDED CLEAN", font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_CLEAN,
            activebackground=ACTION_CLEAN_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.guided_clean)
        self.guided_btn.pack(side="left", padx=(12, 0))
        self.history_btn = tk.Button(
            btnrow, text="HISTORY", font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.show_removal_history)
        self.history_btn.pack(side="left", padx=(12, 0))
        self.disclaimer_btn = tk.Button(
            btnrow, text="DISCLAIMER", font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=lambda: self.show_disclaimer(first_run=False))
        self.disclaimer_btn.pack(side="left", padx=(12, 0))
        self.update_info = None  # manifest dict when an update is known
        self.prog = tk.Label(bwrap, text="", font=(DFONT, 9), fg=DGRAY,
                             bg=DBG)
        self.prog.pack(pady=(4, 0))

        # ---------- filter row ----------
        frow = tk.Frame(root, bg=DBG)
        frow.pack(fill="x", padx=22, pady=(0, 6))
        tk.Label(frow, text="Show:", font=(DFONT, 10), fg=DTEXT,
                 bg=DBG).pack(side="left")
        self.flagged_radio = None
        for val, txt in (("flagged", "⚠ Flagged only"),
                         ("all", "All applications"),
                         ("sites", "Notification sites"),
                         ("badlist", "Bad list")):
            rb = tk.Radiobutton(frow, text=txt, variable=self.show_var,
                                value=val, font=(DFONT, 10), fg=DTEXT, bg=DBG,
                                activebackground=DBG, selectcolor=DBAR,
                                command=self.render)
            rb.pack(side="left", padx=(10, 0))
            if val == "flagged":
                self.flagged_radio = rb
        tk.Label(frow, text="Source:", font=(DFONT, 10), fg=DTEXT,
                 bg=DBG).pack(side="left", padx=(18, 4))
        self.source_menu = tk.OptionMenu(frow, self.source_var,
                                         "All sources")
        self.source_menu.configure(font=(DFONT, 10), fg=DTEXT, bg=DBAR,
                                   activebackground=DBAR,
                                   activeforeground=DTEXT, relief="flat",
                                   bd=0, highlightthickness=0)
        self.source_menu.pack(side="left")
        try:
            self.source_menu["menu"].configure(bg=DBAR, fg=DTEXT,
                                               activebackground=SELECTION_BG)
        except Exception:
            pass

        # ---------- results pane ----------
        pane_wrap = tk.Frame(root, bg=DBG)
        pane_wrap.pack(fill="both", expand=True, padx=22, pady=(0, 8))
        self.pane = tk.Canvas(pane_wrap, bg=SHELF_BG, highlightthickness=0,
                              bd=0, height=120)
        vsb = tk.Scrollbar(pane_wrap, orient="vertical",
                           command=self.pane.yview)
        self.pane.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.pane.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.pane, bg=SHELF_BG)
        self._win = self.pane.create_window((0, 0), window=self.inner,
                                            anchor="nw")
        self.inner.bind("<Configure>",
                        lambda e: self.pane.configure(
                            scrollregion=self.pane.bbox("all")))
        self.pane.bind("<Configure>",
                       lambda e: self.pane.itemconfig(self._win,
                                                      width=e.width))
        self._mousewheel(self.pane)

        # ---------- remove row ----------
        rrow = tk.Frame(root, bg=DBG)
        rrow.pack(fill="x", padx=22, pady=(0, 10))
        self.remove_btn = tk.Button(
            rrow, text="REMOVE ALL", font=(DFONT, 11, "bold"),
            fg="white", bg=DRED, activebackground=ACTION_REMOVE_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=26, pady=9, cursor="hand2", command=self.remove_all)
        self.remove_btn.pack(side="left")
        tk.Label(rrow, text="removes everything checkmarked",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     side="left", padx=(12, 0))
        self.autoprint_var = tk.BooleanVar(value=True)
        tk.Checkbutton(rrow, text="Auto-print report",
                       variable=self.autoprint_var,
                       font=(DFONT, 10), fg=DTEXT, bg=DBG,
                       activebackground=DBG, activeforeground=DTEXT,
                       selectcolor=DBAR).pack(side="left", padx=(14, 0))
        self.undo_btn = tk.Button(
            rrow, text="UNDO", font=(DFONT, 10, "bold"),
            fg=DTEXT, bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground=DTEXT, relief="flat", bd=0,
            padx=18, pady=7, cursor="hand2", command=self.undo_last,
            state="disabled")
        self.undo_btn.pack(side="right")
        self.print_btn = tk.Button(
            rrow, text="PRINT", font=(DFONT, 10, "bold"),
            fg=DTEXT, bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground=DTEXT, relief="flat", bd=0,
            padx=18, pady=7, cursor="hand2", command=self._print_report)
        self.print_btn.pack(side="right", padx=(0, 8))

        # ---------- activity ----------
        tk.Label(root, text="Activity", font=(DFONT, 11, "bold"),
                 fg=DTEXT, bg=DBG, anchor="w").pack(fill="x", padx=22)
        log_wrap = tk.Frame(root, bg=DBG)
        log_wrap.pack(fill="x", padx=22, pady=(2, 16))
        self.logbox = tk.Text(log_wrap, height=3, font=(DMONO, 9),
                              fg=TEXT_SECONDARY, bg=BG_PANEL_DEEP,
                              relief="flat",
                              bd=0, wrap="word", state="disabled")
        lsb = tk.Scrollbar(log_wrap, orient="vertical",
                           command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right", fill="y")
        self.logbox.pack(side="left", fill="x", expand=True)

        # v10.1 window sizing: ~1100x720, centered; height hugs the
        # content (clamped 720-800) so nothing is clipped by default.
        self.root.update_idletasks()
        try:
            _w = 1100
            _h = max(780, min(880, self.root.winfo_reqheight()))
            _h = min(_h, max(620, self.root.winfo_screenheight() - 30))
            _x = max(0, (self.root.winfo_screenwidth() - _w) // 2)
            _y = max(0, (self.root.winfo_screenheight() - _h) // 2)
            self.root.geometry("%dx%d+%d+%d" % (_w, _h, _x, _y))
        except Exception:
            self.root.geometry("1100x720")
        self.root.after(120, self.process_queue)
        threading.Thread(target=self._startup_check, daemon=True).start()
        self.log("AdTrapper v%s ready. (Title bar shows the version - "
                 "if it isn't v%s, this PC opened an old copy.)"
                 % (VERSION, VERSION))
        if ensure_stable_alias():
            self.log("Desktop shortcut file ready: %s — point the "
                     "shortcut at that name; it never changes."
                     % STABLE_NAME)
        self._report_update_result()
        threading.Thread(target=self._quiet_update_check,
                         daemon=True).start()
        threading.Thread(target=self._faces_bootstrap,
                         daemon=True).start()
        threading.Thread(target=self._appfaces_bootstrap,
                         daemon=True).start()
        threading.Thread(target=self._extras_bootstrap,
                         daemon=True).start()
        self._kick_silent_feed()
        self.refresh_conviction_counter()
        _face_problems = self.run_face_self_audit()
        _face_audit_log("FACE SELF-CHECK startup: %d problem(s)"
                        % len(_face_problems))
        # Removal History + Disclaimer (2026-10-21): the disclaimer
        # shows itself once, on first run, until acknowledged.
        self.root.after(400, self._maybe_show_disclaimer)

    # ------------------------------------------------------- helpers ---
    def _mousewheel(self, widget):
        def _on_wheel(e):
            try:
                widget.yview_scroll(int(-1 * (e.delta / 120)), "units")
            except Exception:
                pass
        widget.bind_all("<MouseWheel>", _on_wheel)

    def _script_dir(self):
        return Path(sys.argv[0]).parent

    def _undo_manifest_path(self):
        return self._script_dir() / "popup_blocker_undo.json"

    def _backup_dir(self):
        d = self._script_dir() / "PopUpBlockerBackups"
        d.mkdir(exist_ok=True)
        return d

    def _write_undo_manifest(self, removed):
        try:
            self._undo_manifest_path().write_text(json.dumps(
                {"date": datetime.now().isoformat(), "apps": removed}))
        except Exception:
            pass

    def _read_undo_manifest(self):
        try:
            p = self._undo_manifest_path()
            if p.is_file():
                data = json.loads(p.read_text())
                if data.get("apps"):
                    return data
        except Exception:
            pass
        return None

    def _clear_undo_manifest(self):
        try:
            self._undo_manifest_path().unlink(missing_ok=True)
        except Exception:
            pass

    # --------------------------- conviction counter / face audit --
    def refresh_conviction_counter(self):
        """Recompute the home-screen conviction counter line from
        the live bad-list size and the local Background Check
        store. Never raises into the UI."""
        try:
            self.counter.configure(
                text=conviction_counter_text(len(KNOWN_BAD),
                                             load_bg_store()))
        except Exception:
            pass

    def run_face_self_audit(self, where="results"):
        """Walk the results tree; on problems, write the log line
        and raise the visible banner. Returns the problem list
        ([] = honest face). Never raises."""
        problems = []
        try:
            problems = face_audit_labels(self.inner)
        except Exception:
            problems = []
        problems = list(dict.fromkeys(problems))
        if problems:
            _face_audit_log("FACE SELF-CHECK FAILED (%s): %s"
                            % (where, "; ".join(problems[:6])))
            try:
                self._face_banner.configure(
                    text="\u26a0 FACE SELF-CHECK FAILED: "
                         + "; ".join(problems[:3]),
                    bg="#D92D38", fg="white")
            except Exception:
                pass
            try:
                self.log("FACE SELF-CHECK FAILED: "
                         + "; ".join(problems[:3]))
            except Exception:
                pass
        else:
            try:
                if self._face_banner.cget("text"):
                    self._face_banner.configure(text="", bg=DBG)
            except Exception:
                pass
        return problems

    def _after_render(self):
        """Post-render housekeeping: fresh counter, honest face."""
        try:
            self.refresh_conviction_counter()
        except Exception:
            pass
        try:
            self.run_face_self_audit()
        except Exception:
            pass

    def log(self, text):
        try:
            self.logbox.configure(state="normal")
            self.logbox.insert("end", text + "\n")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        except Exception:
            pass

    def set_busy(self, busy):
        self.busy = busy
        try:
            self.scan_btn.configure(
                text="SCANNING …" if busy else "SCAN PHONE",
                state="disabled" if busy else "normal",
                bg=DISABLED_BG if busy else DCYAN)
            self.remove_btn.configure(state="disabled" if busy else "normal")
        except Exception:
            pass

    # ------------------------------------------------------- updates ---
    def _report_update_result(self):
        """Report the outcome of a self-update that relaunched us."""
        p = self._script_dir() / "update_result.json"
        try:
            if p.is_file():
                data = json.loads(p.read_text())
                p.unlink(missing_ok=True)
                if data.get("outcome") == "rolled_back":
                    self.log("update didn't take \u2014 you're back "
                             "on v%s." % data.get("from_version", VERSION))
                elif data.get("outcome") == "updated":
                    self.log("Updated to AdTrapper v%s."
                             % data.get("to_version", VERSION))
        except Exception:
            pass

    def _quiet_update_check(self):
        info = check_for_update()
        if info:
            self.q.put(("update_badge", info))

    def on_update_click(self):
        reason = updater_guard_reason(self.busy)
        if reason:
            self.log("Update not started: %s." % reason)
            return
        if self.update_info:
            self._offer_update(self.update_info)
            return
        self.log("Checking for updates \u2026")
        threading.Thread(target=self._manual_update_check,
                         daemon=True).start()

    def _manual_update_check(self):
        info = check_for_update()
        if info:
            self.q.put(("update_badge", info))
            self.q.put(("update_offer", info))
        else:
            self.q.put(("log", "No update found \u2014 you're on the "
                               "latest version (v%s), or the check "
                               "couldn't reach the feed." % VERSION))

    def _offer_update(self, info):
        reason = updater_guard_reason(self.busy)
        if reason:
            self.log("Update not started: %s." % reason)
            return
        msg = ("AdTrapper v%s is available (you have v%s).\n\n%s\n\n"
               "Download and install it now? AdTrapper will restart."
               % (info["version"], VERSION, info.get("notes") or ""))
        if not messagebox.askyesno("AdTrapper update", msg):
            return
        self.log("Downloading AdTrapper v%s \u2026" % info["version"])
        threading.Thread(target=self._do_update_download,
                         args=(info,), daemon=True).start()

    def _do_update_download(self, info):
        path, err = download_update(info, self._script_dir())
        if err:
            self.q.put(("log", "Update not installed: %s. "
                               "You're still on v%s." % (err, VERSION)))
            return
        for name, ok, why in download_extras(info, self._script_dir()):
            if not ok:
                self.q.put(("log", "Optional extra %s not installed "
                                   "(%s) - the update continues "
                                   "without it." % (name, why)))
        self.q.put(("update_install", (info, str(path))))

    def _install_update(self, info, downloaded):
        reason = updater_guard_reason(self.busy)
        if reason:
            self.log("Update not started: %s." % reason)
            return
        self.log("Installing AdTrapper v%s \u2014 restarting \u2026"
                 % info["version"])
        try:
            begin_update(Path(sys.argv[0]).resolve(), downloaded,
                         info["version"], VERSION)
        except Exception as e:
            self.log("Update could not start (%s). You're still on "
                     "v%s." % (e, VERSION))
            return
        self.root.after(400, self.root.destroy)

    # ------------------------------------------------------- device ---
    def _refresh_helper_state(self):
        """Detect the companion helper and post its honest state.
        Runs on a worker thread (adb). The install button is packed
        ONLY when an offer exists (helper absent + APK beside the
        program); every other state is words, not a dead button."""
        try:
            offer = companion_offer()
            if offer["present"]:
                if _COMPANION["session"] is not None:
                    text = companion_status_text()
                else:
                    text = "Phone helper: installed"
                    _companion_set_status("installed")
                can = False
            elif offer["can_offer"]:
                text = ("Phone helper: not installed -- install "
                        "offer available")
                _companion_set_status("not installed (offer "
                                      "available)")
                can = True
            else:
                text = ("Phone helper: not installed -- using the "
                        "built-in picture finder")
                _companion_set_status("not installed -- using the "
                                      "built-in picture finder")
                can = False
            self.q.put(("helper_state", (text, can)))
        except Exception:
            pass

    def on_helper_install(self):
        """One-click 'Install phone helper' (consult §4.2 PC-1).
        Decline/failure path: the scan simply proceeds on the
        extractor fallback -- it is never blocked by this."""
        if self.busy:
            self.log("Phone helper: wait for the current job to "
                     "finish first.")
            return
        self.log("Installing the phone helper ...")
        def _work():
            ok, why = companion_install_helper()
            if ok:
                self.q.put(("log", "Phone helper installed. It only "
                                   "serves app pictures to this PC "
                                   "and can be uninstalled like any "
                                   "app."))
            else:
                self.q.put(("log", "Phone helper not installed (%s) "
                                   "-- scans keep using the built-in "
                                   "picture finder." % why))
            self._refresh_helper_state()
        threading.Thread(target=_work, daemon=True).start()

    def _startup_check(self):
        ok, msg = check_device()
        if ok:
            self.q.put(("phone_ok", ""))
            try:
                model = adb_cmd("shell", "getprop",
                                "ro.product.model").strip()
                if model:
                    self.q.put(("phone_model", model))
            except Exception:
                pass
            self._refresh_helper_state()
        else:
            self.q.put(("phone_bad", msg))

    # ------------------------------------------------------- scan ---
    def start_scan(self):
        if self.busy:
            return
        self.set_busy(True)
        self._kick_silent_feed()
        self.report_customer = ""
        self.report_ticket = ""
        self.report_technician = ""
        self._details_asked = False
        self._scan_completed = False
        self._bg_results = {}
        self._bg_keep = set()
        self.prog.configure(text="starting …")
        self.log("▸ scan initiated …")
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        ok, msg = check_device()
        if not ok:
            self.q.put(("scan_error", msg))
            return
        self.q.put(("phone_ok", ""))
        try:
            model = adb_cmd("shell", "getprop",
                            "ro.product.model").strip()
            if model:
                self.q.put(("phone_model", model))
        except Exception:
            pass
        try:
            results, sites = scan_core(
                progress_cb=lambda d, t, p: self.q.put(
                    ("progress", (d, t, p))))
            # Verdict persistence: re-apply the durable background-
            # check store onto the fresh rows HERE, in scan_data, so
            # the main list AND Guided Clean both see the flipped
            # verdicts (single-apply). Stored records (flipped or
            # not, e.g. not_sure) also ride along to _bg_results.
            stored_map = {}
            try:
                records = load_bg_store()
                if records:
                    vcs = installed_version_codes(list(records.keys()))
                    results, flips = apply_stored_check_verdicts(
                        results, records, vcs)
                    result_pkgs = {r[0] for r in results}
                    for _pkg, _rec in records.items():
                        if _pkg in result_pkgs:
                            stored_map[_pkg] = bg_record_to_result(_rec)
                    for _pkg, _flip in flips.items():
                        self.q.put(("log",
                                    "Saved background check applied: "
                                    "%s %s -> %s (checked %s)."
                                    % (_pkg, _flip.get("from"),
                                       _flip.get("to"),
                                       str(_flip.get("checked_at")
                                           or "")[:10])))
            except Exception:
                stored_map = {}
            self.q.put(("scan_done", (results, sites, stored_map)))
        except Exception as e:
            self.q.put(("log", "SCAN CRASHED: %s" % e))
            self.q.put(("scan_error", "SCAN_CRASHED"))

    # ------------------------------------------------------- usb guide ---
    USB_GUIDE_STEPS = (
        ("1", "On the phone, open Settings \u2192 About phone \u2192 "
              "Software information."),
        ("2", "Tap \"Build number\" 7 times (enter the PIN if asked) "
              "until it says \"Developer mode has been turned on\"."),
        ("3", "Go back to Settings \u2192 Developer options "
              "(at the very bottom), and turn ON \"USB debugging\". "
              "Greyed out? See the fix below."),
        ("4", "Plug the phone into this computer with the USB cable. "
              "If the phone asks about the USB mode, choose "
              "\"File transfer\"."),
        ("5", "On the phone, tap \"Allow\" on the \"Allow USB debugging?\" "
              "popup (tick \"Always allow from this computer\")."),
        ("6", "Back here, the dot turns green and it says "
              "\"Phone connected\" \u2014 hit SCAN PHONE."),
    )

    USB_GUIDE_GREY_STEPS = (
        ("1", "Unplug the USB cable from the phone."),
        ("2", "On the phone, open Settings \u2192 Security and privacy "
              "\u2192 Auto Blocker and turn it OFF (enter the PIN if it "
              "asks)."),
        ("3", "Go back to Settings \u2192 Developer options and turn "
              "ON \"USB debugging\" \u2014 it works now."),
    )

    def show_usb_guide(self):
        win = tk.Toplevel(self.root)
        win.title("Enable USB debugging")
        win.configure(bg=DBG)
        try:
            win.resizable(False, False)
        except Exception:
            pass
        tk.Label(win, text="Enable USB debugging",
                 font=(DFONT, 14, "bold"), fg="white", bg=DBG).pack(
                     anchor="w", padx=20, pady=(16, 4))
        tk.Label(win, text="Takes about 30 seconds. Do it once per phone.",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     anchor="w", padx=20, pady=(0, 10))
        for num, text in self.USB_GUIDE_STEPS:
            row = tk.Frame(win, bg=DBG)
            row.pack(fill="x", padx=20, pady=3)
            tk.Label(row, text=num, font=(DFONT, 12, "bold"),
                     fg=DCYAN, bg=DBG, width=2).pack(side="left",
                                                    anchor="n")
            tk.Label(row, text=text, font=(DFONT, 11), fg=DTEXT,
                     bg=DBG, wraplength=460, justify="left").pack(
                         side="left", anchor="w")
        tk.Label(win, text="If \"USB debugging\" is greyed out:",
                 font=(DFONT, 12, "bold"), fg=VERDICT_ASK, bg=DBG).pack(
                     anchor="w", padx=20, pady=(12, 4))
        for num, text in self.USB_GUIDE_GREY_STEPS:
            row = tk.Frame(win, bg=DBG)
            row.pack(fill="x", padx=20, pady=3)
            tk.Label(row, text=num, font=(DFONT, 12, "bold"),
                     fg=VERDICT_ASK, bg=DBG, width=2).pack(side="left",
                                                        anchor="n")
            tk.Label(row, text=text, font=(DFONT, 11), fg=DTEXT,
                     bg=DBG, wraplength=460, justify="left").pack(
                         side="left", anchor="w")
        tk.Label(win, text="When finished: turn USB debugging back OFF in "
                           "Developer options.",
                 font=(DFONT, 10, "italic"), fg=DGRAY, bg=DBG,
                 wraplength=480, justify="left").pack(
                     anchor="w", padx=20, pady=(10, 4))
        tk.Button(win, text="CLOSE", font=(DFONT, 11, "bold"),
                  fg="white", bg=DCYAN,
                  activebackground=ACTION_BLUE_HOVER,
                  activeforeground="white", relief="flat", bd=0,
                  padx=24, pady=8, cursor="hand2",
                  command=win.destroy).pack(pady=(6, 16))
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass

    # ------------------------------------------------------- render ---
    def _threat_rows(self):
        src = self.source_var.get()
        return [r for r in self.scan_data
                if r[4] in ("remove", "review")
                and (src == "All sources" or r[5] == src)]

    def _refresh_sources(self):
        srcs = sorted({r[5] for r in self.scan_data
                       if r[4] in ("remove", "review")})
        menu = self.source_menu["menu"]
        menu.delete(0, "end")
        cur = self.source_var.get()
        for s in ["All sources"] + srcs:
            menu.add_command(label=s,
                             command=lambda v=s: self.source_var.set(v))
        if cur not in (["All sources"] + srcs):
            self.source_var.set("All sources")

    def render(self):
        for w in self.inner.winfo_children():
            w.destroy()
        self.row_vars = []
        self._row_icon_labels = {}
        self._row_face_labels = {}
        self._current_icon_rows = []
        mode = self.show_var.get()

        if mode == "sites":
            if not self.sites:
                tk.Label(self.inner,
                         text="No notification sites found."
                              if self.scan_data else
                              "Run a scan to list sites allowed to send "
                              "browser notifications.",
                         font=(DFONT, 12), fg=SHELF_SECONDARY,
                         bg=SHELF_BG).pack(padx=16, pady=24, anchor="w")
            for dstr, host in self.sites:
                f = tk.Frame(self.inner, bg=SHELF_BG)
                f.pack(fill="x", padx=12, pady=5)
                tk.Label(f, text="🌐", font=(DFONT, 14), bg=SHELF_BG).pack(
                    side="left", padx=(0, 8))
                tk.Label(f, text=host, font=(DFONT, 13, "bold"),
                         fg=SHELF_INK, bg=SHELF_BG).pack(side="left")
                tk.Label(f, text="  allowed since %s" % dstr,
                         font=(DFONT, 11), fg=SHELF_SECONDARY,
                         bg=SHELF_BG).pack(side="left")
            self._after_render()
            return

        if mode == "badlist":
            self._render_badlist()
            self._after_render()
            return

        if mode == "all":
            rows = [r for r in self.scan_data if len(r) == 9]
            srcf = self.source_var.get()
            if srcf != "All sources":
                rows = [r for r in rows if r[5] == srcf]
            _ord = {"remove": 0, "review": 1, "clean": 2}
            rows.sort(key=lambda r: _ord.get(r[4], 3))
        else:
            rows = self._threat_rows()
        if not rows:
            tk.Label(self.inner,
                     text="Nothing flagged." if self.scan_data else
                     "Run a scan to check the phone for adware.",
                     font=(DFONT, 12), fg=SHELF_SECONDARY,
                     bg=SHELF_BG).pack(padx=16, pady=24, anchor="w")
            self._after_render()
            return

        icon_pkgs = []
        _nums = getattr(self, "_original_numbers", None) or \
            original_numbers(self.scan_data)
        for _idx, (pkg, label, score, reasons, verdict, src, privacy,
                   ttype, boot) in enumerate(rows, 1):
            var = tk.BooleanVar(value=row_default_checked(pkg, verdict, reasons)
                                and pkg not in self._bg_keep)
            f = tk.Frame(self.inner, bg=SHELF_BG)
            f.pack(fill="x", padx=8, pady=5)
            # AT-2: the ORIGINAL scan number, from the snapshot
            # mapping -- never the position in this view.
            tk.Label(f, text="%d." % _nums.get(pkg, _idx),
                     font=(DMONO, 13, "bold"),
                     fg=SHELF_SECONDARY, bg=SHELF_BG, width=4,
                     anchor="e").pack(side="left", padx=(2, 2))
            cb = tk.Checkbutton(f, variable=var, bg=SHELF_BG,
                                activebackground=SHELF_BG,
                                selectcolor=SHELF_SELECTION)
            cb.pack(side="left", padx=(4, 6))
            # AT-1: the verdict is colored TEXT (REMOVE / KEEP /
            # ASK FIRST) in the 3.2 token -- no bracket badge.
            tk.Label(f, text=VERDICT_WORDS.get(verdict, "KEEP"),
                     font=(DFONT, 12, "bold"),
                     fg=VERDICT_COLORS.get(verdict, VERDICT_KEEP),
                     bg=SHELF_BG).pack(side="left", padx=(0, 6))
            _iholder = tk.Frame(f, bg=SHELF_BG, width=_ICON_BOX,
                                height=_ICON_BOX)
            _iholder.pack(side="left", padx=(0, 6))
            _iholder.pack_propagate(False)
            _ilbl = tk.Label(_iholder, bg=SHELF_BG)
            _ilbl.pack(fill="both", expand=True)
            if pkg in self._icon_imgs:
                _ilbl.configure(image=self._icon_imgs[pkg])
            elif pkg in self._badge_imgs:
                _ilbl.configure(image=self._badge_imgs[pkg])
            else:
                # v10.16 floor: the slot is never empty, even before
                # the icon pass resolves this row -- the generic APP
                # chip stands in (transient; _apply_icon replaces it
                # with the row's real resolution and records generic
                # chips in _badge_imgs when nothing better exists).
                _gimg = self._generic_photo()
                if _gimg is not None:
                    _ilbl.configure(image=_gimg)
            self._row_icon_labels[pkg] = _ilbl
            txt = tk.Frame(f, bg=SHELF_BG)
            txt.pack(side="left", fill="x", expand=True)
            _nlbl = tk.Label(txt, text=label or pkg, font=(DFONT, 15, "bold"),
                     fg=SHELF_INK, bg=SHELF_BG, anchor="w")
            _nlbl.pack(fill="x")
            _plbl = tk.Label(txt, text=pkg, font=(DMONO, 12),
                     fg=SHELF_MUTED, bg=SHELF_BG, anchor="w")
            _plbl.pack(fill="x")
            if reasons:
                self._add_reason_lines(txt, reasons, verdict)
            if (pkg in LEARNED_BAD
                    and any(str(x).startswith(
                                "removed by this shop before")
                            for x in reasons or [])):
                # v11.3 Learned Guard: a row flagged by shop history
                # alone carries its own pardon -- one tap strikes the
                # package from the learned store (persisted at once),
                # no file editing at the counter.
                tk.Button(
                    txt, text="\u2716 UN-LEARN \u2014 stop flagging "
                              "this app",
                    font=(DFONT, 11, "bold"), fg=TEXT_PRIMARY,
                    bg=ACTION_NEUTRAL,
                    activebackground=ACTION_NEUTRAL_HOVER,
                    activeforeground="white", relief="flat", bd=0,
                    padx=10, pady=4, cursor="hand2",
                    command=lambda p=pkg: self._unlearn_row(p)
                ).pack(anchor="w", pady=(4, 0))
            if pkg in self._bg_keep:
                tk.Label(txt, text="KEPT AFTER BACKGROUND CHECK",
                         font=(DFONT, 11, "bold"), fg=VERDICT_KEEP,
                         bg=SHELF_BG, anchor="w").pack(fill="x")
            elif verdict == "review" and pkg in self._bg_results:
                _bres = self._bg_results[pkg]
                _bmap = {"confirmed": ("BACKGROUND CHECK: CONFIRMED BAD",
                                       VERDICT_REMOVE),
                         "not_sure": ("BACKGROUND CHECK: STILL NOT SURE",
                                      VERDICT_ASK),
                         "cleared": ("BACKGROUND CHECK: CLEARED",
                                     VERDICT_KEEP)}
                if _bres.get("outcome") in _bmap:
                    _btxt, _bcol = _bmap[_bres["outcome"]]
                    tk.Label(txt, text=_btxt,
                             font=(DFONT, 11, "bold"), fg=_bcol,
                             bg=SHELF_BG, anchor="w").pack(fill="x")
            if verdict == "review":
                _bbtn = tk.Button(
                    f, text="\U0001F50D BACKGROUND CHECK"
                    + (" \u2713" if pkg in self._bg_results else ""),
                    font=(DFONT, 11, "bold"), fg=TEXT_PRIMARY,
                    bg=ACTION_NEUTRAL,
                    activebackground=ACTION_NEUTRAL_HOVER,
                    activeforeground="white", relief="flat", bd=0,
                    padx=12, pady=6, cursor="hand2",
                    command=lambda p=pkg, l=label or pkg:
                        self.start_background_check(p, l))
                _bbtn.pack(side="right", padx=(6, 4))
                for _w in (txt, _nlbl, _plbl):
                    _w.bind("<Double-Button-1>",
                            lambda e, p=pkg, l=label or pkg:
                                self.start_background_check(p, l))
            self.row_vars.append((var, pkg, label or pkg))
            icon_pkgs.append(pkg)
        self._current_icon_rows = list(icon_pkgs)
        self._kick_icons(icon_pkgs)
        self._after_render()

    # ----------------------------------------------------- boom text --
    def _reason_fonts(self):
        """(regular, bold) tkfont.Font pair for reason lines (cached)."""
        if getattr(self, "_rfonts", None) is None:
            from tkinter import font as _tkfont
            self._rfonts = (
                _tkfont.Font(root=self.root, font=(DFONT, 14)),
                _tkfont.Font(root=self.root, font=(DFONT, 15, "bold")))
        return self._rfonts

    def _add_reason_lines(self, parent, reasons, verdict):
        """Render one row's reason (AT-3 / spec 6.11): the FULL
        reason text -- no 160-char truncation -- in dark ink on the
        white shelf, with ONE bold critical phrase in the verdict
        color (the first
        keyword-derived boom span; segmentation stays render-time
        via boom_segments(), no stored field, AT-19). Words are
        wrapped by hand at 640px as before."""
        if isinstance(reasons, (list, tuple)):
            full = "; ".join(str(x) for x in reasons)
        else:
            full = str(reasons)
        # Shelf boom (v11.4, SHELF-SPEC §7.3): on the white face the
        # reason BODY is dark ink; only the single loud phrase takes
        # the verdict color. (On dark surfaces boom is unchanged --
        # this renderer only serves the shelf rows.)
        base_col = SHELF_BOOM_BODY
        loud_col = SHELF_VERDICT_COLORS.get(verdict, SHELF_INK)
        segs = boom_segments(full, verdict)
        freg, fbold = self._reason_fonts()
        space_w = freg.measure(" ")
        words = []
        _loud_used = False
        for seg, loud in segs:
            if loud:
                if _loud_used:
                    loud = False   # ONE critical phrase (6.11)
                else:
                    _loud_used = True
            for w in seg.split(" "):
                if w:
                    words.append((w, loud))
        if not words:
            return
        lines, cur, cur_w = [], [], 0
        for w, loud in words:
            ww = (fbold if loud else freg).measure(w)
            add = ww if not cur else ww + space_w
            if cur and cur_w + add > 640:
                lines.append(cur)
                cur, cur_w = [(w, loud)], ww
            else:
                cur.append((w, loud))
                cur_w += add
        if cur:
            lines.append(cur)
        for line in lines:
            lf = tk.Frame(parent, bg=SHELF_BG)
            lf.pack(fill="x")
            for i, (w, loud) in enumerate(line):
                tk.Label(lf, text=w if i == len(line) - 1 else w + " ",
                         font=(DFONT, 15, "bold") if loud else (DFONT, 14),
                         fg=loud_col if loud else base_col, bg=SHELF_BG,
                         anchor="w", padx=0, pady=0).pack(side="left")

    # --------------------------------------------------- app pictures ---
    def _apply_icon(self, pkg):
        img = self._load_icon_image(pkg)
        if img is None:
            img = self._load_badge_image(pkg)
            if img is None:
                # v10.16 floor: no face, no maker badge -> the
                # generic APP chip. A row NEVER renders blank.
                img = self._load_generic_image(pkg)
            if img is not None:
                self._icon_fallback.add(pkg)
        else:
            self._icon_fallback.discard(pkg)
        lbl = self._row_icon_labels.get(pkg)
        if img is not None and lbl is not None:
            try:
                lbl.configure(image=img)
            except Exception:
                pass

    def _load_generic_image(self, pkg):
        """PhotoImage for the generic APP chip (v10.16 floor), or
        None. The chip is a LABEL like a maker badge: it lives in
        _badge_imgs, counts on the badge line, and never counts as
        a real picture."""
        if pkg in self._badge_imgs:
            return self._badge_imgs[pkg]
        img = self._photo_from_bytes(_generic_chip_png())
        if img is not None:
            self._badge_imgs[pkg] = img
        return img

    def _generic_photo(self):
        """The shared generic-chip PhotoImage used as render()'s
        transient floor (not recorded in _badge_imgs: the row is
        still owed its real resolution by the icon pass)."""
        if self._generic_photo_img is None:
            self._generic_photo_img = self._photo_from_bytes(
                _generic_chip_png())
        return self._generic_photo_img

    def _load_icon_image(self, pkg):
        """PhotoImage for pkg's REAL picture, in the v10.15 order:
        (1) the icon pulled off the phone (the icon cache -- WebP
        results arrive pre-converted to PNG by the ensure path),
        (2) the known-faces pack, (3) the Face Book store face for a
        blocklisted package. Maker badges are NOT pictures; they
        live in _load_badge_image and never land in _icon_imgs."""
        if pkg in self._icon_imgs:
            return self._icon_imgs[pkg]
        # v11.4: companion PNG first (amended resolution order).
        img = self._photo_from_path(companion_cache_find(pkg))
        if img is None:
            img = self._photo_from_path(_icon_cache_find(pkg))
        if img is None:
            img = self._load_pack_image(pkg)
        if img is None and pkg in KNOWN_BAD:
            img = self._load_face_image(pkg)
        if img is not None:
            self._icon_imgs[pkg] = img
        return img

    def _kick_icons(self, pkgs):
        """Start (or feed) the background icon fetch for these rows.

        v10.16: every kick bumps the pass sequence number; the
        matching icons_done carries (gen, seq) so the settle gate
        can tell "the worker drained the LATEST kick" from a stale
        or fast-path signal."""
        self._icon_token = self._scan_gen
        fresh = [p for p in pkgs if p not in self._icon_imgs
                 and p not in self._badge_imgs]
        if not fresh:
            if pkgs:
                # Everything is already on screen: this kick is
                # drained by definition, but the settle gate still
                # decides when the scan's one Pictures line prints.
                with self._icon_lock:
                    self._pass_seq += 1
                    seq = self._pass_seq
                self.q.put(("icons_done", (self._scan_gen, seq)))
            return
        with self._icon_lock:
            self._pass_seq += 1
            self._icon_wanted.update(fresh)
            if self._icon_worker_on:
                return
            self._icon_worker_on = True
        threading.Thread(target=self._icon_worker, daemon=True).start()

    def _icon_worker(self):
        seq_done = self._pass_seq
        try:
            # v11.4 companion first: one batched fetch for everything
            # this pass owes, BEFORE extraction -- rows the phone
            # faces itself never go through the APK extractor. Any
            # failure is a silent fallback to extraction.
            try:
                with self._icon_lock:
                    _want = list(self._icon_wanted)
                if _want:
                    companion_fetch_for_packages(_want)
            except Exception:
                pass
            launcher = None
            try:
                _raw = adb_cmd("shell", "cmd", "package",
                               "query-activities", "--brief",
                               "-a", "android.intent.action.MAIN",
                               "-c", "android.intent.category.LAUNCHER")
                _s = packages_in(_raw)
                if len(_s) >= 5:
                    launcher = _s
            except Exception:
                launcher = None
            while True:
                with self._icon_lock:
                    if not self._icon_wanted:
                        self._icon_worker_on = False
                        # Read the pass seq under the same lock the
                        # kicks bump it under: this drain covers
                        # every kick up to this exact moment. A kick
                        # landing later gets a higher seq and its own
                        # drain signal.
                        seq_done = self._pass_seq
                        break
                    pkg = self._icon_wanted.pop()
                _icon_ensure_cached(pkg, launcher)
                # Always post (v10.15): the UI thread runs the full
                # resolution -- pack face / store face / maker badge
                # -- even when extraction itself came up empty.
                self.q.put(("icon", pkg))
        except Exception:
            with self._icon_lock:
                self._icon_worker_on = False
                seq_done = self._pass_seq
        # v11.4 teardown: stop op + forward removal -- nothing of
        # the companion session is left running after the pass.
        try:
            companion_stop_session()
            self.q.put(("helper_state",
                        (companion_status_text(), False)))
        except Exception:
            pass
        self.q.put(("icons_done",
                    (getattr(self, "_icon_token", self._scan_gen),
                     seq_done)))

    def _sources_settled(self):
        """True when every async icon source has settled at least
        once: the known-faces pack, the faces/blocklist feed, and
        the extras (dwebp) self-heal -- each loaded, failed, or
        latched by its *_ready queue message."""
        pack = self._src_settled["pack"] \
            or self._appfaces_entries is not None
        faces = self._src_settled["faces"] \
            or self._faces_entries is not None
        return pack and faces and self._src_settled["extras"]

    def _maybe_log_pictures(self, gen):
        """v10.16 settle gate: the scan's Pictures/badge lines print
        EXACTLY ONCE, and only at settle time -- the icon worker has
        drained the latest kick AND every async source has settled
        (or the per-scan deadline passed). Immediately before
        counting, a final resolution sweep re-applies every row on
        screen, so late-settled sources (pack faces, the merged
        blocklist's store faces, conversions the late converter
        unlocks) are reflected: the printed numbers are computed
        from the FINAL rendered state. Sources settling after the
        print may still upgrade rows on screen; the lines stand."""
        try:
            if gen != self._scan_gen or gen == self._icons_logged_gen:
                return
            if self._icons_done_seq < self._pass_seq:
                return              # latest kick not drained yet
            if not self._pass_deadline and not self._sources_settled():
                return              # sources still in flight
            for pkg in list(self._current_icon_rows):
                if pkg in self._row_icon_labels:
                    if pkg not in self._icon_imgs:
                        # A row whose cache holds an unconverted
                        # WebP gets its conversion re-run now that
                        # the converter question is settled -- cheap
                        # and local (the first pass already did the
                        # phone work); without this, a converter that
                        # landed mid-scan would leave the row on its
                        # placeholder chip despite being settled.
                        try:
                            _hit = _icon_cache_find(pkg)
                            if _hit is not None and str(_hit).lower() \
                                    .endswith(".webp"):
                                _icon_ensure_cached(pkg, None)
                                self._badge_imgs.pop(pkg, None)
                        except Exception:
                            pass
                    self._apply_icon(pkg)
            self._log_pictures_line(gen)
        except Exception:
            pass

    def _pictures_deadline(self, gen):
        """Settle deadline (20 s after scan_done): if the sources
        still have not settled, the lines print with whatever has
        landed rather than never printing at all."""
        try:
            if gen == self._scan_gen and gen != self._icons_logged_gen:
                self._pass_deadline = True
                self._maybe_log_pictures(gen)
        except Exception:
            pass

    def _log_pictures_line(self, gen):
        """v10.14: exactly ONE Pictures line per scan, counted from
        what is actually on screen at the moment the icon pass
        completes -- rows in the current results whose icon slot
        holds an extracted icon right now. The v10.12/13 line counted
        extraction ATTEMPTS in the latest worker batch, so it could
        read '0 of 15' while rows already showed pictures, and a
        fresh line stacked on top of the stale one every re-scan."""
        try:
            if gen != self._scan_gen or gen == self._icons_logged_gen:
                return
            rows = list(self._current_icon_rows)
            if not rows:
                return
            shown = sum(1 for pkg in rows
                        if pkg in self._icon_imgs
                        and pkg in self._row_icon_labels)
            badged = sum(1 for pkg in rows
                         if pkg in self._badge_imgs
                         and pkg not in self._icon_imgs
                         and pkg in self._row_icon_labels)
            self._icons_logged_gen = gen
            self.log("Pictures: %d of %d apps show their real picture"
                     % (shown, len(rows)))
            if badged:
                self.log("Maker badges shown for %d apps with no "
                         "picture of their own" % badged)
            _noown = companion_no_own_icon_count(rows)
            if _noown:
                self.log("%d apps have no icon of their own "
                         "(phone helper)" % _noown)
        except Exception:
            pass

    # ------------------------------------------------- v10.15 pics --
    def _photo_from_path(self, path, box=_ICON_BOX):
        """PhotoImage for an image file (PIL first, mirroring the
        banner; tk.PhotoImage PNG-only fallback), or None."""
        if not path:
            return None
        img = None
        try:
            from PIL import Image as _PImg5, ImageTk as _PITk5
            _im = _PImg5.open(str(path)).convert("RGBA")
            _im.thumbnail((box, box), _PImg5.LANCZOS)
            img = _PITk5.PhotoImage(_im)
        except Exception:
            img = None
        if img is None and str(path).lower().endswith(".png"):
            try:
                _t = tk.PhotoImage(file=str(path))
                _m = max(_t.width(), _t.height())
                _f = max(1, int(_m / float(box) + 0.5))
                if _f > 1:
                    _t = _t.subsample(_f, _f)
                img = _t
            except Exception:
                img = None
        return img

    def _photo_from_bytes(self, data, box=_ICON_BOX):
        """PhotoImage for raw image bytes (maker chips), or None."""
        if not data:
            return None
        img = None
        try:
            import io as _iob
            from PIL import Image as _PImg6, ImageTk as _PITk6
            _im = _PImg6.open(_iob.BytesIO(data)).convert("RGBA")
            _im.thumbnail((box, box), _PImg6.LANCZOS)
            img = _PITk6.PhotoImage(_im)
        except Exception:
            img = None
        if img is None:
            try:
                import base64 as _b64p
                _t = tk.PhotoImage(data=_b64p.b64encode(data).decode())
                _m = max(_t.width(), _t.height())
                _f = max(1, int(_m / float(box) + 0.5))
                if _f > 1:
                    _t = _t.subsample(_f, _f)
                img = _t
            except Exception:
                img = None
        return img

    def _pack_file(self, pkg):
        """Known-faces pack image file for pkg, or None."""
        e = (self._appfaces_entries or {}).get(pkg) or {}
        if e.get("status") != "found":
            return None
        rel = e.get("icon")
        if not rel:
            return None
        p = _appfaces_cache_dir() / rel
        return p if p.is_file() else None

    def _store_face_file(self, pkg):
        """Face Book store-face file for pkg, or None."""
        e = (self._faces_entries or {}).get(pkg) or {}
        if e.get("status") != "found":
            return None
        rel = e.get("icon")
        if not rel:
            return None
        p = _faces_cache_dir() / rel
        return p if p.is_file() else None

    def _load_pack_image(self, pkg):
        """PhotoImage for pkg's known-faces pack face, or None."""
        return self._photo_from_path(self._pack_file(pkg))

    def _load_badge_image(self, pkg):
        """PhotoImage for pkg's maker chip, or None when the maker
        is not one we badge. A chip is a LABEL, not a picture: it
        lives in _badge_imgs and never counts as a real picture."""
        if pkg in self._badge_imgs:
            return self._badge_imgs[pkg]
        key = _maker_for(pkg)
        if not key:
            return None
        img = self._photo_from_bytes(_maker_chip_png(key))
        if img is not None:
            self._badge_imgs[pkg] = img
        return img

    def _appfaces_bootstrap(self):
        """Background: fetch/cache the known-faces pack and post
        appfaces_ready (mirrors _faces_bootstrap)."""
        if self._appfaces_loading or self._appfaces_entries is not None:
            return
        self._appfaces_loading = True
        try:
            entries, ok = _load_appfaces_feed()
        except Exception:
            entries, ok = {}, False
        self._appfaces_loading = False
        self.q.put(("appfaces_ready", (entries, ok)))

    def _extras_bootstrap(self):
        """Background: self-heal this version's updater extras (the
        dwebp converter) beside the program. Silent by design --
        extras are optional and every failure just falls back.
        v10.16: always posts extras_ready so the Pictures settle
        gate knows the converter question is answered."""
        try:
            ensure_own_extras()
        except Exception:
            pass
        self.q.put(("extras_ready", None))

    # ----------------------------------------------------- face book --
    def _faces_bootstrap(self):
        """Background: fetch/cache the face-book data (blocklist
        order, faces.json, faces.zip once) and post faces_ready."""
        if self._faces_loading or self._faces_entries is not None:
            return
        self._faces_loading = True
        try:
            order, entries, ok = _load_faces_feed()
        except Exception:
            order, entries, ok = [], {}, False
        self._faces_loading = False
        self.q.put(("faces_ready", (order, entries, ok)))

    # ------------------------------------------------- silent feed --
    def _kick_silent_feed(self):
        """Fire one silent threat-feed refresh in the background
        (startup + every scan start). Non-blocking: the UI never
        waits on it, and a failed or shrinking fetch changes
        nothing and shows nothing."""
        threading.Thread(target=self._silent_feed_bootstrap,
                         daemon=True).start()

    def _silent_feed_bootstrap(self):
        """Background: one silent refresh; only a feed that was
        accepted AND grew the list earns a line in the log."""
        line = _silent_feed_once()
        if line:
            self.q.put(("log", line))

    def _render_badlist(self):
        """The Face Book: every blocklist package in blocklist
        order, with its store face -- or the owner's no-face badge
        (circle-with-a-cross + REMOVED FROM PLAY STORE) for the
        packages the store delisted."""
        if self._faces_entries is None:
            tk.Label(self.inner, text="Loading the bad list...",
                     font=(DFONT, 12), fg=SHELF_SECONDARY,
                     bg=SHELF_BG).pack(padx=16, pady=24, anchor="w")
            if not self._faces_loading:
                threading.Thread(target=self._faces_bootstrap,
                                 daemon=True).start()
            return
        entries = self._faces_entries
        order = list(self._faces_order)
        for pkg in entries:
            if pkg not in order:
                order.append(pkg)
        if not order:
            tk.Label(self.inner, text="The bad list is empty.",
                     font=(DFONT, 12), fg=SHELF_SECONDARY,
                     bg=SHELF_BG).pack(padx=16, pady=24, anchor="w")
            return
        face_pkgs = []
        for _idx, pkg in enumerate(order, 1):
            e = entries.get(pkg) or {}
            name = e.get("name") or pkg
            status = e.get("status")
            delisted = self._faces_ok and status == "not_found"
            f = tk.Frame(self.inner, bg=SHELF_BG)
            f.pack(fill="x", padx=8, pady=5)
            tk.Label(f, text="%d." % _idx, font=(DMONO, 13, "bold"),
                     fg=SHELF_SECONDARY, bg=SHELF_BG, width=4,
                     anchor="e").pack(side="left", padx=(2, 2))
            holder = tk.Frame(f, bg=SHELF_BG, width=_ICON_BOX,
                              height=_ICON_BOX)
            holder.pack(side="left", padx=(0, 6))
            holder.pack_propagate(False)
            if delisted:
                cv = tk.Canvas(holder, width=_ICON_BOX,
                               height=_ICON_BOX, bg=SHELF_BG,
                               highlightthickness=0, bd=0)
                cv.pack(fill="both", expand=True)
                m = 7
                cv.create_oval(m, m, _ICON_BOX - m, _ICON_BOX - m,
                               outline=VERDICT_ASK, width=3)
                d = 12
                cv.create_line(d, d, _ICON_BOX - d, _ICON_BOX - d,
                               fill=VERDICT_ASK, width=3)
                cv.create_line(_ICON_BOX - d, d, d, _ICON_BOX - d,
                               fill=VERDICT_ASK, width=3)
            else:
                lbl = tk.Label(holder, bg=SHELF_BG)
                lbl.pack(fill="both", expand=True)
                if pkg in self._face_imgs:
                    lbl.configure(image=self._face_imgs[pkg])
                self._row_face_labels[pkg] = lbl
                # v10.15: every non-delisted row gets the full
                # resolution (store face, device icon, pack, chip).
                face_pkgs.append(pkg)
            txt = tk.Frame(f, bg=SHELF_BG)
            txt.pack(side="left", fill="x", expand=True)
            tk.Label(txt, text=name, font=(DFONT, 15, "bold"),
                     fg=SHELF_INK, bg=SHELF_BG, anchor="w").pack(fill="x")
            tk.Label(txt, text=pkg, font=(DMONO, 12),
                     fg=SHELF_MUTED, bg=SHELF_BG, anchor="w").pack(fill="x")
            if delisted:
                tk.Label(txt, text=FACES_BADGE_TEXT,
                         font=(DFONT, 10, "bold"), fg=VERDICT_ASK,
                         bg=SHELF_BG, anchor="w").pack(fill="x")
        self._kick_face_imgs(face_pkgs)

    def _load_face_image(self, pkg):
        """PhotoImage for pkg's store face from faces_cache (PIL
        first, mirroring the app-icon loader), or None."""
        if pkg in self._face_imgs:
            return self._face_imgs[pkg]
        img = self._photo_from_path(self._store_face_file(pkg))
        if img is not None:
            self._face_imgs[pkg] = img
        return img

    def _apply_face(self, pkg):
        img = self._load_face_image(pkg)
        if img is None:
            img = self._load_icon_image(pkg)
        if img is None:
            img = self._load_badge_image(pkg)
        if img is None:
            # v10.16 floor: the generic APP chip, below the maker
            # badge (delisted rows never reach here -- they draw
            # the REMOVED FROM PLAY STORE badge in render()).
            img = self._load_generic_image(pkg)
        lbl = self._row_face_labels.get(pkg)
        if img is not None and lbl is not None:
            try:
                lbl.configure(image=img)
            except Exception:
                pass

    def _kick_face_imgs(self, pkgs):
        """Post face-image applications through the UI queue, a few
        at a time, so building 150+ rows never jams the window."""
        if not pkgs:
            return

        def _work():
            for pkg in pkgs:
                self.q.put(("face", pkg))
                time.sleep(0.02)
        threading.Thread(target=_work, daemon=True).start()

    def _load_guide_image(self, pkg, box=32):
        """PhotoImage (~32px) for the Guided Clean guide, resolved
        like a result row (v10.15): the icon cache, the known-faces
        pack, the store face for a blocklisted package, a maker
        chip. The guide inserts NOTHING when no source has anything
        (text stays exactly as it was)."""
        if pkg in self._guide_imgs:
            return self._guide_imgs[pkg]
        img = self._photo_from_path(_resolved_icon_file(pkg), box)
        if img is None:
            img = self._photo_from_path(self._pack_file(pkg), box)
        if img is None and pkg in KNOWN_BAD:
            img = self._photo_from_path(self._store_face_file(pkg), box)
        if img is None:
            key = _maker_for(pkg)
            if key:
                img = self._photo_from_bytes(_maker_chip_png(key), box)
        if img is None:
            # v10.16 floor: the generic APP chip, so a guide row is
            # never picture-less. NOT cached in _guide_imgs: a real
            # source settling later must still win the next lookup.
            return self._photo_from_bytes(_generic_chip_png(), box)
        self._guide_imgs[pkg] = img
        return img

    # ------------------------------------------------------- queue ---
    def process_queue(self):
        try:
            while True:
                try:
                    kind, payload = self.q.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._handle(kind, payload)
                except Exception as e:
                    self.log("display hiccup: %s" % e)
        except Exception:
            pass
        self.root.after(120, self.process_queue)

    def _handle(self, kind, payload):
        if kind == "face":
            self._apply_face(payload)
        elif kind == "faces_ready":
            order, entries, ok = payload
            self._faces_order = order
            self._faces_entries = entries
            self._faces_ok = ok
            self._src_settled["faces"] = True
            if not ok and not self._faces_fail_logged:
                self._faces_fail_logged = True
                self.log("Bad list: face pictures unavailable "
                         "(offline?) - showing names only.")
            if self.show_var.get() == "badlist":
                self.render()
            self._maybe_log_pictures(self._scan_gen)
        elif kind == "appfaces_ready":
            entries, ok = payload
            self._appfaces_entries = entries
            self._appfaces_ok = ok
            self._src_settled["pack"] = True
            for pkg in list(self._icon_fallback):
                if pkg in self._row_icon_labels \
                        and pkg not in self._icon_imgs:
                    self._badge_imgs.pop(pkg, None)
                    self._apply_icon(pkg)
            if self.show_var.get() == "badlist":
                self.render()
            self._maybe_log_pictures(self._scan_gen)
        elif kind == "icon":
            self._apply_icon(payload)
        elif kind == "extras_ready":
            self._src_settled["extras"] = True
            self._maybe_log_pictures(self._scan_gen)
        elif kind == "icons_done":
            gen, seq = payload
            if gen == self._scan_gen and seq > self._icons_done_seq:
                self._icons_done_seq = seq
            self._maybe_log_pictures(gen)
        elif kind == "log":
            self.log(payload)
        elif kind == "helper_state":
            text, can_offer = payload
            self._companion_state = text
            self._companion_offer = bool(can_offer)
            try:
                self.helper_status.configure(text=text)
                if can_offer:
                    self.helper_btn.configure(state="normal")
                    if not self.helper_btn.winfo_ismapped():
                        self.helper_btn.pack(side="left",
                                             padx=(10, 0), pady=10)
                else:
                    self.helper_btn.configure(state="disabled")
                    if self.helper_btn.winfo_ismapped():
                        self.helper_btn.pack_forget()
            except Exception:
                pass

        elif kind == "phone_ok":
            self.dot.configure(fg=DGREEN)
            self.status.configure(
                text="Phone connected -- ready to scan", fg=DTEXT)
        elif kind == "phone_model":
            self.status.configure(
                text="Phone connected -- %s" % payload, fg=DTEXT)
        elif kind == "phone_bad":
            self.dot.configure(fg=DGRAY)
            if payload == "ADB_NOT_FOUND":
                self.status.configure(
                    text="ADB not found -- install platform-tools", fg=DGRAY)
            else:
                self.status.configure(
                    text="No phone -- connect via USB", fg=DGRAY)
        elif kind == "progress":
            done, total, pkg = payload
            pct = int(done * 100 / max(total, 1))
            short = pkg if len(pkg) < 40 else pkg[:39] + "…"
            self.prog.configure(text="%d%%  %d/%d  %s"
                                     % (pct, done, total, short))
            if done == 1 or done == total or done % 25 == 0:
                self.log("… %d/%d  %s" % (done, total, short))
        elif kind == "scan_done":
            if len(payload) == 3:
                self.scan_data, self.sites, _stored_map = payload
            else:
                self.scan_data, self.sites = payload
                _stored_map = {}
            # _bg_results now reflects the DURABLE store (plus any
            # checks run later this session), not just this session.
            self._bg_results = dict(_stored_map or {})
            # AT-2/AT-19: original numbers are assigned ONCE, here
            # at the presentation layer when the scan commits --
            # scan_core's 9-tuple is untouched.
            self._original_numbers = original_numbers(self.scan_data)
            self._scan_time_str = datetime.now().strftime(
                "%B %d, %Y - %I:%M %p")
            self._scan_gen += 1
            # v10.16: reset the settle gate for the new scan and arm
            # its print deadline (see _maybe_log_pictures).
            self._pass_seq = 0
            self._icons_done_seq = 0
            self._pass_deadline = False
            self.root.after(
                20000,
                lambda g=self._scan_gen: self._pictures_deadline(g))
            self._scan_completed = True
            self.set_busy(False)
            self.prog.configure(text="")
            n_rm = sum(1 for r in self.scan_data if r[4] == "remove")
            n_rv = sum(1 for r in self.scan_data if r[4] == "review")
            self.source_var.set("All sources")
            if n_rm + n_rv:
                self.show_var.set("flagged")
            self._refresh_sources()
            self.render()
            if self.flagged_radio is not None:
                self.flagged_radio.configure(
                    text="⚠ Flagged only (%d)" % (n_rm + n_rv))
            self.log("Scanned %d apps: %d marked for removal, "
                     "%d to ask first, %d notification sites."
                     % (len(self.scan_data), n_rm, n_rv, len(self.sites)))
            self._update_undo_btn()
            if self._guided_pending:
                self._guided_pending = False
                ask = self._guided_ask
                self._guided_ask = []
                n_flag = n_rm + n_rv
                if n_flag == 0 and not ask:
                    msg = ("GUIDED CLEAN finished.\n\n"
                           "This phone is CLEAN.")
                else:
                    msg = ("GUIDED CLEAN finished.\n\nFlagged now: %d."
                           % n_flag)
                    if ask:
                        msg += ("\n\nLeft for a human decision:\n"
                                + "\n".join(ask[:15]))
                        if len(ask) > 15:
                            msg += "\n+ %d more" % (len(ask) - 15)
                self.log("Guided Clean finished. Flagged now: %d."
                         % n_flag)
                messagebox.showinfo("AdTrapper", msg)
        elif kind == "update_badge":
            self.update_info = payload
            try:
                self.update_btn.configure(
                    text="\u2b06 UPDATE: v%s" % payload["version"],
                    bg="#8a5a00")
            except Exception:
                pass
            self.log("Update available: AdTrapper v%s. Click CHECK "
                     "FOR UPDATES to install it." % payload["version"])
        elif kind == "update_offer":
            self._offer_update(payload)
        elif kind == "update_install":
            info, dl_path = payload
            self._install_update(info, dl_path)
        elif kind == "scan_error":
            threading.Thread(target=companion_stop_session,
                             daemon=True).start()
            self.set_busy(False)
            self._guided_pending = False
            self._guided_ask = []
            self.prog.configure(text="")
            self.dot.configure(fg=DGRAY)
            if payload == "ADB_NOT_FOUND":
                self.status.configure(
                    text="ADB not found -- install platform-tools", fg=DGRAY)
                self.log("ADB not found. Download platform-tools and "
                         "extract it into your Downloads folder.")
            elif payload == "MULTI_PHONE":
                self.status.configure(text="Multiple phones -- unplug all "
                                           "but one", fg=DGRAY)
            elif payload == "SCAN_CRASHED":
                self.log("Scan interrupted -- reconnect the phone and try "
                         "again.")
            else:
                self.status.configure(text="No phone -- connect via USB",
                                      fg=DGRAY)
                self.log("No phone found. Plug it in via USB, enable USB "
                         "debugging, tap Allow, then scan again. "
                         "Click USB GUIDE for the step-by-step.")
        elif kind == "remove_done":
            removed, failed = payload
            self._cleanup_time_str = datetime.now().strftime(
                "%B %d, %Y - %I:%M %p")
            self.set_busy(False)
            pdf_path = self._make_customer_report(removed, failed)
            if pdf_path:
                self.last_report_path = pdf_path
                self.print_btn.configure(state="normal")
                if self.autoprint_var.get():
                    self._print_report(pdf_path)
            if failed:
                msg = ("Removal finished, but these could NOT be removed:\n\n"
                       + "\n".join(failed)
                       + "\n\nThey are probably device admins -- turn them "
                         "off in Settings > Security and privacy > "
                         "Device admin apps first.")
                if pdf_path:
                    msg += "\n\nCustomer report saved:\n%s" % pdf_path
                messagebox.showwarning("AdTrapper", msg)
            else:
                msg = ("Removal finished.\n\nReboot the phone and check the "
                       "popups are gone.\n")
                if pdf_path:
                    msg += "\nCustomer report saved:\n%s" % pdf_path
                messagebox.showinfo("AdTrapper", msg)
            self.log("Done. Reboot the phone and check the popups are gone.")
            self.start_scan()
        elif kind == "bgcheck_done":
            self.set_busy(False)
            res = payload
            self._bg_results[res["pkg"]] = res
            try:
                save_bg_record(res, res.get("version_code"))
            except Exception:
                pass
            try:
                queue_conviction_report(res)
            except Exception:
                pass
            self.status.configure(
                text="Background check finished", fg=DTEXT)
            self.log("Background check: %s -> %s (%d ad networks, "
                     "%d points)."
                     % (res.get("label") or res["pkg"],
                        res.get("outcome", "not_sure"),
                        res.get("network_count", 0),
                        res.get("points", 0)))
            self.render()
            self._bg_dialog(res)
        elif kind == "undo_done":
            self.set_busy(False)
            messagebox.showinfo("AdTrapper", "Restore complete.")
            self._update_undo_btn()
            self.start_scan()

    # ------------------------------------------- background check ---
    def start_background_check(self, pkg, label, force=False):
        """v11.1: run (or re-show) the background check for one
        REVIEW row. Runs on a worker thread over the same ADB cable;
        the verdict dialog opens when the result lands. force=True
        (the dialog's RE-CHECK button) skips the stored-result
        early-return and runs a fresh check."""
        if self.busy:
            self.log("Background check: busy -- wait for the current "
                     "job to finish first.")
            return
        if pkg in self._bg_results and not force:
            self._bg_dialog(self._bg_results[pkg])
            return
        self.set_busy(True)
        self.status.configure(
            text="Background check: digging into %s ..." % (label
                                                             or pkg),
            fg=DTEXT)
        self.log("Background check on %s (%s) ..." % (label or pkg,
                                                      pkg))
        threading.Thread(target=self._bg_worker, args=(pkg, label),
                         daemon=True).start()

    def _bg_worker(self, pkg, label):
        try:
            res = run_background_check(pkg, label)
        except Exception as e:
            res = {"pkg": pkg, "label": label or pkg,
                   "outcome": "not_sure", "points": 0, "networks": [],
                   "network_count": 0, "census_done": False,
                   "census_complete": False, "files_read": 0,
                   "files_total": 0,
                   "evidence": [("THE CHECK ITSELF CRASHED: %s" % e,
                                 True)],
                   "vault": is_photo_vault(pkg, label),
                   "signals": {}, "error": str(e),
                   "ts": datetime.now().isoformat(timespec="seconds")}
        self.q.put(("bgcheck_done", res))

    def _bg_dialog(self, res):
        """The verdict window: banner + the evidence in plain words
        (boom rule -- loud bold colored lines, no boxes or bands),
        then the tech's own decision: Remove / Keep / Close. The
        check itself never removes anything."""
        pkg = res["pkg"]
        label = res.get("label") or pkg
        outcome = res.get("outcome", "not_sure")
        win = tk.Toplevel(self.root)
        win.title("AdTrapper -- Background Check")
        win.configure(bg=SHELF_BG)
        try:
            win.minsize(720, 420)
        except Exception:
            pass
        tk.Label(win, text="BACKGROUND CHECK",
                 font=(DFONT, 14, "bold"), fg=SHELF_INK,
                 bg=SHELF_BG).pack(anchor="w", padx=16, pady=(14, 2))
        tk.Label(win, text=label, font=(DFONT, 15, "bold"),
                 fg=SHELF_INK, bg=SHELF_BG,
                 anchor="w").pack(fill="x", padx=16)
        tk.Label(win, text=pkg, font=(DMONO, 11), fg=SHELF_MUTED,
                 bg=SHELF_BG, anchor="w").pack(fill="x", padx=16,
                                          pady=(0, 8))
        _checked = res.get("checked_at") or res.get("ts")
        if _checked:
            _when = str(_checked).replace("T", " ")
            tk.Label(win,
                     text=("Saved result -- checked %s" % _when)
                     if res.get("stored")
                     else ("Checked: %s" % _when),
                     font=(DFONT, 10), fg=SHELF_MUTED, bg=SHELF_BG,
                     anchor="w").pack(fill="x", padx=16, pady=(0, 4))
        banner = {"confirmed": ("CONFIRMED BAD", VERDICT_REMOVE,
                                "remove"),
                  "not_sure": ("STILL NOT SURE", VERDICT_ASK,
                               "review"),
                  "cleared": ("CLEARED BY CODE CENSUS", VERDICT_KEEP,
                              "clean")}[outcome]
        tk.Label(win, text=banner[0], font=(DFONT, 20, "bold"),
                 fg=banner[1], bg=SHELF_BG,
                 anchor="w").pack(fill="x", padx=16, pady=(2, 2))
        tk.Label(win,
                 text="Evidence score: %d points -- %d ad networks "
                      "found inside the code%s"
                      % (res.get("points", 0),
                         res.get("network_count", 0),
                         "" if res.get("census_done")
                         else " (code census did not run)"),
                 font=(DFONT, 11), fg=SHELF_SECONDARY, bg=SHELF_BG,
                 anchor="w").pack(fill="x", padx=16, pady=(0, 8))
        # Detail view is a shelf surface (v11.4): evidence body in
        # dark ink / secondary, loud lines in the verdict color.
        loud_col = SHELF_VERDICT_COLORS.get(banner[2], SHELF_INK)
        body = tk.Frame(win, bg=SHELF_BG)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        for line, loud in res.get("evidence", []):
            tk.Label(body, text=("▸ " if loud else "– ") + line,
                     font=(DFONT, 13, "bold") if loud else (DFONT, 12),
                     fg=loud_col if loud else SHELF_SECONDARY,
                     bg=SHELF_BG, anchor="w", justify="left",
                     wraplength=680).pack(fill="x", pady=1)
        if not res.get("census_done") and outcome != "cleared":
            tk.Label(body,
                     text="No code proof either way -- NOT the same "
                          "as clean.",
                     font=(DFONT, 12, "bold"), fg=VERDICT_ASK,
                     bg=SHELF_BG, anchor="w", justify="left",
                     wraplength=680).pack(fill="x", pady=(6, 1))
        if res.get("vault"):
            tk.Label(win,
                     text="⚠ PHOTO VAULT: the customer's hidden "
                          "photos may live inside this app. NEVER "
                          "remove a vault without asking the customer "
                          "first -- the Remove button is OFF for "
                          "this app.",
                     font=(DFONT, 12, "bold"), fg=VERDICT_REMOVE,
                     bg=SHELF_BG, anchor="w", justify="left",
                     wraplength=680).pack(fill="x", padx=16,
                                          pady=(4, 4))
        btns = tk.Frame(win, bg=SHELF_BG)
        btns.pack(fill="x", padx=16, pady=(6, 14))

        def _remove():
            if not messagebox.askyesno(
                    "AdTrapper",
                    "Remove %s?\n\nIt is backed up first -- UNDO "
                    "restores it." % label, parent=win):
                return
            win.destroy()
            self.set_busy(True)
            threading.Thread(target=self._do_remove,
                             args=([(pkg, label)],),
                             daemon=True).start()

        def _keep():
            self._bg_keep.add(pkg)
            self.log("Background check: %s kept by the tech." % label)
            win.destroy()
            self.render()

        rm = tk.Button(btns, text="REMOVE THIS APP",
                       font=(DFONT, 11, "bold"), fg="white",
                       bg=ACTION_REMOVE,
                       activebackground=ACTION_REMOVE_HOVER,
                       activeforeground="white", relief="flat", bd=0,
                       padx=20, pady=8, cursor="hand2", command=_remove)
        if res.get("vault"):
            rm.configure(state="disabled", bg=DISABLED_BG,
                         fg=DISABLED_TEXT)
        rm.pack(side="right")
        tk.Button(btns, text="KEEP IT", font=(DFONT, 11, "bold"),
                  fg="white", bg=ACTION_CLEAN,
                  activebackground=ACTION_CLEAN_HOVER,
                  activeforeground="white", relief="flat", bd=0,
                  padx=20, pady=8, cursor="hand2",
                  command=_keep).pack(side="right", padx=(0, 10))
        tk.Button(btns, text="CLOSE", font=(DFONT, 11, "bold"),
                  fg=DTEXT, bg=DBAR, activebackground=DBAR,
                  activeforeground="white", relief="flat", bd=0,
                  padx=20, pady=8, cursor="hand2",
                  command=win.destroy).pack(side="right",
                                             padx=(0, 10))

        def _recheck():
            win.destroy()
            self.start_background_check(pkg, label, force=True)

        tk.Button(btns, text="RE-CHECK", font=(DFONT, 11, "bold"),
                  fg=DTEXT, bg=DBAR, activebackground=DBAR,
                  activeforeground="white", relief="flat", bd=0,
                  padx=20, pady=8, cursor="hand2",
                  command=_recheck).pack(side="right", padx=(0, 10))
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass


    # ------------------------------------------------------- remove ---
    def _checked(self):
        return [(pkg, label) for var, pkg, label in self.row_vars
                if var.get()]

    # ------------------------------------------------- guided clean ---
    def _guided_dialog(self, sections, ask):
        """The Guided Clean color guide (issue #49).

        A real window, not a messagebox: every app line is WRITTEN in
        its pile color -- RED = take it off, GREEN = it stays, YELLOW
        = not sure, ask first -- with its scan number in front, on the
        guide's original background (no color blocks: the owner found
        solid bands wash the words out). Staff and customers follow
        the guide by color alone. Returns True only on explicit YES."""
        answer = {"ok": False}
        win = tk.Toplevel(self.root)
        win.title("AdTrapper -- Guided Clean")
        win.configure(bg=SHELF_BG)
        try:
            win.minsize(760, 480)
        except Exception:
            pass
        tk.Label(win, text="GUIDED CLEAN", font=(DFONT, 14, "bold"),
                 fg=SHELF_INK, bg=SHELF_BG).pack(anchor="w", padx=16,
                                          pady=(14, 2))
        tk.Label(win, text="Follow the colors. Red comes off. Green "
                           "stays. Yellow -- leave it and ask first.",
                 font=(DFONT, 10), fg=SHELF_MUTED, bg=SHELF_BG).pack(
                     anchor="w", padx=16, pady=(0, 8))
        legend = tk.Frame(win, bg=SHELF_BG)
        legend.pack(fill="x", padx=16, pady=(0, 10))
        for key, word in (("remove", "RED = REMOVE IT"),
                          ("keep", "GREEN = IT STAYS"),
                          ("ask", "YELLOW = NOT SURE -- ASK FIRST")):
            tk.Label(legend, text="  %s  " % word,
                     font=(DFONT, 11, "bold"),
                     fg=GUIDE_PILE_STYLE[key],
                     bg=SHELF_BG).pack(side="left", padx=(0, 8))
        body = tk.Frame(win, bg=SHELF_BG)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        txt = tk.Text(body, font=(DFONT, 11), bg=SHELF_BG, fg=SHELF_INK,
                      relief="flat", bd=0, wrap="none", height=22,
                      width=86, highlightthickness=0)
        ysb = tk.Scrollbar(body, orient="vertical", command=txt.yview)
        xsb = tk.Scrollbar(body, orient="horizontal",
                           command=txt.xview)
        txt.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        txt.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        for key, color in GUIDE_PILE_STYLE.items():
            txt.tag_configure(key, foreground=color,
                              font=(DFONT, 12, "bold"))
            txt.tag_configure("hdr_" + key, foreground=color,
                              font=(DFONT, 13, "bold"))
        lineno = 1
        for key, header, lines in sections:
            txt.insert("end", header + "\n")
            txt.tag_add("hdr_" + key, "%d.0" % lineno,
                        "%d.0" % (lineno + 1))
            lineno += 1
            if not lines:
                txt.insert("end", "(none)\n")
                lineno += 1
            for num, name, _row in lines:
                start = "%d.0" % lineno
                txt.insert("end", "%d. %s\n" % (num, name))
                txt.tag_add(key, start, "%d.0" % (lineno + 1))
                _gimg = self._load_guide_image(_row[0])
                if _gimg is not None:
                    try:
                        txt.image_create(start, image=_gimg)
                    except Exception:
                        pass
                lineno += 1
            txt.insert("end", "\n")
            lineno += 1
        txt.configure(state="disabled")
        try:
            _probs = list(dict.fromkeys(
                face_audit_labels(win) + face_audit_text(txt)))
            if _probs:
                _face_audit_log(
                    "FACE SELF-CHECK FAILED (guide): %s"
                    % "; ".join(_probs[:6]))
                win.title("AdTrapper -- Guided Clean "
                          "(FACE SELF-CHECK FAILED)")
        except Exception:
            pass
        btns = tk.Frame(win, bg=SHELF_BG)
        btns.pack(fill="x", padx=16, pady=(4, 14))
        if ask:
            tk.Label(btns, text="Remove the junk (the red ones) now?",
                     font=(DFONT, 11, "bold"), fg=SHELF_INK,
                     bg=SHELF_BG).pack(side="left")

            def _yes():
                answer["ok"] = True
                win.destroy()

            tk.Button(btns, text="YES, REMOVE",
                      font=(DFONT, 11, "bold"), fg="white", bg=DRED,
                      activebackground=ACTION_REMOVE_HOVER,
                      activeforeground="white", relief="flat", bd=0,
                      padx=22, pady=8, cursor="hand2",
                      command=_yes).pack(side="right")
            tk.Button(btns, text="NO", font=(DFONT, 11, "bold"),
                      fg=DTEXT, bg=DBAR, activebackground=DBAR,
                      activeforeground="white", relief="flat", bd=0,
                      padx=22, pady=8, cursor="hand2",
                      command=win.destroy).pack(side="right",
                                                padx=(0, 10))
        else:
            tk.Label(btns, text="Nothing in the junk pile -- nothing "
                                "to remove.",
                     font=(DFONT, 11, "bold"), fg=SHELF_INK,
                     bg=SHELF_BG).pack(side="left")
            tk.Button(btns, text="CLOSE", font=(DFONT, 11, "bold"),
                      fg="white", bg=DCYAN,
                      activebackground=ACTION_BLUE_HOVER,
                      activeforeground="white", relief="flat", bd=0,
                      padx=22, pady=8, cursor="hand2",
                      command=win.destroy).pack(side="right")
        try:
            win.transient(self.root)
            win.grab_set()
        except Exception:
            pass
        win.wait_window()
        return answer["ok"]

    def guided_clean(self):
        """Beginner mode: sort the flagged list into junk / yours / ask
        and show the COLOR guide (issue #49): red lines are removed,
        green lines are never touched, yellow lines stay on the phone
        for a human. Numbers in the guide are the main-list scan
        numbers (issue #46). Removes ONLY the junk pile, and only
        after an explicit YES. The automatic re-scan after removal
        reports the final verdict."""
        if self.busy:
            return
        if not self.scan_data:
            self.log("Guided Clean: no scan yet -- scanning first. "
                     "Press GUIDED CLEAN again when the list appears.")
            self.start_scan()
            return
        sections = guided_sections(self.scan_data)
        rows = {k: [r for _n, _name, r in lines]
                for k, _h, lines in sections}
        if not rows["remove"]:
            self._guided_dialog(sections, ask=False)
            return
        if not self._guided_dialog(sections, ask=True):
            return
        targets = [(r[0], r[1] or r[0]) for r in rows["remove"]]
        self._guided_pending = True
        self._guided_ask = [(r[1] or r[0]) for r in rows["ask"]]
        self.set_busy(True)
        threading.Thread(target=self._do_remove, args=(targets,),
                         daemon=True).start()

    # ---------------------------------------------------- un-learn --
    def _unlearn_row(self, pkg):
        """UN-LEARN control on learned rows: strike pkg from the
        learned store so shop history stops flagging it. The strike
        persists to disk immediately (unlearn_package), and the
        displayed row is set to exactly what a rescan would now show:
        the learned hit was the row's ONLY evidence -- scan_core
        returns learned rows early on that single reason -- so with
        the memory gone the app stands clean."""
        if not unlearn_package(pkg):
            return
        self.log("Un-learned %s -- shop history will no longer flag it."
                 % pkg)
        for i, row in enumerate(self.scan_data):
            if len(row) == 9 and row[0] == pkg:
                self.scan_data[i] = (row[0], row[1], 0, [], "clean",
                                     row[5], row[6], "Clean", row[8])
                break
        self.render()

    def remove_all(self):
        if self.busy:
            return
        targets = self._checked()
        if not targets:
            messagebox.showinfo("AdTrapper", "Nothing checkmarked.")
            return
        names = "\n".join(l for _, l in targets)
        if not messagebox.askyesno(
                "AdTrapper",
                "Remove %d app(s)?\n\n%s\n\nApps are backed up first -- "
                "UNDO restores them." % (len(targets), names)):
            return
        self.set_busy(True)
        threading.Thread(target=self._do_remove, args=(targets,),
                         daemon=True).start()

    def _do_remove(self, targets):
        failed, removed = [], []
        bdir = self._backup_dir()
        for pkg, label in targets:
            self.q.put(("log", "Backing up %s ..." % label))
            apk = backup_apk(pkg, bdir)
            if not apk:
                self.q.put(("log", "  [!] Warning: Backup failed for %s (APK pull failed; undo will not be available)" % label))
            self.q.put(("log", "Removing %s ..." % label))
            result = uninstall_core(pkg)
            self.q.put(("log", "  %s: %s" % (label, result)))
            if result.startswith("COULD NOT REMOVE"):
                failed.append(label)
            else:
                removed.append({"pkg": pkg, "label": label, "apk": apk,
                                "result": result})
                _save_local_bad(
                    [pkg],
                    ticket=getattr(self, "report_ticket", "") or None)
                self._log_removal(pkg, label)
        if removed:
            self._write_undo_manifest(removed)
        self.q.put(("remove_done", (removed, failed)))

    def _log_removal(self, pkg, label):
        """Removal History (owner order 2026-10-21): record one
        CONFIRMED removal -- datetime, ticket, customer, the phone's
        model as read from the device, app name, package, verdict and
        reason. Best effort only: any failure here is swallowed so a
        history problem can never block or fail the cleanup."""
        try:
            verdict, reason = "", ""
            for row in getattr(self, "scan_data", []) or []:
                if len(row) == 9 and row[0] == pkg:
                    verdict = row[4] or ""
                    reason = _reasons_str(row[3])
                    break
            model = ""
            try:
                model = adb_cmd("shell", "getprop",
                                "ro.product.model").strip()
            except Exception:
                model = ""
            append_removal_record(make_removal_record(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                getattr(self, "report_ticket", ""),
                getattr(self, "report_customer", ""),
                model, label, pkg, verdict, reason))
        except Exception:
            pass

    # ------------------------------------------ removal history UI ---
    def show_removal_history(self):
        """Removal History viewer: newest first, searchable by date,
        phone model, or ticket number. RESTORE opens the removed
        app's Play Store page so the shop can put it back."""
        import webbrowser
        win = tk.Toplevel(self.root)
        win.title("AdTrapper -- Removal History")
        win.configure(bg=DBG)
        try:
            win.minsize(760, 480)
        except Exception:
            pass
        tk.Label(win, text="REMOVAL HISTORY",
                 font=(DFONT, 14, "bold"), fg=DTEXT, bg=DBG).pack(
                     anchor="w", padx=16, pady=(14, 2))
        tk.Label(win, text="Every app this copy of AdTrapper has "
                           "removed, newest first. RESTORE opens the "
                           "app's Play Store page so it can be put "
                           "back on the phone.",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     anchor="w", padx=16, pady=(0, 8))
        srow = tk.Frame(win, bg=DBG)
        srow.pack(fill="x", padx=16, pady=(0, 8))
        svars = {}
        for key, lab in (("date", "Date:"), ("model", "Model:"),
                         ("ticket", "Ticket:")):
            tk.Label(srow, text=lab, font=(DFONT, 10), fg=DTEXT,
                     bg=DBG).pack(side="left", padx=(0, 4))
            v = tk.StringVar()
            ent = tk.Entry(srow, textvariable=v, font=(DFONT, 11),
                           width=14, bg=BG_PANEL_DEEP, fg=TEXT_PRIMARY,
                           insertbackground=TEXT_PRIMARY)
            ent.pack(side="left", padx=(0, 12))
            svars[key] = v
        body = tk.Frame(win, bg=DBG)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        lb = tk.Listbox(body, font=(DMONO, 10), bg=BG_PANEL_DEEP,
                        fg=TEXT_PRIMARY, relief="flat", bd=0,
                        selectbackground=SELECTION_BG,
                        highlightthickness=0, activestyle="none")
        ysb = tk.Scrollbar(body, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=ysb.set)
        lb.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        shown = {"rows": []}

        def _refresh(*_args):
            rows = filter_removal_history(
                load_removal_history(),
                date_text=svars["date"].get(),
                model_text=svars["model"].get(),
                ticket_text=svars["ticket"].get())
            shown["rows"] = rows
            lb.delete(0, "end")
            for rec in rows:
                lb.insert("end", "%s | %s | %s | %s (%s) | %s" % (
                    rec.get("datetime", ""), rec.get("model", ""),
                    rec.get("ticket", "") or "-",
                    rec.get("app", "") or rec.get("package", ""),
                    rec.get("package", ""), rec.get("verdict", "")))
            if not rows:
                lb.insert("end", "(no removals logged)")

        for v in svars.values():
            v.trace_add("write", _refresh)
        _refresh()
        btns = tk.Frame(win, bg=DBG)
        btns.pack(fill="x", padx=16, pady=(4, 14))

        def _restore():
            sel = lb.curselection()
            if not sel or sel[0] >= len(shown["rows"]):
                return
            try:
                webbrowser.open(removal_restore_url(
                    shown["rows"][sel[0]].get("package", "")))
            except Exception:
                pass

        tk.Button(btns, text="RESTORE (PLAY STORE)",
                  font=(DFONT, 11, "bold"), fg="white", bg=ACTION_CLEAN,
                  activebackground=ACTION_CLEAN_HOVER,
                  activeforeground="white", relief="flat", bd=0,
                  padx=22, pady=8, cursor="hand2",
                  command=_restore).pack(side="right")
        tk.Button(btns, text="CLOSE", font=(DFONT, 11, "bold"),
                  fg=DTEXT, bg=DBAR, activebackground=DBAR,
                  activeforeground="white", relief="flat", bd=0,
                  padx=22, pady=8, cursor="hand2",
                  command=win.destroy).pack(side="right", padx=(0, 10))

    # ------------------------------------------------ disclaimer ---
    def show_disclaimer(self, first_run=False):
        """The in-app disclaimer (owner order 2026-10-21, text v3.1).
        On first run it waits for the operator to tap I UNDERSTAND,
        and the tap is persisted in the app state file so it never
        nags again; opened from the DISCLAIMER button it is the same
        text, informational only, and changes nothing."""
        win = tk.Toplevel(self.root)
        win.title("AdTrapper -- Please Read")
        win.configure(bg=DBG)
        try:
            win.minsize(640, 430)
        except Exception:
            pass
        tk.Label(win, text=DISCLAIMER_TITLE,
                 font=(DFONT, 13, "bold"), fg=DTEXT, bg=DBG,
                 wraplength=580, justify="left").pack(
                     anchor="w", padx=18, pady=(16, 10))
        for para in DISCLAIMER_PARAGRAPHS:
            tk.Label(win, text=para, font=(DFONT, 11), fg=DTEXT,
                     bg=DBG, wraplength=580, justify="left").pack(
                         anchor="w", padx=18, pady=(0, 9))
        btns = tk.Frame(win, bg=DBG)
        btns.pack(fill="x", padx=18, pady=(10, 16))

        def _ok():
            if first_run:
                set_disclaimer_acknowledged()
            win.destroy()

        tk.Button(btns, text="I UNDERSTAND",
                  font=(DFONT, 12, "bold"), fg="white", bg=DCYAN,
                  activebackground=ACTION_BLUE_HOVER,
                  activeforeground="white", relief="flat", bd=0,
                  padx=24, pady=9, cursor="hand2",
                  command=_ok).pack(side="right")
        if first_run:
            try:
                win.transient(self.root)
                win.grab_set()
            except Exception:
                pass
            win.wait_window()

    def _maybe_show_disclaimer(self):
        """First-run gate: the disclaimer shows once per install,
        until it has been acknowledged."""
        try:
            if not disclaimer_acknowledged():
                self.show_disclaimer(first_run=True)
        except Exception:
            pass

    # ------------------------------------------------------- undo ---
    def _update_undo_btn(self):
        try:
            self.undo_btn.configure(
                state="normal" if self._read_undo_manifest()
                else "disabled")
        except Exception:
            pass

    def undo_last(self):
        man = self._read_undo_manifest()
        if self.busy or not man:
            return
        apps = man.get("apps", [])
        names = "\n".join(a["label"] for a in apps)
        if not messagebox.askyesno(
                "AdTrapper",
                "Restore %d app(s)?\n\n%s" % (len(apps), names)):
            return
        self.set_busy(True)
        threading.Thread(target=self._do_undo, args=(apps,),
                         daemon=True).start()

    def _do_undo(self, apps):
        man = self._read_undo_manifest() or {"apps": []}
        remaining = [a for a in man.get("apps", [])
                     if a["pkg"] not in {x["pkg"] for x in apps}]
        for a in apps:
            pkg, label, apk = a["pkg"], a["label"], a.get("apk")
            self.q.put(("log", "Restoring %s ..." % label))
            ok = False
            if apk and Path(apk).is_file():
                ok = "Success" in adb_cmd("install", "-r", apk)
            if not ok:
                ok = "Success" in adb_cmd("shell", "pm",
                                          "install-existing", pkg)
            self.q.put(("log", "  %s: %s"
                                % (label,
                                   "restored" if ok else "COULD NOT RESTORE")))
        if remaining:
            man["apps"] = remaining
            try:
                self._undo_manifest_path().write_text(json.dumps(man))
            except Exception:
                pass
        else:
            self._clear_undo_manifest()
        self.q.put(("undo_done", ""))

    # ------------------------------------------------- report details ---
    def _ask_report_details(self):
        """Ask once per phone session for the customer name + POS ticket
        number printed on the cleanup report (the bank-proof paper)."""
        if self._details_asked:
            return
        self._details_asked = True
        dlg = tk.Toplevel(self.root)
        dlg.title("Report details")
        dlg.configure(bg=DBG)
        dlg.transient(self.root)
        tk.Label(dlg, text="Who is this report for?",
                 font=(DFONT, 13, "bold"), fg=DTEXT, bg=DBG).pack(
                     padx=18, pady=(14, 4), anchor="w")
        tk.Label(dlg, text="Customer name:", font=(DFONT, 11),
                 fg=DTEXT, bg=DBG).pack(padx=18, anchor="w")
        name_e = tk.Entry(dlg, font=(DFONT, 13), width=28,
                          bg=BG_PANEL_DEEP, fg=TEXT_PRIMARY,
                          insertbackground=TEXT_PRIMARY)
        name_e.insert(0, self.report_customer)
        name_e.pack(padx=18, pady=(0, 8))
        tk.Label(dlg, text="Ticket number (like R-0000):",
                 font=(DFONT, 11), fg=DTEXT, bg=DBG).pack(padx=18, anchor="w")
        tick_e = tk.Entry(dlg, font=(DFONT, 13), width=28,
                          bg=BG_PANEL_DEEP, fg=TEXT_PRIMARY,
                          insertbackground=TEXT_PRIMARY)
        tick_e.insert(0, self.report_ticket)
        tick_e.pack(padx=18, pady=(0, 8))
        tk.Label(dlg, text="Technician (printed on the report):",
                 font=(DFONT, 11), fg=DTEXT, bg=DBG).pack(padx=18,
                                                          anchor="w")
        tech_e = tk.Entry(dlg, font=(DFONT, 13), width=28,
                          bg=BG_PANEL_DEEP, fg=TEXT_PRIMARY,
                          insertbackground=TEXT_PRIMARY)
        tech_e.insert(0, self.report_technician)
        tech_e.pack(padx=18, pady=(0, 10))

        def _ok():
            self.report_customer = name_e.get().strip()
            self.report_ticket = tick_e.get().strip()
            self.report_technician = tech_e.get().strip()
            dlg.destroy()

        brow = tk.Frame(dlg, bg=DBG)
        brow.pack(pady=(0, 14))
        tk.Button(brow, text="OK", font=(DFONT, 12, "bold"), fg="white",
                  bg=ACTION_CLEAN, activebackground=ACTION_CLEAN_HOVER,
                  relief="flat", bd=0, padx=26, pady=8,
                  cursor="hand2", command=_ok).pack(side="left")
        tk.Button(brow, text="Skip", font=(DFONT, 12), fg=DTEXT,
                  bg=ACTION_NEUTRAL, activebackground=ACTION_NEUTRAL_HOVER,
                  relief="flat", bd=0, padx=20, pady=8,
                  cursor="hand2", command=dlg.destroy).pack(
                      side="left", padx=(10, 0))
        name_e.focus_set()
        try:
            dlg.grab_set()
        except Exception:
            pass
        self.root.wait_window(dlg)

    def _make_inspection_report(self):
        """Cleanup report for a phone that scanned CLEAN -- the bank
        proof that we looked at the phone and nothing was found."""
        try:
            self._ask_report_details()
            model = adb_cmd("shell", "getprop",
                            "ro.product.model").strip()
            ver = adb_cmd("shell", "getprop",
                          "ro.build.version.release").strip()
            serial = adb_cmd("shell", "getprop",
                             "ro.serialno").strip()
            device_info = {"model": model or "Unknown",
                           "android": ver or "Unknown",
                           "serial": serial or "Unknown",
                           "customer": self.report_customer,
                           "ticket": self.report_ticket,
                           "technician": self.report_technician,
                           "scan_time": getattr(self, "_scan_time_str", ""),
                           "cleanup_time": getattr(self, "_cleanup_time_str", "")}

            def _kw(*kws):
                n = 0
                for t in self.scan_data:
                    r = str(t[3]).lower()
                    if any(k in r for k in kws):
                        n += 1
                return n

            scan_summary = {
                "apps": len(self.scan_data),
                "threat_count": len(KNOWN_BAD),
                "overlay": _kw("overlay", "draw over", "popup permission"),
                "admin": _kw("device admin"),
                "a11y": _kw("accessibility"),
            }
            reports_dir = self._script_dir() / "CustomerReports"
            path = generate_customer_report(
                device_info, [], [], self.sites, scan_summary,
                str(reports_dir),
                numbers=getattr(self, "_original_numbers", None))
            if path:
                self.log("Inspection report: %s" % path)
            return path
        except Exception as e:
            self.log("Inspection report failed: %s" % e)
            return None

    def _make_review_report(self):
        """Cleanup report when nothing is marked for removal but
        REVIEW apps remain on the phone: they were looked at and
        left there on purpose, and the report says so in its
        "Reviewed and kept" section (v10.13)."""
        try:
            self._ask_report_details()
            model = adb_cmd("shell", "getprop",
                            "ro.product.model").strip()
            ver = adb_cmd("shell", "getprop",
                          "ro.build.version.release").strip()
            serial = adb_cmd("shell", "getprop",
                             "ro.serialno").strip()
            device_info = {"model": model or "Unknown",
                           "android": ver or "Unknown",
                           "serial": serial or "Unknown",
                           "customer": self.report_customer or "",
                           "ticket": self.report_ticket or "",
                           "technician": self.report_technician or "",
                           "scan_time": getattr(self, "_scan_time_str", ""),
                           "cleanup_time": getattr(self, "_cleanup_time_str", "")}
            kept = [(t[1], t[0], t[3], t[4]) for t in self.scan_data
                    if len(t) == 9 and t[4] == "review"]

            def _kw_count(*kws):
                n = 0
                for t in self.scan_data:
                    r = str(t[3]).lower()
                    if any(k in r for k in kws):
                        n += 1
                return n

            scan_summary = {
                "apps": len(self.scan_data),
                "threat_count": len(KNOWN_BAD),
                "overlay": _kw_count("overlay", "draw over",
                                     "popup permission"),
                "admin": _kw_count("device admin"),
                "a11y": _kw_count("accessibility"),
            }
            reports_dir = self._script_dir() / "CustomerReports"
            path = generate_customer_report(
                device_info, kept, [], self.sites, scan_summary,
                str(reports_dir), kept=kept,
                numbers=getattr(self, "_original_numbers", None))
            if path:
                self.log("Customer report: %s" % path)
            else:
                self.log("Customer report could not be generated "
                         "(PDF generator returned empty)")
            return path
        except Exception as e:
            self.log("Report failed: %s" % e)
            return None

    # ------------------------------------------------------- print ---
    def _printer_names(self):
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-Printer | ForEach-Object { $_.Name }"],
                capture_output=True, text=True, timeout=25,
                creationflags=0x08000000).stdout
            return [l.strip() for l in out.splitlines() if l.strip()]
        except Exception:
            return []

    def _print_report(self, path=None):
        path = path or self.last_report_path
        if not path and self._scan_completed:
            n_remove = sum(1 for t in self.scan_data
                           if t[4] == "remove")
            n_review = sum(1 for t in self.scan_data
                           if t[4] == "review")
            if n_remove == 0 and n_review == 0:
                p = self._make_inspection_report()
                if p:
                    self.last_report_path = p
                    path = p
            elif n_remove == 0:
                # Only human-decision apps remain: the job is done.
                # The report generates and lists them as reviewed
                # and kept (v10.13) instead of refusing to print.
                p = self._make_review_report()
                if p:
                    self.last_report_path = p
                    path = p
            else:
                self.log("This phone still has %d app(s) marked for "
                         "removal - run the clean first; the report "
                         "is made when the clean finishes." % n_remove)
                return
        if not path:
            # no report this session: use the newest saved one
            try:
                folder = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "CustomerReports")
                pdfs = [os.path.join(folder, f) for f in os.listdir(folder)
                        if f.lower().endswith(".pdf")]
                if pdfs:
                    path = max(pdfs, key=os.path.getmtime)
                    self.last_report_path = path
            except Exception:
                pass
        if not path:
            self.log("No report to print yet - do a cleanup first.")
            return
        if sys.platform != "win32":
            self.log("Printing works on the shop PC (Windows) only.")
            return
        target = None
        for n in self._printer_names():
            if "laserjet" in n.lower():
                target = n
                break
        if target:
            try:
                subprocess.run(
                    ["rundll32", "printui.dll,PrintUIEntry", "/y",
                     "/n", target],
                    timeout=25, capture_output=True,
                    creationflags=0x08000000)
                self.log("Printing to: %s" % target)
            except Exception as e:
                self.log("Note: Could not switch default printer to %s (%s)" % (target, e))
        else:
            self.log("No LaserJet found - using the default printer.")
        try:
            os.startfile(path, "print")
            self.log("Report sent to the printer: %s"
                     % os.path.basename(path))
        except Exception as e:
            self.log("Auto-print failed (%s) - opening the report so "
                     "you can print it from there." % e)
            try:
                os.startfile(path)
            except Exception:
                pass

    # ------------------------------------------------------- report ---
    def _make_customer_report(self, removed, failed):
        try:
            self._ask_report_details()
            model = adb_cmd("shell", "getprop",
                            "ro.product.model").strip()
            ver = adb_cmd("shell", "getprop",
                          "ro.build.version.release").strip()
            serial = adb_cmd("shell", "getprop",
                             "ro.serialno").strip()
            device_info = {"model": model or "Unknown",
                           "android": ver or "Unknown",
                           "serial": serial or "Unknown",
                           "customer": self.report_customer,
                           "ticket": self.report_ticket,
                           "technician": self.report_technician,
                           "scan_time": getattr(self, "_scan_time_str", ""),
                           "cleanup_time": getattr(self, "_cleanup_time_str", "")}
            pkg_to_threat = {}
            for t in self.scan_data:
                # scan_core 9-tuple:
                # (pkg, label, score, reasons, verdict, source_cat,
                #  privacy, threat_type, boot_hit)
                pkg_to_threat[t[0]] = (t[1], t[0], t[3], t[4])

            def _kw_count(*kws):
                n = 0
                for t in self.scan_data:
                    r = str(t[3]).lower()
                    if any(k in r for k in kws):
                        n += 1
                return n

            scan_summary = {
                "apps": len(self.scan_data),
                "threat_count": len(KNOWN_BAD),
                "overlay": _kw_count("overlay", "draw over",
                                     "popup permission"),
                "admin": _kw_count("device admin"),
                "a11y": _kw_count("accessibility"),
            }
            threats, actions = [], []
            for r in removed:
                pkg, label = r["pkg"], r["label"]
                result = r.get("result", "removed")
                if pkg in pkg_to_threat:
                    threats.append(pkg_to_threat[pkg])
                else:
                    threats.append((label, pkg, "flagged by scan", "remove"))
                actions.append((label, result))
            for lbl in failed:
                actions.append((lbl, "Could not remove"))
            reports_dir = self._script_dir() / "CustomerReports"
            path = generate_customer_report(
                device_info, threats, actions, self.sites, scan_summary,
                str(reports_dir),
                numbers=getattr(self, "_original_numbers", None))
            if path:
                self.log("Customer report: %s" % path)
            else:
                self.log("Customer report could not be generated (PDF generator returned empty)")
            return path
        except Exception as e:
            self.log("Report failed: %s" % e)
            return None


def main():
    root = tk.Tk()
    PopupBlockerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
