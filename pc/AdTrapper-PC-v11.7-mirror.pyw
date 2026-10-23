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
VERSION = "11.7"
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
    """Cleanup-result column text for the findings table (11.7).

    Report-integrity (2026-10-23, REMOVAL-REPORT-INTEGRITY-SPEC):
    the text names the VERIFIED outcome -- "Removed (verified)"
    only for apps re-queried and gone; "Not removed - <the
    device's reason, or 'reason not confirmed'>" for apps still
    present; "Could not verify" when the phone went away before
    the check. An attempt is never worded as a removal."""
    if is_kept:
        return "Reviewed and kept"
    a = str(action or "").strip()
    if not a:
        return "Cleanup not performed"
    low = a.lower()
    if low.startswith("could not verify"):
        return "Could not verify"
    if low.startswith("could not remove"):
        reason = a[len("COULD NOT REMOVE"):].lstrip(" -").strip()
        return "Not removed - " + (reason or "reason not confirmed")
    if "device admin stripped" in low:
        return "Removed (verified - admin stripped first)"
    if "uninstall" in low or "removed" in low:
        return "Removed (verified)"
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
    n_failed = sum(1 for _, a in (actions_taken or [])
                   if str(a).lower().startswith("could not remove"))
    n_unknown = sum(1 for _, a in (actions_taken or [])
                    if str(a).lower().startswith("could not verify"))
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
    if n_unknown:
        result += (" %d app(s) could not be checked because the "
                   "phone disconnected during cleanup." % n_unknown)

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
        L.append(("Applications not removed: %d" % n_failed,
                  False, 9, 2))
        if n_unknown:
            L.append(("Applications that could not be verified: %d"
                      % n_unknown, False, 9, 2))
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
    n_failed = sum(1 for _, a in (actions_taken or [])
                   if str(a).lower().startswith("could not remove"))
    n_unknown = sum(1 for _, a in (actions_taken or [])
                    if str(a).lower().startswith("could not verify"))
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
    def _result_text_base():
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
    def result_text():
        _t = _result_text_base()
        if n_unknown:
            _t += (" %d app(s) could not be checked because the "
                   "phone disconnected during cleanup." % n_unknown)
        return _t

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
                       if str(a).lower().startswith(
                           "could not remove"))
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
        if n_unknown:
            sum_lines.append("Could not be verified: %d" % n_unknown)
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
                     % n_failed,
                     new_x="LMARGIN", new_y="NEXT")
            if n_unknown:
                pdf.cell(W, 5.5,
                         "Applications that could not be verified: %d"
                         % n_unknown, new_x="LMARGIN", new_y="NEXT")
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
# guard with that ruling. UPDATE (owner ruling 2026-10-23):
# com.piriform.ccleaner joins the guard too (27 ids) --
# CCleaner is PROTECTED: the guard wins over the section 14
# cleaner-name flag AND over ad-software evidence, same
# precedence as the CVS entry. It also stays on
# NEVER_REMOVE_PKGS below (nothing else about CCleaner
# changes) and the section 14 keyword law itself is
# untouched.
KNOWN_LEGIT_GUARD = frozenset({
    "com.facebook.orca",                 # Facebook Messenger (Meta)
    "com.facebook.katana",               # Facebook (Meta)
    "com.instagram.android",              # Instagram (Meta)
    "com.instagram.barcelona",            # Threads (Meta) -- parity with the Android guard; standing law: Threads = KEEP
    "com.cvs.launchers.cvs",              # CVS Pharmacy (CVS Health) -- verified real app (Google Play, 10M+ downloads); "launchers" is its legacy package name, NOT a home-screen launcher: the fake-costume finding misfired on it (owner ruling 2026-10-21, law section 14)
    "com.piriform.ccleaner",              # CCleaner (Piriform) -- verified real app; owner ruling 2026-10-23: PROTECTED, joins the guard itself (it was never-remove only), so the guard's precedence covers it -- never convicted by the CLEANER keyword or by ad-software evidence alone, same as CVS above
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

_ICON_BOX = 40                       # px, icon display size in the rows (spec 5.2; board rows ~40 px, democopy4)
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
    "huawei": ("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" "QfQMAAAAAElFTkSuQmCC"),
    "lenovo": ("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"),
    "lg": ("iVBORw0KGgoAAAANSUhEUgAAAKAAAABQCAYAAACeXX40AAAE20lEQVR4nO3cf0zUdRzH8dfB" "/YITiDRFyDi1qx0iCRiGpbNWKWtttlYxXG790TS3crn8p02Xs7U51lbO1h+1VmtaKeo/Ciat" "iTkL2lQu1tGgQWJgDi8R74AD+vZPx+667x3fX3cfvvB6/MV97r73ff/x3OdzMHYAERERCWDR" "+waSJNUZMQiZk8ViOaLrei0XMTqSoyVGVQHKhVfvrTms9qY0e+z2N235/5qaEBUHGB0foyM5" "0TEqjXDaABkeqaUmxIxkTzI+0iK6lel+X0gaoNwbEimhtJmEAUbKZXykVaSdZLugbICMj4wy" "XYSKjmCiVIkLkLsfGS3ZLsgdkIRigCRUTIA8filVEh3D3AFJKAZIQjFAEooBklAMkIRigCQU" "AyShGCAJxQBJKAZIQjFAEooBklBW0QOk25KqMtR+cSBu/ds9H8LXcMaQexSUeuBeW4GiihLk" "FxfBmZcDR64Lk+MTCAdDGB4YRKDnGgbaO3G1tR2D3X8Ycl8zmnMBptLyDWvwyLaXULjKK/t8" "RmYmbE4HXPPzUVDqQcmzjwMABrt6ceHgl+j67mI6x50RGKABbE4Hnnh7O8pe2KTp+gUeN5Zv" "qGKApF6G1YrNH+2Fe22F6FFMiQHq9OSeHQnjC/Rcw+WvTqGvzYfb/TcwPjIGZ64LOQX3oGDl" "A1i6bjWWrVuNTLstzVPPHAxQh0Ul9+OhBMdu66fH8MMHn0Oa/CdmPRQYQigwhL9+7Ub7N41w" "5LiwqvYZ2F1Z6Rh5xmGAOlTvqAMs8V+v4zt2Buff/0zRe4wNB9H6yVGjRzMN/h1QI6vDDvej" "8UdvODSCFoXxEQPUrLDcC5vTEbfe0/IzRoeGBUxkTgxQo9zFC2XX+32/pXkSc+NnQI2y786T" "XR8JDMmulz73FGre25X0PZv3HcKVr0/rns1MuANqJv/dnhKkNM9hbgxQo1Dglux6dr78zkjy" "GKBGtwduyK4vLnswzZOYGz8DatR/2Y+J0TCsTnvM+rL1D8M+LxvhO6GY9Y6Tzeg42Tz1+I22" "BjhyXGmZdSbjDqjRxFgYvRcvxa3b52XjsddfFjCROTFAHX78WP4L4Cu3bsaaV19M8zTmxAB1" "uN7RhV9OnJV9bv2uV7C14SBWPv808u8rhM3pQKbNiuz5d6G4uhyZtrn7DwjR+BnwPxv378TG" "/Tunfd2J197B7+dapx437zuE/OJC3FtZGvfaRSs82PTum4bOOdtwB9RpMjyO49v2wn/6nOhR" "TIk7oAHCwRGceusAur//CdXba7HA41Z+sSThzyt++I42obPpfMpmnKkYoIE6G1vQ2diCJVVl" "cFeXo6hyBXILFyIrLwe2LCfGR0YxdieIW33XcbP7Kvrb/ei9cAnBm3+LHl2YORdgX5sP9d6a" "lN+jr82X0nvMFvwMSEIxQBKKAZJQDJCEYoAkFAMkoRggCcUASSgGSEIxQBKKAZJQDJCEignQ" "YrEcAYDd/qYtYsah2SrSVKSxCO6AJBQDJKHiAuQxTEZLdPwC3AFJMNkAuQuSUZLtfkCSHZAR" "kl7TxQcoPIIZIamltJmkAUaXywhJqehWku1+QKJvWZQhSVJd5Od6b81hbaPRbKYmvKnXqblB" "dIQRjHFukzsZlcYHqAwwQi5EIjXhTV2j96aMcW7TEh0REREJ9y8R1XN1PnC2vwAAAABJRU5E" "rkJggg=="),
    "motorola": ("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"),
    "nokia": ("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" "OP8Fn9kasecUqiwAAAAASUVORK5CYII="),
    "oneplus": ("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"),
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


def _device_package_set():
    """The device's current package list as a set, or None when
    the list cannot be read at all (phone disconnected / adb
    silent -- a live phone always lists packages, so an empty
    read means the phone is gone). Report-integrity
    verification (2026-10-23 spec): removal claims are checked
    against this list, never assumed."""
    out = adb_cmd("shell", "pm", "list", "packages")
    pkgs = packages_in(out)
    return pkgs or None


def _verify_removal(pkg):
    """Re-query the device package list after an uninstall
    attempt. Returns "verified" (package gone), "failed"
    (package still present) or "unknown" (the list itself
    could not be read -- the phone went away; never upgraded
    to verified)."""
    pkgs = _device_package_set()
    if pkgs is None:
        return "unknown"
    return "failed" if pkg in pkgs else "verified"


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
    """Returns a short result message. Three methods, strongest last.

    Report-integrity (2026-10-23, REMOVAL-REPORT-INTEGRITY-SPEC):
    a failure return carries the device's own failure text when
    the device gave one ("Failure [...]"), else the plain words
    "reason not confirmed" -- never a guessed cause. Whether a
    success string was TRUE is decided by _verify_removal(),
    not here."""
    _fail = []

    def _note(out):
        m = re.search(r"Failure \[[^\]]*\]", out or "")
        if m:
            _fail.append(m.group(0))
        return out

    out = _note(adb_cmd("uninstall", pkg))
    if "Success" in out:
        return "uninstalled"
    out = _note(adb_cmd("shell", "pm", "uninstall", "--user", "0", pkg))
    if "Success" in out:
        return "uninstalled (stubborn-app method)"
    # Brick-wall breaker: strip device admin, then retry uninstall
    if strip_device_admin(pkg):
        out = _note(adb_cmd("shell", "pm", "uninstall", "--user",
                            "0", pkg))
        if "Success" in out:
            return "uninstalled (device admin stripped first)"
    out = adb_cmd("shell", "pm", "disable-user", "--user", "0", pkg)
    if "disabled" in out.lower():
        return "disabled (can't run or show popups)"
    return "COULD NOT REMOVE - " + (_fail[0] if _fail
                                    else "reason not confirmed")


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


# === MONSTER BANNER (PC v11.5.1) ===
# The owner's monster (the ChatGPT square logo master,
# rendered at 256 px), embedded base64 -- the owner's
# pattern -- so the program needs no external art files.
# _header_mark_image() builds it
# at the slim header strip's existing height (256 px source,
# subsampled by 6 -> 43 px); if the image cannot be built,
# the header keeps the drawn phone/shield mark, unchanged.
_MONSTER_BANNER_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAIAAADTED8xAAEAAElEQVR4nIT9d2Acx3k/Dj/PbLne"
    "cei9E+ydIilKpCSqS5Ylq7j3Elty4jiuceLYcRwnTpy4x73JkmVbvVGVvYMkCIKoRMcBd8D1frc7"
    "8/tj61H6vu+p4MruzOzs53mez1NmFgGtgAgAoP1hwEB9ISIwxgBQ/RoBAbUDELQTjBcq/1EAAGY6"
    "QHkDDAHVw5lxvPkoZvoN9TYYMmTmcTKs6FI70xgqMsoYIgLTx4nawYxpzaDput/6Bo1T9C9R+14f"
    "ozojTB0TAiBRDkBEhmi+fjDPrXGxqF0JY8YhxpFa50wdOAADdQ6YqSGtLfUwZWDAGABjlGr9KIfo"
    "s8e0UWh3lZlv5//jpUwF007XT2EMARgq12HCEVPvHSICMAVRCKZrRUQGjDFAQIaAwIAC0yffNBWM"
    "VYBKuXat/f9fgzfwpn9kCr4MAdAm1zgEESvbNDWjwMDctYFC/a6haRoAGWMKJPWrV8GJpkvUJ1Kf"
    "Ge2WazjRbr52sjoy4zboQ1C6U2+86TI14LwV1kYvgCaRAFSwrrxTxc84+C3zi0T9qIqgeRYq/mgT"
    "p/9Pl4FKvaKCnUHlLTaJlw4NfTJUZCNTMAf4VvlSZoYxYIDIGDWfrveBoEueNpGmvgAYVTtnFaej"
    "ohYqL1zFjFkEVZQgXiXgFXNgRpGu/jR8MXaVQF09QeaXrv6UOQG0mXSoaT7R0MWmEVXMnHo1b6Pe"
    "NPCp06EN1JBd0/Qpw9Gu/m0uABAZMILmww0ca+pD68u4UP1Q5eareNX1tK7gDUnQVbh+mG49UP1B"
    "1xLqDOr2QZkuQyQQiaHC1KmqEBjkkDHdbpgMiHEFxuxrY9DEQL9AFUxomjx9EhRwULUdDR+ow9I4"
    "hxrd6ZpJ123mlpWeFK1khhxjRnOa+kf13htNqpPOGNPGi1cP2VCK5jEb0/62IDE6qESgcYQuxPop"
    "6rgRiO1tDnur3Ji+Ug2ZocP0Q1jlDVS70W4cmlQCmpFhaoNpkDXmQBUB1I/VUFjRGzPGZygjzUya"
    "4aE3oozMjH5Df1f+aliDqwBROUGIYBJ0TSwNY6FfFBJwWvl0ugw8MZlYRLPWqbg8rc2r5woAAUpl"
    "QEJEgVKqipQBcabZw0qboHxmOipMv+qNM8NEq5JsBhSArrI1ymMWAKqqNAZXI8/En5SGWMWJqKkC"
    "/b2uvtS7XjlSRdjwrRpUs4rw9ndNNVmKAFRML5iuu/KKDaBj5WyYxIGhcSoaP+nfKMbORAM0kq8j"
    "WPvJsPbEfCfwKiDiW2nBW2fBbHPMRMjEgjS+bjIOiAYoDWEwrhkMMgaACJQBQxQIo+xq9YmGwkQk"
    "ILON7W6bSI4PxxjHIYcMACgFQCAEVJ5o3AqjGTSpWqVNKjcFXPEiyyxGOK9bphQ0MVBPB6aKgXIv"
    "rhIGMBS2NlIDYcj0+1dhMQwSqLegAQLV6WYqsDWcaXfKfF90pa1dkiqZurYHEyIUu6Gfzcx4ehsB"
    "rbxN5s8G2lQzpQoAVhqYSl2jtq6afh3YhnpgFddkYmmmOaocheGZou79VHSuzafJE9VsKKswaW+r"
    "od7uhTqaQZM6AEREAgAG+isUvzEABMYU71a/HPV+MUI4oKw1IMoMZsJFYuEopeYrZbo0MQZIkBBa"
    "LK1tcnTWWl68mCozwqgc9Igc4RajBRSIKrJoZipoXKI2fiRIi6XPXtu1r6Ph/+alF59/jXM5KKWM"
    "mc5jDBhFBoxRkxHQgV6BftDYOQN9gkw3j4Fq5A0gAgBDXdvp9kRHvyESGny0EyttnabvDUteeYph"
    "9ZhJvar6R/3hKi1tfPd2L6Zaa6JNKDOONut3Td0iVoREruaHBnkwNIx+0yoOMIarzy5DzcYx9Qz9"
    "jcorFMEzhnE12BGYmeUYfaI+BDPFB2SKvkdERIbACKq4Rx30CIQAEtB/IgQ1mwBI1LYJAiAtUSqz"
    "2Xi5qcq2qdNNCxISQjiiNMUQAJExYGWZMWQMqCRzIjc4lRuJsru3B5CWmUTddr7JL3AcAiISAkQd"
    "IRCChANCgCjfEyBE+YkhgsD9ajA8OLrwd830m1/7rJxKE46gOnKCRH3PKq4OEBXWoLyI6uogAmp3"
    "QZ0WYAga+UQk2hzqhljVgoakMhWxRne6yKr3UGnwKiuuNmFWm8qhJmkCMA5QhqTbObXFqzicetfh"
    "qt4qjmDEOFOz5yY51tS74e7o+P7/o22BMbOnr+l0s/022lFmTYlzMtPsmQehnKUASJtUk/4wTAqY"
    "Gb9htE0iYLxUGQADHArcCQBR3pt+QhPsUDEdgIAEsbvB0l5v8biEM+NxO1/eu95DqEwLMnIEOYKE"
    "IIBVIJs7A3v6AlaeBJ28XJbAZRueLXGC4PfwAkrX97pmVwqUM4QTCAGOA8Ix5b3yL0cACXCEccgI"
    "cFYxnUgcdzW9/vzhh9zz3/jWP8rxOBEF5BCJdiEqxIl2vYQhQa0Xpl4JqZgTHX/K7CHoCkh56Qcj"
    "ADDUbzaqN6CyBQWviNqtY2YImQ4y3CTl7qHaAapyUHFPmSFgqAO48s4jmiByFRTVl8avAZUgBXsb"
    "UUFDmtCgyWo/jFXKAmrzohFIfehIdNToFww62pGB+ruuHwiqwUTtjTZ0bf70hnRxqrg89bMGAs1h"
    "06yCpp6ZphQBEYBouh8BURC0j4o+VjSrqjVBuZ0MIFWQ/Ba5O8CuXevlrFx7Df/gTs/GDhsrSVaB"
    "s4jIECQg0XRxS4dzQ7O1ucYDSNa3eHgoU6lU5bW9/4amgen0UlxCTu+RU/IJiKiCnhCmoJko4OYA"
    "OcoQRfHC6FjDrff+8Ms//fItfbc/+G45lSSCoAgzQ0Si/EfMRlFlFoZggCr/ALrV0mVGNw7KYcqk"
    "6VbFiE9oeQ/UEWncTf1OmbW8MgZQlBZD3e0yY1VnXQisItqkK1n1pmsWxnTuVSrYBA7NohCNdL2t"
    "ajd+Mv9VEK6ZJDSYhXlYBhJRtaNMY2+VapkhU69R74cZ2FLn6KrLQPM1VAy7UhiNedeEF1WU62Za"
    "EzbViGg3FQkBmbZW2fvqnSBRwhHVJig8BPV/EThuKcEuzhUQ0GUBIPxTpxPLyfyOPs+tW/yFVJog"
    "RZ6nvDC9nPvxU0Ndja47ttd95s7eejcn5dJuCz54bQMn8mdGc7xDoKBofUSCwClmR+mFIFHtAHIc"
    "U0kRYYBgsYSiSb65w+kWYgf+68f//lWXz08pRcIxhbYRBALMNHKVxanajDEkpjkBVROpqkn7XjkU"
    "UVfLumBU8EYD9Np/xiTjW9SlntDTPqvQMZQ5Q4N4IGp9awLKmAke+P+gJpp8GNJiwhMxc5KrYKbr"
    "UEM8DM9Eh5bpNGakWkyBOKbj0OgX9atVJ0nRKMxEVN6GsegpFKZLEtXGUmnldJOtglvjsooaI5qa"
    "0fWc2QcgRBVvgZ+JFxp9AidwFDnlGJUtKBqaECAcQ45YLW6fK5yhpyaLORlu2Wjd0mf1u0oPXuf9"
    "yK31NXb+um4nzckNtY7uzurfvzD12oXF9+3v/Ju7e3Zvat7V59/UbD0wECdOkTEATrEwisHhgRDg"
    "UO9Ls0XEwBkhhOdBlouCpbq5YeK1V5o9ifc9+BBLJYmFB4KKe8OUEwkqpky7JRrRVFCnUCzUWLFu"
    "LTRXQePIKmvSYKANhqj4VNwqIKZQPxp3RheNt8BNlxMGFUKhKSUttajJqeYn6vmTtyTd1EszyYcp"
    "6KrqWC2sYeJhVwmRZoCY3ruOcbhKngFAl1HTSJhB3nS9q1MOfbhME2djQJp4meePaUOv9Cb0qTXb"
    "XLMzDvpN0t0+NLS4OnKiesOEIOEQUZKoRQRO4DW7AaDm7BlHwMKD3cKJPNISXQnlrsznQxF2ZjD3"
    "xzcS//br+T8fjIWi2W98sObv769rCQj+oH1hscDx/L7r246dnBydS13T17B1TfW+XY2jYcnltNEi"
    "lSkiIQSw3mPprXGATAnHAeFUzc1xyHHAccCh4Q9whHEc8DxPMFEmy4vIhp764HvfLTjtMgDyHBCi"
    "oF914pVpJzoZMfMcgIrJ0VxhNGde1TvINP2kzbBmrACZbjeIJmBXMRP9qwp3GMGsIytRVfm1wcO1"
    "5pg2uqu7gQoIabQF9d6Br+yJKXOgut2oXD01YVL/T8GaGg1SNDKimg5gOiArhNIkP8ZlqKLANOWC"
    "mtVBZSqN/q4m+ZqbAaAcpphE8+UT9dpRjVsrt0e50URrTnNqNRdEpfsKz+WwBFhSsjrAkHDAsLfG"
    "XmuTGKUyz1FZanSRrs4AEeSx2azLzg1NJBditqUEPzZHvvxE5vULmS/c51nV7mltoocu8QePz25Z"
    "V/Plj21qqnUeHFzsrZUvTyf+9dfn1qyq/chdrYcvJadTUjmWWbs+MB+TNKQStVBA9XWIiY8yRKSM"
    "8jZLlcM6n4xVtzGUwxtWd61as+ri5XFitTImATKkwChjBIERUNIUBIBqM830e8W0fBNRw+6mUIam"
    "dXQ0MOOeqkBApobzmI429e7oDVQSCM3ca8gy63A9tYWgJvfewgnMRyj/KOi9KoMFRpDTlGMBBroA"
    "oGIFlXauIj46l0DD5VWZmPnqDGEw96E2j1flbdUzTAKsdM60rJOasDdJkjF1upVEBM1/UEFsNimo"
    "Vh1p9kaP6GlBMy38r9p3FDgsygwYE5E6nFa3jZdlChSxmGeE56wWmYHL6bS7fCenZqVy2cFDb6M9"
    "zzsvhWQbyUUS8tR8anOv447qqolQ9kqUt4mYSpf7L6f2rM1fv9q9c1Vg32rr+fH01m5blaNQ7bEW"
    "/K7vPz0LSClIbfW2FwaSQTusbfYWiqVLc2m0W5UMCSCnmXqtqkTJnFCGSCCb6ehuqcGiNZ/wOkEu"
    "JAWE9T1dFwcuodMBVNYQDgAEKNWLGbSqNQBV5Wlo1mKXuvJR9T5DpqZ4K2iCCZjqzTIRGGK4fTrd"
    "MpEWANC8Q9PtM45nOqD0hKqGF82D0KCnQvJtKmrMKXlz2hQBGK9jV+v3rS6BNmp9igwdbhym8mYj"
    "C1+h6is4kHaWUuKphzANY2qcrL5X5VNtiimTBrrQ6n2YDaB21xGIdipq8WtjKKrhpYxRWuWx1Xqt"
    "kyu5FjfvsAt9zfazk5m+Nv9N61u+99TQQjSDDkfQYXPYrQW0BX3ORg+3kikRwXZiOgHJhOC13Lt7"
    "dY4jF69Mx9PZazd4nz5WDIXldLKcSZds7nx1sKathm7uqc5m8pFIqG9V01/OZm7dEfzAnQ2ReOH8"
    "dHFbp+PWTuHVS+kDZ+O81ykjp9Fs1NJBzDQ5DBCQ52mseMu1O+aPHHADuK0gczYOoq0NfiAEOQSO"
    "AFWOp+rkMDPOrip+0bCiaxJDRylfcpoK0tBpmnDjxusFbqCJmS5sAIrxQfNl6DfPrOOYJvTaDzo9"
    "MERY86L1SzL3ozRfKRDaJWvH8WacaU28fWGaelEIYMKaajuYXtKgGQHtFFVwWMUotVNV1qarCG0q"
    "9AnWRd10G3RLpkqOagL06jWNE6HWiaosKiKwiiAiMkSC0OIXGWI+X0SJ3NDnOzeVvHBueTLhDbq5"
    "8ekIVy/93+dve6l/8UdPnvDYRZQpgoScZ29b7YN7nLXrOjNnp/7vxcuBQuFTO1hVr/9osjE12X98"
    "KvPOneKzp8pegYbTpR6fPBdZCdLa9f72iH1wIVz0OmBTMynS8sJ0qjZg/che/1xU+L+XQi8MxAW3"
    "pSwx4BlwCBynWHUABCTmugYUCCuXqjo6Hti26twXv7Whm9hqKAuuAUg47XngLIAEkAOkgAwIAUYB"
    "CRAAShmgFkIgBhQ1MCCo8RGms0bjbivv9LCKCUFg5gG6YdFQafYNUVHaGofRjFElPWJX41GtlGZo"
    "allhJQyVf64mDBo8rsIP6rm1q3wA5RLM0wH6BKGmqjVIGWYIiFENqSkShbWqomCmZBoXM8+deWrU"
    "tisdbJ0LqYjX4c00jaBgWmFQJmJoxCJMqW7QnWDFcMkAbhvntFo5gUuXpY/fXDc25zwzlrhrU8Pv"
    "jyaG5xdfPD3z869/Enn7i6euCESoEyyb1/V+U5i0D5+BLTycPvg/dhnqS4BE8vXsdBdfHJJshB9b"
    "KObypdElbq3PMh+JWcD20DUPlHkynzyZTJWWU5l0skgZ44k0cCVzcabAi64b1tpLUrDOJVxJkLNL"
    "BYZ8mlGJUWAUGBDNF6eUAiIhRIrFvvnPXykceLTbmt+8Cd23tBfrekA+UJYJIFNDt4AABBllBIEB"
    "EmSgmAVOkwGNEanKW+PLwAAJ6GU3qGt1nbOauZAJaUxT2dq9UIAFurbTTLkiGzqe9Zul/qanPQ36"
    "od1cBK14W+9RkQPtbpv4jMlOqRKt25m3EYC3XM5V7ExV0YbZ0CahUoKVYeg5EfO3+n+o8by3dqz3"
    "w0zTzAytrxX1aOEI7Ro1MdHHbrLCBE3yoAooAiDOxsuQpIAEUIKF0unx5IO7Av/+0ZbxufJPPt0d"
    "iwsv9Md+//zhT9x9I5Esl8cXe4L178Jk5GB/JJroOPuUp9km2XJ8krLtu9DuwMHxMwsFl8v15W2u"
    "0A2B2Qm5dWFm3NN049o7A4HqiezU2Qvh7q72Nlvd5fnoqh2rMkUIDZScQmFiYYpYxAKTfnM21dzS"
    "uLUjOBCKJQt5wnHAOGCMyiVADmRABgJHStni5x75mw2XXx19/slNLSIWS6x5B3HUQ+npheWSEs5S"
    "BACBAGWKnVR5IFLFLuqLl3SWyTS4qpAxgi4mSoQ6zDSMqRoZdX6hhTB0na5RHdNNMGqGwAwE5aYZ"
    "DE2945VKUTcgJrKgu8qoygIDnSK9bdEkVq4HUPvS4gO65KBOAjW3W81RayV6qAucmU693XtUnVOz"
    "bqgAsfZimpibfzVCRyqh18i/7tqqXwJDQghjjOqcwYjumYJ0iABAEJnAAy+ysuSE0q61XlmmhGBj"
    "wNJW7dzVYT8yLAedVZv7mtqqGn/8h4lYLv2/sdfnhqf6U8Qn0421UOYhJ5Pq+1eLLruUKYy2rA1E"
    "wnUkCpv7YGSubOGEjhYAH+Mz+TPnZzv7guJG/ni/VO15dqnWHlj/rpudxJY6Pz5zfOCi6HQdubz0"
    "+6E5cDk4oFDMy/kcIALP9XqbLJQmefKurs6BcOrWG/ruyV4efewn7auxfr1YjBXdD/wNrqkn8ef3"
    "fdr35pl5zmmRyxJQihJlEgUqI2WMMmWRgBEuocwEHVXhatjV77chG1oAULlNpgpTxpRmlS8ZqB2Z"
    "hQSBMT0larLKWlmeiiYDaTpB1rvTdTkDE1c3Y9X45i0ugU4tdCHU1gNoGH9Lrk6VD1W09co+XapQ"
    "90w1jJs/XfVi2lyCvtRL91/NJlWZHV1nqANUZEE5XVNYRGX9WqJeGSxhlEKhBCiglVPmGhG1ck6C"
    "qGaIVDkkgEB4gd/WYt/VaTm0gKfOrABfvnu7r7fBsbrRaWW8IAmCy1/vI87UHhweqXr1uyKjp2Ps"
    "Sgl7rBCU5Ss5WLfK3XDPdhpwcflCdiGBvUE7XYHuzVADkAjDxSvS0DCTeOGurazuNswLEydGx4dX"
    "1u/bUbWhlTDkg83RiVRkhgt4i5996k/90fnxdAKSmc6GTgtvqbU37vO3tG3o7JBGA+FnPB0e/5Vz"
    "F1+e8da76vaWxF0+1vihwljB3vHXULJu7UfFWDZPCFJJRpkyWQaZgkyBMqAaKFXcK4hnylICI7xg"
    "jiYqc0/0ynDtZupQoQyAIWWMMWQUKDMK2KguAFo5qhZyMXgPGshWA186YVEogI4zAE3naoKkn40a"
    "hjUzY/iiZjDrhwKgQoFUnsHgKvQbVtEwdKqp1D0Lw6+s6MpsKA0epHtTWu2mVi+ExPCHTDMOmr00"
    "83494oUa0UO13ksbEuFYsQBEeNeNuza1yF997AJTiSzRDgBARQq03AkSwug1bZZEuvjkucJkHFb1"
    "ehsctMWPLkHyuGgmJ/XWiLwg9V9e3LpqNOhfXnDXRRaWR7P5LMB4Gdjq5jWtztpdDrZOkAaXyvNx"
    "fnWvRZT7+zNvDiY6r9vbNHaRP3yoa3sNP51M/HHOvn+au+3OTp+jc984ZCaY203r10mRyYA3FNiw"
    "HWTrbzZ//uj5/NOPP5drDf/zu7prnKnYcqB85FcNvPjcS+MDh8J794BlHax/l7h4Fgu5bqH6Wqh5"
    "hMv8Bi7OHU40xWIy5+ZlmQKHjCEq4X9CGKNAVNqj5knUAkhFc2u3nTIGgIQApYwBImGMMVkmgsDU"
    "XIEJRowBQdAUO9NhwVCZdcaUEJTiu2oUyGDGBni13IJypokU6HyEGbEYI/Jd4UBoqYBKTJo1q255"
    "mLogxoT1CqukMg3TFZlcJEVeDIOjUe0KKqOQEXUwujSpbRi2xVgWZdhckxHQ5EstXNPiOaiVSSEy"
    "DrW3hJVKLoftU7ff8/G2kV+OTHz7z1nOLciykRNQmA8SolaUABCOs9t5ZFxHkOxf7YpEpXhG2rWt"
    "5ZpaMR+yWgRa3xr0JOacfFzyV/GlMbHFj43rFy4UXvj6U15ZWrN/X19HB1x4uiQt8NdVkbydWlaD"
    "lMX52OnhQqq9I+gvzTn3WIbPX295nhc9i7H2mjtv4Dddw5BB9CyW0yw+BVYnzI6XFpdnhA8G9+wN"
    "VA/CDIB8U/Lim4O//XoDG2vYv/r4y3ONllTnu51npyxDj0X7enHzhy3Uayst7xb6/KSzCVb+j0zk"
    "b/1T34FBnrODLFGgEsgUJQqSzGQKskJLAPTlAUwtodFoMlXCpgjASmUQBI6gnM8jz7udzmQqRew2"
    "Kkt6FpSZaY+i+LX3qNEgc+TKRIS0TJceEDLAquWbzDrReK/pU12RmuiUrhpVm2F8bbZn5veaD6Cr"
    "9EpvQc2A6WkYFeqGwOinmUyL7ilAhRFS3QYjZq/3+Fa6hOpk6VwLNe2NutgAU8JPSq28wv4pE0F+"
    "5GMf7xx7afUe1/VfvyjxNp0vaYZCFwDkBOK3csvLWc5pvWNnw+duq3n+6MKTZ6JfuXdju3sjvUQK"
    "CVbl93V1U+n5/xOn+j27vdTBZHuJa24h3WtYOApLLJ/bxU4+JbqmSlHGWV2Wrlra2okOrjAxZc8m"
    "4OZ1wGcgn4WmAExPlC8s8ZuboWcNTXIoucFezeZmQS6A1ccRW5JW/eL7lqruPRtXLXV5fyPu3YXu"
    "6+SEN/Hor8ef/7lQWIoXxCpnfvWnvDO5mwf+88DuW3J133ukcOhY8dBZ8RqLzZ15/WRg/19XgQ2U"
    "5AbIMsgUyzJIlMmyqhupVhWjRFKoLgaM43nCmFQoWDisqa6dW1qmuYy/OsAzqKmuTqSLc3PTICBI"
    "EogiEl6984wBo4pDi4yxt5IrHf06OlQOZgDcALoaumAmeVDpkKbUNdZilB4oqFFzAzrz1wOmOrl/"
    "C9VAm4pCk442+dsG2VAHhwhMD7vrMAemRUJ1sdRGaqq4U49HTRyY5lkbFsdE+k2NoCYDqPEi1Gp3"
    "CaJahQIcz8uxlYc//zly8qUP7nc9H+G+9oPzfNAlSdRgrooTjAgIhOdpmW7pcN6xzgkc19roevxY"
    "7NJc7r69Te/rurE44OLLQjHRL0iRxJVz8cujrV2OPsjZuu3gs3E+P3P6WSHMnJYyBCyFkHwF8myV"
    "vZuSgMjKadLjQ1taLi2DDCBlaKzAFhPCzg3gKFK3j0gUmJ0tykicbG4Rl/Nk+7uz0E7HF+hQLDyO"
    "dbfuF1tybHRIfGg7tkFhOBH708nJx/+Vt+cvLdv2rN3f84mOi5cnpn/x7P5vthF7LPp0xtfF8c2w"
    "+89rTi27OQuVKUNZZpIMEgWJgiQjpYxS9aZSjWErPjGlFp63CHxyaRksluaGxtDU5M59e3ft2LE8"
    "daVn3TpXS3s0Fl/d3HT2jdfHRoYuT85yHFkKR8JLS2C1aLYeNJPCtKIBTQZAkxNNYFB3McyCoSND"
    "/x41e2AOmoASHFFJjVKIoQdkjGC87rVX5Bh0isHAyAOYHY8KsGqnKJF9owoamLLtjmYKTaWeuuAa"
    "4lEhKsZboocbjL4RDPFVkzColi8Zy4u0fIRKhJQaTSKnk5t27+r2OKcvndvwX9/4/D88gVYLY2Cq"
    "ykL1dEKQQ1qWm6usH93bNLyYfvzY4vV90th89j03dd/VviV01jvJJze2p7f9/rczk4lpb6Bu/84N"
    "VReA2KHEcT6OSbb4SRtZXHC3laxNAhDLdGyTKPFuPMmqVnHWLJNj7OIVNlIAB8FuN9nUgWt75BfO"
    "kzYH2dcAyTQbn4K4TONlrqUJtr6bxrwQI4VoGVIZa34u+9tB+yfuk9pvlF4RhN3RS09eGThZu//6"
    "/yr1X3jPzfcNzpw8/7V/2vjjnbOnms/+cGr3+3lbEazzpa+Fuk9FvZydUsYBUGAMOAYUkDDGE5BB"
    "q/hXfmTAGBJgMoBMC+Xy9i076m4M+uyW+qaW5tYmJggtmzfPy5aiS3DasbCYGyyXvffXv4dnvT77"
    "hfOX3njh5ZfeeCMeixSKpXJZQgDgiAYxPTdkSp6qUX8zGsz0HY3yC6ZjSDPeQJjGkPUQrdquFqg1"
    "J2p17q0pPkAtaKl2iQhMcYIRlHQDmgZp9jkMNCtNYeXWRlfHewzIK4M1ah90Z0Zf8m4Im0H9mel4"
    "rUH9IyoBH0X2NJcAFKcWKL3/7rsuPPGzd2zmmcsTTuSYIDBAQAJEuzZEIIgcAQp+l3DbpvojI4VH"
    "z8SBE0cXMndf01JOWSPR2p0f2HHjhmDuq5+KjyUSjY7WjX3N6ct8RqIcSCWKGRuBJZsvIzN3XuKE"
    "iB3Sc04ccIiWfLTAHTwkIIDVIjslzm2hHAMPBZpBKyMP9bHhSew/QZeCLM5IUMbrGwvPjAoTdu7e"
    "v7UNXHY01ELfmmLBLw8OlX73qOW+Jda1mkXtW6/ptBbnvY71JN1EbHPZ5H++PgL23/Rf877Ww3/L"
    "5yfQ65F+Xer81mIX7yjJFIGoOzABI8AxAAKy5kEpBl6hHzJlksxzfEOwen1v7/0PPRS8Zsdcnq4K"
    "WCcLcD4n94OEHM1PLM5Phz63f8O5UPa18VC4NtDYWuffvOmedRve8d4Hnn3y6aFLwydPnuhtax68"
    "PAICj6hB2RT3ADN8Na8Tr1K4usbVQaUpbyOsBKZfQPOZVQHTF+cwpriMurBV5HcVra1ZAB3GugxU"
    "mANVUDUh0/+Ytbb6Ru1QS1ShLvlm6alMH5oFxkyHjAlS/V3VpqmTyVBLDyjQJ4QWi7UdHT5aDF+8"
    "VPuAB6tbRVEEkJAQANCj/kiQEQ54AhS6GtxPnVvxOlycS3RwwERHpNRe17Rm5809C//4QKy1s27j"
    "hvDOKWx1188PVkkpPoFgL2fRSZ11RIpb8rFsXl6ZEmqua7Tz1jpbmS57OF8PEJoPnyaeRbG7u3hk"
    "WLilBuM5sGVxYztzcriXQMGBR4aJzV7M5/DladK8A6w9MDVQHJ629vhnzieef1raedf1626rZv0v"
    "wtI829vJ+urXtqyV5wLyxjauJXX9R/899cV/Dw3MtWwIbd5lta1kvs91fS62llnLUoEgVe6oEdRU"
    "CvSRUj0zjwyAUtFqcSD/wC237r/vHYuumudLAouXffHo+YPjB4SAta2NHxtLFHLv2L2mw8Z99/jY"
    "XXv67q4NJKPJY5nSBQkHZ+K3B5re9aV/+GQu98ZLr16eW5xd/GkqlaCUAc8psQr1RjIGVKPoqo1H"
    "449u9VFX3xpaFcAxLfXJzF8biAYlMaw7lbowKWEnFSgm8qF1xOvHajEsrBA/rfRClw4Dxto4tIgV"
    "aIFaVX6YSY60t0yFtRbHUq/AUA/alOldoYZ01KLHKts0BsMAOMLJheKa3u7E7HijCLWuEtg93T3d"
    "54fOIm8FKquLYDhkSJDnGBKPS4yVIFxiDVVOeSly2x23f/ETH1/Nl4TI9MR3vx4qutds2r8yH1p2"
    "VK8JDYnRSAG4o2H5tGvz3c2sZnje14SpuVyZqypUW5bOL8YStp6q7amlxanFs53rbq6r/lD89GMl"
    "p9fRvh6PXcY7muTzIVrlYdtvlQf/Km59J959DVk+hZOZ8Y+c7tg8Y/nOp9jZw1go0IaOFCmPSuOr"
    "C0524zWwfJ5Mny0PAu90YHWJ1ZbIfAtCNYPud/z7lw597juTz8y21ns+Et/4K6EZBGywuAqQj5by"
    "iAAUmAwqfBBBQT/TbwIA42SZ3rBnZ+OOG//haGiCLUAOrtvaVWOXfzwSlSbOQE29fd9WWsy9aHEG"
    "dm288LunDocT7V1teYkk8ysQjUuLeev2jrlCLloWH/7AA6uXc2va277093/nd9ujmWyhXDISwxSA"
    "AKPavUYEoKb1XBUxz0rdaMRMdKwY6he1YInxGXQcMx33b9s4ADDGv13LYJIa7edKi2JocaVXZh6U"
    "8fXVdEiTMy0epPE7DfqmIyuExyTYmjeAptQvoKLmGxsaZ6cGGQIUi4CRe27refzJM4xoVkVbQaKs"
    "e3LbLILdgmI5Wyj91yOff/ihu+QXHo+d7b90sl+8fv+2XQ35/hO5Y4fK8dRyq7+udb0E9Nc5jzvP"
    "4fIlyqXTYjtvbULOs6qjI3k2Es0mL8cWq/xe64aWP176Vft47dadu6zHT1nWOQg0Fn41KW62syOD"
    "HJX4UILJp2DdveXJkrBEm754d/npQfb0j7C5Vfj43cXLmbV2yzc/2eJZ52TDEbbzkzB/QT59kXN2"
    "cu9fw2AOczNY7ssu1EGM1t35gfzxF/Mf+F/3xdk1Z59OI7+tpuHNmWnCc4DAGAWkiBwAMKS68lHe"
    "MAqsWKzyeK7Zf8d/DxfmwWWRs87ZuTWd/j8P5CHYa993O714rsBV20h87A+v45pOWzSVn01dFrx4"
    "cUjcslG4uIRlnLJWJ7OJiTMXlujaPfWed7737j81Bv/42F+efOavROCZLANBNbqvuN9Uye4rYNB4"
    "Gmg8hBlwUPxYA1fMgIeuPPUKJgN1Gki0CJFJA5u8aFXJMtAzwVjZrU64Vfgb5uoqqCtI1ngcqssa"
    "dRpjEraKtwrXISarZhI31KNBaKriVB1iQGVNIzECo4TwoiDFYl/84t/nj70oDZx8/xbY8tV7pS3v"
    "2HnjD88NhziXk1IZOAIcBzwhHGECb3NYVwcCoXhpXWPn9/7mM61T4z/74t80r+q77ctfKs/PXH7i"
    "sdbrtziHD5ftHqmmlZy/wGLJn67suM+zVG89xTH/0YWqoXDKzqqqxWa0uLo8jnxhKJce2tbXng6N"
    "nF9esBOxxeXwt1ssd92Qe/NYcWrK2oQWP8Nap+y2kyaBZPLlVwucbz+5flv+F1/jdqwRb/0YLO1g"
    "w1asc8qYXH6OYVVbzd+52WS5cHqWb3UI7wvI3AKcjLNAYyrrk+ZWPLXTFk+CEvtMNH92NPSZQ29E"
    "kgtgtQJhQBgyBhJDmTFJBkpVOkAZAAo2hwe4b376kcfjdYcmonw6Via291/bcnAsMrsQFT1uye3h"
    "3ES+MAJda4SlEejqkqfG2ZmLuH4753EWj7wO8Sxs2gUiAVYGS86zYZ1HEKq8tq11vk84i5/8xKdP"
    "H3pT8PvKMgVgSBko4VHKgOrlEkyLwJpDpWb8gVY1oXuMumuqCYD6SUsPKzDU45h6GL3S1dDxyGu9"
    "GaKHOksBUNd4oUbEdAmqkCzjg4m/mWyBmd0Z8Fdln+k1rPoFVzbEjO/1I7WcPBgRIaDMahFEu7DC"
    "IBIn0edeqF637Yf/8a0993ycMpkInMwAOAIEZFYCqZgtwuVM4aFrb9ztqf3yp770uTv23v3Vf8al"
    "udDLr8xe6Pc01SQnr5x59UJjUw9Nh5+YT0lcjV1cdrojCXl92vnwmurlWPibDntpPl9ISDXr3N6e"
    "NSXwt5bSTXz8yr511XPpUhKrk5fmhJUD5Z0bO7aszj/xBljbrIKbs1tKh2a4dduFHltxbh0vbOXa"
    "WspTM6m/TMwONHlgh299lb+7Lp6cGbp0aVPe3bKvm9tdtfyfbzgvB93f2EX31MGhE76mQEiqv3iW"
    "tccHvNfc1Fa9tu5G2rh5278//djR6dFqjzchZZayKSCUFQpg4QF5JerPSZQxsr61/qt/+9WpnP3g"
    "0y8Ki1fKvqamtvrI5OTsSJj310iMkLlJuasXpoYo72YtHdJYhB48DJFZHDgl923bv7tTiiy6aost"
    "PS2zS5HQeOz8wkrrHdtXp7LjwzP/29b8uS996UccGR4fWUklkfAMKFBQeSwaKl93LTUCrifBGFQs"
    "LtGxpMVoNHBoYDUjVV9qYs7VmrS6qncVXU9sGsBQFSktTqDre1WyDIOi/s9smoyKf139a79pbryC"
    "VdQSJFo7aiIQwMgHG0AH1P1qbaLUSI6x2RMS5ARBikY/9cin6+YvTr34/J1rhbV15Y5PbsN9j/zy"
    "t8WP/t3XwCEKLjfh+KA7UM9XS6XsnLwSlUvfuOvDZDGWThf+7dP3xAcvxifH8xLNz8+khi4OTF0p"
    "+NtuqW1IRNPnHJ2buKQ9Gx1dij9Bt25re/ftpRW/9C2nPXFq2XEq3bbFKbS4Eg5Lq6PrvdV9y+Tw"
    "d395fnSF8z7UXPv85YG8O3jt/e/fzGaot70Y+KjIXGIgk89YeacD0mWaXLCJh9ILUz//CwxnGgJV"
    "3T701PvJmg2tzFaOjrzhng3Vb14D/ASdm/f29jq+cDfX3UTPHKSnZkjrDZLg4xAxnCnGVlY2W/y1"
    "3kMXLv5h4OibifFoPskXaKPoS5VykUKCCBwIhKbTO9ds3PfOv4176oqDw7987ARHUJqbWL9rwyK4"
    "l2UbN9EvEQu/eh3L55nNyoYHGHHD1CXL6PG23RvWf+T9W9obejpaj60UPS5Li0sQS3KB4xqYNJIp"
    "zVISsFuGJsK7Am7HlfOPfP5z8egSZcDUMiQGlKIMAMCULRw1I4DAgKpAqwwMMdQphu4H68sIwLAC"
    "GttHHa0VRQ269ajgQtqKMNBxrPcJehhVTaWZCI0mG6g5GPoCUrNk6meppUxqL7rAqJ1qTo4hLFpT"
    "GtFH9XA13av5ItqKFlAOE8WJ2flNjXXHC3BhmbkFcD5/xpX4wkf2f9Tz6//67Dd+HFqcd1Y113DV"
    "gr1pa2vXPwRrHg2/Rv3eh9/34O///dtThw7Onj4teZ17Vjc889IFKVNo9HfztVs2+i8znKxZXIrR"
    "soxVi8Fb5hcn10RfOcf739FwjVicPZOYOi+nHekunnas8fiS0/22xm5H9+3bEuLzI4O26u0PWAR3"
    "8yYh+A7S3MgWL7z2uws+ae+ad7a6dvO0BGwd4Kxf5jY4V2f25V+3vvpaWBgUbNWzS/GxxyP7gu6b"
    "blmbX+8qWpcwFeWnzsoHj5VnjuNnHiI7VpeTBTZ5WfCsZzU2stFTnkg/8eaho3Lsvmu23b5xk2VI"
    "yjDZZvOMxZbmZi8TkQDPvLXCNdt7b7nlkX+edG6bvLwyPEPksoxWoZCRZTk6OQEUaF0vhqelsSkg"
    "HHo9kM1wxx8LPPievh98urmu4fVw8UpLcC8tTmdTb7w+vubadWx4ZnE5u2579xZaTmeLzy0X7t7U"
    "coEXP7x90yc+9OB3f/RfJYnDIqpRGqVqiDKDp6hqUE/aXsVVsBJ9TPMBVPCrfzUoGujX9KohIzp4"
    "VfWvWgC7LgMa7K6SGZVWaQA3rRBSP+sRHAColJQKidPJkpHkMHLMZsqktqviW8t2gab+CRJgSnG/"
    "stkBQeA5Jsk1Tc2/+eSD//nwwwEnu74Z7BT39dGGB2q59s0R+3t+9kq6MDuxa40kCg31Tk+Do9OK"
    "J0t8Z+TcmVMDpeJ0NC8UP7Rn9+O/feaFldRdLfVLKw0bfYvd00+tELDwwf5C81DB01D3963cQlvp"
    "yRkp/6q0elP1u4WFQ0uJqSZ76wybrpXDq13Yta6LiHyJ5UqhJcFny8aXl1OrEtyu+rre5lUd0UiB"
    "FqxSNmNptLj7RMhywmZWXJREtwhpyRZYzl65nD4z6Xb7uICYPPfiwvmLrbv2+W7aDDWu3MoAnuwX"
    "HQG0W/FvP8Wqq+XxWSJ0YFjAbbwkFgcPX3pzYfrZqdG0nGwJVKVS2bOpyVQhDjIlVEZCZV/2h/d+"
    "+s/pvcdeP/Q3a6sefeFMIsXkbNrW2YXTQ7lshq9pk0sA5SzhrXJoHCglmSXhlj109V5wWmo6fWxo"
    "PjQ+0/eJd+wp5c7NrnTsXm0JJ68h9NRsNJkp3tRZ//yFCeaxHV7I3Ll34z+6wu/5+nsuHZmWM5xc"
    "YCgzRnVTUOEDVLzXAaiTJR01KnvQRIXpJcOqIGiH68F5zT68TRTI7ASb8g5asN0kNeaQpgFQYySo"
    "41xLDL/V2BhRHtXCaNLJjCMAtNUCAGqey6T1NVdE3SKKAWp7RSHjOI7n5Uz2x9/4SujR/z10Zqyj"
    "ltvipdvrWFUV8zSBx22bwntqUv1yR/voM0fW7W28PCg1u+ff6Hev90Tknk+cnxUaXMKJ1y78YV7+"
    "wvW7303PXkmHOi1z2XR6OErGkpZpunaQVnu5te8ISNuqD86lu55aaV3k+d381qHwC3WML3D5RpHj"
    "izObvM7evrVX2tcftFV3nX987Ny4rfmLTrs/EZ9NSOGlXMbO2iIYFYvod/Fb3Ou3frBTuJZlD1He"
    "R3g/b/PwF89fSS/PdTQ2TB5+6ciB39y8doezXColUxsf+Uxpm4UeeTPdf9G1bYf4/gdJLi9bBCh5"
    "5YWYuLk6ls8NXbickcpX4pHvjh6S8qWl5JIsl3iHVeZpVV3yuvXNDu6zvz2+7F2O3bSp5q9/OcJC"
    "IehZxzgeB4/A+n1ot0AmySYuMX8dnH+Z2AG/8M945y14eUoeGAOROGoDLB2zO709u9cF4oljk+Fa"
    "J2d3una01ISWk7tXBUuX5pMCz63EfzlX/sLubtvC777+g/9dGIiRokjzDGQGlBmF2UrKgtEKeTBA"
    "c1U5v15fRMGk0dXVMoZRYKCLxdUg00/RZUn1AfSvzaFUnaObRUR7q0mCqSwbNQEy6qpRFWTdQugZ"
    "MpOLg5pnorWveeKKD4CglO8rXWv7WCESdbczjjBCOJ6Tc7ltu/Z8c0vd977xXbTzN9RJXV7FdedG"
    "Vlg0Kt+3G0bDlnV1xeUslleYP2gbnCiJIot7tu/fuP3JZ44+tlgqi/Z3Vtc+wI70OKLZLJYsWCD2"
    "pVzV66mdYVjfbLFtsx5GW8NY8YHt3q6OgKsoF4cnL1hRpgmp1d04mhuxOxPN7qKjsTHU2BwPLyZC"
    "+RfmYjypWeNt3tpaJ7oKK+nsVDRdyOXrRHc8lGta3bjzo01MgHAoPnV+NpfPjeYmQ7ml6dRYX11n"
    "uRx2D09XgdXpKDWNZzZ/4WG23V+YmGCX55hDsH/mIRpeZi4L39cphzK8w1YoZ/uHRta0tMsC/vDU"
    "60+deVNm0iKXXrGV/T3RL173uUdfa7h09Jwlll1/Xe+pNy/i9CiraQS7FxNhKJeoLwiZBM5fhFya"
    "OD3sc99gHjeKFlu9t2hzsZErbHaStwqli2PQ3uHev8ObiYs8P/f6MVy1unBh0Hrbnvc1eU4/d/rW"
    "+/bGFyI1Hv+D/kuf/fltZw47U1MllgUoMiYx3R8ACsaiGaoWolbKgE5wjOIiMN4zA2NG5YPJhqhx"
    "HA2jzGhT2RZGp0AmkTNx+QrtbAa9oqtNTrpSp6060KaUmFGkChqT0ZcpGrKqxXnMK/NMu08q9Qs6"
    "BQKiLI5FxhFADnkCiIwjnMDL2eIPv/S3+PxPXnxzqL6KNDlp0AYywzfnIGjDvR0wOkPft48cHOK8"
    "yKWoHC84HGWPu64rMzsfSdSMsc6lcqILxz/pHCFyyc5BiDW67TVLBXy92FfnaHcVxi/knRG2t8/W"
    "kiwkCzQiwQSW8/cE7rfluVcyB4bI3Dvsm+9fv0t2pX83eKC5rveW3ff2Dw7868svZ0S2xb1tb8tm"
    "SYiNRxbTmZIsJq/f3Hp88CKgVLvWMZoaOjT4KhNKHrenvbYNgA1MXWyvaU4tLNhixRZn8Fqf1zsW"
    "X3fnHZ77Np1/7qUm5nO5GHnvDZyFRyZITk/JZmf1lv4rI0dmR2aTyVihMJuKTieWkoXlUnVu797c"
    "avz6D/84x0didPSSd//1sUuTMH8FVqZh0+0g2HDkMCDPykUSHkG3R975bsgVoDrAda2V/VXICuzs"
    "Re7WveSFJ6SShdu5m06NUypDvmwtRwuUCNX+8nJ07ccf6AjNHJ1IuByWQEvzj66rHRp+5Ls/P375"
    "RJRkBJajrAwq1mVqZj6oVVO/3aYMusuohytBX1ymAVfbOkVVy5pLYNr+RdPmoImZsSaYmUiUYk8M"
    "4F5F09UhaFVNJqamYt7wpE3euHGqIo+VYSvdyuhXZKqaQ5NI6q4CURwAtd6CI8p6JbRy3/zjk79/"
    "z3t3Tf3rhXAulsc6BxN5KMrQ4KISwbE0nh6mFJsGpsNzUrlJxFqOO3D48BlZFLhiE8FmS5VIyqej"
    "Jb9NSDl7X5V6u8FT7euyBHbHwbIYTy8uJwuJXDQzVyUH7fb2Yt43UbwYzXICx4rEPlgcxlKub6pu"
    "zWdvzY1d/s6J/5ieW7ht8103dnSfDUUj1sj3x37X62xN8QslmgqnJwdeyd68YecTSy8cfvr1ak/1"
    "dTv2AsjZYmqSzDidrlXbNkCRCm6Ym549OXFCxG2SJfXSc79+MD5fu6P7f/769O6mrvav/IG87w6S"
    "LPh6m4Qdbracv27NJtFt+d3Q6cnlpQUh66rzWotSyBJuDzbH52uRX2bL81SS4yPj3PJUbWSwvrEp"
    "npmYwCrgRUguQjFCbQskWNc+fqRWoKPZxmiZoMvPLS8wWYKTg6xlEwxcYOPTPEGaz8v9F3D/fiG1"
    "zGqa+fnQ2InL/D17HLOvWEr5plrbczPkOt++JHvM7gjmM5LBkpXsEq0Ahorzq5iPFuExvzTXV2c9"
    "+rY9BvUwYF0BQzR1p1kA1AvbQA3IXOXJmhkQ01ZuXsXeFXFUV7egjl2mq3djAXuFcOHb9KKcrtdB"
    "KFtkAlG3byOEIVHJD0dA2f2GEOQ4wvNyJrN92zX/vtb7wg9/cDmHHA+yzATETUHGEzw6B9urxV11"
    "q45Pzx5OxqoYvwX8syDNSM44s8jMGmaFG8X4NRj9rdw06r3zvQ1t3kK0kMpzWJVHa6kgNpHOdcLq"
    "pfjMsDQpOMTW0sYJaWh1czcV6JHZN8JsaYFesOSX76u++zpL9SI7c74YnY66PnrLl4/NnUmsyMmG"
    "WGg5s9G9XaQxH7KL2f6zsZOLYsLtcbQ098S4uWTVgK0h7akB0QrFKJecdpKF+nUNu0hSnj94diy1"
    "bEdrULLc1r3J0tZ09tLktpYOliPNnb1bey3Fd/WslGyrynlc230yHzu7PHNyaezVsWPxZJhUz3/s"
    "ptte/1nz+LlLfF03nVuiF1+uq7bXcWTjlmtXwqEXzp6R3A1cbJzdFncRW9/i9s5A66adu5986qmj"
    "ywQ3Xk8sHM0WGBFBLqOVZ4shwDKkQmxqGFz1WNvMOlaRli7OWixb+KpqV+rgyaZNq3ev6v3ShtS3"
    "H/3M7/5vkKQtNCtDGZACo9q6ZEqBMmSU6a5wpcI0xWz0b1WmpGFIMQjqejPdUhiqFE2rkMHkWBth"
    "ULXO3+DlTGcmBunR+tB2scWrAq2o+tuaZ27ws7eXX8UEVNZBab/rWzZoUwDGWhZFVJi21bGy5ytw"
    "yBAolTmv+1T/qX/idnzpfe+2PPb4WI4SC8oSjK9AwMLiErAsg1hWkqyIzo1CV4A2hUqDVsh3gGec"
    "cciVeyFnFdwOIraVFneWeve31JRKVyKxsdFEZKVYsss9DmeyQ3AV5PiCnH6seLij9voDxfNVBeht"
    "bqkpua+Pku17Nj83+XrIBk1C3c0PfenUcOzHTz3zyS0PJlpjvzj72Kqmhj+MfquRqxnNXgiVQl6v"
    "32f1d3avX3b0k/UX910LHS1cjYPU2Wp8Yke+WBOfue7iwcRQ//C2B2459+hvl/NSwd/456K8Ni2u"
    "2XnTyPiw3e1x1rZeXh845KEWf9X4zPzNPOyuapBLhbno/MbqximfNG0bWcXxL3ks4BVZKccgD5Is"
    "lmLU6SvnM5l8wVmIZyElO3lHueOmms1ylFq9njdee2NlfpI07qayTEcHIJMESwAcHHMwkCJQXGKL"
    "IWAWTEwzjw/jCRo6CM1Nlhp/0hOo2r196ZlnBhtbxov1QYe3q7dl8uQSUmSqDkV1RQwq9RkVu9no"
    "jMcMb4XSX8XLGTM5kKalLGbZAN3j1bGvCQSvg1erd0CtRkcRHIPIqLKk1kQweEvkXxUZxgCZiRdV"
    "EC8N7cwYtFa5wcxGRk2b6ZVwxER+1O2RlUUASlJM3dKZQyBIgXI+15Hz/fHyxk/ffrf70OuXIikQ"
    "SKEITsHb5ChfyReKi0slznqjs9lVcBwqjhIo7OCaUtB2SSJbxQxnGQ76uj6ak/uLpRfnX7LFMhvr"
    "bV3VtV19fSW+LVZqnDny2vbepkan0H+5NCZnTsX/mAIBi4WHHR+qof6J+PTD1R+arsn+5Pk/3NF5"
    "/as//sOmD39++1dL//qPP/6fT36FTpR/NfSLdf5tIpPThZzF7vC4AuvXbu7Y5QpujAQ9XI8fGlzE"
    "a0ErprwU7GK9Y3XtDas/fObMpR/87//c+cB9v3rlZMnmTtRXuz74TiKiJ77ew0LzVVC6tiYVnjkQ"
    "OfP3W3eeKhc6KGysqkmWW8tcPFuacdQFwpAW5DjEQjQ27iqk0nanpS7u5QorS5HYyowVCdavxFc3"
    "rc71sQnIlLJjb76RTiWK5SytA4zMsliCIQNvEoQV5FOASUzEsNvN4ozlrZiagtgMWmwsHSk5bxT6"
    "+4UHbvXvuqajzlGW+C7xZkfmSb4YKclUTS3pLl+Fh2mO7RjqV6MlTJcE3Vk0/zU1Y+hRPamrp7OY"
    "4XNW7ApW8bxCBaQmJWwMTJdRs7NtKmmqYE9XXZ8xSD2UpLAvfb9i1Eegr1BTBUt7RA9qckG0nT2V"
    "MJHGiHiQOeB87ksTQ38/khxfvbW9rcFGoEfk5qKpTaK1IJGDJWlWrAllki/nxqdZqgZq6vjdEexp"
    "5usc0mKCQTPlBUZ7WLraWjjIpFPRxdMTg6HR6ctjkaSz5vck80+X3zg0PTpJ4/K6dflVm8JiNmVZ"
    "OBY/1L9ySXI2feavXy2fW8nlM2dnBkWwDfS/UtuzJ3ut53NP/PMDG+5B3pUukIvJIWIRGqrbglX1"
    "VR2W1Kqng41L3XXQ7GPdDmy3irUC5yALAikWSqFU/vdbtwa/9JWvUsjd98GH0r3rYm7xwOL4hW7b"
    "+Hpb/JZeaZf/SmllR2fTvTXB5xYG4lBMIM2J/O6m3k/03fBvaz52rWtn0pGx+ybI4mRzbGxHfb2z"
    "kJQcck1XYXkpnIgve6rLvTulHX2yPZe6Mnl5emIwJ83y1nDK4oXUEmSnobHIbUiibxQuHIY3z7EL"
    "83QixY7MQTEOrjhISZBzgDwE60giLPUfW5oMpwM1Q5en83ZhYoFcOD/BGGmubmAyRURGGSg1vYbK"
    "1u6mDg/N6BsoN3CFoFXqmDkKVsaGKoCopWJV/DIA8+a4OlgV46DjU2f8hgFSYKf2xAzFrw0G30Ya"
    "jTfGYgSVU2k/6GZPy/OadrI3lsMrfoZpTQyoMSLl6RU8YTwAIpVkzirmSplfLFn6Wm54aEdDD4D9"
    "xKupqeEA0n6uZbxcdT86m0UblAqMCo8Vl0Msup1f3iFPnS2IJ8oJp9s+kmUXZClZyoHg9ZfpbvRU"
    "C6X4+Knb1t713cM//fPMyUJ1l9vVSCSgzvZUWrjCFi5nX93qaveA+0oo+kj7x3965a8SPy8Pzg7/"
    "Ba792Jd++oV37EqM39hx3/DE+aXSeFv1KqvD1VDflmk6a3PMNtv5Bhf1clgqyGiRXFZ3sRgTxZeB"
    "n7aCD4D09X3kvvsfPHjw4DZP4excXDh2ZLnVZt3VeryU7ePdc+XoNkvw483rh4sLYTl9GbN5sPai"
    "I0uzT0RfOYPzdljYvrN54UCoIVzFCVabFM/MZDzXOqWDNtFaWntb6fxIlfWIMxK9YHfbqltkqZSd"
    "q7aXauxidlTOFzCZY4dSMBlHnmetXiwjcDJYbBDniYWA18VKIsRm4IqMzr3Q0A3L8apN7YmpkFxi"
    "D23edaFjt4DF/qkBoOqz6Sr0o6GWNY2qURvTrnEmPJqQogEL9XIi7XcDcLrQMKOwAoAZFEj7XRVE"
    "XWBAJTc63k0OrNI807s3DUYnSag7B4YcYEXok6pjZoYMq82iuvuVRv0VwVOflmWoDLMMMA6BU9fL"
    "UES0ChaLe33Nqhci87/xOD7/ro9NfftTCcaK7lZrgaX49s4SnqSXOUutREVkkXpuuolgirO7bK4k"
    "yiNAF9ytHSwmkfBrKefUbKjOulznTR6eP7/Qum0RovbWNSl7HT/1piDMpe30Ym6BF3GocKFWrK6y"
    "OsWc5VMbPviFsUdJ19Zsdrah/40NH/67F14fquZoGIeRQ95i4zm74Md81ZU6K2ZzNCVAk5vaOZIu"
    "FAr5Zb/PMntl6me/WoosB7o6lz7woa4bb7p5eHjidmf8wsBZ4NssgyPtXNzabK9xtzgE/luzJ99Z"
    "3dVutdiAF0GaY6FmCGzzr9/mrzmSe/X3haeiVfF3faR1+OcLsdCizOXr6op9HcJJLrzr9lxitz+f"
    "9dVmrDYuYHEIKzOTKd67ZOsjkSvlcJYtl1gsASigYGVSGbJ55vagxGPQBTYvkziMx7EoM8HDBA8t"
    "ljmPEz2ByGLeHfTOL6Te39753w9/5ZX+Q7OpcK4s5QsFGUrIKlCtVYmZlHelX2hmHQrMjZoCpuHB"
    "CMBonoTJB1WzuyZHwrw1op771TmHqnsVKUTUvlJXRCKaRsBMFRLK2ca2wJVkSfd51K8IMa5bSaIp"
    "up6oal7zk3TLqHyjFcMRrSAUlceBgS4kDAAY5Zj85nz/EpEfXn/X3s69hVu//Jvjx3i+RsiPAnhG"
    "iGjx3mDnaqLJE7fgUitmTpelCVY6XMCSpyFTZSnmk0vlHOesO2sXlynsEGs2BXZ8uqXp2pr6n185"
    "PDfwAsFiKjnEikkOCCeIeSkponU4Pcxb+KnE9Obu9fUePDxyuKnr04ui37syFG/kJ0amiyzqcVRz"
    "gkglLDjidS3ZVh94bcxCgFKwW8HmEEvF8uyo9N4Hueyc0FRHbaTvJ79+4oMfCF2/77rnXnp+Y2f9"
    "qcujl/jM9GJ1V71vrvF49e71727d9nxkcFt1zW6rtwrFJqwukNk/nP6n10cG7tm17rb6fcfgwtZb"
    "Pe6lub/866TTXW6/ib4SzlU3ZkrNlkM2+y035ObP+6OZfGhpvGUdpqQGYWyqnCmyqnqwroCLoihA"
    "NguSBFkJG60gl5mToFyAQB2zVkE8R9x1VOYhE5NCK/aWxvJK3LGjd5WjrZiUSyLtn5wYmpogokgp"
    "BY2fg1Gco0bzUWcDVy8e1PFu5kO6f6vWR5hdCQ2LKryY8Vb9iX8rXWEAWvmappXVfswJLt2z0LW6"
    "LsZaUwrYzV600qJSpWS+LjQkGNTjdDOmu8JqY5qJUmK4yv+VR4Ki9rRTAhzHgIhWkWekUMjUVNf+"
    "9K737Q/2Lo6nSs230nlL5PzzO4LdnFQVi2Z3eNZfSA/UwPQ6yMTKcESSFzmHBYTdVbZ4trintnEm"
    "g6f53gDnCBXjj0VGD0y+4CvJ1Q5HC+WTmUiapGqdbsnhAqACxwl8dVkuBTlbSYJLieHnJp8PALGl"
    "r0w9/m1v90ZLR/Xy4Im8RJxy3uOoZgilcplBUcrTsgQuEbwWACTpIisVJTtPfvhDWLjMbt0ERYv9"
    "hs11v/jTmdPzD/30v37Lvehcv6bx1EyMs7vSk1fORe3E3sAGLp0XRJfHNl+OlIREgLQ38Z7H3/zf"
    "93/5SXsQBtNDb37s3Zvcvd+M/6jv1ubWJ/qXYpx/Kz52NHdNOyk5bIUklIcKkVC4fsPKzbfHTw0E"
    "hTczVbnYslWUnGUoMMY7mMUKlKIkg5UHB4f5EhPLzGlHKQs2N8h2yhAaWklqgRVThf5+ftU6XnBY"
    "5rKzw6V197V/xvGg3+vMh2OvDBwLxec11xHVQlANRFcH7DXsmpiEzmrUP2ikkHQwAZjhrm1Toeth"
    "5S9vxqHWl/qPysIMy6IPwkT50WS2zEZEa0H/DU1SpQ/BkLHKNIaWMVCdAVBCtCoLUkKfBJWnZWmP"
    "jgNO3epHWfCFHEdsdh/nuHZt3xfveXePo/mVV88t5eXDU6cGT/y2r3H7Fzofebb/yaiwcjD7xjI7"
    "/S6epcuiFbxr0TnJbFJ2JTI1X82VqyRHESw1K7NFSzDBOZycrUhjI6mLZ5cWgq6GOn9NKl9obWtu"
    "aa5joiWcx/6hsUIsXGWB5saa5s6mi8mp4bERkdg5ORofPZhNNFHGUUKQsxCeBwCZyVxZsHEiIXmR"
    "Q7eIHhGslPCUZpJsYgqsInthrDAdm3vmxNfa/ba5WTzxt793BO7orqlzOC7lO9tJR237mvqu3uCV"
    "SGh04rWcVe5bfdOQQC/h4Kf5jdlsGhZBihGp2VkGr5tUfVDY/lvLszf9e7D/eyuNkrX2vNx6E0y6"
    "HLWE+CPZxmuXZLE0+Aq97iNzh+vsE4fd5RorijycltHrYhJByc6KEvIArTwjIlLKamyYETGSp7wL"
    "0AJjp2WpTNbt5h0umVJPlS8ylbBcyHXuq9m0rltavvGnf/xdk68+X8rG0iumtJhKWkxKVYeW4Sga"
    "3AbRTG6MLVF0Ta6upVK+0piItrZGP69yd2iT/2qiT0p3ejRTLzyqwL4e19KFy1iRqTivuguhXbPh"
    "kxvVcQhatSnTOL55Nzgt+2s88g2RMFSe4UyAKOt9gTGKQAq5fHVz15fe/153xP6tf3/8zOJocHVP"
    "NLZY17Lxazs/cfzNN1+y5yOsvLXotXFd9vxCBErtTLYzaxW1ZCEXyRUkVijTQhKsiXSxGM94CmxO"
    "nhEIn2PJan+j319v83IPv/ODsq+1PyWOJlk4lk7u3imXMpl4eHrqUkt6as/ObWJN8OzpkxaOI97W"
    "Up5C5y6yeBqQY0goY0BoKcrXOD0Cn88WSZQwWQK7DE6ZZXJQ1wijMqtxyNMxVmS0jDmaxDPjhydn"
    "Fm/d+A9BN5t+/UXe5112F7jVtv07ry2E658b/vNA/FyVa+M2JGfKw/tv/MS//Ev+pRdGMVnwilJc"
    "ijnFpd1yh3/tet9/PnbugIMLZ+N3d40tVSfHyrE7OXg1+8ZveYhC437nJz66dvbd00+Q0UvPtSIT"
    "0CKTUZlZCdhFxpVIHWP1LnYsjSWZ1QiQBlxJMI6ivw4AmASyO0Bra3qS5cipuUQ6J/xA3vb53pnF"
    "hbls+MTESSgXQbQAR4DKhl9pDvPrL7Pi1v1Zs28AoD2yWwkroZ4WrrAlZrhqZ/MaTdcFSxO8Sl9X"
    "rz81lDTTlqebaJIhuLpJMup/NDHW/ADDvhnkTgmEgTm+qUd7VCFQnxxKVKKvPgwdQVk/SYhFFHjK"
    "8rnyjTuu/e8PfDR/uvQv3/nVFXn+7ofvLVMhVYjvb9t94cSxX3CTKSI1lyw9zi3HM9yzfOYuGonL"
    "C7MWl5MLFOSE1xkMO+ovFzPx+MJiPrqGX9dsrS4WsxGItzWtdzgd7S2Bd3/8E787F33+zQi090Br"
    "IwRzwICrq4FigV6Zzi4MDY+/etu+azdtWv/4E0/MhYex40ZwWmh8RpIlmTJKKRFgeaFUirQsC0v5"
    "IuTLLC2wKh6dVqwJ0HfdiwOHsIXK7RsJJ/CHBmj3ddi2qnTy9TASKrTVirfc6OCRivnZ2ELKe+XB"
    "ztatvf90OTlwTJrY4671l3yEX/NPH/zlR+55ufuGzz526Ofvue4ndlpaT9JLxcnG4G1H5wY6tyas"
    "tnVpRvOu9HxbHU4vut1S282QtArfebz3ptbtf7sj+9oDTx/oKqaO17EcAeQhx8DHY7iI2xyUBdmQ"
    "jCsplrFAiRBMsVQS/I2sUJYcdn90uTyelULQ3N0qOoTcG/l37rulJdj06vojx86cujQ9spJdQY6j"
    "MgVl1bIGC023o/HWpKZNH1XcKtlZZjxERseUssQMNY1MK6EOvBbQrGAghsXQs7uatka9Y/M71PW2"
    "HjJiuvLWejSTo6sLVA0fQS1CUi+koh4OFfRrGwEhAscBApNLwAuqkSoVeZv3mo5VjcGGr915/9QT"
    "s489+sa5lbM3fuA2ifBzE3PLsxOOvtbHHPl4PExysVu7Pj04PizY/azUlCJLHfxSLWefs3dmsrjA"
    "NzZtvjs0dlKydZPkRfuyOwZLYbrkr2rzun11tZZb3/vhzz5+aZFz8Tt3Qnczq3Eyh0DzEi0juHns"
    "roLE+i9v/Oib//SFPTffJtg//vOf/m84OYUtG0EUpGS6zKjMqN0iZrOZhdO19XdwuQLLAPH7mM+J"
    "LitIJXLNdvj+L/FfvsqKK1DM056d8Ll/gTkJa73NUZajLgdYBMeNm+4IViXjC8fmn56VDm6r4e9w"
    "9rWHTp+e/d3qrneWiGe64Gz1tH3+PTs+99XHG57ll0uhKX4oDtH4CJkSira13EfcIze1N7/ZaXM9"
    "G3umn97129r5tHNwKTA5Ozl8Sbx2aO2XPnCff+evf8mHSqNBAIQkhW4bLRI8kyKtHlzloaMIQBhH"
    "GXGCIOLKHIguYW7aMjmTD/ZFct7MifEbvrEfEkUeOX+Lx3pa9FndK7EI44ERTndJNV0MBiQr8G9S"
    "wLqk6IDXTIAeUtKUsaKuNa4NTPW/ARCABz2uapAXNb5jrAwwx1u1pbyGIw0Vf03A1nLX+m8VNkW/"
    "5op3inerRASUimjV/zWi/toCeoIMqGh1ujz+fC7BWcQ2b/UN1+xrqK5yeR1tWD//6tKrb5waLU96"
    "GxvmonLXrgCbTVgsgRO53PjiJVLK717zURophaR4VcEpFRenRXux5DnMN1a5mhljA6mwmItW9Wwv"
    "XznvpB3BhONkboBaiM/j57jS3jve9S/PDC3WdAnr10jVPhK0s1oL8xOOE2mYMpFxDYGVhdJXneL/"
    "ffHLT37727c8+KGxiTue/eufCpdeAXs9dcRLpWLJYrEytDhx/JjYsG2rUHMyaONrXdQisukUQgna"
    "A7B2A/vF79jYBBEs0NbLVgBfPMqaGtcf6R+8UmCuGzYtp0K0zv7Bho7VtZ+5Ujgfz48MFGee/p8n"
    "jj4Wvf/8SzU1jRwJAGvbd3/w/xbpw0/+buZNyFpBEBAzhFsLYpR+/k8DW7oHOpLeHz6SuvlfxTcd"
    "7QsnCJRQ9JdXrVo8f3Huuz+/4d673vuFG/p/ZpuOpVEOWlHggbOzSwUYXWGOPPqqQSDMZgeZh2SU"
    "CXasasZzJ53g89d6wuEpG+8fOhxavaqGL3OtgYbNWzfwdjEjJ67Mz8/HI8VSTl8Ppiptg+FUPCzS"
    "QNpV3xm+sYmA6yREd6M1aq3oZAbatih6YYIJ6Kp7bib0aKw0NkNY71pFpe4raz/pyFZzYPpSaENg"
    "UHdOUA3/g5bSQM1L0FaHgX4AwbKUL5QKblewxutfXdNe7az1OtzurA3OFk9cHJ4vZRuaVzuqvLd8"
    "4KaRbPz89Ex3a/ezrx1ws1jL3vf1LQaPhZ4RAUqpmW572+lcxMbv7ajfXRQES037jr0PeB3eyyee"
    "i81eqHZt8mA5yxUC7jqG8tr1q16fLIZKAl9XIyFAwM5qbOhmyAEnAPpBkjhgTIzPjCSEH6xpJTXt"
    "6fj8vXfdMnhxcHTyCt1wL3UEirOH83Y3Xyo7OctyLDbwp/ZbvrRYgpnZCB/iWa2TtfmgLANHqLca"
    "dtQRWcLlNDe8mF9arLWV7LM86bpz506Ph9hkImXGOftabiS48sOOIG+1tuff2bQ0Lj/6h4mvffbZ"
    "KvHuo/D9h188mzjPyUu8y0vpJSQBTgySXDpfboHQRdsfXygWB5JCPbv9rtUTcedic4LGvPWBlX+/"
    "cfg75YY3XzwRz655YP69f7/71H+FD0QzSOeKUGeHRhuLUBzL0aoMFgmwPOPLUC5yxMqdOwFoyaUj"
    "i6FQS8Bv8XsPvHK+xbsP8iVrhzA9sfiXY69ykiyKdlkumzxMTSHrjmyF04qV2DPQw0zhGB1betiS"
    "aWSCMR39qqrVE2FMDfio/Zur6lCDsOF5oCGBTP1PNyNme2JyEoyaJhX2etk0mApIjSiSKgu6Cw6q"
    "QVC71RaFAUA2H8vJGYmXUtmVweWZOzfd6MyR4ZVw9fbgVueuM0eu7H1oq63L/fJPT6wK2I6eOZGO"
    "DDXvuSlYco6MvjyTG+3mejJcSmK2EqUuEO22GnTK6HfwBK+8+EJJlong8+RyIRrJiflqT7vHKYCn"
    "/vVQifT0yk4b2HgoFDHGASEUZFouci0e7sg5+e++QuNZG8sceejDYc/GujMH3/e+D3W1t16ZXSo7"
    "PXI6l8mWKSzIdmfBYRd4GLuwKH5v6/aPkoaaKQ9BYGSlgMhY0EHKFAlCMl2aj8NrI+1CzecIyrad"
    "9es3bN7EbM18LZWTDi574k//9r3fn1v1IH71nuQHd930zj97//nbjz7z5HL79t8//Jf+3CUOwpAT"
    "y7ExRlIcjTEaE22yvcTnCokiH6TMR+xryFBm/D86/R/L+pxldoNj+h9fq56Zd3FVtoXlcCwiVNHq"
    "lQuEvcEgVYD6DEMObALWWYCKlAhEQlxZAhnZ9CXSeJPF47HWts5Jscjc0j8+9InnfnTo5Vf6N1fV"
    "rPW3vvfB28aXpn75wh8y5Zxshjmat1ZW4iwV9KdC8eoOsYlimNDDKvCoCYgRm2SgR4F0SCqwRMYU"
    "+q48Pkov7jSV6+l7mRjugU5lNEHRhqhpcM0bqZBfwwgYfgSaqBFqgSDzE8yV2k+i7HOIyHOCYJcl"
    "JC63YLe/Pno0FJlv7d20sW5d6Vzm/e/a493Z9JNnjm22lq6E5Mk8BV9zq6UpOXRsInkaBd7JCx7W"
    "eaU4Y7fWbnFuHEsv5lg5ZSWR49P79tw1Mzcr9kc8xfLJ4ptWl0Pged4iHlkRiv4a4vOCxw1VXlbt"
    "ZDUcsTIsIy3K9EoUHvkyLsZZc+eWHVs2FpZ/8NiT57d137wY9nh9VoGX42HfzbcW2pzZ6SnOZpHm"
    "R1tkvxOllVfFK9n91o9cKLSMSnIiZgerCJkkFDjg7fKhpdYRuDtate29m7cVbdFgJLRYWJ5EMl1I"
    "JLD8FfvQtx89l3qdOxVi/3py8v/++WJX8M4/f/2rl/J/fN8vX576K28ryMUlhitIrCDyopwliLxl"
    "2dG1usPVaB1/40q4OeXthcOhTHvN1I97d7ww/GcxLU4ttsbSIjiFIpWDPj/1xrCdUisHiRKOJ1Hi"
    "gQgs6GEzIY5amIBQygNnBauX5cflnLUoN7tbN2y6fuNrT/d/+IO3pS7HPK2O0KVwy86W+26/cXhy"
    "+KVDfwG7EzgOQFZWaGlPUwFNdWqOLJpQUwEhQLWuWt8g2iQ0WqAdjCVY6ifFIvAm6TFEQ+M6ukix"
    "Sk4D+iDZVYNTmqmUyQqX/W3MGJh/N/2EFWlk1HwcZWtbQpiRqyalYl4WhLycnl5YkcuF3trm21s3"
    "SKHk+p1rPdfUPXV0qN4qSIHao2+O1/vd13b2jU8PDZeWrZ7GbeWOgMxfkmeqnc3t9qYIb5sunCtk"
    "E+m23Wz/jS8JVS3nTzrKhXPZo0lYqhbbOALhTGl8pYROoKUyAmMch0CpjIxxmC8BWOGFl2F6jgYC"
    "cOHJi+H+E3wdm+5P1QqhpeV0LOHr3JYX3AyJ9QOf2rGhVh5aWHjh4rcz9VIsMxefe/T0z147mXOv"
    "quu5YVV3TyTCs7I7EA5Ly4775kNVPvR8BDPr+r9WfX3rfcHgxPLUz7xVrU7Zlh8sRQ6tv0E4FJUb"
    "GCEz2V0PvHbHrefvv67jRPPY3DSKc7SYYkRC4AELvGzlKVK5BMU0LI+UvDcG29Y3Fw5N5xKp8Bnh"
    "V1OT//juQg0LvDbrKVKLqx1vaxu1FrK7rln7Ujxj93N5p1wuyCAjOm2QYZhnzCWyxQgtZ3lPo5SM"
    "iu37rU5bYepKgfNMjV/q61h1wztWXT58pddfkwjltr6rKxfNO5y2Tzz0XgsPRwZPRLMpRMK0Ldv/"
    "n4gAM0Mwvjc8Ay3NZKhU0AtBTazF1DD/lggTaE831ffBwoqfFWhq2VwT2JnJLGnOs/a1OgZmkgeN"
    "3mi9alent6S+1SsdELQHe6mVcER7OBIFInCyXJJzkk+w7V6799Y128+HI8tWWtvF/fzA6TqxXFtT"
    "/c3f/H5LlX1d9eZzF/rPZmMWKlWhR5TKr8OlVv/aUko6ED++UhcU8gu8q75Y1+iorW4aWvAVyBki"
    "50sxkbPwopUjPEVEQQCLDXgeUMsR5hlIEhACCZmNTUE5AbE8SsXk3BjxIXBWKOaWZqKRpWjevV5s"
    "2ho7NsBt6PV4YMPehqcF4UDJ0ZOZ6z3j/ueN3/n5ub9MLK8cnr7+zaJDaAveur5vqTR/aWLpB9KF"
    "rWw0e/RQsSN4/Du/qu+0t7W6NlpzYV68vY2mx+eub+I6v0irvbhjo/XERf6//zv58dOnoQdyb3LE"
    "SmkeeB/yhJViMkvmAaBclOW0XFzMpeeSHKOQs1iuBAtMumiNztyT5II3vXE8avXx+7pWll9ZOHGZ"
    "NdQ82rhlQ6vfM9zLIEGxYGFxCpzI0gVMJmmVj6AbVlIcRSE+x5I19uo1nqaNi2/+PH7+TLG2fmF4"
    "bv3+xoN/PF4nWuo/Vjd/JfKDP/7S6fT0tq6bmBmOpKOmRbCgcnEVuKbnoSpYoVS1D6ziF2NVrY4j"
    "lbZcxU90ecC3e06wkZRCY+GjsWpRd0+ZabBXMTEtYqrwd8OpMTE0fdC6xVK2ACYay1eIFwIQQC32"
    "rywIBiSqYBBkgMgBEMYjNvnrr1u7UyTigYEL631N79t988VS9t17elcy0le/+h839bT5JHz8xCsx"
    "Vy0C0vgcitZT/LTP0+Uqu5dr0sKq3R1CUJRum+Vi1poqH5PLeTZaU1UHW0khfyX/mijaGEcsgoXZ"
    "Hej3g88LditYBSbwKMvAUWbn0Y9w7fXw2I+xYTV4ggR54KyQjLiqms6fuHRr7Z0/RYnQnDB0oPS9"
    "2b9O3MI2b304kvmP5184/dG93/pOb+3R0m33dh/0sH2Hz/9XeqXl1u4dQZ/kL61+5ru1I/3pnlUD"
    "/RMb6AqUIXx5UeDy6wv5hUgq04X5OA8W6FvHFcvl0X62eUv5wF/XvuM3Y4e/l/NaWcrJ7nsfn0Dp"
    "1MsgxYEyCShhuTIryliS8xIAR4kfSpPgXe+oDfhfmVvZ5758X0vREU/N/izx5hlmacdf/Tzy7c5J"
    "lis5ai2pOpHMMbraRS8XocXHxsschxArSZKDs1XJ+Zwz6GWFueJYce2Oe0+9/mi7ty5vS4cm5u55"
    "//W56QROwm3v3DMyN/XNX/xXCooolRhBbXkMMgJANU1fobyhAvRXof9qHGuoN57CrbsUxuH81Scx"
    "86lXSY4xHhP/R1U6wLyKuGJ8FXGjCvdZDy0pPaBK07TnIBkFEVrs39ykGhLiCHAcQ0BKBZvrqTOv"
    "J6PhltbO6p7VljZvc4a9NhA68/rRNc0tWfS8eOAJ9469JFaimYTT1mAn3kZv1zq5zcbD+M72ocRE"
    "C2ufWZmh6/11tbW25exicsKbWGjLc2PFZQqM4/iyTG28xJXSFBgABeVZlCWBWRDLwGQZLYTtXA+f"
    "+AL++U/M341A6cxpcfVODm0jo5c+1HjXhx+85tfhwe19D7cG4+Ejk47nF3atvnbw+hv/6acn/zmc"
    "3HZT3/nhxOkojR095YguvtJbnlrfsO3pJ951+GDT1qZS/dL6G8unx+fPLModfTD9Uli2cvWb+FYB"
    "SbXU0gORsI2miCNRdjWKi83luYU8HydFF6tbBV/6SLvH3vBh+uZABnKzjBYoUAJApUIZ0rKlmi8l"
    "C6WiXMxmbU5HvxfTXWOL34K63ZxrR+0712Re+VV6072WJo/N7igU3XlCkbY7YT6HnU6YDaNFpJE4"
    "83VDUxtNZaWVSVaOS5lCKTaXkHHdupuXRuYeePfdL3z/+Wb/O7tubi3M5Lgid+cN16UL6Z8++2g4"
    "tqjaUoJMNtWIao7s23GhtzBmMBVOq56AWcFWEm+tTV5DrRprUQo9TVV1RsIL9O802TAZGy29BW/z"
    "MvVsqhXSGjGGr770xV9K/+pKGfWZSGY6RhE4AohICAVqtdjml2Y4X6Cn50aPw7lmy6rGWvEvLySf"
    "fvWCdW4xUNd4+uUXu3feGHY34emnLY6GOqxvp9w21hKOTnfV7Hzi1d/eEbhjBUPLyUtr9z0oZgrj"
    "r77YyjfnU6FYli/YnDQNZSpDuegSoboYX0wmiIUDoCAS5hKJyKOdyHaeJctQKuMXPgk7tuAzTwLl"
    "4NrbGqb6h84+ucm6v93e8cZ4ODxyfnxkxpvrq82FfS3N33/6B//k//C/fure2QOnJ954vefzGxsL"
    "NBM7e1t+buv3Xmvwwl6hHNxYXxgZIHbnTBKresSdN+V33t09cTry5AuJnj3OKwv5a64X6hsCB55f"
    "nFsUbYvkRAy671+KTjBOQrCwzbuxNVgXEPd/52Nzj6Qmxg5gfo5JWRl55OzA+9HaWWzpAGeRu/Ca"
    "ROrLmRDffS9u/mn3K+760zOsKx276ZvDdav21Ajbmup+PTxVKq+x0OUSXiphnYuWy4RYYNt6Np4k"
    "DQF0OcFpT0xcCLbdVNe5efbEH9rdu9rtLbUF16333/jSM0db1tR5Oj1yvlzr9jf4gqtae5KpaEHK"
    "gY4fNL1TC0MVwqOV5hjOpC4cV3maoGtkZgaultnSBYtXW1ckRo9IGlpb3ajE0OAGvWembBi7WsL0"
    "465KtCm0RjUCapGTVvev/ateHSjPtGP6g/FMAqMnipW/yPOZbJxRBqw4R9jeOx9a7/B9988XZ5fz"
    "uYkRWpZb0LW5dy1z2q68/mchn7ZzVdf72hti8m+nf7rDufvfpr9uswR2V635fezA2kDtlqLzDy/+"
    "oMnR6eXJcChjadi4wmKYthVLBVF05ctyJ0uFoxHwecAiAscBIrOLpCxzg0nGE9buQk7GG7bQVRto"
    "KON74TnH2NEFe5Ms7nh5YToXit7hsN3cvmEynfzF0J82JHa2W8Uzf3l+S7RQV+XzL03P/PJPPRvr"
    "3rOm7IgkEym6mEiOQ2KczETdcPSZiL8Wmvu4hhoINu1tb21LF74cWpHSJZYqkr7q92ze/NeJzFRf"
    "LeewcIsJZCUACZmEPU0kIGKpYL+m/pZ/+sjjfxddCaWQlplQA96dbM1mdsOm+ndt2zpw6eJDZ6ag"
    "ppTnkc+XuLbaC6ftJJE6v+IT1tz5jfb3MeHPq2ZCqRnnEb/L4rDnhmUoI5QlmZdIsYg2AmNnGLWR"
    "qnrGion5Mw1rt9l9XaMX+he5gRa79ZZb99R/yfP0fzx1/xfvFTotXLXodNh8nF2WZcYoIqc+F10h"
    "72Bsj2JStSr0zJ6tmYmoR1IjdKmdZ/B+zbYoFqAigANqCEiva9CwrnF9ykBdmGg8/UaDsMZklPZN"
    "9oBpXoFJClSRU50Jc+m19kBm0BwBZHpASJFG1JcoACgVQRwvIhCn3bNmx75bN2+9bs26f/zFa5DJ"
    "O61V0YXprqCr3eYYtwSG3nilNpkpl8v3NW1vz7qPhF4rEjpaGI9L+Wssa0KZ6Wx26YYtNz/1/P9s"
    "qd/CSqXy5ExbTcuR2HOSbz0s23K5pMPhkMBC4+GN7qn+eBB8HiIVcWWZ1dZQlxOIANUiFGUQCQ3l"
    "IVp2vPC07YnvLbTdbrV0FCdSP536+Y1V13nmQ21u/70OtnXzLc8FNixcPvtvE084J/7nQ97rbnvH"
    "bRsvn0tdPAP10m8uz7LGwrkV4H34wO2e6IS8ZSM3M8Ca64tlBouLJ2q67yXuVedeG4nlLVln/uYt"
    "xdvW7KXuqfVOsibo/tN8VT63ggITASZCdDE/VWedZ6XeO/v+ceSeb3/lUNjZjmvvYe++v/rOzi2N"
    "ttsBUk9GXgKKhUlayrPZFe6rDZ7WDeTMTPAXy+EtuGqNs+WpzPnJkGxrZiQHZIWhRWDTKbSLrKuG"
    "ZXgIuGmoAHY3JKPY2CUtzKYnz6zbepOcHwxU2V66cpg9RW9/3277Vt/IXy5s+Mx2kuZuvWPPpYtD"
    "S21956cvFyWJUaq5iEZqSI9doqH89dI0BXmqAtYCoazSe9Bpvx6WAS3xzLSlaRrcgKHJ69BcYc3T"
    "1fSzKUBpVIiiDnHUks9Gw1C504tatGdW+doAQMtXIFbSL9RGov6LyuNGGLBigbO73e2rra09K0U8"
    "PDHznVfPyMB2XbsrnI5ubG/tsgXzsUz0yqW6tI2T+d3266RM4Wjo0ASZzwAMyOf38fuzUjKSnbS5"
    "iyvhK968rWYxS6cu3dt6+3DiRCk5za0MUrmQT4fzhQJjNJrKWib7tyQuC+FlOrFAx2ZgJQ7ZPFgQ"
    "xqMsxegyY6ES/4dfWH7/nTg0FMue9kjsZn/NTf6+lchr26WlDd1yVVV0dd2anX9302duXreRczzQ"
    "uy4rnQkP/jIVOnRlafE3A3MNd256348/+bff7vLLbGaMmw9bp8P8sWny5HH0UJyZGaJsMl3YdHGE"
    "ylTKpMmz4795aealNnegyisDMCrZa/tArEYosxMH2CO/W7gcfyXKDp+IHDw3kZXysOdO8vTX2j61"
    "dmujsLtczhbZG+enSywFUgRAgCavmLIITdX197Wv6a5rub5+QzgzmaW5fJtPbiVCrlhMFIEwZkXo"
    "8QseDySykMpA0EdWIhCoh9vuKbf1jvY/jVKSa7V3V/URYktwxed/8NLOzVvQxaPAWAEc1Hntjh0C"
    "E4hgpVJZX3SFOgT0D6Cvj1UQrIAKmBquVOI9msrWi/lNWhhNGNNf+vMBVN0Pil425ePU4ge1ZtRU"
    "xwBGNkDHb0WlhH4hijyi8S3Tyuc0YDOm7PuAasEDU8gP0ZNf2q/KRCjXgwQoFWw+e01DIjKBIkGh"
    "lmUXNtT0rl23M7OmPHQpfA2rcgU2/7X/td4WV0e8aqiwILNsvaP9ysrpCIkMi4tivvig48NThblq"
    "hyeOSw1yVWCRX1NuHFo6cdPau56eeCKRSIm2+rIoMG+bJBUTmQQSdIi2SKpYNXh0WyY2W9u7UttW"
    "yJZpMgfxLAeMJKb5U/2OM2fbJmburXnk2XzifCEzGJkcS730Le6GTpTH008uJ95VbK//l+mzMr31"
    "Rx35ZWdon7tX3thzamngycRyS5Ut0FJT29bqr/+Yt2bHn/7w8a98Jyo4SC5Pq1vgZBjFV/gPfqyc"
    "kYacjhqOB2KntbXkL29kpjLpu1cHLVnbqZPRs2OLpA4sQZYdwcQAO5SXPx4e5B0DU8OwdAYEAadz"
    "dD7bGxCDgKMCz46Fh8+OA6RBqgbnNraqpepsbs1gPMRNzz5Qt5kHP1J6Z7rjcm7uhfkaYbhs32xL"
    "jCbJmhoAJp9eZLX1gCLhLTAts3TMxpfkG+6R3D2HXv7D6pY1L09cuq5rdzyyMh2eXne8sW1ta/jA"
    "dO1DPQvReafFesOO6xLH8xGnY2lxQSEgSt6UqSUGGu/RkK/tp1IJPbjaJ1ZlQStuMG1EYRAiXidD"
    "ahsVJXDa3g9KIB8186OKy9XSpHvIJrlQ6Iu+kFi5IMIAGdEGiVrxj7G4Ufs/MCBqDtjsJyAq4JcA"
    "sVTKWwTrdbe8b+OqVaubmrrrGi/PJB9/9kg5mv5M05aL0+Xvnfrz5o0bmuZtA8n4dGmkx9VVEOMx"
    "B51Avpwu73dc72L+MXqgjV1zMXf2Xvs7B0sXHdTjCTqPhd44u3jRLYiL+RF/w3vKxbGsWETJXkgm"
    "smTF5fJFkoyePuwQTzqq6hMOF3U4JUdzlvj5ZExeCW/KeT7l+pStyAoB+VQw4dmzSaD5X//lz/eK"
    "Un1ZPHblNW/vvVsSh73f/HgRis2BwqmVN6dslrQo7W61FoATbI5CoRgNT/tr7hjOdpfwkoUHbwAk"
    "QIcN3rhAG16FG/fPLK14UAAgUKasmfKHnqPffSLaUc3eczf/jx9c990XJl+LZkU7ZOaAjbCLCSYV"
    "sLyCNEOJk81egr//3Wufuq3D5owMzxb/8mp26TKgCIygMINByetybzgYXm0lg9f7Lm9w7vZbZsNn"
    "z9RPUZ8/M0p514yEAiVrrOxMnkoS2VBH/3qKX7uKtnlli0+KpwgrONdtymeWJhfO8cwdzqRT+el6"
    "r2NqeOqau3bNvXQ59+eZ4MfrXz9xkDJo8DdOzIyo0NExr5cvoLFqWAvQmAk2VLx0Tay9RZWh6JTe"
    "OIXXcc20zitCpWjCNUMTxNVfK4rvjLGjqRPDluhnATBgRF3PbpAmRc0TptIfxeQZFRCI2rJ3AMFX"
    "x1utVrtYV1/f0tru9nkyYvB4iJ4fHz566lwr53sHqz9/bubRxIC3gd8s9PafOXmZXJEg31e9ZgIW"
    "Z4P+fDzitzbG0pHnihcfsrxrIjm0h9vxx+Ivau3Vo7QgZtxXEhNBa2OMyGtb7gtINYtEmpKnnFyw"
    "hu9wOO2xcjQcHSZSNuvw8VKZt0QzfAICbQ1BZ7yuKm5z42uXYlXZ8s2dR5fmnIvzlrCjubapevO2"
    "wMHvbXGRi0vRxZOPJvhEfWpkORBgW8sXY7bWLt8zL68Eiuz2Ouqw0lSylJh9IVi3sbv3uudfumRn"
    "WCyAiCCXwW6nL7wOTT+4cPhozmoFKrPFObAKcnaQ7X+Af/b//DwCQP2d/PKsPzNXIlKeSXnITgLk"
    "GZUYyMAoZEfh+C/K598YcTVCJgSpYZATILihHKZSBP7h1sE7/+6Dzdd9ZJ0t/1T65zEhchfuttRW"
    "12RkcSnLh0RspqTXThxCKZVGL4/js1DMydFl2tXFFktyLFsaOkxqV1dvv60GpcFf//fKSqK9elVx"
    "ZeH8ypTvx8/tefdeiJfhXPL9n373l/7h36LLsabqliuLV8qUqupW1b5XRRY1R0BVw5XlcpV1OKB7"
    "CeYQETM2CQJAXvc+dWHTnVnV/UWmRYGUvLK+fYnOwq7KGRPNudXHhpo1UBoGbZWj8rXhFJtDQAwJ"
    "IgHUl7wQwxTwXCm9IklOWuAydZ1DoVQV9cjLRyyik3cEd1+/Z03ePzsTOc7P+eNVjbiOZOTzbDRS"
    "WtxWf/sioZec7mJiyeFskkqT50vn7xXvsDFLO2s9UTo2wY9mS8mF0rIVgtc2P9Ro6ZzC0Dgun40c"
    "ZnJObN2cs1unSwk+Gra52q29N6TSc4JHZD07Fk8e3xFs//tkrZwrff36NZheHlpYeDTyRmBlhAxf"
    "3DB7bs0lVpdKrQ8IKa74x5SUbfV1dQf27lrV1Tr21B9n/FWe8Qh7/sWVeFq6EC2nk/jNTSVHQ+TV"
    "516bnZ9dCvECgbKkPHIOmMQ4gmjD7/981uIEfwt4WxmzobcOvvADSyIg/eul7NkX5cmRA31d7k2r"
    "hSm3DJQgZYhMlgBkQEAogLTE5DCU50nOy1gR5BTjAoA8sk768CNVjoneJ/500XroO8cphN286+E3"
    "7oHVlpUUlkTLU5m+ape0lpRGSPbPi8RHYFVA/usc5ktsbom0dct+t3ziGBOdUneP3Ytrd1wjnbht"
    "dnZha3Or09lS2+59+eCLdGrp5kceZO2OywcG7tx9w8FjJ8eXRkG0QNnMOhRcURMwTSqfAQDR1riA"
    "jmFts3RDErQCCSW1alARYIzXPWWmQ1itLTKExmwMTPKoKXN1BxPDW9cNmebIGwFQvTxV60t/Bgwo"
    "QU/lyhX2z9QdUBCQMMIBhyojIjzjOFku5SU2PXgUka00trqbWpz+hr66wDUNgd8cnYrHlzbMsMJI"
    "ur2xZaGUHEnO+hvWCQ2rFr3uwuw5Uly2BHckF062WHrs6MjJmSG4dBYv2GXnkpQoEtgefMDP94wX"
    "zuVErOJqna13hKTlfMAntvYU3K4UFMrLM1ZZKrfv4m7eFb843lOC6199k9RsmGChm0NHD27e4gr4"
    "Hhx8Mvx0dF1ZBJqycsURQb7Iy5YOT3wemqvttQ0N9Wt2NN+yL/zif37hJytVFlzJyzyAncDpZfjv"
    "I2E2uPLUG3mA16wcOKwgy5QgMJkhD4QA7wFPG7IycH52+4d5N8cGJuXUAvnpr2jPtoI1Tf/5w4G7"
    "tnaESr3h4m/P2En4TcbCyDkYzQMqT1CVAQjIWSYXGTqQD6CjhZevlb78fm5j994/rbnzPe+YG/zO"
    "9377ozjfxF1cz+D2s+kr+UAL8fSwhRRXU8KwJCWjJVdVlRhwx6RZ8PlZNAnPH+K376feAFuJ2+qD"
    "qaXY6OFXvbX+rJCcnhupQ/d9u/d1r20NPXk20j/ecvP2BF969NlnuzraImxlenle17wqojVMMQ3J"
    "lTtFMO3RY1rRG5qzYWa/WPdOdWYPgKA82N7sjWoGRt2SR8WvbhQ02UMlxWBsSWEInHaGmW2pel/Z"
    "QF3zZbWPCGjYAXWlr1b1qfB9wgGnrIHkkOOV9ZAoiGizIKEMpXxmxV3V+sA1e79+ww3PjiwHGPfZ"
    "eEP51OWadTXFGuvjF57yrbtOclUvVHsSiSkuFfI2b8ktj1JKLWgpU+mM3H+YHXaCqwqb64TeIOkd"
    "jB49kHr8Yq3NXdu3JdDcl4F3rru7z9WQHzpVWghbMowxB5udsBaW+bFR6xsHHowLbp/zf+d+IiWP"
    "fSaavf257zUe+FbZFU9z6fNCaL6epm+pL9/avVRvs3bXXkgU+4JiMlOIR2KM35zgq0qU5ovMhggI"
    "aQpI4OlzmafeSDo4sAuE45Ax4DjgOCA8oAjgYO4+uOez5NaPIOeC+Tm2FIWZBdbWyNXnueVR+MU/"
    "iA9c286LfR2utv94593tfTSwlXe0o6OVCB0AAYZeRtyIdsQAE9rA2g5SCWhb+f53Q+EEKyZS/uVT"
    "i0nHuo3t0CxLtPiOqg6yxBdpPnkpHRTFGnuZnF7hFiRri2gZXZJPh7DFD7312FRHO9YwC4F0CgRB"
    "Onc02X8sXGBFL79t1+7Li8M5UfrRX3/S1dNWt7U5sLohN7Kyc+eO1eu6D030Z+USL4hq+RpqFoDp"
    "nqYaPjE+ook16GBTtTFWQBF0osEMbc+YUg2qSZthYipKP3VtrYZP9Yb1lhUiVkHVzL6CLk9ag8bw"
    "FOiDFkLVc2GEKTU/oOz4wGn7PnDIcYzjkCDwPAg8CDwS2tC5vrHnmrbWjiaf9xvHhvunFv/TterE"
    "5JnR9W6LK/DS60dsvZsYR0GWopOTLHEp2Lw5m1jOrJzhGW33bRmInxym59zgqYJGu+hPcgl0ViFa"
    "pNqG4I5rpxLRfP9In6MhfeGAw0L8wfZwbFGaPGMBnmAWjz3DLpyzOr1XCqPrs4lNXJIvpiZ8jtHM"
    "5eYW9xgp1rXamoAenc2uXtN9Jcz94YXsjcWlyXTxzHR4x9bqsanFbVkhLdUgXC4hlqjyfAigFCwE"
    "CEHKGAIlBIgIvAAEgbNAsBvstVgm0N1OFpblYhyO/VWyVqO9CqdixUcetrY1pzvdHWlJcoIF+FB8"
    "ItP/S2jfydM7CpFxtHshfxlL84SzAfoZC5DyEMolWvcg/dSnej7W9YHP/OQnL/zpwKo7D2y77it7"
    "brz/L0HZCbab23sKrzztamDVJ+iuLd7QG8loymnhWFUo2dTJD/Fga/BAXUP+3Djp68KAV44toEUs"
    "ngtL2Txs3RPY3OMtk2tX31xbsj0afW7j75/etGFVNhqt7tnErhRvuHb3Xw69eGTsgkxljXCAvtMD"
    "gqb2UYu9gF5c+ZaXYQpMlRFgrCszO6UAaFSDMpPG1h8Pw8yCYbCZSphXuOGavBh5ar0NXY4ZIFFF"
    "B5nh5ioPc1dYvrrhM4eEA45jPAccxzgeOQ4FnhGCSt2IyDOOrBSTXGggUkydneJba9f/cOuuxUvL"
    "Rza3rOrcPDd6ec3Du7jiQmR6zOpqhJh14tyaxPxYJhehINZXbRvJjcyVh71CLSunKW/PylLWym+o"
    "2y/w4lh6PJPP5a3W2Wa2GD7vyWCr7Lg15v7d3NmitBSxFKmjPuis84ZPbhpbdOdjNpQ9AvdmIXM+"
    "Eq/t6Nhw7VYixzZvZGTixKGFxEd/PIBFtJbw4GDCS7ifD0ZtwdkbGmyQjsXiMgMoA8igUUWAEgUO"
    "GEHgEDgOOAF5K/AcoMhWXcvf+YDlh/+bfeovtCTT4grICA4PeqowBZRvL/W0tcisy8nVTNOTyyl2"
    "/8MDvXXk+e+3nY5xTwxdGbpciBRZ3i2XGASuA6sImQKUOXjkvYH3dH8oVGz4xg+/8tjjf3xp+lgt"
    "PCGkP3Nv63fAUSrPPy12BdKvJ1nU6hVZIC3bNvuHn8k47Jylx+cMc+HxtL1XJC4fGzjJLy/DdXfS"
    "gYOQy0K5OPfkd2v2PJCw1N+wfksxE7VPOwbOn+mpqVk4e8nbFMBd1W3e6g/ceudcJDS5PIeEUCoD"
    "guYDmFZEvvVhAqjVZL5VFpgWeURTIwbEFVkxFcNVFBlc1Z45C2v4wEoKjiler2FwDN9YkxE1ImUS"
    "HAbali2aRVGyDHrwBxEIp+77oIgBLzBBZLwAoog8RxDEqlpr0Ov0uAvZbCnY3Lv5Oi/lb3YHk4Q/"
    "trrQOjG6cu7xpamRlYmp5YkZlPnOnua2dV177r3nrz+eIii46q9fXjoN+USja2uyMM6DmzAxw9Nm"
    "xyZviZyffDVR6yxOnivKRWK1hFd3Id/s7p9sWUo9JLkPZgdDmbn11irf1BFLZs4LOep1FZrkuUii"
    "w+qzOwSL31GyONuaqlquaxhj009NL/OMcAAcEoYsRwGQfO/NqbRcODL/zSOHLiNAmSpPTmQaVVQV"
    "SZmysgRYZCADZWCxw8AFuW5V0VaAs09QmxOhxMCBzMX8jeisk1rcAYsUGCkeWO285vOvDbz8JBNS"
    "/K9/JHrluTvqtt7VuP3zmT9N2+W9uxvD2WJrMwsK7uCn2n/2g8Hf/dfidX9cmpHqbSXftpu2/Pbh"
    "I6eXJj54zXl59Vpp+WVOPidNp0cPSOItOPZKQogI9nihfDrC390mpagnm7PuqHIvjKzUWkMSJ50/"
    "Z998Z2nz9YUX/1DddBMrpCePHChJnvq27P7r9gYFX5+rw9NYwy0tF84tOXc1xBfjN266/siFiwuH"
    "woVCHgnHKDXQUgGtCkVt0quGJ2vmRJoLUXmcXn4MzEiEaQKjnoc6+9J/VJqgBsS18TFtmePVy2bU"
    "QaI+QG3kul/MiLqvLWihTwAtEYaARHnyBfA8E21otROLlYkiJbyMJF+iUNdTu3r1NWtXl2QuEJpP"
    "Xzn/+PmTE4Nn5NmJ7OJiqlgCAItj/ebdtzbWVQu85fHf/2ZnLrf9/ptO/O5QITXMyumAs6Vg4fP2"
    "BiEZnS7NeQJbi27nYiGasQqJ+DDND1lsbtK8VuzcHnrjr6WV0EmWj1nj/ZFLTdZgfP5QOBcPcfSm"
    "rqbOVat72hdPPnUhnSnNLGdutVfliuVkSeRcDYvWOoENOHguI9MyA5mhBOoeBT88tACHFkAvANSc"
    "LoLIgJUoEMZqLdjgwCYvOKyMIslIGLtCn/8PKjN02kEug+BA3s0Cjfyta8UQlAUuyzG7s9xVxqx0"
    "UMg9JoOVhqNcMl5YoGNdLvnNV7N3X9/9mdX7r8CZWWhsg+Rl2L/vYdfr9z/+u8d+2XPT0HTinqZi"
    "/b/c/oA35lnrvQ7LS5wYIeF49HTEfws3GytEz9HO+uLli8u1FmhxMXl4OVXXbF1Iy9NJR9cWu1SU"
    "p2admVjO7qWNG+wZ1tewzysUBwdfmx4cqdl7+83rrw8dHwnY/ZZdq3GBFkrZgenzxxdHO7u6blje"
    "fXq8P5pKAJpcVeONhh4Vo0QzCjq5UHGoxiBNS+vVSgk9MKpRFc0CsArlbnB4834p+koZhZRp7vHb"
    "EDHUTgZdtSviQVArYwN16wdNZvQ9INTID0FCGEeAcEg4xls5l1/21cs2Dzgc9rq6QHXAF3BV262+"
    "lYXcj56fPXX02MilXDIOgIIgcqKFWRwoSQLvctp8i9OLl84NpfOy4G448eLRB76574KPlJdX7J6e"
    "TDlE7Q20kM2V4kLNlmJN/axApjOXqh0WzDm8dQ3Olu40k8mVU9Zc+ED64AOulrOJ2XXMl5bKF8th"
    "P0BSYvFsdltfp7/RdXD2LC3nBJDPjMy2dC3Nh31yiS1lmvIAPEAJQAYoA5MBlIeiCEgQoSRT/RHR"
    "6ksGAFhl4zbYycYq0uyG6iCpaiNukTqcpOiX55PSc/PcsxdLOZ41NaCrjwhOOLNQ2N+waoSN9hdP"
    "brVdc7Bw5vb3l2vcHCvCdc3cZJLlvLGL85nQFNv+NfdxWibl5ctIB2OjDQ6p7Fq1d6vzx3+TuumH"
    "r77rxvyl87dbJzff3tFIi4xFhgXnUvTZlSQ6OXdh5I/Suj4IuURv2uL3YVU07qqH6PmJkKsrkg86"
    "BuYdxCuu6i2ePywTp6dndfHAyVxJfOjG98/OHs0Ww6HBkXv233U4JZ9/7vmN+2/CerT4bDF7ZiQ0"
    "/OrFi5wEFqsNM2mqZAMMAl4R+tFVsF7Sox6BTAvp6Og3CLqq0/XnmgIwgwLpcNYs79USZ3jfumNg"
    "4v5GbAi0gg3dVUHNWpi9+MoT1T5V75hpUqNEexgvELtLrup07Ni3dXV3kBRdS6PRodPzz/SPXRqI"
    "hUJZucwAAoGgL1hfKOXzhVw2nbdwPr9Y5SBVrpyTi0pVXHWZhwiml2RPdPDS6ptuOfeXV8FhAbKq"
    "sNjPWfzYehMlcjq/gMwuO0iOZZrbN4kWWgCUR1/vKi3brJ4YRxbTkVVlFFwNRU6uS6x0IEuAfHg2"
    "3Hbo9ep2T64M9RwRGTebyBw6dfa2fVtDoRQl9TkAGyAFlIDJgLIWJSszCgA+jmsThR6Xo0HkvQSZ"
    "BYd5LhZa9maLgRLlihaxACTJ8VneWSXamwV7VbShxrXdwd99pfSNpzLxGvmOmwPtVbb+zNyYFK8V"
    "O4kQfi15ZC7BRWfQ2SHf5+W4mVLILY8c4n7300J2BZdiS876heOLucsuliu13uWzcvGh54/lhF7u"
    "1W9RP72wGtfbwo0LS7Plmnz1nuXiK6FYzILNxdkXSuEwt+eddCEpTg7wHinjl60l3lZtzyUE5MJ5"
    "13KYrL/O39ISn47GRpek0rCFLs2msgdPS9dUd5wNH3nq+BMPCnft/9t3vfD5/2wZGvfV1hMBd+y5"
    "9rEXn3dZhcnQFJQRkNfUoilAUyECeiDGXLXJdOTjVcFSRVObSIh6Axjjrw4BVXb61pdqPjR5UOt8"
    "tDM1qUP9R334ZgOjPA+DqfUVRq6XISAx9oVWDAXhBWrxrd6175F79s2dOvHyd75w/sK4zFlAcEGx"
    "CHKZ50UASGWLyYKVgtvG6ursdb6y0y9zDcyz2tHS1hQMui0CT/40eeh5m3X85OW+j91AuUKB2qTs"
    "IrF6SMtOKZeQy3GWDtNyhlZ3VG282YPl2dNPRqOR67c13emndGQeq23+gq0WOr4plRKB2rbc8laa"
    "jNH8gFx+5shF+QjUA8/JAAh2wh8fmweUV60OlgoCAJQZKwOTEGWmPBkUAKCRF65zum92Orf6XA6O"
    "1Ff7uGoHYAE4lmMdQ+Xyuf6xfCRekMVsGdFlEWxOIcgzl7UYsBBrbOutdb/dUvjt5FzZkxNsXK/F"
    "czEXWosSJh0nBpJcGkPjYJ/BM5Jk2yRWb7T957OF8TepYyd+9Ueh//6+xAdydlozFPAtcFUO63hn"
    "jzRyFNqC4LEFjh53PZhKSHLKuVUqnx0bez0T47ItmcLkBKCbWHKwdK64Mie/oxN5ofTC65lyZxcs"
    "JTzzC5TaHRQL4XAxmhQIBF29ARtmpdnwzHgfNPA8TZHYL17+8b90N9rW1uZS0dp1XbnRpYa91fft"
    "v2PysZ8TTmCATFYioSpq3hLvwUpSpH+j5aJUHa1HjnQ3QncgDN1tfj6A7keoJN2I3RiVz5rd0WXQ"
    "0OiGljf1iHrjRiipMg181WIABfqaG4jA8YxhbWPjV99xzcsvHRn5xdeGJpa37r/X53advzQRjkRJ"
    "yU85C7NWMeIA9HHlvC1Pe3P199b2rgoEWl1VNVanmJcgUwQiNq12Jc489fLs6ezixaoNW1bOHONd"
    "HvR1l8sFSE6A3SnJJfQ0CL5gOhEdjC1mk7maxrZgY5W9muICf1Nd4GREfDIG44LPYmGOljU1c+f+"
    "BsnXcwkb8hyAyAhDKABQBm4iHhsNX/nH3xWQ2IEvUioxoEABKWXMhmSXzbVZtG9xONtEwYWc0+Us"
    "OR3E7WE5BAdnaQhs7Wraevv2xQuDhQvnM0U5HcmXXKItJpA5Cf0UqlylQtBfS/6uvulHYxfP5DI3"
    "Bhr7vOJfL0XOngFPUVxZoEthuSFL4oxbXKCcD6/ZJ4aOy+FZ6foHbEGxpo6Jr83P5m2t0WCdyyJt"
    "+Uah+3x0fokcuLzu7gL68iWbp8TmxxcuzTJXuc7FcikyOge33MnGjtPlRdjeAN2NJFWQFxdhjWvR"
    "L7Mrfvt8zuefGLHU1s5HY0IqG/CubGhYdzGc4IvQyde/L3gDFunLuUPjzxxtWd+am5oUNtVCNTz3"
    "xpOegLWpNnBpcYTKPBJgsvEMUi3PpTEPjcpob8AcHtL2XNflQ1lXoENPq0zTVLUeBTKQquNe0+s6"
    "qK9+6UKnh2zBCDzpUqBRGtCIviEemt+hJz6QaFEgAkCQEOQ5yvEffOiu//3LSf+JPy1Gops2b40s"
    "zF+4mC+ChdkCsqMDXH3gbLI6nR6XkJibKw9euL1388cbN8JiGpISjWbKHo7mCySTb27yXOtpOpkZ"
    "jfafatr1nuXhFnTZZGKhsXFEwHKWa10HVi/I6WxJpoLL1bY6ECC8ZWUow/GScyIhPjkzR7tv9Des"
    "z40eT3prF2bI1zZ0To5e+Vki3oIWHkFGKAFDBhIDO8cvJCUJGAMsM0aBATDKmIdwt1rcnZzVAxxQ"
    "kkculKENtGANeEgiT0QeAwEpWJs/ccGyubfuA/eznbU4M5yNSpmLi/Iiz9e55CKjMuG4Upmu5qDm"
    "U+1t/z322En+iuWK9fTLJDrHlqKlUgKyRWBF+tWf9ckDy1MnkniH8Mnf860ieaW65kdxvM2OIcua"
    "hRSeFMKfC0bfKDf/uVQnDGTalwSblFnKlZrd0XA0shjPHz5d3rFBbHdLdRYWlOiZBQx6QaLy6DwX"
    "CssWid1oSxcCTtsM5lZi22ssZ1ZW7C5HPrpQmL9s6Qw6gMzh0lJubkfXGi5P09bclfjo7f6to/zl"
    "7NFLji9eGyzVf+/1nwaqq3x2Z7SYNyWyNDCqIGImaqPJgFonodNy/aVpfROaK11dBgyufk4wGG2r"
    "cGYVnN0U0wHNodA9bkW1q9kL/SSzD6CVeTIAggCkEv1G0ZsqMwSpJPvb62fLrlM/+80DW9BfXX/s"
    "yHlwusFWDZ4NltotvpZmT1ejq8NdCvJlL7TPyyNf7LJiGcLFQjLHVQnwt+1ksx8SBfaFQRKVtlS3"
    "tkV8AxeG+m4pCHVNci5Dk7OYnIaaPlaKotXF0kvU7mFLo3xsSti0R/bCQGhlrD9edc1HcsOvWZ3E"
    "BszGWW1tO3LLw0ut2+bd+MjOwMsvvYbA7Ig5QJ6BBEABSpQRggBYplR5GjoF6iTkFtHdgKINkEOy"
    "ILNUnrKyFC3SxvMz1R6bt7ee46zcYtSyeYscnoYFJ+ncDI0tjug01+hLPXfRXyWgVyTFKHQ7OTEs"
    "0yVe2PWxzuu+f/G1F5/Odjajx8IujIBchL/7RMP8nAQ1+YUs+BO8bcx5wuHqagx1lOnTqdwrNI5C"
    "zU5H/YunBt7VnshYCCxaHSW7wMgUTXgyyUMX4y08P7Psqw1GV9WUD52gcZGLL7NyiV3bwt64jLE0"
    "7XTQFQcKDr6lCeZmyhYv1PAFB7r4RJqDAk+L7nShLe88SvLPLb22saa9tbmlsVwzPHdo+tzp/4+u"
    "v46T9LrOxPFz74vFXNVVzczDMxqUZoQWW7It2zIlTuI4uJtkN7vZJLuJw87mG7JDjhllW7YsptFo"
    "mKGnp5m7q7qY4eV7f390UY/31/pI1V31Uqufc+5zngN36OARmqnIm+k9vrF0Rn5v9e0O12CltCSp"
    "FcCIku0cfhu6aeO1Dm64WyP9ucihZg/1txDgBnOpRR3Nt/i5KKBJlG0URNe5VrMFbYuqm2yoyTww"
    "Qgij+jW2DKA2Aa66DhgEW03nzlxHrHgrzfR0BEHgGasTO/qGPvaZ3V94wvnfdhSfd18b0m5bKjM6"
    "2RxhXI/vOpOw5dpFgeHBZ8IP+OGXZpkZCX63l5SVgbauUXNQq/D63M2u3X5jcw6zFLX0A1Dk7yep"
    "CM3GaD4JqRU8fBTs/rWVzM2z62rvQ6rBtHeMm0eOc/5B3uzSE2HRFZwaOnxmXXKbxP9xYK9MVREz"
    "W+2bBKpLgUKoSrZkH6BAOYQeYK3tWLBjbGcYDiOkKSWpXNSUdV2d1YzbyeLc5dXy9RW6kkDrca6z"
    "H9Y2oFhBwTHSf4Tfu0s82F2Zz9HbZaoHoIKgXMFE0vQZhzCMr9oiEzTkh2AAV7LAGihgS//eb39M"
    "KfhKVqVUZPdpjnw++O8Tfat5t8ewfUoIVeK5OcUA3l3Qg1/qFR/bWSkYpKIqAi6UHWWLj5RKZoS1"
    "jhZjdV75/jo73glUp8sVxBqo34Qe7IIuN6R0XCqj1JqeTChdTs7JKj5AIU4Y4gZ4qrP5/LOtD+0Q"
    "OhbJ+qtzb95ZuzHSNnxP572b89Nmu8j3BTDL/uflb312x2NEpLdyNxXQAWNoxlcDP80ga6bcddzV"
    "QNbMNNDd0GxclAKuM5z63JOa729Sc2rn1pYRgPq4/5/7uruR625TqJkRqv6OtbUCNV7rXAgAWDaf"
    "yWcZHUCeX83YbBZvi8PAViG0x/2B7kst+ixL4hL5YzfzeR8T5I1wSXEd4u+YHdMlgmwMXZGNxRL6"
    "g04Yt0FC1ljdoqDdLYMOoXPj4u2uVgABMaBRjofUNE2tgCqhwUNUrcD4A8QdlGYuKXfeB011sbpN"
    "ynH3HMc2JzWMUjLsFpFGNAnprwM3MRN/Zsfw44FQ2dA5jHUADahOqUZBBaoDNYBSIBToftYyxJkd"
    "DONBCGsqqZQrpbxczIFU1Iu5mFxZUJXpQnH62nJycpNcnUO3l1H3OI2VIJMFzgHmkOXEPeB1GEkD"
    "zUmQIaCYQAVc2qSK8fzOXeYo/OxfyZtfJVgFJcssvSNnM1M9/oMzNwqIMbdLzp3WvI7F74U7bpW9"
    "/20juabhhfk8LJdi86WX0qouF3FOReHM9MRiUinIvDBXNDw2BYP51IbJ4WaGnPDdO6AzyMUhM0MF"
    "Bl1dxx4egohyGcOBwYbxYloJxyMol21lvT5kNRHcH+w4AK37cNcZ6cb3J77NR4sjI7udHn9pbhUh"
    "xMtm5OdemHn7WM9hlmUIrqXAmsqOUR01TYhHDXzV6oIoRY1gs4qwuiVs8/I1sOE6aAFQvRGsfuft"
    "WG7ueEHNl2rO8tKmp2zEwo26para03j0WlgMteo3WteFMEIso6dSFVZFFkI1ZiWtHdzRBUpFLhaU"
    "+aITMVhS/85t7LUxJ9zs34UQIizp57UdtrcW8pqDw8ky+Zs57VZC+9Yy/uc5jgGcN/w2H1ism2s5"
    "Pr/h7/NqOsFSghKJsiz4uyG6CKFB8LUZ6zNSSQYC7N4jtKMr2z8apagYXitFpkQLyB296s4DGsfd"
    "OvCRc6ZuMjf7Ox9+vA2ITikF0GqlDQaAARSAUKAezOzizD6OCwAxVLmolONyaUOTlnV5RilH5JJU"
    "zJUVKU6NuYo8G07lNkpkch2uzIIhkkSBVhSwhnD7EDPUJUcNtEJJXDBWShDDKCsasVT3wNCzQ+5c"
    "GEgWSQWIb+hqnFmdi6RTYT4XsHKcCVni12mBMRPAe33mlwf7P95WQYqJi1tip1PfuSlLOtE9q/JA"
    "TGnhYnnLtXmxxYoPBKyT6ziqwdPd5svr3JrMHG5hUwZ/K8pIZZhP4QMeOuSjLECnjfPyzLVsSdbp"
    "Ia5N0GU/FhfV5TPJMxwlH/UeHwTPOG5dX7+TSa51791jYIQ7nbCWe8p/PO8ongvf5kQzJaRZ49lO"
    "v5s9LGpwmRqvrwWZ2whJLU1QXRVo/UQKUOsJro1U3K4uNc0C3dJVUWMwRY31oHpYUJeF6JZuVf2x"
    "ce9tC0rD89fvR2usCKoVoDXD0HWyuQAjA4jjrse5jha/CfI0NRW7HG7VgIDh4nFUpysKGRWB08ga"
    "Qy2HHSfLWkTAbJDlN8rCdzaE8ynoticCltOG8u9LS3Gk6lhcO3925MQhagpRA8DdA552un4D8mls"
    "90JqAzgB+drp/o8w9zxVNpsLa3eSV8+mZi6YTD4uOCT39CsrN6wOf9DGvCvJb5S8bpPwa88+UDIq"
    "BGMCoFPQgZKa7weAIUb0MBzPMJKqF3UtbRgxIJsAS6BPgPY6Ub6vFWflPK9WJKrPK+rN1WR0MUPP"
    "TKOcCvYAjaZoRSNZSRjoJqJdWSfMfAlFAC6m0HTRmM7ReOlDhweEIirnaNBveeC+Yeug1+ntmbq2"
    "qm/KLsrImD246tduW/WiEYlWIpTzgUiX5wkjYLdLVbOBNu2vf80YfSZmvqdc0NW5dJzj9Fen0M2U"
    "MeblMzn0zjLj41k3x6Y3aK8bx8o4q4KBcTrPlIGTNVqWdd1A3VhoE80VVExBMSxvnlo/NanM9tmD"
    "lKV7bYNjw7skOROZnuRzoJWKq/ao1/Dtd4+V2JSklVG95n4LcjVtfSvABNqUMGyC6hZ0G+NGUNNg"
    "8WbcbUM4hVpRWrMTb+QAUB3rWxhuqKG0VmndVCLRfBeAWqdy3QhqP9QXleo2wHVbwAg1dcrj+u0p"
    "FQSIbeDBTpanlWQqnFaG202QX47Nrrk2EWsz/UESORDeKeD/uoEkiWQSJXaHEPYZ31+er3TaSl3O"
    "mTbbDw38lxPS79wh/7Mi3jlwiIaOgGdwcTrhMMuijRilInJ3ofAdJJegvR/mT0NiBfIZ9PCHma4u"
    "/eZZ+Sf/qF76mZLaYFzBwZLqSUr82gZcPG22eZLrU+fHj/1s5xOxV0/fs3v4490dCUPiEOhAdKAc"
    "gAUwAmRHqB9xIoBu6AbHaIAVxDDAuAE7gHEjRgQsAXpHl38k5yqKVDL0GaIvxdIq5eHCHJrdwNhM"
    "sgWSqSDGLO7rrqxJ2rxCJdEgPlo0MxmsrwpjwyNtmIluopFW/evfv++X/uD7usyXEkbpthIw+aZE"
    "26Zi3nmKMFn+juR59KzyL0s9zMBB6gR2r/qFo5ZPdtB9vewjA1xGjsW19EBbJV/RX0toKosyMltQ"
    "iA1hC8sPOXALj2ISc3KNXahAocSYKGfWEaqgH66XQWHvsViSemZGD99SloYYf0Yv2QiLiRwQbWvS"
    "hsnn9XX1pCOrOGAXNNvZ+K1X5k5/fOChVoEBxagO5N+OJlrDeBOZbvDxxmjBxnn1PHBTOFrHf1Nm"
    "oTEVotYMjFBjhkm9lwaq60AVulAr+0FbD9a0Ax+qiUHbbg8Nmg8ACJpa4IGirbkoTdMkEMUIGIYy"
    "mLIIWETlMinFaZsPlWM3l2OD/Z1gZI3sSuZ6sR3oZok8vw6PLqpnNORz8q02czlciatLL8TP/d75"
    "679/NfxHK8a/mvxvHhpZ/YXD+q+coI89PvSxXxdCD8qqGJ+43DPeAoINFImqOjt+P5UyhBAwO3Hf"
    "ONy5QlZmjc01NtAj/NL/Rt5Wrq0vaufJ+mzlzRfb7J1A2UQ2ZxMdG7NX32G8ibdv/M4nnn3C6SwT"
    "zYoAAzUQZRgECILA2CjCxABNMyOmw+FsNVm8rCAgZEPMlt2bAJsB3ybGl5R8WVMEQ4sY2uLUirSZ"
    "p1dmyWoMygowdoQdwlAvcVkrkwV8KQYSpRUWBD9J5gSr7+HRkK7QwqIycelV0Zp1OocyE5tjVivD"
    "2ld7XaefcmGPyRwuMyYwG6S4WQGHz/AEDGThWD8ChJGn3RbKFyXWLLMEvxKReI7bwXpTmpg1xCWD"
    "7bCZHXbPnYz4VhiXFaAMCpr4G3Hh5SXkYE2awnSDudcd3OlrV6jWTa0yyLu51gXY1ET6QPfRa8pc"
    "ZnNTzpX27LsfDTmNAftuPPC1yTffunp7J3cYlfUqQmoUpV4r03DP0LQIbI82oeay61ZS01bqnAnV"
    "39oCG64Sny2aQ+uuu7aWUFoft7sFabQd1j/3CFtJgbo4WrtZ/eAaxBtxfSMvVv2oFgRjYBngWECA"
    "MILlCTq2k8GwsRHjBEtrwAqZidVTV3wJxuNiu3ncK4sDi8T1Wt72xSX5i292ZSeTpsz3xPzpR0dX"
    "Pn9o4+M75g92XOKs1+JoOaplHS7v4C4wty+du9i3cwBZnbSSRR2jRmoFRadR506ILhpz12k+C2OH"
    "AHPoniehWGIU2X7w0Uz7jk09jboHC65gMpHgjz3t2TO82D724tBDV9Osnir+/e9+bq/AiUACGCNK"
    "8oZOKOUBl4lRUTXNoEDBjpkWhnUynIB5HRACbKqqAMgJuEDJl+ScoWsKwjcr0srkhjIbp3EJKSzW"
    "GSIRYHjHw7sqRVCjFMuIEKArSSQLoNkf3DHQYmYHunwrt3OrGyd5O5ucor02J/L6LfOzbT71zBCW"
    "pPzHvLnvHWE+Ok6M+RVO8xrLtrfmU1albT6GfrAUV7JMdpNcXydOzvGYM6Rr/ExRP5lU8oD7bOLq"
    "unEpTC0Myuj4qItnCX9+nV7IE2zwNoa1MRa7zK0o2T7q+kV+txNzbaxdxehs9PJocHTIOZKqxMML"
    "kybRKro8KT67sZlkc/BHb/7z4mZ+R+sBbNQZzTYv3wDlzyG+9m1Vl6mR/SpOt9x9javXFobaxevF"
    "cHW00qZioepV63iv6UTVUrha7TqmtXRWzfKazJZWuX19eao2ZTZWA1TtfdliPhhXg2AGAcaIwcAA"
    "mEQi5cHKCe0DNJNcjGs7+gKRs1PSkn3qr9ngji4hKnMLGVcmMoKK+735ofsW7RD/p7fNP3F2ibt6"
    "byYIUojI0I+NkVQJ3p0nsZzW190acfUlw3Om9HL7YPv66XPIbiXROdR/iK7PgcXBHHmCVvL07EuM"
    "32/09Ovf/ierRZDnziob86zFnknEoHOHzmMmHabWVrvbv7q8sGzvjr93rf1Tj/7n5z710S99HSG8"
    "x+d++Pd/7fs/ezd87koCeDB0L0ZI10EyOAwIUZ0aOgCDEAeIB6AIEUo1BGVK/rmS/Q2e14FOlovW"
    "zUzrShL1dxErxkQ3ZJWziELInbmd9QoWrp81PDzc3KD2rr7dB//uDxae+e2/+/pf/vHCzSWTW7ax"
    "wvjoLhRwoL1CqViMVYjuFo64KkO8+kxQfiFT0W9u4lbzyxccr7y6ovEGuYICs20B5PLxVq+CJ1L5"
    "O0o2B8SL+adb7E5CTq+USwaUKTIovVc05fNsSdP7OOFGWdYIdjLspUI6akij4H3St0dVbs+lV9wg"
    "SuWyrFT2tO5qcYW0RCExvdQ+1Gv3exZKEXNFAMxMRaZFYgKCYGs8KCXNYWNTvU8NvM0RJNTafuvs"
    "vZbCahjOVrF5vYIIALZtk1r9bFvUXYP+tkb4eqFSLf+7jYEBUAS4Opur2UpR8zNV16HaXvC06vK3"
    "ZFlctQqEEUUUMQhEzhoIuGyF9NBu4/037qTJh8Z8HHMLypPqpQX+SuDTA4GjvfmBQ2G3M4nNK6Cn"
    "AOPfp89ePakbRdVmYcsV+iuHyB8fRV4Tc3qZPPFdSXZ4Xe27spn5qbOXu49+YP2qCRky8nVTqx8t"
    "TcDu++nCNTp9CVqGqNNHvvNFJMn607+aCy/hG+FUCiFFs/fxfDLq8XmCc7F4bpOUk2c5fnn0g4+/"
    "v/DgodA3fvWzf/n9F3Y9/9Dnnr/XZNH+5NzlAqIG1TeVYieIHpYHtJUfqPo6lVIGEKY0B7RAqRNg"
    "mej/WUj+lugqAFnP5l0LUWv8LfLxw9DaihKbBpJd9/YWxEh+OuVUKPS7SUnR49nAkcP7FcawW48d"
    "efKdU68k9NxQSgs+Ozbv2EgVYgUUBGJCa/mvzVkyO0uvLlDoGgJOIDcrqrwD4ubAwXUFF2jZ4Bgm"
    "rZU2i9J+LuhkaYXkbALXY7LMZ0uni4aNYbOG2sOL2LBaEJNDBYYwN0pSiLPlKJkoxjkWPCCqFmZF"
    "SXcjzy62Azh2I7V+ZeNW0Nfmcvp9vYNKKScyQxVBnk0sOpC1YJRlRQadIkpptUC27rC3J5q2zUFv"
    "zk1VHXTz23U0V/lH1ctXTao+ibbmv+8C7LYLNL38P95owv82o9pGmKoL1ZYSVS+Aqw6AQKjeBoAx"
    "AKKIAcQCMACMZmCSTXUe6NV5X2GzuBGXRzyMkVzuUuN/sn/l9z/+wuEd/+H1vUjJGa0cq5RQKV3u"
    "Gp991JXMrWY6XBwxoMcFXjPOKbQMwLF8juX9Q7vAFJy/etNploWd+0hkAWEBoksAAIl1OnsDeDtY"
    "XPSd71BPiPv0f0XDQwZvRb/yx/y+h1jW02LyBDwhbjWyeedWmGDpw7+ycOK5eT40a5iTX/9Rf2/3"
    "X/zGL+Db0zMzd47sa7EJbNHQY6TSdvBA0u+c1isrhr6hqRlKS5SUgMoAFaBpICmgAkIUQAQ0qas/"
    "VUsOhpkrlm9MryiSxrx8keZk6O5GbjcaHnDcN8h6LEpO0qMVUDmyuELzMsn3hZfe7x7vCi7i8Msz"
    "TwyPFzCd5iuSpz+mOdT+cXANXvtm8X9/x3vpR3akCrQvgF1OZimO7B2P3tM1+EAr2WNaty0vVtbc"
    "rLlAjJxh9GDLAxZPpgCvZ4oJqjOUdzH8Ud5VVriKzskGGqe+fcgX14hZce2H0B01bubE2VL4VG4a"
    "AI25B7ptLdTBzxfX0psb5VzGPBw039ddnAvzIl+QCyWpAgSjLZdQU3QQpVt0qDY7c5uS2ESNaP1t"
    "ehdDr1rCFgeiNWJV5y/1ILgxwaHJchqi09ZSUM1EUKjH0Y1wuklDauo/Q/XHukuSqgUD1RtWtf+t"
    "/S8AAKq98QzCHMUslWS1ohSJ5dBIy+EH948fGMQ79vR88hdt3e0mtWxVI1DcVOOSbhmGZ19jf22N"
    "++hPWVZAsPBY3zy6terlECugfzlvPPFdeddXyeNf07MKLhrY1h3ieUYtq8WJa0NemZZkShm0OQ0D"
    "+6gzAEoedQ1TSYYdD+L7P2gQTTv5JuruI1JFmZtjWtuZttDq2Z8WN2crwW7Z46tkisbUcmLh2rVC"
    "5oqnc/XrL4b6uj9z4n7mnZu5uRWn0xSjysFH9//H6Rd2PffEHKgrLEQdpijVCogWKckDiYMRA8oB"
    "iAAGw5SBsoDeVMsntYqdZ28V8pdur5XDEn71PL2zDp2DyNOCujutR/oMhXCIR5wFWx3AC1S1ZDcS"
    "y7G1RAb9XqjNve/A20x8IV0afEdCYh+by0BnP0ghvui3Mhb62ir66i06m6LZCizc/MHJ+I1cybKX"
    "FXZ67XangdnbJG4BuEdoWS7oX4tHZAPGsWtGLwcEvttkTmpwulywYeGYOUQ4QTC4Htat81yFakHG"
    "uaCkQTeKvHGxvCAb+lj36IjYJjBCW89g1lRZw2kX8pRKkmTClOercnEt/G1uY6ypLHQ76OqYQ1A/"
    "oPHZlmzTUDKh1oUITTFqUwxQxzGlqD63sGpf1RUHaHWySQ3QtGkyaZMdbIF7GwtqjoOblCGEtrb+"
    "bTCfrR4AjCnDbYlFHOaxYApYXU+PDpt9AfX/fDZh4xamVtmZhQ/+jxH7jQtTcrLHLHXRd1iLmbYd"
    "onoJedq51j3GysXhrvW9l6aW58Z8Acv8ijofE8EGNhfvNCGnAJmJpKoWwRaav3Drnt88PjFRRkaB"
    "YhlpFZg9A61jTKibXj+HDj2FSznj/LtIKUKg27h2mQZ79ejs/PKUsucIL3BMKqvldGf0fa51sJyJ"
    "XG3tA8a2mU88+tU32567b8Qqvv8fbxTipQcP7vvQI4f03EJHm7wO8M9/+mlP18hnP/5bbsQqlBSA"
    "5AAAwAJQpEAMg0VIBBAoerFS0DA6JFiv59LFG6UjlS5XeQpjkz7YDpLG7RlkY5Xy5IbJbSFPPwwa"
    "DV9YKfFyaW11h1Ha/fnPhivFWU82XijZdIusmmG8C6aXu+9XHj0ezejeH7wyAq+s0M1N1DkALAxY"
    "Lv/Zx9tPTme/dYZlJTaqpzVD6+JDZSpsqqSL8bRh9rK2uRucbdS0rLCvlwuLRv6Dpq6iia6WKgPI"
    "bjeZf6auWICLkjwuMU/jnV7GPs/lIac9LNh2DO8mZd1xaLfs5/5m8Uf3kp4nhg5/59abyWIGGbDV"
    "CIlqZH8LmXVZ8675sg1soibk17cArpbto2abuAvrlDZvkFFz1XfleOtQrU1Pr0o11ZCjdnBtWHQt"
    "MK4/Vv1goIAwqg+Tq18fIQTVMegIMxRjCtUZWKLFrrM8Jzr+60ee3LNzx/fz4ksqY9zegKXFth98"
    "fY/J7B4ZCvX0uf1HZl3OpOnX7PNfHzj5v/muMSjmoVLQDbDZp+7tHDh35mTvLz7N9NpFAdQK0HQJ"
    "3d4sLK044zePGcl1m2tzc1WJLTq9em4mjBHQVAxEN97/mDZ7CekFurGgX38fu0Lo6ONk+g6jVUh6"
    "WR2/jxkcFNvc+R+/LGBGY/lyZtabjNpsfeu9J24oUbklGTz53fK/F7z3jh5/6ql/ET3XNWVhJRb6"
    "1gvu6wuf+sDx++4Z4zuGVBO7JhtmRHkKbox1hCqGEfC4Bvq7b1y6YUXIAMQAfKuUT1LyQdaUAfnN"
    "O7NjyXRfrGgZa8O72+lAp/njfr1zEno7WZsTvXc+Thj53yf3m9gdn/pAodNQE6+qeeedfkcqw5dn"
    "itgm6Hbvo4dtX+xo+Wpm7geeVjh2Ai9songRAsMt/rnjraOzifXS5kwP9CJWC4LHjK3TcjQKlRaw"
    "nNfSA9j5hBhaMsoXldyqURpADkHnvp5ZojrdI7aVQA/LaR6EeTXVgezHvbswg5fy1xRkxFdWA+4W"
    "s4jVYYemqC1m7zdvvfeLjo/02zoWlFlE2S0NpwZc2miLbIiLNQRvo941fDVTH1pl+41+3btlJArb"
    "muJrYlHVcVfHazWnuWpRAa0bWDV7UJ8i0bhWg63VTQjXhw1tZb5q8yAwrY67qk1DYTnEsAxCTqdn"
    "x8Dgrzz58Lro+/Uza4lsBe8cYjUrM7vUr0tie38sldiIhDVNKVeK8WzhmCf/F3sWuKkfonwCOODN"
    "gETN5lxJz2S0l0VXd7e0mG1NpEZoYsi+Me4Lj+9NYWC/+rr8jxy/fOHCyKHHLrz/Y2jfT+US9rSS"
    "jXmYPIPsDnrrAliC+MCj9PZ5Vi8Zsxfh2KfBGaRS2ZiK0dagGlkDoxLfc4THYudyWvN6C0sLy8X0"
    "qx/4OM+ZH5y+/Wj02tHnnhlaWH3pvZMvZHPD9x69v9+mSGqrtbTfY9kM5ztZkaVo05CzQDDAcx/Y"
    "9/df+7cHD33o2s0JE4Nlwwg67OzOvrcWlsdK0CrwM9HoaiLtnVjqfd1sHe8TA3ZdktH0ZXkteSqo"
    "rJm1Y4ZlxwNHZF/L2tWzE/e4XckYRC2DvajwbnldxdCGs/d0ZaCYLhXgygQNa+jwcWZhnV3dmDu3"
    "40kpvhJWbaSPSHKJFoPIsqTGrulzKkIitVDKDvABlrWHy9kVqDhADGGnSlBKk7wglhC1AOumZisw"
    "CMEyzT7q8N7MT++39oezm9nlaMv+cUlL41ZhfnVDWS9Mq4svXH+1zeS3UL5sqAgwULJFvRsaT3NN"
    "Z1NWtd7+WGPhd60ctf80T0uktVNrHzYMoNms6hypkfvdpilVffsWpWq66Lawe7sdNDgSgtooXLxl"
    "U5RuaT6AKQLALLAc4gWC8INHD33uQ09/+8r6j2Zu5zTCUmRMLZCAC/sCqUpFmpmSFUWRSpVSDmml"
    "Xx4Xfnt0ha0ojGiG1n5DNS3n3O8v4r8N54ldS09+pWfS/Be7PEfuzQdcaRavQ/YOGAD93c8c6Hr1"
    "JTQ9OT346FPCL/4tXZvSr7yBrWb9+quMtx32Pgq5JINUevFFYnaR2Crq2ocKSbjwE9h3jKgy73AY"
    "elmfuWnc92GxUughKH71pGTn1oHLmr1BuTSg6ctLMfcPXvQ99egvf+jJ1985eXHpdq99mOQzQlH8"
    "9WD7cpqLq8q6oR3auTN0755vf+kbY51eXcv8l9//zDMf+x0GoTLQ3b0dY10tt4qpN8Mpe0HexYtm"
    "RIxcpiWV9sxuOEVWxIYhcos8k91Qn2vr6/v8x7X2hSXh3SwNaj+k3bbsoejsAnr6GZN/ZipyJSLd"
    "sKlfeiL9xrVBRFpgbY5s/szwBTkkFuZcc5NlB+cE1Vk0LzNlXDb0KbopsvZhCBBDtWFTBxM6L0XO"
    "6HEDkQOoRUH6+0Z4HwohjJa17BAVO5A7RIU0kqdorKiUCrJ0b2gHzwi3V6dcQ8P21jaWhRv6QpLm"
    "l/Mbc7GlfqF1b9eeyzPXVKo34Q/VAgK6HVRbR9QB2xSEVud01s4nddq0jeLXmmJgSwald8O3ESE0"
    "YxrV3v35qp6mSPj/ZQi0vr9Go5avugpU4/MtOQhv2RRFLEcx97knHvzIxz70D6eX3r46R+0edHPC"
    "cFqQy04dXtXVFzn8oPO1H1GtUpElYuZbBj2tqRjjuEfG+E5ZvLWunsrga8iSavU7PtFpmoxVTt3+"
    "7X3cczvfpNllUsKaRujwE6CU2Y2LPe3uIzZ+MsnkZ2913vPbixffArNJr5QQy0DnTpLLI95sLN2E"
    "ob3QvQPW16gik9Qq0mWIhIHnaC6LGJ76ekgiyTg8y2ZFLec+ocC7AzviWI9V5HA+d6rjsCc1f/zH"
    "bzh2Dz/20Y8NXZu4OjszWcrgCV//0f3H/uqpr/7K/xje3/3Ir39C93gu/uR1zkDRhZuHDwQOtrjK"
    "sVzCarZZBdDVwc5QGqO3pyOXyrkxkzDssjAuczpdLlZUHVO/bhyyeo89/QAzGNJdCTl7bsW2WsnL"
    "rot2xuV89BlJW1jyxk1P0973lMoX/+3dL55i8dAwlHQ0fgTOnzOW58sOPxo+ZHe2u/DlyOx1oqlu"
    "xhqFkgHMYW5fQk+uQuwg7prR8++qqy3ILlLcz/leN2b9yHmA7X6bzGVJZdzoCbKeFkM0MQpHUKyc"
    "XNEy+w21jBULy1lYE9/pkdWSppVWCimTxkp6ZSY9m1UUm8WVSkcRMLVgt+Z4mwBcc+e08WMNsVVU"
    "1kar18G3LVuwNTu0yZs3JsPVsdz07TbhZtva02iLpE2HbL3eDf/q2oNQ7ZJV5G/NPm/I/wyLGIY3"
    "25VyubUnePjRJ/7oQia5lpLuTNDOQcFlVgNt1O+jVIfVcL7naOE39+CZWySbMEg5K6384Wr0jZ+U"
    "MwH7UpvJGBjBA0Fx0NraKugmpTfiXawkDKKTkiYVCMMx7Gd/yLbu0G++qM2cNvk2T3R3vVVuWbk6"
    "tWvnzfnZ27zXORhyTK1LJJcEJ6LRFeQKop2HyI3zsJlAz34GFufg4jvUJMC+Q1RTyFs/5fp3MowY"
    "zW5ev/KzD/WNjsYTV3Su0N4q3jq/npfW9PYWRJLu/gN3VnZd/UHPk493Hz06c+atuZduqJ0u5viB"
    "gx+5X9LSGbVYvr7cZuHzudL67bn2oZZdI52RWKGHt2ipXEIgLreF4TivCiHEu+wmJWBi+32nLpWz"
    "ifIJJDzc0tb/gQeTT8sanFV/GNEYXXezI88ulUgHPufm3/PvM6eT8ubFhLana3BPsOvSzBVsydCu"
    "fXRtGZxebHNBJipPvpfY2+3+oHXnLtetf4mmF6MmztVudMqakiSFI3i4HSwvqlc8SNzJdqyTxLKR"
    "VQg8xg91C8FS+bZCCMOb8oY6KAaWtaUDTJdukKiSjBbjTo0fcHUZA47J0dIwMZ9dup2v5IqyijCH"
    "zEIsHQWdAmapsTV4hyJKtnznVsNj1W1vZ0A13NWpe5W3VM0CQ7P9bCNHNbCyddBW69qq+K4GuHTb"
    "3VB96lxN9ERN9UGo+cING0NbZlkrf4AqM9qeCUYIY2oQ3uG3tfWaN+Z+/7OfeOF69NLZOcAMJ5gM"
    "wpDRo2hthv74G9A1gnoHyGaSUgDNAiUNO3lyeWaTE35odY588pjnkfa0vVjilFXYBFWFjBZoC9if"
    "HTn5n9eeF3sF0xoxDLp4hrz8O+jAp0j7LpS8sXfv6NgifXV9qbC+vPf3fjPIaJZodno9RUsRqCRR"
    "MYt6H6K3rsL0TbTnPlxO0rnLpGuA3bkX7Ca6HieCaJJkKGfiC9c8gfHR1sGFiLGm6p7ZK2OZMFHI"
    "9fBtp+ASlmbmpaSYjXais8JAx0j/6MjY+MbC8tq//kiXKheLOT6a2SVzH/YNnF1Mnd8oDu3r+CV/"
    "f+fffCLy9plzSys/ubku2uwhhXsuMJ7JRhVFWVrLLUzGkYGecrkeGHHxD9jUs7PR19djn6mEj9ud"
    "17LQTQuq1PVsJBfMF8/yHUjMraVDyP/m/JS622rfe19pWiZLy/y+YwYrktU1dv/jxswF0Xzpd06k"
    "e1rtf64P3PhblckUsiRPoALIMDPspBFOkNw93C4nY72iL+cQwwMzzgaXIFkm+ihqpQBzJHqA6czK"
    "JZETi6AOQcCUMzoHx7s6hzb0ygyb68s7/U7Xjy+8ZVAEBFPdwIihyKCkHrHSrcqFWhxcq2KoCz51"
    "S9jKGiDUKGGgtDZ5vzk4rkqXaLsZ1Zriqxet85w6D2osGc3aTd2imqJcqEuf1RtV9Z964VGzeVQP"
    "orX9LwAQg/BY3wgRxHsOP8d0DL3+b19mvS0ol0aHH0erM+rJl3HPCOrZQWWZTk+i9VlcylKrGXg0"
    "pCU2dKVst7N+0fGg+7JjnpQNs8n623h/O9j+gT8fg1Tf3o5z32ano9zOVh+JJ8FqJ11HwLuDYd8n"
    "OhMI5Aa8oppjN8++G/qnH166OZP58n+jng4QnSBlgGdpqUSKFdQ6hAbHjO/+DWrthLYemLpDe/p1"
    "TwhnE3zXaMHfwm9uWF327y7e0jyD6ubVjmx4lHMp7b1Lqj4bu2NGyKVnx1vGXk91DlWivlPXPU8c"
    "bR8fbh8fKGWLlnOTi9c3iGSMtnTZdWcsWyp+41agp48JJ9uHho5ywsl31viSarBohUZWpRwjETcW"
    "uu2m7h7nSBlbD7ObnzJ6aezce6zc6Rx5wMSmSi3FfPk8JwwrvnuLa2vm8vvuh7sj6c0eTuo8M3FZ"
    "84b4Hbv182e1H87yz/6CoVOS3sSdu1hX2oKkoOa0hvKMt92q2JhSSTKKFoTXSGyabIxCh4faugyf"
    "mXIZkMZwSwqVv1+6VgLNhSwApGiUL0mLfup0i/68yWDyCSdjDQ70cLu7ycbCWxfP7e4PIIVazGI+"
    "VUIGQwmlW5XjtJH8rUGR1pz/9nmgCJqhXD9te7FaYxpWs4BU9feIUgpN26TWWM6WrHM3squnoyYk"
    "N3fn1GynhnXaOL7O/lE1SKg+HkK17sctIkRZfmb6GuXNzz5+74/PzUBFJgpBFMj8bVi4jtvHoJCl"
    "4VUoJoESWsnSUhIXKyS67jy6N3Dw4Klrd9R4JnYn4jjK51Dpz9D9vwWHVnDOKnD/Vf+h0aZlRtpf"
    "vHFrZ3c7ZdMIm0l0Fd75GOtlsIiBlBx2C2f1bq5GW8+8mTo7zZTXSGgQi3a6eA4GD6LOPnTmLdzW"
    "ayyuQSaJW7uoiTXKAs1V0LkzJlcvPXSYm7lNssvrKxtOUycfvWBmiof7n5hm0Sqrq5OnXKWVBNE9"
    "ns7TlUqxNAOyVarw5on1SjiLSynrWPvh47sPP35IiqRLq/EOJPNrZcVhymysTaYW0xy7MLvZziK7"
    "W0txBUm33xvwDlkkiThdQyX7J6Spf3G7OVpwe1Zd4XOsg1sLdp9O3ttR0soizjORN3V7GxoPcqu8"
    "NZHQ2gPlxaje03/f3Lm3sbss7D9OrpyWT5/mD92LN9eQVikvc//87n5La/7CqVRx83KxKLaznWYw"
    "C4RMG2FMsR+5ikRZZFISQvugx8uYL8mrHOV0qORByhuKF+wVooxDe8AWIFqGxWbB5bO0eW6PVjIV"
    "pZio/Pmtn93X3Z+XipgyVCdb3hs13D2FmvJeHRdZo9FN1KLeJlBXR2tzqVAjdEY1VtREgGgjcABg"
    "mxw6qqueNX7SYO81lXTrYvUV4i7H/vPs/64aDtTc6FkbfEEpQghhglHF0Ftd9rKG13MS1zWozV1H"
    "wS46eRbUCp2+CJoOnIjkDMglm93Tfd+npn/8P4mO5qbSn/mFx+9sJLRgtyUm+PmuK/zKHE2/ZswN"
    "soHjMODUbWWxFDza89KpiV/POVpERn3hf/E2Dnr7gPEns+KZ6+orsaRgE/ObGlq502XSV8GMWIEs"
    "XkCOAHTtIpOXIL1MQUUr19Gex9EDj+JygW5uMu++iLCla/QIPxmZf+89oYSO9X+6hfNcTZyLOjq/"
    "wloNr9lz9ZVPux33dBwsSJV3C9y76fkuVstK5nLAb6zFyWrCLqDB1WtlG4/39LMOp8eLyIPQsslr"
    "qd0bmsINT+zob9v9l22VAtaHdMuuS98/7w8xhV33pQtRXDlZCXUK39a1+Em9/XDh5imU1yAjmDaK"
    "FpxQEk5PuIsO5Urr37GMP2waecTz7R/63l3IjfUW6Y69Lh+buXRKXVoUdhzBb/1Mk4pssIMPtjGl"
    "nvP/vt5x6BFPvkdwTpUry4vqnW7UiYFlqTAOnSHknUJLM0bMoMTFWmWq5oliRaJAUYLmVWI4sKmd"
    "OsfFHoMBocAPcr32B/fSTl+RjX+9+M56YZPqMT+DQ27fZi6JKdPc/l5jOtX6n1qNcn00P6pu/N4s"
    "WFY1yZrEA83SUb2ijTbYfdPN2CYhlaLq7njoLnbfdES9gKERjdfs8efMAVelnsZOMFA3pu2Uilbj"
    "amDZXKUUyUvxtYi+eBvlo9TuQ4gFqxcSK7RUAE2lVOZYdM9H/8gs2ZadO3WcLf/Cr799aCf7/OfM"
    "vX4ZaOH9qWM58WrbzYcsrtv21Le5iYpHKYLk3+9dDwT/+dLqH+wbhYBtNW9bup2PFPJLaipvhwP3"
    "Una2cqWIl65c7vjwJ1av7ECZDaoWkH+ULl2HlQlwtYOcw04vHT9INhbpyZco5ZhAF8qXlasX8WrK"
    "ltV27P4ECCjCGr62JxLqZkVXP1GWpsvZtHWwI7jvdjTBQ/qocpMjJVmrrCXUb+QKnz96v02TpiZv"
    "dTva0FsTvGKYHIzPYXJpaHb2zuWD5rnF3PERPLwL+fLF6S6BzyoHjPkZE1d2YK5TNtbQqb8Q+wuq"
    "F9HWf0hyGe9Im/tOrLTitb+05A73u+8L6t52QdrBxGb6HW29u5zjl8qLybAcOfme7zMf4WUpcemC"
    "Vihzbb3a2jRduaMEekz9u1F6AWYzZuJMFStWSyuPWE7jJSLZwdrC+hI0VzI0DsAP9js02oWdMxDb"
    "TUM9uG2KRkOcdydVK1pJJorfYU4TtQN3VNIV3O0V8WZCzy0mwphQmqmApiPKUkJQreTm59Fb98I1"
    "2l6LeZuBXKtjq+uNDUbTOO4uX1x9m22sE42dXqCpWqgpDIZGqL21scV2hQrd5eurd6lbAKLNDWjb"
    "Dq0xLIpZq80ZCnjE0mS5lEWVLKxMAMMAMFQnCAEYMmhlLbMx+doP8ejhyv/8S7bdTvvb75QkSBew"
    "TROvXDnw9e/s7Oxs7+oodedsIfdvOQ4eDodebg8r8YpSyf/bUv7qOulw6MFQtGOYdA7Y7+syt/nL"
    "Jmv24nv4f/wTM7G02MEwpnabdHsVzGZKMaxcA98gOvxhWLpGC0maTNGbJ7G/CyLLJJsy9z6YvPDa"
    "Thvx3vf8fHQ+1W561rzLE8/eISvU5Dx76/oBxxMi5f/46p17nOZxPDMQQhjbX1rFG7ql3Ww7OzH1"
    "fJs1zClXVpcdPvfleJiEdh9O9uy6cEr2BV7++nz8gG/9DfMviIs+Z2kFt119XfyNX7evb8g/Rt4T"
    "Iu07sc5+LefyiNDtuOYJtcVN8yVb8rDbpBY+4Da+pw+VfNaFOOk4JDE/6MjNjC3GZ3e7Ou2EfmBl"
    "8eTJa6aBkfJaWgOsrs+ALQSJOZSOKrJOCpnU/E2me7fo6c6tvG8QjaeURYwdrNNkzU3NDmzRqTqM"
    "OifpKmOwVso7Gdso172s5CSsYcIIVNQVTe41uU1eixiCtK5UimskKbKigokqq2kqb26mEMvTWsXb"
    "9jqHugnUwNP8WcMCGgSf1pBUXTJqGwY3IxKhu+6CWID6pjLbnP3WXWsOfltXY7WBmDabSM1OUP2l"
    "lvStRdLbnqMxrKu2IABFFBjM8qJlcilqsthAtCPeQhkW5CytFJCugiYBBZAkpu9Y6qNP6od3s34b"
    "OXtLoxbs5RBhqcj5pqeDFk6xseFcaunsuiqXKumsVolXxoXJQg4kSTfBokg+8Rn05AO826QCbICW"
    "BhVICQ4dC33wIsyu0+T7r7fu27t4/Rbj7qdYJIqG+/dTtUBnL3N7HqbxsK5r4GmlN9+z3/egxxU0"
    "KQ6BES+vXyotnel/6K/FqdwrqxfcB3dYMnIL08noxjfmX6Us+5SvJ074WzDWAWVKbKIodHKkkr2V"
    "Z7g9XaR1j+vHJ8PLIMUKmn9tbXzUhlP0cw7uz69lY0o58bBhaQ88urY01ef4S+vxkpGML4aDvZwB"
    "HCgJXweS+7ryl0Wryu9gS+uiDRj0dqI3l9TfGD9UPLfo8g1k9MW9ZTN2iCu5uV5O2OGV3CvJk9Hc"
    "qmHwI6MWvz+3HqaVhJFP2trGkKdTmn01Zd5ASmt3+1NaelkuRBAQEQSdqCVGmSfhHajTxIqKqmnI"
    "CILLgkwKJkkorRgpkeKQEGw39fO7PSZsO8+lnRLfh8X5RGQyvY50HSQlIm0iXqAaRRRtDXOgW7Xh"
    "NWw1V+/XBJdt4P35N+o5LwQNg6rx9dpnjdMRUMpCE9Wp3RCg3mW/HbZV+FeVTdpkmAgaommjZKOe"
    "LWjcuMr+t60vAAgowRQQMdLh6EM2384HR/4qnoRKvmrgOgGap6qGlAo+9ix9/Jdxr48hxDh9ky7H"
    "cCwFRdU4shvW05rZurA0K+SzUqmQTkbkTBoPM+rHPJzJ+WgL7/gIefm75hGl+OmHdYRmSZkSEKnl"
    "fsbzASP1Q8xMHDnQ1XOOzN260X/sYez1gUFIOgrOVmpQ+v63AIguGaBmcesA2YwI/n5voFM5/aKN"
    "Zs6nb1dsg/4jz6NM7p077/gGR3v50Kmb/yJU2LTGWKwDh7uPfy959nqqaCHKB/1DD3fs+8OFHymm"
    "hT8coz9bjhRHAyPjfT0L5cG8EVXTA/d48ZEx+Z8ueJ2kf0J5/3zl0hP3lVw9xpUvjx7r/NrpPCPZ"
    "IGye7dXm++/bdTgx+e25A5vtOzZAxqaFHUIkJuj3etNPPFR6ZSX8j3F+6EjHtNQTPBC+kXgwdP+X"
    "M3/fanPJTiXWu9G71H0nuqFIBd8jH1QTSdXTpuXjBkH+/l00aAV2IvzGrFJcbzEH3VyQauU8LSIM"
    "6yTXQVvMSJzXNwtQ5jFXNrQcVabVhEjFEHGFBDdyWkz3jogmWNxJI5eUr5dPdic6Rm2tUXVD00vY"
    "YKhBQAdEAUitYK2+MySq7w1Gt4G2rtZDUxwKzU62pkxCfXuBbUvFz32heiZ4S0hCNdJV/bg2CK72"
    "JFvQr92ziSDV1dE69al9Xp10C3czsKopQFXHxZxhaJ32lo8eelKLlVmr6OtsT22uomIcKnlKdSin"
    "wJDx4Q/RRz+N2t1UFEgFhKFu7fJFUrRyTz3Acki+vRyvuKSWPufUOQJElfPtD/vv+UJHS7DSYYkC"
    "kzAjWRd2Tf5nfD0S7OgQCRtErf8fY3uYanHMdkP00yO72J0dwsRSRl+47d07lnj/BrJYoHUMVm+g"
    "QgICO0CXsMVNwnM4vma59xPFRA6lFxYrMf7Yb9mCbfL5n7ovLfV17koZxutf/x+cIo91ftpk4ARX"
    "fCvxbj5y5zP2Zwsk6qDc2dJiQl/5jVZfYJzr1PRv38rZ5GvHDvgtvL45GX2DGz+12XG8e/HIE8Gu"
    "W/n4t0vvrgfutPdPvjXa9qn7hRMmOU7zs8abE8KwxSrsHGr/LptJcbrHupomhu94NicX172dQtHY"
    "t4v828sT0VLS4/4NNDDW1prYSB8VjlQq6w+hw9Hc6XLAen95/+Tixbj/WvuJB6MX3ssvTagrt2WL"
    "z+byc8XDI7v2r0+8uph9v4XptCFriWZt1GKhlhbksSHTkhH2IFuSloLY20L8BNEDzGg7ard6bGy7"
    "uzRmdjv5VyKXLQXbair6L9lX7h/te2x3z483z2PGBcQACtSg1bkZhKKtouftnrpWdFajOg0baNoZ"
    "oDGiuTkfsB3LTa66KX5G9UwwqnWRNYTOegNC43lqD4gA02a4NyBfe15cXxLq8XTtKZtspGFClAb9"
    "XWaL7fLybMDm/+/375nTlB9OTWC1TJQSFBKgyfjBXyddw3RjCTlt9M4sJJP4v3xa/PRH5JmkZvaC"
    "WQNpldyZzA8cLncMcolZuYz7PhofHHxNyxiabpF0uWTQg7tTF4YcJ2elz/a41HxSYFqodAdhAbme"
    "MZL7be5bu0eDL12zJq9c7P7kbyYuzwDLQzkH+QR19CKGQzY/nbtCI5Ps7mcUIaDcfomR1ro6niFd"
    "3Uuv/pV3PVWx9E1U7sxfue4afXK/dacYLS9UVpf1zeXCjecdj/cFx+M5brIyP5u//l/8B44HHZMb"
    "q4WC6cOtgtkwVQIj+4LRh+wrfxAxWXyty2vOdKHrtCAbDzqWl8qbzorK+KajLe5Hj0J5kW3TN6K6"
    "7QtLsSF/z/NPvpFM9MnSKptZHGsxn79WmV9ZemwPa/Fyv/d73u+9pJ2+eIvZ6G+79//mvv0py72E"
    "MYmi7ZfzA2csK1HPyPPeZ/5z6pWcwPXe+2QULJkbJwsT7+D2cS2zziKmrfs+kyiW0wtmg21FbRG6"
    "aQMLj/g7ZA1A60ZtBjH6xH6LP0DjKc9ojyIhGPY6ZxWLJBZkbV6NuY0Sp6JFfdOlpT/78bZV1XXt"
    "RYoRpoQAociglFJEm0LdnwdrXUehtUG59cCyAfc602n2sBS2X6zpcwTVcmgKtYHqzYOfGyc2cbHG"
    "hbddsnFG7bAm/lWr2qtFGLTW4YbqlycAqKxpTEU28YX/dfD54oWsvLpgdljl5TgCCqoOxz9Px+6j"
    "yzfQwCjSdCjk8fiIfHkRYmHWhIxvvKAF2xhaoh3t1NumGe0acQqDxYGDp0qa9YOWfx/gnrhE/ucZ"
    "40utptTovpGX3lp7Lu1kySbN/QgHfodWLpDkP+j5SSQU7tnf0vaWb3o9M1jJ2rtChaiMSmlqbQM1"
    "RzkrzeUgn2FGn+bbhtSbL5K1S7vMJ1zWlttvf8WxrjrYbkmKk7LUt+OpgROfnbj+s1w60k1bNwN8"
    "UOQduvdM4bxVY98tzwy5Qkf7PpAX06/NREfFHjtn+nY4/7GkWb7v8KXdj0tfulWJXcu0joZvMJu3"
    "4qFferzCQuV7b5LlJNppyBNFcHRppRu2nh6F5UpX59789UOsGU+akW5i08m4+1NPad96SXt9So+n"
    "uI89N/D8p/avW1+9+Y+esvys58kfpF44jndMrC3sGHCbTHMJSKFAS3vw+IXXvm5EEx2HHuFUPTv9"
    "fil8hze7ExuXKtkNl6OPM1GjlM5S2YRsJmQSqZWn5i7GaUcmSsGye2dRK7hjIhP0+XXr+hO+MloP"
    "Yoy6OpjLyu3cUlhak2j++sXci/KGC7WAVgYC1CBAaiNFqpyd1lGyDYNNHcFN2tB2M0F3KZxNlnMX"
    "BaqRHtjaJrUeuaKmlC3dnlNr8tbbDLVGbZreqkUbjc772s/bIvB6HmOrIZLBuq4xhP7G8Q8KC/T/"
    "fusrflU7fuAoMbWArZ0e/BgceQxMAAZQ1aAWDwAi8ysouklOvq1du8k4zLC2ZGxuGoUKnZpA51+h"
    "qVvH7/uG278oGm0cdt3Uv0oodw/+jSLOHdnL3qLi+ZuG6LTS9L8aszvo8nNs5usiX8F8KJ0RiyqW"
    "qWnj4tmOQ3shvYL0ImIIklNYLsPCGdYX5KxW+cx/iJHVIfOTIrZUckt4M3Of5fEBNBpEPcOBBx7q"
    "enp6+RaXYz858ty9vUfkzdkjRggjblVKUU8r9o0U7S2zZdOfK66v2McWJeuZMO13diyg0H9Jj70k"
    "3KNH8kpBCj33NOodk4om0KydO0fV0aNkeAcplaQcoSEX7morvHpt857Dkb3jarggFfRSpMI+80Fu"
    "cT3/+mX8+c/gR07Y2kL0j/535rf/okt1Ped9+lzlzVhp41NdnzRYIGV+MV1eykSfdK+tuLUc0j09"
    "e9K3z6rpzf6DR0KjR+XCptXZ62+7P5+fjUbPaLpMkEEYzCOOobwZW73Y2cK165TzUw/b10IdnL27"
    "228PtHd1q27m/f4oZ8dTqaRJ49aVcDmbk3MSpPDsa8LF18sIIaJXU7+IEqDVaWpV0DTc5Rb66wS8"
    "IZ036mqanG/NNLaLOY3Aun7F2ktzQ8xWzq1pK4DaIXU7ow1Js+me2+dHo8a1GmtQg0jVf4GG+EMN"
    "jeqSmRfvH97/a4c/askKa+Hwxx5/ytLiet1LcF8/Xy4IR+7NbyyjRAR0CWkyunSGGjrKp+jaIj+8"
    "Sy9VjIKCZy9QpYL8HdTCgL0MmdOpdJEtWHMkp9qkLu5+E3bE8fQV+I+AZ8PcHvje5cgjD3Rx1mUw"
    "NIC2dMo2O8+evQ4vvG+sFCzIZFmbmD1y7EFWyBqMC/QySFlqpWBUkMmlRldYoXOfeY9RUlyyWpKi"
    "IWztF53XjDu36flD7NPv62tSS+BzuN+RpW+svs86fe7e3eFk1OLuKQyNJGdXQoWM0z2WMG1k3YWl"
    "cOzB0HChxfJ3pta1U+umDUJ1ylCOujzZ1AzEEvmiql8OQ+cAe/uqceoduu8AFkTnfQfTSUY+NckM"
    "DxisBaWSpat39Hvuc/3+LxV++68kmZo/+VigdxjkPH3xzFXVuQsc/0P41NXc5JCv7YTvsIpKSTHb"
    "au51pYqHTOHzA8MUOQwCy+/+0Pz4L3QdOF5MbmQitzz+EadrT7mwommyQkou5BKwmadcDkuggWq1"
    "oJKOWSs7nehgzOVf2qsluVBraCN5+rRj7bNs1qd5389cL8oFUJCMDF0xkCKAjkExEKm3/1aJRE31"
    "oajRDlkNHlFDqoRaU/vPhbR35bi2xcS1aqGm97e+tu0SWQ8lttaDu2/QmDtaTy1Xp2Btv2+tRab5"
    "utBkJFULp5RSluF9rjaf0z/SObi3d+ebl84e6hnr6/JfuzT/H69/afBzn7FYxdYdo7F0BPI5SGyg"
    "3hEKAqgFSGyA1QEM0XIltDiBKilSKSK9DPF5p6VSWryh88r0de7xE6LERdaNdwvMncvGlyScNohO"
    "2LXWtuBr3xe+9jWyf0ff3IIxMS1uhFvTmRDobXs9I36Gno2/LpWiueWplnsfD19aw/kN6hqkoh0x"
    "glEoMr4eWwVpa+m4Gt7H3Z8xzPt4Z1nOzssTGMFiXygy5Nq3mAwm7N+6/W9v77S1PfBr112oeD4n"
    "i97KPn9lGXaK3W8tX5gfEYP3Hi6t5B3Wti+6LKkTx93nzudf+6nhG4H+9nQFytgLxx9SphYrVo/4"
    "2HHSN65HdGZ2rWK3aff3YWQ2vvozfG0OuR2c28/mMvJ/fIf+9qctv/Fx7T/fQv/5UgnzHe3H0L5S"
    "fi7xzfLl/2569vc6P/+fme902B5T+HKXzea08PlC64H3JvP9iZtju3Z88vM3v/kXt3/y5eEPfJZl"
    "Me/tkajG2wKUAEtYDgm8iq3ULvCMrFYCzgFkdlG/32vr4A52d6SMhaHAla7Mjg1p7c7qGqz/EfeT"
    "3+951sbQZF5BlC+W86BRqiMwCDJqtKXGfKBJBKrrP3WeXVcWETRso7E0VDkMQY0eGWgQljqpQtuq"
    "iba8+V0NMbWP6LZooCYE0XqBKa1Fy9VQuKnnkQKlFAOuPf+W3eH6SdWFZqsa2tDViiYnM5Fz6cjV"
    "pflfuP+D/f7AC//+WqGSHWjtblHQ6K4d2NMye24CyxXq8UOwEyauUJMNmeyYxfT2BYIFyvC4FENy"
    "HvLrpJLuHBtTDz0w29pKdrafYlsHTJdvaP+pYBlxIICH5lumYo6b75Bs2vHH36Ut37VZhJ2t5n3D"
    "1l0HA21Ww8FiwE4oltSLpbnI9am2j34mfHqSYgBrEHIrtJThAxy2OuS1d+8o8SPiiQBjL5C1ZWX1"
    "unrVylh3DHz8zr5jzunzHXfyP05dOiXcsAz/IcNDanm9WCh4n3qMWd9EcvaCEp5Oz+0e/PjRKelV"
    "KbI+t5Ibe35Ik29VKvTYE1yxSHyO0ruLzMiY6Awqf/3X3Gd/UXSZCgaPP/xh/OqPjPdf0zr/Py5d"
    "1h84oi2l2HgK37rCjByQp66qP3ybtrRbfvFp7uqaA+yZ02+HFPOj7CMrPucP4698wv7sThj83sIP"
    "ngg8aGcNxUgJzOgs1l1lwbKwbDY5xz/y+bN//fnIrQsme0DZnBTb9rBmh5aLYouJ42w23mJv3YEW"
    "bln6e4jVbeloMY72296Ore/3Jni050o+3p/5Oo3t4bu/ufjS1RZ5KbjoijIwayCCKaVgGEgHMLaG"
    "BW+hgEJVWKwXNdxF3qFJMqfVUYXbq+LqkWj1ik3sqWYfWzonqatIdabOVq+DUdOlquC+i1whqDOg"
    "eh1E01l33676Fq2VKFV/qmq89ZgC5YuxPDFGu3bft+tenMeXV2Yf2X+EEvK9qZfjMzMffOzD37gy"
    "CZthVIlSpQQYo40b1OKjglMvbgJiITUPUo6qGawUAQCOfXzmo7/Ihlphzwjh4cp7F40JEuwKmJy5"
    "YFs7WH3v3bx95ceTe5YtSVleVLUBzyd/oe+TUOZIHrQilAVdUondzh1ruedW7nxy5e2OSsbS5Syv"
    "JFFpEzKL2D1KLG598TSuRHy4pZ/pfFt5cVa+SgEjxD7p/dzlDpFsrnasFK/mr6ziJZO1Rzr3SqpY"
    "Npxtvr4RfPuSaWKx7OyasReJtt65kLzWkVgwM5zmfD7FTH//JL9jMDQ2uPGf/06iYdTRJezmylmV"
    "GiqJRJW5hKGx0Npp2Oz01HfZr/xYd/TBeKe4Ghvf0DK6aTXYEzTp8de/qft6ypnH3aW4mqjsxr3G"
    "yqmX5JN/6v+d7zrDP5r++s72/e/g16wVFUC2O8x3yqWl8Z0386s+k8/yxqWOh+/PHvvEwumXLLue"
    "Ntu9icmftAw/xll8eiUrtO/nqEB39ttDFsnfgjqD3HLY8FqN/cEuyr2sLJdxUZ+T36lMfdx6sNc1"
    "sOY9f8n76sG99usXEGgAxpbcCVui51bnI6JNcwQpNFUub3nPWvRZs5Cqp22YQXUhQHVSUj2QIoS3"
    "9NB6CIvqcxDrBrbVjY5Qw/zqY6CbjRGajaF6XMNAaePzWihTs5jakQ1rQg1Tp4hSoITH/J6h4yUF"
    "Xbx26trqxAcfOMoX6d+8/eWT4Tcf8e50F4z5KxegkiWAkCrhYhwJZiRnEUPAEUCUACOAnKWahPY/"
    "znzh+8x//3u1u6+ilWBmUr14bee/fXFvYc6pjXajj+D5Xam3sXPK/BXuxI/Gnvj2+NNjUsjjCAkp"
    "rpBSVE478Kf6ib9Fo8/ifJzuamvvcowTYo5fOu89sBd0A+UWkbWTuvr06Aot5lzs0JCw/6p+56J6"
    "2Q+tMkiHxYc1HeeWL7S881YpMhcBGamCau8073zUFgyZswuF7/519sxl08CBEoC2en637DHL9ht7"
    "ugIf+63hA48tTV5a2YjgZKYYLxoaIbfOMcRQXz4JhOBAO715nXzzGyAXhLEOs91CHd14dh5Ov8K+"
    "e0agAg643e1BmJqyPPKceM/zOLIMP/k6XS2qV98KX/vBbmu/jMu3Umc/5/vkDyrvxDfmdnDtlwtn"
    "rl55xSirK6DLnDS8c8/y9DlztsCeuujztA3seyR26yc8w1h8PYX4gq37CO/qAZcXn7iXcrL5gw8E"
    "/M4uC288PLSpZS5pm5bl/MEWzwvF6y+snNQ47Up5vkWyw4Yczaxci4WBsFSjsLVNCFSFf0QBSL0E"
    "mmzXK+tSI6pHxVvIqWFyyzxq76EGELd5Xth2yUaaoQFkihsIpnWuUwN5PeJtgj9tLsvYil3qMXpD"
    "6KydVi11rj8Gaqxd1V/cYBh+dm2mWMnaQu2/+/in9PncUj4aahv403v/+s6lW5cuXzN5vVDKUsFK"
    "RRdRdUIxqCrNhlExCZqKdA3ZQ+jZL5DP/Akd2k3eeB2KFO0ahbY2JhhCgUBWoZN3bv7wJ9/9+6/8"
    "3V985a96vnnz2FXZvpLYIdo+3zkWWZpVHTqNsTs/g1tGcSaMRp9nnQMGk2f3+kaA8yQmpl1eG3Za"
    "KLUhixf0CpTXLQYj6niRjUxwcSv4/NDdxnWJBvez8pdwenkud35Zm7eaW0xt+4JHn+jcMy4lwvzl"
    "a23EXNJy8xOnK9ElVMx34/YEV4Tpq3afWT86crk0cycZwaFWxu3ktAqVK7pKjLLCvvUWM7iX9O5R"
    "Lp2lGrZwBjAWcLUzLBGOPaJeerecWZ0e7cx87DFrV1tlam7fr32y77f/rM3X27Mp7Al8KKxPX4m9"
    "NGp0vaG+jUqZx9wPvVU52ad7vbb2HjSYXM60dfW0RTZGdZPP6nhp5XU5ldGWFllPoGv8aGr5kis4"
    "znEYAzH5e8uxVcZpFVvacbvN89C43aTPWhSGU98qXIkzajhSQHZTQSQL4blr0dlSLq5N8stX9f3D"
    "MRAxUApbg/9JzbOSpu3s6qDe+qEJh9sDzBqXaIpWG0c0yzCN4KB+dqMatHFI03ToqtRfi0yqAmd9"
    "hNx2C0NNUn/9OeorQRMnQs0PhRpPVF/jMCNVchyo3Z3dx4Z3BZPa9079VHVgTEkqufTGysnEwqbZ"
    "6QNeQPkYVSWIr4EsQS4Kazfp/ClYeg93jKHP/TM+8hBMXtev3Ya+nXDtFj0/jUpAKb8c6L597uyN"
    "q1dmb98km2tfzfX/110Py4dDhm7QROJEV8CdTa8qGw4vs/Q25czUHqKsSBw9NLVOd9mHrJZBWeLp"
    "ylzo8G5KWNAlqCShsqZp+TSNZwQoKdPD7F47Yx80RmeM6QyTjpcSOT3aERzuat/j6d/jdzrUuens"
    "5JVWhclZ3NLmtJJb5Xx+C++f4bMXite1yQuxcHRh4nI5UfYfOtrS3qK9/65SVJixY1iwYOD0pWnR"
    "4xHbOkloxDncp//4XTWRZ1o6ZXBaXB7nr/4fAqL0gy/Ff/CCtXeULG9aw+E9e4dCjxwXBWnMs+e/"
    "DX/5sO3IHtQVhty/J772sDaylxmZpRtFtdTpPRJEA7258AM7xhbe+Gmv/wDf0rVUiI3z/fm5GZbz"
    "mi0taipi8/ZLkeu2tj7e084hqe2hQXsLu9mqT/GxWSNGzHSNRN5Uz+dTcdkgCja0dDqVWsnrCnB8"
    "LCK8dgmDTqhBgUDV3xNKm1pfqgBpyr82gbZRjVYDMWqylG0XaDKGGunY8re05qARwNZQ/oZF1fYI"
    "A2i+HIU6Td+Kh2m1Srr2KFvLzv9zdOK2n+m2dPGW6FtjXLU8AMdygPkuZ9vneo7PXVsLWNpeeudF"
    "SY4H/Z09Q0c2bkwHeBG8biRlUXqFamXIrFNdR+UEKGk0dj/Z+TCxmcHrQYeOo84uSgm2i8zcKjl5"
    "i753PUXtK56uZDobQfThwJFnP/Fp5R+e4f7gUfKxA/pqpg2RA15xOTxvH4LUJNz8Jll5i/70l421"
    "U5jq0Gbzem0dwIrhc2f8Q92AiqAoqLAC2GKITtbcms+db4WOVja0geY2cWQaz2LUIgHT6jp0KPRh"
    "NbeaXX574eQP11YjfDk7qSysttpY0WK2iSYlQdTSipEzBu+nnBm/+ZPiqddUnljdLvXOzfwL/04E"
    "B1CWy2QZhjd8HS6LyS6VYG1eKCboWhQjyhCZ2XVUmY+aSxB67BkuFCz+9Avpf/0zrlReu7wSmVrp"
    "2j82WfrJjyb+53puus8xcNS895OWx+aMjQvKVQW0TvDdURdPxa/ZvAdW5zZDpYKA5NNXfjrk2ZlS"
    "4koy6ZBweO6K09tnyAXMcEKgB2dX/aEBXNC93Q5PyFbCyqxNSa1cWVYTFqd1zkhfnT8nxdZ51QBZ"
    "1XQ1KueBiKVFtPqeCeUxUAoGpQbdanpElKKtThdaQ3YN92gb4puw1PgB1V+rSK/JKog2Q7Lmzuu1"
    "0s0MvGYvTYOxaheltbihlneGZuzXzYw2QbtmcNC0Dm1PRtTe3baeYUQp6Kylq7X304MPTd5cXQlU"
    "AhLTSrmH9z9Qkk25Sn45et1yWbS2BsubPIgWJBWBYyklWHDRYx9FXeOU6pBLk2QUOR0QWcNH7ufH"
    "9xrxBJ2bozfnaEd78eFPqpIkF9Yd8xLpsRuSjs7Och/bp76zaFrJHuuxX7q+kNlxr4UXrn/JMNux"
    "qw+bumhBUd6MzUfz81hk0vHYQGbdPdKXmVhFrIat4yxiy+oKp7HjlqNL0pXb5JYERcGxn2c7qRQd"
    "sYwmF96bTb0kCViwdkDkYnn1svOJz/kHBvKvpiE1K22uER3bB+9jBveXbv2gnQ0yyKMFu/PXbxXm"
    "3yGs1bX3cPH2TbQ2bz14gt93sHDpHG81gZIxWCfKRgh1ksycPTpTuT5ZvDPde+L+8cd//ezC5eLa"
    "+xWBV8MsXznmS4eOPvirM9/5j5fW//kkwO8yT/3G2C8mI6mFbDiMU0NG4LB118nU9V2VkWvUsXRj"
    "5sn+/eduvBoNL2isHtMXfa7OKI90luOsVkUtuIaPmMp5O6uY2VZ5Lsvvc3FFkZitomiZWZkyBftS"
    "K4tmoNnVaY41I8Rqiqopla2NMqEMVIOq+yfVkodaJUOjD7FWYtMksG8rfKtBh9ZGZ1WDZVotI63x"
    "8PoHqFZR16D2VfjWMloAtLpFUoNCoZqnrmXjqpINhe3o347s7eivB9F1jlTjO9V3t8wKYaorPCX7"
    "uoZ+7b6Pnlmc+MLcDxJavk20dbaEDANdu3VpYvV6xd1S2FgNdXSAv5eyFmB5IBq2usi9v0RHjjN2"
    "C8UMiodRLgXd/YzA0LdfU149o71xhsg8DfXC3ApeWVOy2QdLxn+5s6Z98wIfcOITI8ZEGCGDqOUd"
    "Zp4Is6/MXLC3YO9OTh7SLpQjX124/Fd3vvHNyT/R9ZOIVgA7M7cmOvu7gJQxKyBDNQCBLreKu9fo"
    "jVtwC1GHnRlE2K1pWZ+GQjHjSuLlEk0IoXsF0LXobVN3V+cHn4PoBiFsMZbUNQMhBaiqzl0WVaaE"
    "kO/Ek4HesfLM25WNSf+DHxrfOySUspym+VtbO4a6tdXbxSuvIpsDTA4ml6IqZ9r9UTK5YITPlRd+"
    "xJ89M7KkPX/i79o9e1GuSFZnZn/8+xNf+yfhduFD/b/1MfNHXCBeMa4l8+H7vUeIobAEFkhYBSnM"
    "Keuri4ddrT9Oxq9Hk/s9fWAURYJPrrwmkWww1Id4wdo1qsolBMR7aL8w0q0SJZdny2UllQq3tAQ5"
    "p1fKJyrZbK5QTKsK4nhNk4EC2gK6TkAHqiKkIVQteaCUkFqqi9RQ1dAUm2kRbeCpCUvNjrymtjRx"
    "bFr9oDrmv7EiNBabbYLMVjFck6JTnwqKav3wzTdviinqClVTmgHVAvKqq8dQGzNajz/qt6bECLha"
    "7KLVgtgvvvHtola22QNPdx+IrtxcLK+PysfP3HmLObSHkdTK+p3ywprZbK1QBMEhmlpDLX3QPwZy"
    "0bDZMAuM1WpwAl1c1nUeSXl09g0CAp2eAV2mxTTlOVpa25VUbJZRebNkfOwbyDBwIs9bBPDYBYYn"
    "wuYrq1+OlDd5I7icW8moEyqzAmwS81mkVyjGSLBG1yLjOw4BGAixiLMaSoTXS2Vzea14i3BuFzXp"
    "rF0QBnDqYpfuXIVomdU5IWR2eYzCiq5mPD1P5372zeLsgr33YCYXBzkheIaIoijFSb+p1+7t6hgb"
    "jp1arYRvOseOtQ/0C4u3jcnT1kPP+kQs5ypyhRppyXnwuLOcL6qYS67vf/BhZTVcsvOV0lp0/t0N"
    "cPrco7/08Be/8+4fsrYum82bT6ytrk9YLaOfCzy9N+77fuUbf7L6xaedD4zy/TuotgqRnJbNgXKL"
    "ao/m+XsDnSc3lyxmI02jo4799kpyau5c//5noLApMxDacyJy8V03z4Q+cDAys+rrEIIuuy/NvHL6"
    "ZNAVYLBJWZ6mmqLU9k2kBkGEVNUSApQiMNCW+lnbP25LrEeUkjoz2VZAU8dbg4Ns+2Tr522DSGpp"
    "4LvSY/VVo75obC0p9fWHhcZdmggSaqhLDWXn5xqA7xqFUr3Ndt2zmfJQShGuC1w4J5VSpUJKVyuE"
    "dreMfeLBxyxx+eStc49/4LHbEzPWYMA1vmPzjRdQ6wDd3Bw9euBKOMJ27TBMdvD4UDZG12eMjlHg"
    "HTSTBk2FdATahomtE5beRr52KCWgFEeAILvJRxYnFf/6vgMdRQGyFQi6jBHfet6YyBdOrV2bk1JU"
    "KFzL/jMwfuBUIGlgKggUilidcwDVoLQydPwJxeIFwMCKVM2Q8qphCia1OOb8JltXPjfbxnWrpSmX"
    "IRcgGUVLsi452x/Wi+nC4uu+8eeNgrx28v92Pfn3kmxQLYcRK3QecA0eWjv5T0PWvQLjg/VVc551"
    "W3dy3t6A23P+r/6St7ucPEtWwsVEzDF6f2F+0skJno31TCTnDfS0zm5mUqXDI09lFpbyRmwtcX4z"
    "eqtPO3i0++EfXPpfe9wPLUC5UJm6Is23Crlf8X40E4/+q/INPfdOL/Y9zu59IPDggnGroKBJxugV"
    "BIbCpho/6BpaKy5SxLZ1HYmm5zam3w61HSA6pbFE/xOfKCwv+vOVwP3DNqwlC8UDvTsrufx7b/+U"
    "ZaxquUSJahAEBEAnNdzXmIxBKaFAmlxpPfeLqtSoQRXqLLleirYtNK2CuibV1MlR/ZvtgETNZzTU"
    "/torBVodjIWqmL/r1KZtw7bxn62npM0TpH8e7bXX5g2bqnZY7TRTNAnzlnwu3uIMugT+iL0vP5Pe"
    "d+DI7aklXdUcrCOciFGTiBlSiC3FpqyDjz68vhHXBQeoBl26gjx+ZHXS5TkgKh4YB2TQ1DItlUEv"
    "0OWLmMgku+pkKYeZIhUjLP7J2vqHdt8ny3g5XZhOLF0urkxoq0leyYuYEhtwFrC6nB2DnUNDS1ff"
    "Lc28BXoGoGy2mUPH7rU/93tn//KfMGKoVgZQEGYM4ChVOWsX5UxmttVc3ogbt62oRQVDp4bXOsDo"
    "XGbjnNUzKgih9evf4GyDjGjXMsuI5bmuI6beUW9/19oZp8fZaVEgd3PSJraqRA11dhYXZ4mm+9t7"
    "pLkzaW+AWvz+jlCbYtFXVkghc3B457Wz7zmKQZvZCYmsz2vdJd/3xfhLNsGZuLl+f8+zD/g+ZMmS"
    "NvaeC/KbAdRyU772Q5bPi7kntGNFyJ6BxRKRftXcOThwL47eTMnlt42sy2ydyE56zGKXo0utFBWl"
    "0Dl4Ir1+sxBdsrvbLJUKkSqme/fHXz6/WzwROh7qcdJX5uajsZinpS+TSDGiqEsGUALV+rYqPAG2"
    "ity2Ej6wJf5AtfJ5WzlPDRfobgpUPYOierasCtzmg+5CXxXt1TI2VN/nrjkvUDcbxNY9da3wc1uv"
    "Tc10UN2WUK1RsjaArub1a78E1Fc0VKNMVfuqy6fVdDCiQHRF5M0ibxnzd3SDE3dzb165klfSuirP"
    "STO05OVYHgOUMmVjaeGex59cW1hh9IohURTshWKczl5GmgLAkbUlpORoLooqeQoESUmaWACDGL7e"
    "Q4fG3nnzfEQk3yzMXDyV0Qm7BoWkqBYEI4cNAAEHhlrH7g0NjHvcdrmQLSxch+S038u4enZZe4Yl"
    "33BR6Dr599+FpUVgVIzt1ChT4FnBR7QsZThS3MByJkqTIggOsDCUxQgh3VxKxTjWwljGUgtXWd5v"
    "adutSUXB5kLWduuBx+3tbRQZNv8gAZOfY24un+loMVvtvVazK376dbPZUdrcMICKyXhwcHeHLxA7"
    "P2tC3QHJV4oleG2jVSJ2f+e7t9/67OCnGQt3PP/EgjzXKoSUhehj/ofmuRvdECqyaxE9kkKbr+Ze"
    "9TKWIBX7cdCEBDMmM9Hrxwc/JPi8fDQrmsR0JeUWHVPJeUINAQSXXFLii70D99N8KrNwVSnnMWVt"
    "e4fEJ+/ZODltkxXzL/R9Yrz/l25dXDv7Fsdy1GQGVQbV2FbNQKuSf21BqKNzawJK/aBmh9z0H4S2"
    "Fg1UjR2aYkvajLD6yXV4NwYG3SW61BhQ7UkQhqYtku6iN7QG01pquqYMbWsYQM02SOuW3LSi4WoC"
    "u9qzQ6HR6LkVwhNKwecNyUh3iNzN80uX5852BloSiTTq9VHeigyWISzCRCskJ1/6AYCFqCq22oiu"
    "Y15A0QXqCEFmCdJL1NsBFEBTIXyVKjmERSz6C2Xe5gq0trnXNiuqBa8aqxpghcUGUMz7ex95vmts"
    "zCAmObeWnnxtMzLNMlmz09z75IOKtSVV4iKpcmlmCua/hItJEEOgYwysruYFax9FLEUmzDmJMpmi"
    "S37kHIYBBIQCVWjRr/lLvAqcV9NYQ81bQyPWYL/V6c3FN3SDBvr6XE57cXnOWJ8KBEby6kZE2nBI"
    "abBKmembakaS8jm7p48qaVeJiAt32kSrSQ92eH07rO2v3v5GuXJrPv/+Zwd+65v6cqWSaWsPfMT0"
    "4beuv3Iy/8N21P5AZfyQaddSeX6UG8oZyRFoYQyybqQiWJgjm5/gj2paadw5LBWK6XyWI5AqZzfz"
    "MSflnaLdQrgVeSOSnNzB7benVjXR0zZ6Qp694SYczZbEo53agDOxkJmPlnWs/NlHnv+rUmnh8ru6"
    "lEWUAjWqhTZbdT5QbXNpQmB9Km2N69M6cLf8ZLP/rw+0atKB6soQJfWzatSoxlmarKERF2wLGJqW"
    "D9q0TSpUlwtUm0LXSATXTIzWn6jZqBoyaz01sLV4IIDqpq+1/yPVy9QfD1EAjFBBKh8fG108N59L"
    "SfeOHeazqmls0DJ6BBKSp0RQJYmcXkPO5668bnB2QAIlBNKbFPHU6qXRRarKADoUE8BgUEvIAMAC"
    "UIoYhJA+naLje8eppqqimOegImCD4ylvNVRNScXXz7659OKfxi7/C2+KBO4/4j7wbNb+8NRksfD6"
    "lOPNG+j8K5bFV1BxBhhMlDDDOClVMAZe8NHKEsuZaSVsMbATBW1gpVRDlERgkwMjSdbS2hwnWhFD"
    "KSkohTlb2zA1SOr6j5wdrS2trTQdX3//+w7ECSbv2fn3A0JfuDAPDF6//A7DiJ6W0e6e/Q5kMecz"
    "+vIt6fWz/by9RzR3FAxejfRRSzh5NZG62eawvrLwbTkZ5UC+v+O+Tj50xTj91cw/Ojh8wr8vyxY7"
    "wG+j+DnXiV1CT9jIiBRHjdwaTa9CnLNZUjzpsrevZyIL+fluXN4jMK1297h/zGpipzbe92SiB6k6"
    "3rNz9PCjgVS+9+aG+N7qQL/f9XBnWmFmN6I/OX3p4OH7Ow4+avG2MQyPGREIuYux0zooa6Ji48Nt"
    "cWJtvWj+ojUQNfTJJje/7ccq2uvga5AWBI0xnM30qvY8ePtdq6SrEcei6lM0fp06vGnzqTWcQ1Nc"
    "vDXXaPvS0lgc6FZxEuKQ8EjnIUfYeWlzOXrctH9ol8PTIdx/JLYRDcXkgSwChIEoNLtGWDeZO49c"
    "LtArIBVoeh2UEjKZAWMqWIDjQSlTCtTeCqybMmZDK9BA6zzuZ/uOtIQ4LbZBCaYKobmYubLREVID"
    "rjX/Hk/LY0+h4Wdiat+tU1MTV08a4/ln/vzoHxy77xnG11mRQTIoYiiREOUxshA1xWALVKKgF1ld"
    "ZkuxEG23gK2Htg9Btw1ZzWAmoEi07CJugROMypoqLZgdIQHQ8mt/RaSCf/Dg+uk3pr71p0auMrD/"
    "sbOFHy/ps62mbsKo5XSUxw5NVb3BgVGHe0SyZMNn2WwsNneRL2c6OHulHJcr1z4M7b/Mn5iJXXJw"
    "ymnt5fOrry6GL/a3Bj4WfPYeNLJCV7+R/Wqr1XXEsU8DtQW5RcQedowHwM4gJkfKBuIKuhqPrjOM"
    "VTdkVS93Cw4PyJ1iqcXEmQTmnvaD93u6+fSd1ZlT8vVXO0RucGxMnVtd/9FZ+r3N9jJOadre7oEd"
    "bZ1INQxFIqyJd7QhxFFCoDGwkG7742/RGYAmN1lDTnUpqJahbcEN1VPFjVDhbrL/c/M2a1HyFruo"
    "qzr1hMLdN6VAgd3+SR2ftXK7Wi1P0zLTTHYa1tRkpw2baNx468KN/AACQERXAeH9vbuKaulvzv9b"
    "//BOR7o0Ggv4Dg5fWkrp4du8alPkErb1QCQMniHq6iXZRSa5Rnp204oCiTmqlUGwI6uLEoOWC8Cw"
    "EOxHG9MgWgE7aSnSisve8LlzCffIJ//QduVn+UTGFWzzjuxSXe3FVDmWNxIXkxqJgJFigi7h4/vM"
    "g63DfbwyM1/c2dseGR65lWDKzB0jaxgqx/ZQUib6Oms5pKppg4CZWlqQK09nDMjvxPcRkBfILQKG"
    "F5whcCSsfkOt5HKrmO9kOcvK2e8oFSN0+DmbRbzzg/+jSEb/4c/rZnJ55mUv7xN1rVLOggk5Q6Oa"
    "FLdgDq3Nu7WMWEryULRqnbgc6+G91ysvHGNK+8yj/vY9K9K7QnrNhvR38q88JB86WYmd6HlsLbaT"
    "aOhd9cK/bvzrL3Z+4mb8nA88Ns6aB7mT8V4my+3Q0oNbNmihE6OonCxXEhalnEeyx+w1yzEH66SW"
    "obJJGObHHxDSG0phKbEIN2VTYPjEvqGDCgTjxWv/EDnywZ5MmziRyyCi7Tr+gWuv/Si5cVWX8giz"
    "VNeasVCNI2mTeFPHX4OdbOkztPFOMxMCgKbtuYBWR6dsa5Gpfgr1/i1UHzpY72KpWw1s42XbMsHb"
    "F5gmrrTNgKozLKrDUep20QhhqspRzeabemvq10EIUcPGW3tah4ua/K1rLzrMQnKq8Hef+GMmvFHK"
    "yc5syppdt4o7Jauf4S3Y00sRS+USlLJkcRJpKlhdSDSD00fLBcqwiDdRbwdiDJRLEt4MZjtSSiBZ"
    "9MzaThKXitzpVLpl/1H7rqCuojvza/nCDSAZoDwcOSZ88Lhx545+a0nr7zIic/YDY3g1ceeFmWPW"
    "Qy1W24XsWqfYF5EiOhSormFkIjpVtQwntpopo2obCbpxDxrLQvY6nUBAd8KoGzvO05vraqxV6pDN"
    "PUWGlIrZyuZVsfdR567jayf/UZESon20vWvPyuT7vGuHXElq6Zi3fW+Gi/hc7UYe+jW8u4Bm8/NB"
    "LUwol+BYk5FX4ytQPnPY5nI6BjQmZirMtkrKDhzAhjYqi3PS8lvGC3u9Y7FoBEHPz8qnnqjc97uD"
    "n/+XuS/fy+/rxeZ+bv2CujpLYw/a923o2cnUvOBlZnJLI1YxnJgxiX4vp6X1bHtlqd9mBkWYzqQf"
    "8jG7DgQT3oHFVVibWtjX1+8i0rHxQPhO3j3mXHfwX/z2tyxWh88WwIARJ1BV3/rjUowAAxh1z9hU"
    "+IOqYK0HAjWasPUuae5oaTabhuhSNZftuK5LN3VvTendnzUsqgH5RgywfSHYWo6qRAk15nlCPUfc"
    "dHSV4te1zsZIruZABzWfRSmlhGEWk6tXFq5RwCF7x2DLkFNzY8TbixV5/nIPuHqFHgqULF5lrQEq"
    "2qAcobxITC46dZJRimAPAKGgq0jKA0IoswGJdZqJg8mOPK0gWlBLb9wx+LJ/XzE0gKAYe/vlxZ+8"
    "uHTndL6dwb/yMfdPvyY8dAREk7KUJFPz0Ob3BMwBO8rP3vGMuWlFOj377g7HsJN3JuSYmbUTkgGo"
    "YCQyhm7iAibOQ6SNIon4kDsAniWylqaFEIRkRJI0n6DpgG5vAZfIWijG1CAUsGvsQOraD1Pzs6x9"
    "2O4eXDr/oqJJzt7d2NMni0bALIvJOz2Cd5Q4+rPJeyxON2T69WIry+RxVKpMRFNXl8srVsYKggNo"
    "9J5y8ikUPMr49qCWYSE0bGq9mL48WZx61Hrok8y9IzTw08jbPmQ12RzXCtNtgd5OawcmSAPk4F15"
    "kOYya2NiS1GSnMbGfj9WWVlG5adGI/utcw8N3rl318bBLtOGooSnJvu46OOfGh66b2Axntq4PhO0"
    "cJ4e/8JG/vmhHX/0K78vpJPr104pFCjRgWGAYQDhmperQWfL5dVYdQ0MqMbQmwBYb0Sv0R8ENfOh"
    "tPmgu2Hb9Iq2g60p9m3ExnW4sk1MpvmaDWFnm+BfD0kavry+cG0ZS22B+n+bVbU1BygFjEtSHjAH"
    "QFt9rZQy5XJZNDSfwxe58HJJi487eqPKKi1nRQ+niha0vgByiRIZWIa6O2DxMtr1MPUGUWQZSlmI"
    "LYHJQq0e7HUhQUSIUncbNXTsb80xbK53iPPYxM6gbjcrHAYNE5unkizpigIVHc3PwMRVuP8pQIwl"
    "4AgyuYBdpD0dX5r5h6ix2mcaTCqppBbFYKOAGMYuMFZCUbk87SN+DvmtSCiBUqQqBpMF21dJpBu1"
    "WsC9n+wtQ0WW1hjfkK4mOE9/cfpkeXMd+8cZrSBVShoPAgasCS09e4tTV5iVq62ygjfnBouZYWTi"
    "7Sk/hHvsFp1jlXyKI2ux0tV3pcQY59zpxIyaNAnaaGCXnl9+NbMQt1VYjQOFLZezb8PG8+4HfkV2"
    "/Ubxq9wKOmQfuhi7cUTKhzytHyYPfCf73rqeCzlb/yP8I1vKeo/T7FBvU94yirJ5WWF57G23r8YK"
    "nQ9YF26Xuzh/25GelWu32YtTQx/9jHafd+X9Kdv714K//OB1EX3hx28c6ms7/uHP3Zm6mc0mc7M3"
    "9EyKMgxCpEnWbESSTTyiWe+pQ2ubYIQQQHVkKGrCbrNgipoxW0NYc51y8xit2sKBAGqbVG/RF7w9"
    "OKibSkOrqdO1qkE0XDqtQrn+fdN6VU+ENGjgtm8QACDMIoQQgnQ2PB2+MdTd5jbzSzev8JjudfQf"
    "cO1aK87mcFxkORZpoFSgFEEYMIdBKhIVwcR5VJHA14H8HZTloZhGhQQt52kuTjJRkAsg8FSVkVRB"
    "xYw2O6v5/OrCBrl2h96ehqUFeXLVSBSQoaLoKtq3H3s5fSnidtu0RHx1eVGNS0/5Hr6QvJCSogbV"
    "EVBCZQZZiaESI0v1lMmQ3cgMFOzInYDCFCyYkUUH8GKvjGgJqX1ch4F0C+cRRRNRiwZmSptLfOsg"
    "4/Do3m7VatEgV8pmWwxTO7ZaOK9Twzu5NiF1RU2/1U1VB7oyaNc6PTabSd8JcpDLcWS2k+hzpVhR"
    "WiFMQhcZyeNpDXYeNoWSajoD8i6u28s6VvTNiJ4Y6R3rZ1peKJ1aqKyzPK8JRpLTDnbc42HsP8qe"
    "Ioj2WPzzkSkHK/bYjKBF3m1Vf/lJXrcirDosfDuNx9sfNG9U8umFZPtTT1o7OqT3r+zAlcf++2Om"
    "J0bIeuIjdtdnWoPvXL16+dQbkYUptZBj/V2Mpw3pehNnqDn7LYd8V4AITetDHTlN1KheMIdQU/DZ"
    "5MibDaOG+Gqcffdgw7oKeTcrQrjJf9eftv64W/82bKBpEuJWIV3dfFFt+2BaS/XV+FCN6G3/7Wn1"
    "HwSAsCSXBjsHtbLObCgQ8AcP3/+B3ofy5Wwe0rzVY3H1Ic6OeAsyEPIM03wKkIh4O82G4c4ZWL5N"
    "iYrahqBzB7Ac1SXKcgCIGAYQHXJxKMTQ7QtodVl+6XXy3rtobhmiUbQWhnfeRZMTsLyEVIqAwUqZ"
    "+hzIIpocrq5Wz9vFd82y+YDtYEmqEE01iMogBoFOjQLS0sTIu7A7RZMO5CxBYZ7MOcEbRCEZDDcE"
    "01RlMccwXFqsuKx9xfwyIYQawPoHhNYB7PWzw3s1VVHiKxKRJTBKlCiBzlbeMe4KHacxG8rl6YTV"
    "u8xaeN7K7PXox9xYE8saFz4hIEqVOyunr6/PZlQENo9gde5p7+1vaU1h+cMtx0tazoSFmcJahegH"
    "+aE25HmrdCOr5g0BCoxKFdpt61g2InPailkgcvlWheRXJfeeQYItrAps6F7kfUbhe6XszVIwtrTr"
    "uI24VGlyw7fzKDc2pCbTlbM3PV2OdL6w8fU7x7rGP3L42O6B0Up8LT93S5q/YaQigJna3x3XyEKD"
    "BtUDwq0BPE3IaKZBNRfa7H0bttQwn7tQBQ2KQ+ugB1R3/9CIRWuYhdpTNuyC1uhZEzHaeta7gukm"
    "m22sOtsNqf4xajLaxrG0WgTCMLzJEU9nOnFopVD4Zls02ibYGO5U/JSAGf/wIRUTcWmKMwxqUCrl"
    "wdMBVhc12cBqp+UkXbtOJ06BooDVB65WsDkRRpRhgeFAKlO5ROUylWWajeONFVQo0XKRrq3A9CS6"
    "ehpbBJov4qcegbUp/dVXXXaOF0jq7GyLKDz+kcNXpBvr2lISJ8bM4xbWRqiKqIGA8sCxlJeoJICI"
    "EYqQiAbGADvmRJ4y6JTFRVwMsN4IyuRMzvnSDMUc8BwyO009eyhm2VAXVTOsZvDmTtfgsZhJXNfy"
    "bAfbZUYmGz4cMB8NiRU8q8iVnMJ4rLSl29k/5HCzZU3KBp2syNFpKf1WLikpBLktt4wI73VrHtNV"
    "edHicQ+Z+x3UUeB1RdWPW/YcZcaiRsEgWC3rwLHnM7cqJqUESb08bwftXpfhUqcjBVkpqKJVu/hO"
    "2dgomNtjjv1556NWfaeLH4i5Bzf00nkjck1HpQpn4J42+eWJjv1djsMBe1ybm55LKhVPRz9YrYg3"
    "1f7gqO60UcMX4xr+thoBaohvTgk3tW9twxCtaUTNpTz1qjXYZht1RNJt1nQ3WaqDEf8cna9de0uO"
    "rYo5UN1zqam9sW5OaCtPQOu7atSITpUnNRo6a79DnQgBokAJkQxtT2jH7djcf5/7t9fXz7cZTCof"
    "syB2n3mP5ra4EqnWtXVBUkFsxYgib4hKScCEGoAoAt4OohNNvA0T79JMBhAPSgWkEgIKhgG6DrkE"
    "pQB2D2TiVJehWMScwE5dokRmdw0jWqGsav/Ycb7TFT91zpRc5HPZ5Kuzh/y9R0MH3Zwno+fWIYIZ"
    "nlJVp2UCsgpSDhIG6G7UooJeoLIVB9zgYpGIkVgmcpKkMcNfs0RinKJjFZcjwFCme6dq90i8FXJh"
    "7cx3LdYWT88xi9XrELhAaZOZ+OmQHdpEbPb4h4ecG6Xcj+flisi5OKzaOGPI2+Vhd3rZSwXo9bIM"
    "lvIVeV7VllfmEqV8vKI7cQDJJCMY5kDLLvMIw/AXywtWb2DMO2KnVkGwhbNxQshladaicyHQsspG"
    "sRzb4REDduIWKqtp2PEsJwwJ134KxnzBCJpKG7JQTrLHPeIzbm0oXyFh06ERob+VdzuimUry6+ft"
    "AXebg/nb+070sUK329fa0o0xQ2vEoQ5J2vCidW9eL5AA2NJ/qk0ozcisxwz1WLQKvpou0zxsqmET"
    "qB40Q22SShPlvsusoGoAzYZWxzM0h8K1cj1UDQ22WE4jpw20mi+g229Vt+yaPdXfRvW7UYOnMBoY"
    "RSz70tIrS5mlHrNzX9+Q39P7RMtDXlVgcgV3RbMhnkdICA5iWxBzHBADqIYsTkoR5jjsDBHGSitF"
    "FJlGS9chnwMKSJWBE5HFhb1tmGegkCbxDTY+yyxeRTNXjJYg7NptVrIIKrYb7923A7p7zIKqmZKZ"
    "dqfjyjdW4FU+j4om3oWQsVqZV4lCwTBoAZCRp1EOmTpQrwTKEqxVsGZHNgsyzdHFCshxqHCMe0Fb"
    "3iAxnhosawLRyQQHoKXTcPqpVKpMX2EEn61tp9gzbARDfVqlPbk2IBcVo6xDAfy2PGcuVeQbSTUt"
    "qZFIqZwosm7M8mz7Hm87q4tmvCskHLGYyqLp/8y+cDu7frGYIHlmnBmUNVURsdXu7BJak8VCVtT3"
    "DB7qQp3LKDMNkXc3r3g5O2eIbWa/n2NWlNK6jFv7u+47YH5zDi3Mw/HfDEq6MPF1iWGp+RMjhQ1F"
    "/cktLpVu/bXRWHfh3d/6QnoujJ22wHMH5q9Opb78bvlGqmVd/cunHmN5C6djokiIYQDVS563BkTV"
    "WtebwboduncNTm7yrNCURa6+9XMVbU38hdb9a+1CW+SpulNdNTJoKsun0CyD1p/mrgujWhkQbZCx"
    "WvZuW0AMtZwbbaC8cSxqvn7T8AjitYdiudiljZuI5Wm5uKd/4Gfz5x09LaGOPpNZcKRUVi2XUBkz"
    "hskRhEKWVIpgsqNygnpaQbSSShFUGbUMA8NSvQhqiWbDsH4HoiuwPg2RGSaxzGUisH6TKcf0QoZ1"
    "WmkohAZHzI/fq2yukJVFXMjixMa+e9ts6eiugENIpheT8YvLq92W9qnCtN/ayiK7ThiMRQCqUxkQ"
    "8iFfkkYW6YIGIALPILpK4stkTWUQy9oF1qFQwy4GeDCQu5X2Hia807h5EpQiVWXcsc/qG8elUppX"
    "OivpvSXp/uB4r6v7YiW6qtwwQmVVKz84KD7lY7BO305J8Y2SyHCBMQ/T7j4xZFWBnM5Kvc6eJ507"
    "QhJZi6ffWJ94oXia+ngRmd4sXF7TU7vcuyQLmkmuMoLZYfFtasUshYu5O2XOwBgLvF3j0E4LO6vw"
    "l9KMwVg8LrRxQ5E3K8MPsqwVzv316uork+7n7XRHT/bFjc0/Od3faYz+9b7we5dm//aHeiSz/8u/"
    "zFBkcZqWZ5NoJvvFYw8O+EI8x4FhAMKAa7hHqOpPUbOfraqI9bXh5zAN1SmdUINKI+htkiObAuL/"
    "vyFB/RrN4iStTSGitDYppRqLIGi+xbaIvH7L6nfVp6dNaxFsdRujWthCa/UWtUesy7vNix1mNguR"
    "dHmzUklTpdIV6Lo+NW1gDdlwMh/PVsp+FXkFV9mI20s5q4FZrQQsg3SdllLY4QGrB4kumlmH/ApY"
    "XIi1AgDS8qBXAAOimKYiWjqmllXsaKGAwdmiYh7GR7FAzaWsWi4zB3cyAl196WSfUz4QInRm8ajH"
    "YxGYn0TfO5WaHvHszbKtjo6HBPdO1tTLsyGWsYqMrQyFMF0UQACqCJTP0XIOSj7c6RHaDJ6mjFVB"
    "cHsdfdQkqJV1mlwxNAKBTrJ8lcnF+ZGdXKjbyTCd0ejuKzfaeVvQ7tRYqcfLBpyQXJhr7xMdO9sG"
    "Qnh3pxDTyZm0kblZ0vIyWATGZWpzGCaFRAqcTWTHLKZ2tsVFPW9FLm/KydPJWxdjN18rnO/w9djs"
    "nh9ET93aXPDbW7NQFkSHhVgm0nNO0STw1himu3uscUzfWg+vG6HODle4TAWBOD/T0/kI7nhYT0xm"
    "cu/H1di6+R5bftDyvT8774H4wd865nJ76EyGz2nO58epD7mPBM9enl+6vPILvQcO9+7lCaGqDBgD"
    "wzScJ2oOKlF1YWj4w4b/bsDkbsmkfkRTuX+dHDUKzep1Cwg13awRtVaJTBPBobSpKb5hIg3jatoU"
    "shrYNEu8WzerlmygRkqjEVdUM2q0HhDc9Vtt8SgEyNAqQIlhgGAyDdo75pY2NJfjwI5Hd0qiVFwQ"
    "CDglyZlPIUwY0c3kcyylnCsArACVFFgdoJVxOQZaETCHbG3Y34sEEdQS+LrZ9iHGbEJmC2rtB5uD"
    "ii6sEGHvLuW9c2R+3uoXh/d7nzpkbTv5jd8Mbb7xlcuRU/iR/vuA4W5V4kzbTlNLH2WFtvb9bf5d"
    "dnOHyzqiUpIlEQqGgSQVcoABIR4wqEyxgIoRNSHpiih4y7yY0op6OQtmM9MzAEDI/DUMhPJWiTON"
    "UNMvK/Zuzi7yrKoWbHwBs5YVmZcNDoKtGic6hq28nxuyQhGz70zmFuey6lJMQnrXXvN9QcHHWW1B"
    "R8CbbzU7Kiy7lxn3sf6p9Nog7dpUkm/lLkCJ5Ij0XuJWt6tHR2hVjR32H9IJPpO53mv2KLzzLcbd"
    "40VEV2bEjoEHSMUNb7ySE0w5vMevslZLJ+d8vqvk8d54b6P7uGnPPzzwhf9Y/tn3zqdZeb2gSKqh"
    "LiW15YTLYdo91Pnlayf/9u2vmjDf2T0eHDrKcBagZGsT9DoOaFUbRTVeg5qw1oAz2s76t+k2Dd7c"
    "AFQVbFWKU/PXtcWlXsQGAGhrK8bGBavf4Kalo9Zm39CAYNucuS0jq4K9FmvXfinUlAzeMq5tmYSt"
    "NQHVN1dqWghoLd5BwAiCrlcYxH2dXL8wpgkhh5DOOVi3mwqt1r6QxNqcAW5tApfCTO8RmoqDLoOv"
    "CxACTSZSmXJmZA+ArQUqZSMbIyzHOF2kIhNZosUs0zvAdfQzubR+67qttcVULuAWdzC90HvyB88M"
    "mUagiKMVH3H+45XruqwP+0aQtW9BU0KBtk5/e7uk3esb3Bfa1e/sGW65J2gfYxhrgRYE5DSAzZJY"
    "FNazdHNDj6oY2bhWxdW+xmR0quDBw7Sjl25M4PAMN/oI72rnomGxkO3JZVA638+GxoQ2kt30QVCn"
    "Q4sZmXEPRPKB5UiRt3BOO0vMghPTqVjh7QxWC5rVZyqNdqhWZleHI6XqHR2Oo31tFmQZsvf73EEb"
    "a3/Qeaydti5Wkm7sbTOFFpSw395i5TyL6dUSqoAodAttcUNd03iraNatotrdnWfngsf1ez5uuhHV"
    "X/vndYuPEpN5Yd24/f3F4EOBwK/u+Ye/T0NLx6Ev/M5t7sQE7n5jYuXSjya5fX3YbFGSlb42z2cf"
    "eHBVk8+s3l7KrGcKYYoIVFn3FomgdRRUgXdXthTBtt0uoIajuqve3mO4zWU3enZR3efWeUyV8TSO"
    "rhJv1LhKdR+LrWO2GR9tuidtOhu2v1P7VWqd+vWgoC5G0f/Hg9cZVC2sphQQ4sSl6GqPO/ij9SvT"
    "+ua5yA232WTYzJ3m7hHU0s62mFmzmfda569wZjcF3pi/gIkBJjvEpqngg9ZdyNtFBQvJrBNqIF8v"
    "bmkjUoEkl4nAsyOjFlZG194xwguudmlH5EW6PnNw3PxsV743FSUnb3isbf/5OlvI4YygrmilAWtg"
    "2GS3Z3Ol1blRu9POKtnw7Q4GP9A1fNATGrR2jjkPuEV/mebzRhgDzWpLOtUREiyYU1lacfgVvUwZ"
    "jJQCLWahkMLukBjs5KmBbr7VurHsEtlrsQlLmZiREc/dCdlHdvj8+1rE9Yx09crqyevRcBoLVkta"
    "h5KmPtjL+UV8dkGNhKmcwEkVZ9jUufCUS+hiQrab0kqnpd3CWVVEnFZ3n7lvPrnstnvbna2SppQN"
    "VWDNOqJLlQ0GCRu4iBlEwd7SYjnV0XmRNecq6ZOx3avOsWOPkmXM/e8/L1bypYf+Vwva2/vFv5kp"
    "jbSiB/b/7r+tnRNW0Hhg/5EDXQ+N3JlYR5MKOxRkWG52ef2R4ZEHDz2oOD3AUqWUIESmuDpwjW6f"
    "DAU1mlJXc2pEu8bAm2DRJHRup/eoWWtp/rQaoyKK6hJQjf3XK5zrQKwuNk2DsZrijeavbc1osLWW"
    "NCxmqxG+yTDqrTONhky61WFQDcFpDfvQZF8IiAGKcqh3R7FUOL90bmH1Rou7paW7C/PW4b4j/Vwn"
    "QmBYbV2xgo9anJzJkoqYMitCZBZi88jkRYFebHZhzEMhhRiEPUFst3FmM2SWwCg7Rne67SZ046JR"
    "ypl62h7fQ/esn/KVNo5b4kN2Iq2yySnNodkY1RzLGboq3CrFlrXoCTP5C4f7OR5sqeu7R8SQr1RM"
    "3iotXe829OdC7c+19HwocE+vpdsnuhmGIsQx2FvR4xWtbAg2Uk4ZcpkWs4ZUQakwcBbs7zKc3lIm"
    "Tnhh2N6ZSkZuFSbOpW8t5SdEruLi3T3t7t3d1ETXb0fWTWZelcimLFhtfEIy2lotB1rZSFGfCmvK"
    "kuJpafneavJcIa9KXWtFrgiy0+YkFGFOCNhafJwvLCUytOjmPC7OG1HSm0YsY0gE2VTRsom1c2Z3"
    "vnf0QnvoTqgdc7QYNP37Wf1f34AL1uC+Xx+TWtg//Kp6fbrQ93BP2eX61rn1A790NP/k0y/i3V/T"
    "Z7/ybz99YGCP2i/+9P97RXptnRX5QE/oW9cu/8bInk8OHUGYB4MgYKp/W9SAP70Lw/XqMXSX+E+b"
    "/t1uOnef3pQlq0OvdloD9E0Xp9v4e/WbugFsAG/HNwAAy/hJREFUU2ma0N8cBkBV1/r5iBttt8gG"
    "rmsLYGPJ+LnnAYSAsgh1BnrShfK5xavxzJKZ51FZzy5FKm3e9JCnzTWIEGrZXPWnIjzH+8rgLiSt"
    "BFsYC+sIcu17GDUHS+dIeAqZnezgIcwxOL4Eq1OsYVgHDpiiC/Zy0Wy2BrzugXZhEEnrt0q7rPBU"
    "q7xwMn7C4bt4kfzzTwvxCu30toeCwwqgNVJZUZMWc+GEg/i4jG5s3r+z53ceePjxDm4Hjhay8yYt"
    "+3ir+4DbxRMeAwbEa0ZG1tJEsOrSMkhhWkpQXQfRTQtpxt/GdvfqkTnMiaMdu/VKKpZJtjGuK8Xb"
    "a9mNTq/Dai8JrtRatuR20O4AWO2czcZPz6cCNjQSNF3c0D1t5sGguJYm0QhjEnzvVowNYL67urma"
    "1vvZLt5kNghys451Gp8lm25LUEAOl8mlMGQxHc4rqThJrglFxSRGPF0z3mAuYD6b46IxR8Y/uLT3"
    "oEmM3Tl7/dvXPRNq76/8Xi+zP/BbPzB95TrT/vR9P1u3rEYig7nN4iTp/eVn/o6N/tr7kzZv35VS"
    "Zu16+P/H13/HSXIe5+F41fu+HSannc27t3u3lwOAA3DIAEEQzAQpZoqiEinJsqJly7KtnxzlJMm2"
    "rGjJsiJFMUgMYAIIgEgH4ADc4XLc25zD5NDxfev7R3fPzB71+Q0BcHemp7t35qmqp56qel//eq0/"
    "lv3ArgMz65UnRg+9a/yuNNfJdwK2HywT0pODdmEUVYcDXxzs0kLQszxWF5ABuHY65qgXOXo9iiXR"
    "gNcPDKt38dgL3XAgZgecdxCWHrePvSAH7OFe0A0y/4i1hvvj9Z6uZ7oGehJ4sVJZubj4ZltZKLiv"
    "YICl1uL2V1LXnqcb5uDQQ3zvnpbRADvuqn5p5mwagLSZyCf1vkSjxqpb6Llm32isOEQLl4z6VjaZ"
    "inMtXpwaHRkaNXjM9/qsjceH3bGt6wfB2b9WP+L5jWX72oJ2tHDbNg384esr6GClbhfj6V1jtw3v"
    "u/d16f66FF/J5F5dK82Joecr62eXFo5NHn/XrtyHx+Omffb65tnHi+M/MbrnuJ6V5LqyyrnWdK6Q"
    "ATxRpMYK04grB3bfrg0O25ffdLfWh/J7bq/CnLWyJLddBofE0EArd23dbdQ3VheuZAbSff3GiaNZ"
    "m6CiTG6IpTbcsT9Xc9RyFV1fnLT56+u6Vc4O6hMHk3cXzMOzm81jA7fNNDe3mu06uafK15e9ikVQ"
    "bjbm26vXGlcWnUVfS9WZXke7hI5rprx4vFoYbc00VGpvo3+PY1bH9rsHfv39qyVYu3Azmbbv/NjU"
    "Qmr3bz/FX8wc4B/53B+csjL3Hd54/dz0Ju375SdePZH7emWjsevQNUdYl+rAYXCk/ysXzv7xW88u"
    "ri/tG9hfTPWDUtChPiHZ6cgznae61tDFYFcf6oUf7fDLocYYgaq75m2X4fxAwOmok72ZCCCFy/jv"
    "MNQur4oCVPeewkNUVAbrKegGtAcjFveDRtSTUGBPcAjwL5XnehagAumS0xpKJoVg/2Pt6VfKV7bs"
    "jfxAsUhZwTUfYZdWLIKZI+0OdiArisWN1dzqbCo5FMuNoOcYG3O4vZjLFsaK2eFMfCChH7Bu3sk3"
    "jKtv3BG3+t3WPWmQy/Yhnd5/OL0wI95co7+4RAvb+mExcZvKVxevOH5rLJ+/p3ntE/5ly9r2Dt73"
    "oxMZ1cyOvvdz/ZPzr7z13KsXW3sHjv/UPbd9am9tV+ragyn43PDkfxu/87HMkMlt35lHLSVrK+CU"
    "MTui0v28OOYuz/rzlzBTSHKz6YPN2QptJkQsyQzB6+vl6o3Zynqpmk8Li5tHT4yn0+baZnuyPxnT"
    "Rc2G3SPp02uy5GhLCp7daq/WB8bMqUO52waye9pS8xP6c9vn3BhWlVP2rIyerVJtCxtL7RUEuews"
    "+EZcxQvNypwX74eVi97kfhAmrq9Ca4Otrly6wL808KnZ5LD2/mMvDdzzu+UT4vCRow/sXxbmk1+a"
    "UTeczfjU2bY39cSDS89fxb0jx+4eO/DYob5Dff57j7RNfe75ucFY6uBA/yszZ1ecyunFS21ucBEj"
    "X0WqSQfZnfw3+DcMAoSdjWK6QAzFmAiaPb0POx/UC6uAxnfJRidZCJODrv10Dg0b2nrS4g40qfeK"
    "FNG2DtfqxpLgJrHj66GjZXXS9568O0zEI7tR0ZUIIFgWw/cSZrov3v/a7FvT5RnF5eGBXTkZL4vW"
    "wPDhwfjkPjY2hn1Flo2LeF+91teuGXoyaaZjiYIhjERtq2CmUsVBv23lfUvMX06nNT2fKFpWfzxm"
    "1N3DSfHmd1bTOk9z89KS7gl4cvOqVdvm7cpAi/1Ics+h8um3Gc0p3/+NpPzs9nf1J//zp+PLn5z+"
    "Ruz5Cx/aL97xw6Ul7epzJ6/T7vfnJo89csR88FFhs424TT86sP+YHktqBjqOv3mN4kUiBq4ly1ty"
    "cxOEAbUNX/fOa+0aqbzRP5mYKmvbN9QbiQQ/WVq+uN7erIuVOq9XfK2Yubrm2h576L7dWiouTENp"
    "Zk3EJeZnXe7GJuI873BlxBJMaKfWzq27FRdxsn9fw/elwho0ua7N2DcV+CVUABZtnaHJ+1hhFAyN"
    "OMpTL5BjUVKXu/dWGkObsaMLX7lhPLTnzGX4w68lv9XcKx95F49Neiq5+tK0XBQNfVd1yVZPP3vt"
    "9766WWoucW34+KCcYM29hXVH/fV3X//o/jsemTpSdeqI2Cot+W47nNjqZJCqx4UShbWpjgfEiHtg"
    "L3x6APuDySkF+WaErJ7QERQaesEfvCE6oAP0HUlwdFnaUavqjTQQFaKxy4HCd0bWcevuHVFajZ2z"
    "BIYXeoDwUwj+UeFItZTZRP/VtemF0pX69pyhaJLlZ6yV7aO7NseSux591z2546PaaFpqLbk9TBkH"
    "ZZw4Kj8byw231KTL9kzcAcvrzkYtxo0RTdcsCavlvVINbW6PSsC6sOutayvaVy6Jm1teVVp7KVV0"
    "7GHXvlqfzsed96v1+1a/sqt8U+w6/qCI/VLqmtO//vg96/vP/eGV7y/olv6JT6eHzKtbT59srvRt"
    "XW2Zhv/DD/WPFFuOsj6eGz0YGy7IVhZEnARtzavyOtgtsKroWRBPr3JnkdWq0k6m9w6ZY1LTC/2i"
    "MJA4VV8qN92LM9ZoNn5jlTxm/s8F+PYaU5rGk6YTM0sysezmmT4EkH1te7EqZSE3UPMb1WYlq+fr"
    "fqvuWJarbF9Zmq+zxFxjdtsq+1qyqgM0liCV4YVhWroAiT6+cB0uPAVMZyfezhsOa5vGrqPoFsov"
    "L8uSdJ5cffMrlZvpA5C53X5+c+iff7bRyi9tZs23H+ef/gCtl9rzlWe+/9qbBbbabr+20t5/YPKq"
    "3lis1CYz4w8MH01JRBkuAIoUbYdBocMlonCNFIoQ34O2HhKyM8ncoWp20BWJjNBBf6ib3rLu9A5i"
    "FAWUyPxQdI7bYWOdS1A4xYIhw4lKXJ0BNYzGCyAUM6HHPDCiXtFfQOGViAAVAQuboUABICADUsDE"
    "SmUx7B1UMt+/b1LLPzdw9fXam32Gcf+xt01M15e9WnY0kVleK5O7G/c6OmfSMFYWmG3vS+TWZmZF"
    "a7MRw5SkYVObrGxdn69kYlqa4V8t0/3Z3GVZmVtrXfZLU8L8EBdeY+GAlpBMu2Bde+SAy3JweeZG"
    "0p5rmQdHdS+TJ3Of7i6z97xbWMQ3XlwYerDv0EcnWpf6fG/Y1R/YvPj6wBNHHxGt069sQLL4C+bQ"
    "X24tnrZt3twAYOBbUFmmjUswdBBT+Xp5hbya0HA9N1QpwznXnmA8yfU25p5x+J7NdvJGY3gQgKfi"
    "A4NfWFDDRTmZFmc2ybZHL9cdAeaA0ffS+pmpxH4l8dXp147kpuyYZm27882VgvRNQ5sr3ziQOHS1"
    "cbkCFYMl3OoisKSWHfPe/AL4Bj7yI3TqqxhLMU0HI0bTM6CI3BiVyXkWxL4B8c/eo771ev21NZbL"
    "03TZOtcY2TN8/anTuRNHdr3vjmql1D559eEff//qzMqhe3ZdP7P4cH9c6PTKxorw4PVrZxkgAUfy"
    "gcL1UTpD8gAIJEERUs9AbzhZGwKzMxVDEXo6v/ZsgtEbL0LC3zkAoXto5+DusZHU3/kxigA72E7X"
    "mjomSD0vhjcHUUs3wU7r6Vy45x6i2+rpEt0RK3quTADEgAMTxPVHBu54qz73f7eeX6ktbSuntLjc"
    "1uwb92WaD+4bMIYyg7tiJ94+DP3jC+tk1TQtZnqKbK8Zzx+HpNfwUma8UqXvtknp8a9vs7Oue2Gt"
    "HVeYY9Sym3GvfUjgqre0qreP5cw9Wi0RtyfuphMPGfsnW653rtauKca9ug8mOHHT3JfNHky1r9bB"
    "zlUBSpBZquYa5aOVC5aezx3cXWzyxvfW5j+cH/7IQD+qulJNqC/C5jXwLDBT0G5QeQO3VjwzvtZa"
    "XOdOIb3vqeX4UlUfyu++nL/929bIf71AX74OX7qmOZCqkPGls42T097aRv9udn8Bhh/M3j4ZHz+a"
    "OhpD/bX112IkUqn4fHvxWO62rWbZVrYjapasK1Jv1U8SY46zrsDTCrvJRyUFjh9U6zdVaQ0KeyA7"
    "jG+9ri5eUg3Xa0sYGoem6b45WxiYT9xWUF95SX7nDAyPbPzOX3r5Ijt3qf5HXzZr7fSB3WvJROvM"
    "0lgysfLq/AMfHlxrlT9zx4nXb17eLG3vLo46vhtOrksCpUB1vF/vF0zQi6coCnR2mMAO/DqZMkG4"
    "TlDkfaNHN1Z0Es/eAnCIp5CId3XZgLQQhc1wvTSry9OiG+tUMyJb6/B+INyZoP/gI7pglPh3pyKD"
    "q1BvOtHJzQmIPOtA4eharfJn577Uqq3XZWvRreqWt3J04Owu1jQSo0MH1OHJ5H17dmNfv+gv9B0d"
    "0ydt1dc2hzJeSqNsTet/rmY8uy0rip1saq/U2xPxdEapuVat7Di3o1C+z6j+8YQ+01wR/qVHUmqx"
    "4nsWF8zQzNjQQ5mBA7G1OUUrh63ahLvQblwScTF8cW7or/5BMblfYKIqTPKnculP4fKoycfvGDzw"
    "Q5OZVay4jn3QSI4IKZwWNDcgSLc8DwFVeRljuc3y7Iqs7S7s2/bGv2Fn2slU3HVNc9SSuXNLYr6K"
    "a03honbZin3/htS9oXR69HD2wEZrPSuMR4fuVra8snUtpvOKt32lckHjOues6lbKVt3kmRn7osF5"
    "UR9JZ47ERu4Vu+7x9jzMRk6AiNP8BWBJNXoY7zgGLz4P7QasL8Ozb8D0XMFKZZZF8/K6WTSZ0GB5"
    "m3/kwzS3tHzqhvjgO+X5awsv3RCFRP6hqc2XL9VuWL5rxDxOE9rqdntXf/8LGzOEnDMRbAEWJoZR"
    "Rtn5ZnuXW+6dFOm0AFGHK+0gRcELoY7ZIzj25MyRKYWNER0iFTno3sWnO66X9UQDhN6LRj0O0ElZ"
    "o7wcorIahc3+vXQNIsWrJ0wF775l+4LeoBPVx6KkCUi6fYnhplt/Zf7ptl2ndrnmVdrU0g3j5UL7"
    "4tKFemW7XUg0h1KGoVu37Xbe+chgaoI/eA8ev694931TE8cqPL9KON+2bJFMG4XZVjMt2RCLzzS2"
    "dCBlt/JKxnzX12Qhye4UtDftg/IaCBtznjKMjQo5G6J49Eg5Obl4434t/qnmWixtH62XH9939DM3"
    "VfryamJ+051MHV/wja9+6bsYf8TZHszFb79z8PC/evsdP3liatJkAnmWeeC5yBAa28xqQGUNSGG7"
    "Bon8MjXnnGY+u8fRBl8WpJrbI+trvpGuiNjs2pJmppXZz3hatfMextes7de23/pu5bmYzkyGy86C"
    "60pHyTVrc9Pa9H2viutzzaub7bIj2xqkx8z7TW3CHN6f2nOHMTLOVZONj4GhYbFIRw7HPubhvZvK"
    "2UL0gTx48kmwmtrSTC431rqWanzjkvnAbcbAGArT+KEPuF9/QfG8+OFPtZ47XTk7t/v+8dFP350s"
    "xJJnlhIvW14czrVWalbTYX7ZafueDRFiwoVBwy82AHB3Tr6HdEfLuUXbsESGQZ1T9eC4axldWh0l"
    "CQSMIMxVKXTxPa1B1L0mQijRMOjcIELPjVEnWe3cYjgI0Olx7fHhPaYMHeUq4jzhn4ysYxM/MCIT"
    "/qCibEkhsobbWq7etMlvuhYC48ofjZk2s//m5j9Ydj2tm88caM9n/UVTtvoT3kA6mc1c/uBuuHNf"
    "PpdJD+zRY8U86XltIK0NMUmDhAU0Nacdc20OaCGeSGsPFAzf8a63HFepzFB8akTTXfYHJ/21Wb/c"
    "1DTnTrf9saW++15esah6BGL3Xj93LVuYSsYmHpl8/LmFm15sar7KRiYeXWpmZs5sZE68rdVSlLnv"
    "+lvVe/bt/j/veeRdhf52u83AI+VCbR3Xr5FvAVlUug7CWFTlt/yqSvT3p4dQGFZ++GaKbRfGlpHr"
    "ZsGMFdI8EbPdIXMkp/Wd3rzwZP27hmIk5XTtpkNtSzYvWTMXK0tj+p5zlYttWW/5zYq/HjfiTCRL"
    "QjanJvnBY661Zs+/oUZTOJ7UHj6CP/tj+N77cf0mvXVFFdN0/IDYP8i1TWTO1tpJZa2zF06pZ7+p"
    "vvfdxL33+N98EY+dwKwhT76Y/tT7db9R+vL3Zr5xqZnUC/cUpoZjq5sl7bJzqN03YQ6DdBpujQkN"
    "pOp+p0CkFBJRuJhh4D677jFAY7dPoUc2jJrcEKgXnz0uPBoAhh699BY2/oOPHW6+Z+PITsMR7jwy"
    "fK7L87uRhYU939SJcr1vDC8Q2tOOzBx2FB6AwqVIqfOHEBE5XgO5Jolc3wHpacqtVZafWT3btq2R"
    "9NAVe+n5+Hai5W9XNvs8fTXZKh/J2dub/nhh+MP3jUBiIj8+pg2NJPcsOzQKWpyxGOPK9TTA/Uwc"
    "1Phk1qwAjBpwLImZhLZd433J5OHd+5rt1JX1sWl3cmn1+Ox6Ls7uWAXWrhoicY+txb9xfv5kKX2p"
    "XjAyB95aWofi8MXFrcP73t3whmJqJJ7fA+3UjaZ58crcczfmPrNn4p3FgQE9neFptNqytAAMWXKA"
    "WjUgv4r1RWd6wa+kjCI5FUilvdH9CApZrD+19zbWH69UxyjTp+Vm2osvV98cxfGCVrCc9ne3Xxgz"
    "xjnnl5o3t61mXIvPOtNNt1L3Nn2qa7zfisdx4ojltBunv4nSOfb43h9+ZPFtd8/l78/DQAaSQ+rQ"
    "e8beZR/57f7kB8f97ZvsbcX8HfsHj7wnPbpviKXTFmQvLRZffLmv1da/+m3zwcc4IZy7qAnQdk+M"
    "DWebr12nnCiemKKD+t8snqmU6vcVd43G++1mWfnuDs8dBvTICXe+/V4k9eIlwnBU3QoV9h1zKtF/"
    "euh39yxIGI5nhecPi9IQ5ds990AAwCKGH4mT4bm7Vwtddm9qEQWk4IXeVoke0hPe9a32GJXtOklA"
    "91I9yjAQILBQNQNCztvN7UJ6yI8brqwvthZWZckslSpya9utt4YSb/ZZdoaDWz99h5kf6Xt44ECS"
    "8SPZfSnUB5W7m6CG0gZZRX+f0NNccMbOVKxyyxkwjduL47ZIrtiaxyf89L6HikPzzuBzbeNCK0mx"
    "0WPF+2zSF+obM830CzC1JIe/daX69ze+Wm7VWpbn2rDcLvksg7umpq9txicPxrA41ffYesOY8Vp/"
    "9eapDwynsoJlQU8qCXaFmiXkCeQJcBpopNAuLzWu+Jafq9dVe10oXzKNPG+/OdTfrGpOc4znF+3F"
    "Z8vP5zE1znYleOJU5bxs8l2p8QbVk5BOiWTNr626K7aSwGR/6rCZ3W0BetWl9+qj9018+J0nDnwm"
    "++zx+ObYeMG48Dq98DyOj+sps3GZ6NzcwaPt8T947Mi/eDT5kT0Ddz34QN/+R9mew9kHi+14+tz1"
    "vUulQ5fncm+c3vOR93sNX3/obdho7dtTPLA3v/XFs62svs8szIjqv77+1VdKs/ePHR3P7TZj6Q7e"
    "ICIfFKG9p7+t48E7GI76bLouMfT7XRuKosbOBKEHfj0o6/zYvYXOiboXIgbRuuXdBu1gZrmHYUF3"
    "aYoOFdpB53uuH4hDURWPel/csUNMdPKIWQWqmSKEKFYSBUvKI6JSMlPYnUwVb6yett1q267ECcHe"
    "eKn5WhbhleQcczcuJtfn+p041u9yY06lUt1YmsoOpJpbe8Ctgaoxw2XaIRFXyJvIL0tIG9qgrpEx"
    "vslvK6vEMvWd3I57VvvEcPKhvlylXT9dnU2Z+bVGLZub/Nry2Vc2vC/Ye2dZdjBXRFBvbb+ec3OL"
    "M5uZRN+z518Raoin+mSNzNHR/QOHMuy+tw0Pvvuh0Ua9/TN7d1my2pBrgATWhmptgWDgNMC2GOnA"
    "zfNbr/WLUa1tq605zpiWGU0A+F7dUZuLzmJZVg1iQ6KvDNstt7nSWn8wdt+N5g1QNKoPrfmzS+4y"
    "KI1Qz2fu0cYfr6SMwoGH3330k8MD+1fXz77X/eIDzupkeTk1c8GbOJb/D/9C37xe/9OZ7dx/vPz1"
    "iRU8nO3PyFfX3Nxe7b98cKPP3xPf+2uP/fx7zX27t2L5LXuAG1PXNkYuLNx13yTUGoW9o5e/f2Xo"
    "rvH1759brbSNkfQhlq3WSi/Nn/72xRctz+ZmBjUTlEIE1onzUUoQApJCqr8DHR36ErjCDhuhTotx"
    "5yQ9cuEPwi/AVaSLdmhMh7dg9zIAGMmg3YJzcMnI3MIo1emqi84f4jekapH5dlKSrgX2svzQsUPn"
    "3ZGBhscAdWJm6Pg77yUCzl6Ze75tN9CT4Lhr1s3Z5g1hOzbYV7z5dmP1irrmNhfl9lr6jYbdth7c"
    "e/v06tWksuvo2UbyqMhNsmRWxFLccJi4PZG4d7gwVRi8qjLfLZdNnp1tJWZajuVX3VRz/xj7zK6R"
    "pyqnn58782ZpHgsTKweP/P5xvp7SIF640ZoeYHv3pu94tXy6Wq5S1U2k/RfPPD9QnFIVVl0uT68s"
    "3Hv722XtnocP7W7kvdOLaz89Ol5ggvwa40lwLYbInAq0qjGIFSDTbq5XmJ3zY6qxLrcXskay0apc"
    "rF5JU26XsSvGzSN4UDL0lExBssmaDdGcteY54wJhU81vy8WYmZoaeBSy+zZKF2Qik7Kam9Mv3lx9"
    "8nNTpw8KvzGfqj1jxcv0i3veYM/8ub1WY4+8N96nseKEf+RD7at9a78yu/Z7C1fPLaz9+EP2Tz0W"
    "S/J/9r6Pf2b8tjvjA4O2sUdPJL50cmKz6W9vafnM5tUFSmYn3za1tFWe6XMODk0KibZtNaixVV9u"
    "bc1Lp90L1VsS3o4b793LBSmSVzrOnXph0SXgt9jLTgmmuyJhz3EY3Eq4dEPPxGKA1ltngjuwjRZJ"
    "v4WidQJKZ+nPbmijzpmp1+Z6zKD39D3GuVOegs4CqOElSQFirbYulQ/ISSogvyGrCCxpDl2pX1iv"
    "XPNqW6xWbteXnmiN2XXLOZJ2PXWmcWMwlTvOCyDtYYAc6jZPvAE8kUiOJdOoJZZRX5XtNKcjmdE4"
    "CCWtvrxfNewbGzNjfeZDw0f+ZunkRa+9OJSvHN6/+uih1lTfW5ur8+72mfY3+sCPJd3l+uzlpVMH"
    "rJwhq9PXp1MTw6l8JpPJtlqN0fSx+eu7f+L2g4bJrzSrhxP5BHIlfUGMEwOvIXyJrpV2UZCySaQh"
    "nVNxzbFHKLFQvbRsL4zFRgTHDCTjPFH2GwIgzoyy2jprnRWgb9P2hlwDoLieMDGxYTXWrHlVGFVK"
    "rpeuviun/ZcRodXs69em1hr3XI19YGxXdujq6Z8cXNg9gDgVF9XT6uJFMV1P9w3c9Y5P7sZs+uV1"
    "+5f/xv/qmdTUmDaQe+zB+945PJluVO/LTh3V06PPLB2OF7Vj+xPx2Pq51dseuCs9kvr7xbm8nhgv"
    "jCyVZmt2BYAD1zCCyK3I34Fi6lH2MUTvP3ZcN1+99amQiNMOXrTjimEljTrkBnveGv4YGABil67v"
    "zM6j4EO9T3aaLbrOfUdsisrD3fsIcpAd3n/nEZGR9GQFENUiiEARIu9M25Av0ZeMWNPatlqLClqK"
    "PJ/kvX33TVqFfzt1ifamhcfuTx3eZ/Y5srlhlw3OBs34OSa2cn2pRLyQTk631fe2t/LMj7H4oVzK"
    "YjYw/uasI6SYrlnKSB2fODY5vC+TKKYKudPOrHd1vk7Vl8Wb87Wl/uyuL9V/O68aW/zCG+4zKVd/"
    "z+iJm5dfbcwuL5x+ZWC0jydj6ZjY3Mpdnot95o7DC077sl0eYNkkSeW1sVXhJJIYQ79NdpUri6zV"
    "LE8MQCbtEFZq6JDBEoyk8pycTFyD65bfGIDcltpoU92VbRdcSXxBLhssq7H8NtU3YctNpTW7Yup9"
    "R4Yf3W/s+k45e6P+rpvWw0827/J4Nbm5cnhX7B39zbEB3YDFtx04N/EYHd/6+mfvFqufOn5gqm8s"
    "1/+2H/7IwIY3/XdnT545O+2uPPCjH5kqFPuUde/Bffzqzc8aw/Fqe/iuyZUrq6ub9sE9xZeXr335"
    "5tn9xQktmQXXQaJwe7xw594esrIDzdHTO3xil+tAl2Z030U7baCDm+7L0GE9XQR1FssNXHVXo4+O"
    "Cduhd1Z6Iyv5R3YB61hqqH7ekt5Hf1eH2PwjLwcMr9sW0T1nVzGKwkm3iBjsL45ESAqUAl8qsj2v"
    "hAqZJzOJ/F19x+/S9/9779vT+fohc6zmNgezfWQ5p+2tE0buqJFQmqZSmXlKrZmFgmk0lZcT0pHt"
    "y631t5rbthB1Ll5ZZ02VulDxt2VqMalRX/rk+vmzB80NzQMb/Eyyb/8BLakdG3/0bv3EdOuVOf/M"
    "Ji58rfGV9dXFHDPqpfVWu754+gxIr6Us0zS+PF3bVdj7gYlJUNoKNRJMN4BrpGmKp6VhgmlZG5xc"
    "2Zht1+cHeTHhWu3SOcNrZMGIediQVaXcpl8zGTOZsU3lOMRNiNWo7pEvgafie9OpvRDvL/QdeAD6"
    "R/XxRLw/S+6XzMxlOrxn4INLw3v3ZeiAWnr3eH5/kq2ePD1zZWVg6cIHcOs/v2/r0Y2/Tr74dCoh"
    "73t8/+iTJ9dnKn1PPHTXp+7py6X/6s//582LL3/0Zz8Z1/wH752YQu1OS/WfnHUHc1s629DYggZk"
    "rX9j/vvXrFJCpM1kIeLWPT67K9pEX3O0nXXk9gPRr7OcG+wA447wESGoQ+W7aLr1mMjFdxxvd9i4"
    "A+7gHxbh9FYDC3sdensuul4aAKCT5mKYdQRSf4fLdN+AEbvvEQWws3B7T8VO9XxYUf4dIJ7CmWMK"
    "E+XAUBSQAukbKOKg1ZX7tcpbN+XmbRumcb06l6BirvhSebYF8L78cFaArdwqcis/1RcrPOPqMU3u"
    "yybuGxnXeftS7bJiXj2TLcaNU5vyZts7V7E3hUhOjF/oE99pzgnbBUdhrv9Hy4OHMDazfVHjiQfx"
    "7kFKTVGhhVtf3/hKa7uiGv6R/Q8V0sMr12aXFc/sP5E5/K6/mKk/Onr7+waOMKRNfxvIAnQ04E13"
    "w5SkKZ+kl1axVns5RpDwmtxaV1RNKGCedGSrCiWp3CbUalAjwDwbjrEUEWMMTC3m+LXl+pnJ+NR/"
    "Vkf/uZNJmKna9vS1wuhbvlypL/wt205V18YalbeNHTGLw/WKk6XYF6e+/rv7XzhQSN6Xhff0bddP"
    "Xhj8ky/1n1z7cGxf398+s/bqdNvm+w7s+7HHP3Ltu8+1q1tuEeuba32D5u6J+M8MDdqvzGTBqVa2"
    "h7Ns777jsrY+s3G52dhy3RawSFWPtgDGcBNI6q4k0uvno9DfkRV7IYgdehTBmUL76Slo9bDvjreO"
    "ZJ2u2NO50o6ldhEBGbslIvScNiL64c31KFhEoDprTHT6JXp9OUUGGLwzuscu84kcPHVOF+yQE+4k"
    "GK2u1FMmA0KlkELJCCPhiBAsZa/VFhab82urp1KO84AafH1368BPPhZX8Tll743nU6ZokDVbWwOr"
    "9gA2rze82WzfbKM9Fsvk4+agsPZlqNVYhmK+cvT2V/cev5wrfLO0/nzCvJrW5AMP4ZYl51eh0e5/"
    "5g1jo7QnPnhh87VNt3okvv8EP7QXRipUAdU+7Zz+u0tfvbY8venWksnkrFW/qbPE4dueSw6/uu1M"
    "FXYNatkYx7baVqqtE/dU05HlBBpJjA+wfILEnHW+HxMaqSSYCtxNWqrIrS215oJtkeWBn8N8gxoS"
    "pIuWRzaAWXMbmcyRSbv+xcXP/9vWuXNrJ1PFCZ7Iltdna1x/1/r6Qyube1c32WpZtW4sXd7mM6UH"
    "uH1YqyydfPPky6XZrfydtw2/Y0WxUzO1Gzc/ceId7o0zuFpnxPeduO3oY/c//a0nU4XYS+dfm3xw"
    "4urVi3fvzR9dtUfHRyrcvblSOzG2Z/T2hxqbcyJhSqcNpKImCAWkICL6EegCXHYh0oO5DinqYCda"
    "TqTjRrvSYWdlxQ5xCl6iHtrVW2kiJCLVqbZ1WQUQsa7008PgQ8sh1bm1DnUKzHJnv1F0MSKIxntC"
    "wHcMp+cv6zGQiJkRdEy2txYSWUywDl1PcTHQTKUEpQJnwzRhWyUd2RHb+I4//a07rClXP7e4sDc+"
    "9ZC+lyNULPua3xpx7QOzN2qpAvdb5Zr/xnZjvbpUw/Ztu83dBeEtnnvKct+aOrK5/8jZbOp8c/F7"
    "S1dleQn35GnvCNxzKBY3VkiuKOYb2TQfGDYHlM5PwtzdcKzN7aQef6r+WqXeeGHurCNdL26cblut"
    "mrOr/9DXNku+WWz6VlykEjxN5HMgAwSC54LlUIvQiaGoetuGkhqpCpRquOXJVaZsjVgOUkmM11S9"
    "BU0dcEHdbKn1lD5EaGrJgb7M1AuNay+O7VmYOMxHjrfs0vz17+9ODX0YCo+4Mstjq6XNN65OPz+L"
    "Xyvtf/YsbCzHtt5o/a9r7/53a5/9fPORTJ9hFMtqlS7Xr5ebm29/9KH//sVfufHaC62ZlV0H9gz0"
    "79o7ODB6cBxaFrS9YRAfGh0ggJE7B/705ee2Wu1dU/s1I2ZXNxGRwhpw+EWhCtsRInx2gQ47UdDx"
    "s9iJBlFBKnKlFA24R+J5JMCEmW7P9GXHU0ePnv6j3s5qBERgOwvI2PH6ESY7Ok2EZ4SeDqDu39MD"
    "+p1SVNdAMDxlN9gRdo7vrWR3c4eAICoiRUqFH6YiDHCvCKRCIpBSuRbo0k16r+m11nD87mm9Nt24"
    "sjt2LHN4VB9otbWZJiFqMSXAjvXV6oNLq8OGOaTLt7a2M3Ezb5i7ctldpjt9+vWVc1dbLAUf+GF4"
    "/RmcuYGDg6wvoQYGoFyav2v4m7mtp0+M1yaHGItXJZ30Zq/A2kR8v6tzM5vIULKQGTvWf+9WSy16"
    "7Zvl5ZjjHvVyqcTQk3MX7ul7tOxUEHicpz2yNAADhK+abSqX5QYoawTSKRItbNpQzhNOEk6i6UNd"
    "Q9WGZplKDVUFgDY001rR98nlMpsa3dq6qOlDo0P3KsNgzZqot714PtMsnWg0yVOXmu1vWtt/6sT/"
    "pfmJ/zvyU98wT3ztnFu/tnVzO7NcmKy85+Nv6lPN8fk3Vs4/cf/Pf/7050G27nv/o9PPP+8tlmoX"
    "r4+OjJ9/69rxfQc5qbn5OWeu/PBYbtKAlpG0G2tf/vZXPNsZOXhXN1ZHuiVRp7oPnepnBy9B+0LP"
    "Ji4dyId20FND7YAeiHqG6XvABcCwi8euRYU9BRFXibh3B55IwUhkmND2PLq/YBCLumym68fD0/Wq"
    "up04casJdBLtbljqLlz3g7pwN2JgxP7DqKgUECnV2VOQgBT6Usd4zCwaud3vuO2jn4odT83BNw6h"
    "dmjUSRpVwU5WbUkZg/Sm7fTpydb69bwv+8zMoOBzLRrA4vOXeY5iLWm0qjZdmVaZYTxyO43shxvX"
    "aHGJzs/hzXlcXyWmyvFmNePDrsmtJHwLLtzwrH1422W5eX/qnSXJ7tEfmfa249lhP9+3d+/tnt1q"
    "lssxy3pg/K6rpasbbvlg8m5JvgstB1oMfA6yTdUsCIMcV25r6LSwqqg8THoRRZbxGlRMahE1LWrp"
    "qLWgYYPFUfOUhrE+Q49tV6f7aeC9Yx+u1daSN688YGcf1Q7fV20Pbb11s7083WhuxhLnC/tvDjy4"
    "0cxJs7A9fvh7du6VVqattMHXX9x44/q3/amN9NDgY4MV6aSKmU/+9YeGjPTe40deX7t6cXMWhPfy"
    "9OWVFy5o5bZRzE+fXdDr8p1j+YXN1bG+/vWzr559/tueJxN9Q+TYSEELdMD4Q90iaPHCiO52WE2X"
    "ZPcaAYU0qQcMvRS9O0y/0/X2nhcig8GeecyQf2OHX0TvjeoAXb/fO33TvbNbmBB2mYnqWXylh95H"
    "HK+30XTHEf+YhHprgOw8p3bwre7nF/zMCZE0ig8m9uZrlS+sP/3ksS1Lr5zID/TvHrtiN877DYVi"
    "FxYGWEoKuu6sTNu8aIzNWalHB3edq8tLFXemItqNGGM5iBVoYRZf+T4CozveRpsV9fS36bXvwdwN"
    "lAhj4+zKG7CxRDH9JX9ulB84IR667lcnskcvW+6xsXduOPjc8qVtlxglj+25HWruxvbWeGxod3pi"
    "unFl01tIibwtm0Bek6ocfACXQA4CT4IlqN5Sq/tR0wEHgd+EhkutGKoMMEXKopYG3IKmRW1TG5J+"
    "o+GWJnMnHkwftkrTxzY29rXUYTTub5c/uVHWFXwhm7g03je7b49z8F5Zk4MXLJy/qqBW6k/PD+Qz"
    "lbn+Uy/l/+Jr3tnZ585uTt4/+vTiN63yZhHRf+pUFrVyjl7ZupFvqLv2H12cnjPSscRw5sULs1tn"
    "qmMNfZIskUiwBFqVxY2F63qyj5tJkj6QAiUD5RoIgBQFWYHq7IIavKZ6OHQHtYGP7c2QdzbwdPTz"
    "Xn7TQWoPRqArsXZyB4zA0yOSAkRLI3YZUHesHbFrDr1muMPJR82tveordGbIwiDXKUp3eE501Y5F"
    "dsJBFCwx+jCo87lFqA+7C5XC4FNm4HiV+vbF9dnnvnzz80ulObldnrOuvHS3l87GK2BKzFrIJkTR"
    "YbRKVoWcUaO/QtwwTA1jz22Xx5J9VUcre3pdzwvXQRTqjZOwtoJH79TvuRtKa0AI1y5QqYm6rtoV"
    "1mqX+vLT6Tgpn6GWgKHvbr+BMOjGjXt2v/2p7dNvbCycX9/UhX7b+H6H3IXV5V25XVW3LDBdcrcN"
    "TBgYJwAL2hkQMUCJ5KGMIU2BKgKXiAQwo2wDSAG4KDwkHnpMxlFr+QuuV9qTf2DQbs6Xzlbrl4ut"
    "1gjDdKu2tHb6JrPHhz96z9A7z00Unt43smGtTuQP7nNGmxevtIoHpm6jez/cf/uJlrO7+NLV0stf"
    "euXK1ZXzl68lWLWwvflR2rUFZVqrF9f9tc3t1dm5vX2ja1ZrY2Z1LN5/GduLM+ur1xvDqYF0YkCP"
    "xwHJr65XF64gF6hkSFmVBFIdWh52tnVpdCQrBvwk+n4jEQdDVSWCyI6Jk1vEmtDRdvSfzmT6DpDS"
    "rW/uABlZL52KRE/sZO63HB62bN9ibNCTIP/g3QV4D8SinjWBISgjdG4tei7abaC3shbZUEf8IYWK"
    "QBFJAp/AB2QCdd2y6lBv9tHg9Na1p5wLc/aWjBnm1J40G9htDK9SRSKVLXmI7xvRi98uzQHp/3d5"
    "48HC2K5E5qptPVWq9bHkaN0YOndVW5in/XfBW2dgaRZMBflRKkwgB8gVwG6QFr/Wp+mFAcv0n4NT"
    "d+fuuurWK+S+Wb4hnFhfaujCxlytVo85dqVZPr7v2PPz3y/E+/vMobZsJfSURz4DoaGpiGkoTBQE"
    "tAl+hfwxLgzkQGoNpA8QJ2YTXwA3TYYJhgOKQHrKUco5mLwbqguyWa3IUoHiKd+4I7EXSLVRLSs1"
    "COmjXN/woOK329XF/blhe+OmN3QAXnr17Aq/ULhz90Naed9uPzuk7v4wwdDXvvPcbSy+vz/3iBga"
    "Av63rddHIFGw4M8vPeU0WyWmbtxcUjVRv+vAqX53VVaffPWZpKJ9t78HJSAguZZfLyEgKBV8R0Hi"
    "Fv0afsVhf1snS+7MgHXqVRDSGew2xXQmbQGiNDgASbQqbYCT3jpr78pVHfW9A7weaBMw7LwWvSdI"
    "uHs4VkdeQujsk9Hh6MEvPaMHvaJt1w6C/AV3/JG9Ilfk6m/pm+6aXue4KLgRKEVKkVLgEbmSPAWO"
    "H/fjrXZ9Qa1oEvpr7smDja19cOfYifH4sI1iW8J12eBaqurqc479V+sLSsVGWf7vV7efLdV9zz9c"
    "Ebmyc1spwda3obQOvOWe/D7sewRKi7A+D9fPg89Ysoggob05XK/xVGEBazP+fE3ALEy/Zd2wQeaS"
    "/clkcXX++iTrvzo/065Yx0aOXVufPdL3oOM3PdnmqDnkCzAQmAPCAsoDM4H5CBLVAkgdGAOMAasD"
    "XwbfITeOJqFgwICUYKm98QcaznbTLVno7IqN5rQMA3hr+2LDb296Tcdz+yy3tbl90I2Nnzs1eGNu"
    "de78WXcBU2Pg8mk4/kYp8cpFKMUPopFkQjfHj6T48PTi8v70gcta610HHzu5dektvdQ/MCLQ/OtL"
    "zzakfGl6ervcGir0Lx4aFkPGen3xhef/wm87OjPBcwPEUajLRc4rxE3wUJ2kroOmHRCh3v/rUIXQ"
    "NLoafGgIXVWxp4k0UhO7Hr3H3+KtNCV4dHKA8IZveSBCz7Odi1JkZeFJsTcKdI33Vkr/A4+I0nRO"
    "3quZdphSVyrofKxhThCWAqQCj9CTDNDUkivlSxrjcUOVjdp3d63njvaN7t59rl23teFVgAW1ncfY"
    "mdbmDatW93IFMf79ev1GNRFXAyZkK36tKrdaou0M7sLNdfB82Jyhm2dg4jBYdVpdgfPnyUaob0Ft"
    "rdHaWCFH6n1PeS+t85lYPLnh19sJfcOvAzMyZnJ9oZQx8s9eeeH4+PG4kWl4VsJMWLLCQHCmAaCP"
    "6IB0ASTwIRADwK8quUl+nvERFD6wK+C6qGKotRAUcEJk3EyJAY/kpreqISfwYmRWvfoVNbMiqpuy"
    "BkodwUFWrT554/8dunz5roXGwdjR5spcqXqDFmfw8R9rNnfP3ShuXC/4NsLwPpjeSHvJu2gchw63"
    "adAe2v+6Wy4kixt2M5kbnNx1m21mqo4zkd63sFq6q6QOFNONQVFMxJuN5Zun/sG3GgHFR6VCx0QK"
    "iTBcDEJFclDgVnsEnC75iWR1uqXHGCFaZQEhGi3ZybOD83S8+w/S/FvI9S1IDFtWA0mqy1e6WTRS"
    "yIciI1ME1M1moj+jm5lEcwzYcz3oJBTdpDYa4AyqvBGv6ir93XvpCghdG8AeF4AEKAl8IkmgqNZa"
    "bWnVTedmzVlkIjlqu4yLCtUXNJ/zvO/xPE81yXmueS4GQ6PaoW3feqO23qflEAsJUaxBGzg7LW+g"
    "ZpCuw9xVkDYs3cCZsziyHxJ5bNUoliK3Aes3a5pqpgug44raWmtddXQ+6y5drE17GLtQulxVjemt"
    "6RvrF00er9Za4/nBS1tv9sXG8saYIgoydx/QBSWBb4KwgSdRayiOIHzgdeI1YIQsBXqbpCJsQNsB"
    "CaCnxOCWvxoXqT59gIOY89b1WNrQ04PGYAw59729XuaV2qldZBYa7enWejE1ogkd+8dZusgMA2pQ"
    "nTG3XluVlXq6b9eeC5u3X5kb0JMr1eU1r3qguO+Z1bceHb47xTLF5NBCy9qTvaMVy7PBYj4+MNLi"
    "vFI/77XHhQH1qm/XpLSJFJGE7lojXeUncFLYo/VQBJEOOCLGC+G32cVzSHwjkFHvtO0OGFPnzN2j"
    "sadmHDGT7tswEiZZhKrusx2lfgfbv6XQ0OUjHVSHtK6bKHeYS6RC9fp47Bgv9ZjpP2K5YRTtBITo"
    "UtGaM8HqA5JAkpJSMYUm07m2V01Se/0leBk8M71/aHTqoC65zrRBMVL1fIYwwQ8PUn7WWYyz/LS/"
    "FGPJCtSUEDUz2dJTWF5mTGBjDR0L0v10/RQxDQyD3CaAT40t4MlyMta0b7J4ktwVW9JWc7kp5JeX"
    "v+Z4jmbEzi6cSsSS6631S9uX5ldX7y7cMxQvzJSvaCqT4n1E4JOKQRxBVyBM0Kukl0BLoL4GOAtY"
    "AeYDM8BwQSjkNjk2OUBehg35ipr+5qA+Soo1UO7u22+hF9PiRT3ngFfF1pvuleve7InM8Vcb5y9p"
    "5OXGl9xFunKO6jZcPYfP/h3NNyizF0YPeFcvx6326bU3wLFX16+9sHXOcf2SbY0kRlaJOyL7SvNq"
    "3WtN7LrjzdUlPZfcc3Dv9cq1K9cvSV8gN0D5GEKDOl6qhyeENP1Wlb2zHlSIiC7kqceZdrDWg4ku"
    "O79FV+y61Ug46jrpsDWTbn0PEACxDg+JLhARnB7wAkA3KQ+ac3Y+281AcKdFdLx4h71Az5Md8nML"
    "+8KIenWmPaO76XRVdG4GAnqpCP3wLUQOKF+B+VL7xfFWn0X1P7v3XKyYSKUyg7HRJBVdEkNi/4Q2"
    "uexf8Yjl9PEmrfjcr8nGqr9YMRlqOpFDpXnyJRgpbDcgOwEbN0H65Lm4egOkB3oCXJcQQDWVXGOx"
    "AakwJowr5fkzm0/HyY9r+kpl+Y7RBxpe7WszT85vLz+y+91DiT0xjHEQJpoExEGkMOuBaIDykDto"
    "tMFog+kTbwEw5IQxGzUOpkRGKFNavwS5bp/rN4biLDPrrewv3OYrb9VZlqhs6d9w1+KY2aYaQ/p2"
    "8xXGzKxIuvXNVVmD1AhsLMj5m+QTVOtw59v1up3YqpSdUh7z3yu9vjc5eSA3dXLj2orbdut8ltrT"
    "7daxoWNXVuay3BTMbNj+yrBzxVyYW7iwcuMyci1sJYOQjwQl+g6WIj4Q9ET05J5BLTUoFUeQQICg"
    "8yA0hK5W2ZWJoMt1cCcOwrP24jX6XwdbXVW197FjHqCTMlD3VnstJwhBbEcRGAk7aufOINGTfCN0"
    "SFE3akQWFqbsHbuOTo5dN9E1m9Cces6jAFW4vCQqACk5xOKxwXWaTZjJql/6Vvzk5eRpVzVzdx7o"
    "GzusxwuK9NvNezZh+bo6u1u7A5QLjG/Bhq8qxGOICLIKXCNmUqwfpAS3BWYWtq/DwitIDNbPI+fA"
    "ddg4R4hUW0JtArggOQeqKWm7KetNex1ZrK0sXfC7Bk+U/IVvl19SIrb/fQ8b42mDCzOX0TEWEylT"
    "xU00mwgesjppFYgJNA0wS0AMNZPiHIwsyzHUYyynqXhNriSNzC7z6I3G1UKsLyPioOS6vyUwbiu/"
    "5NePJQ/HtPgFmqvIakzFJttYX3/V7h9CjgQcUYd4P155CZZusLfeGsDMmrWxL7PHQVjzvcnc3iW/"
    "ZkvztdLWuluf29qc0g9njMLVmZtCCi2b/qq4zuNGs7pVc0rKq0YLJAQeXe1AUSfhxLB9p5PvYcR6"
    "IsPo9Zg9X3XvMxF4o/FgCieCO1Dq7UCmyIdCxyCoM5weXSJ8J+se08u7euMYdlwwRujECOLUiUmd"
    "QIa3XAE6YYE697uD8XStrfNR9Jrpjrp3mJaHoTIqExBE0ZZAKvJk01tu+WsVZ2ndn9lKzJuN9sTu"
    "saXHrNwTB5xMoj+9Zx1WL7tnOebSNFDxNhxqN+Q2Ch2oTc4a+FWQLpM25KaAx8Bpol0GWcfWKqxf"
    "BVJkZtEugSxT7Tr4PpAA5frOGmNE4CpSEs2aXU9q2e9NfyMu2H5jypnE6ftbMJjWHhnVjuTFncW+"
    "sd0aGeZ4NqWlY5TiSjhCd1GPqRiIJEAyplIgBCOeyA7osXTCzHqH0yyRHNAOLdiXWmojrcUyIv1m"
    "+VTFaxXE0PX2cl5k47H0ZX/JI3OIDV2FskPNV2CaJfLQ2EIfoLYNTgva2+zcS/ba9IZsqVje0jmP"
    "mdfcxSub5RFjD1fJpo+rzY0z61feWruSiWfjIn18/x01U72+ffn82tWE8h3ZBB76+06rVmceEDrE"
    "vCvIdFERRYlbgjp1pgp3QLdzKrh1RquHGXTw22MFXd8PPSvR7TApABLd56hH9OmpQvS8bQdNibo1"
    "wtmYMNvoGnLUybozr8deq4/+KuzYWTSqjMjCzDy6TleuBQoL7cFziF1zVwCSlN0mhpjkKNDXWoau"
    "vd1/9OodazcLK7iZzhwvNJawPq+Em09wbRvm12GeYdonD8AguQ3tGsk22hbqe5hbI7cOXgnaLUCf"
    "nAZWrwNLYGsetSwxHZszxPIgLbB1wqTnrnJRBHtjWzYUlVbqc8PJXd+6/rVH+t65wKul94nKtUph"
    "Orn93inc3nDu7c/+/k37tmTqDXT7uCx4xqUWIz9ZSIgVt5DpV0Nmc3HdKGQVqQz2tT4U046Iwd+M"
    "VVvzZXeWscz+1IHXy6fmrNUPj35aEJ/3F9+bffcVZ3FBVu427h7Ijr5hvTLfuIbZfbB6gbKjsLWE"
    "fhPcFvguoQByyrqfYpllchfcjbgSr7Wv90vOhLkC5WJ8dLW53rDbHBN3jo00706/oc3caRdP0sus"
    "uclUMESlABSCokiZj3piiACAAahQG4/YSGQCIdEJDoj624EQI4fWi+su6neUC/AWOHeZUOfpztRJ"
    "SEl62Ezo19lOG73FPrpmhNERPTiOUt4OYeu9MEKvvBmRm+6N/P9/EKjOn03RTgtdThX9HI4/R/+g"
    "IpAIiiMhkARUST19xDr6Mrz6dPJkmW9JrczGfP7AyNTY/SYbSMeGltRN4DoyE4nALxG1wWugAlKg"
    "2mWoXAGyCQGkjSAAdZAMSZJTI7cBrgsSkVrI46QcxsCzlzgqAGjJWsNbmq+dETyR1SevNxZ2Nwf0"
    "662FY+2FB6W+O85u76veTu47C8wV1tvTzseHkid2ZXw9+fC4eqiga7p5Z7H9mYI+kIg9PpzoT2of"
    "HVOfKZqnwGpa2+66L619qcOrrbU3t1/Ynz8+mhw/37hUB4tY7JXWGyPxKS1mqoS24iyzWD+2Fsha"
    "guwAuk1orIDbpsIUZEewMCJNs+ZtXne3EmIsZ+yekytnGpfSZvGqNVfQdhmQj1OhkBtQOlbM8hdj"
    "J2um1xdLK25JFix/ooApYgSMumSit79nh/YS9ghFqKAOmQh74LtY30HGO+jCTj64Qw7pQCo68w+A"
    "iX4A15FloIBQ0u/Av6vf9LKRW84dFsWCYBH2h3buGsPpY6ROCx700iPq2Z8bsft8L13ryT4weCoc"
    "sov+21lEDDrUrGvDhARKoUvcwrOxV1xojjh3t7O4S6Rev71UWMLtiZWBzO729ZV6o8R1UtKhmIHx"
    "YdSSykyh60CrSsoDaxsYg3gfmGkkAN+j9ADqMQSPXAczAyA9sboI7Tp5daVJX1meu8GZ5bXmQPSv"
    "1C/mtPGhgdG1xUUnbxQasZsbpe0CoOdIIFc68x/Ah7/af/nBSn23c+R5ERvJ3Xi/7gs+OTN57dFm"
    "a59zYGLXwiEtk0usv88X1wx/CVtQR6an+J6WgpnS0wydMXPXG9uvnm2+ntFHZt2FslftT+2TQq60"
    "yh7P6VrSrZyBoaNYnQZ7ldqrCDoMvgN9CWBC4xoRa0rQY/1KxvxmMw7py83rSS3XsOojmYmJkQN7"
    "7to1N+E2q5tu7No3nI0sy1cMXTkSeNSTHMRqRp3hJkQk/AEP3QHYrXltz68htnoR2w0J4ZOq0xAX"
    "4rNbNO4JETuu3uM7g987P4ueOwNE3Gkr2EuMEChaAyhaSyhY53fniAP1kvjQsjuLIt4SSHqei0Tj"
    "ThkNkaJo1uFUQbZM2KMQARAqBBXSseBe0SfwiXy/Zq8Bx7ieZ0nMeuUbuelr6cW7Bzzvvji/IptT"
    "dt/5u5anL9HEBABSKg3ZAvTtQruF7YbaXoHly6BpYLeBx0AzIZ7EwgiJOA70I0co9FEy528s49am"
    "OPcam31VoeY460xopJq6cVja62vVay6NJtOx1dbNzQIfUNqqX1/DesoVUspmv1x/PMcNvm1Wpw+a"
    "++dj6xNtZsRq782U9myTq8Pdmc37qlZDUd3hhFVq6gnTbCUIxFLrui8r44nDBHS2/rLOkwCqoZoI"
    "qiRXuUpsyBYwko1ZRJPHs1S6phpbwOKAAqQNlVlYu4yo0HOUNtwW8ba/LqC1P3FkwZo3eUIY8b7+"
    "vj1vP7JSXPjGrhsfXDyWsPVK65qv7SKQxH3ggIyIBY6cAAIb6OHsEeBDuoGdBgLqwh0iXtQNDb3e"
    "tjNPGGGk+1aKiEb4npA9h6S5R8vcYQi97dAEQQ4Q2Up3+f/euBKJ8OEWpwBdrT9K7aPqb7BjXnCm"
    "rhV0xqM7o2qdG4hIf0ephe4UMkUH9Ob33aBEkcIVoD9okO7U6BSBD+AjKIO55DStZfF6ivJWNuW5"
    "1y73eSPTfY1HNtSB++pfHZT5IpHPUgkVS8LEfmY1YWAfbK2xRAL6hsFzoLoJ5JNmggeAHPqKwDgW"
    "C8A1NTzIDuxSG1XnvsfYs18UL31JeQ0lfRQmh02mG45bqza1obsnMyO80WZrA07C9xqeVfeJK+A1"
    "uFJczLgaVOo1Q1VuS1mypSvv5m1OW/q5ulg7sNXwqn7WMJrMXa3HCnE57DlzTcvd9JWT1ibzxp7z"
    "jVOWUgTObuPemrtoGtmGu+Wz5oq3BrKtyMLEJFQ2VWUFzD5UnLwmn3uR3Lqyqyw+Tn4b/GkPJZei"
    "IUsgp0Zie5rMGUjvxvfoc4lZn7ll6+prgqclthPUdteJORit8o9AhKqzjiEghV9Dp+UhOLADvR9M"
    "Rnuf6XjwWwwButUzREKK1mPb4bCpB7y3NlVDhz50nkVCAgGAUWMDdiEWLaKy0wQj8whUF+xmoWEg"
    "DG8/qmCH74p6vKPcvdOl3du20Zug9BIwjPghKkXIsFNQJwClQLIg/UKfyMVod1oIF61mgIxIomrW"
    "wZPN9HY99UKqsB9ZduW9GdV+CF4c8+SK4gSpPspkYWwSDIYpTl6d4jGY2gPI4eYsIEeyVaMJvkKm"
    "s8FBlc5TjIOSrLSuhveAqyPX6YM/TuCop/+AMMXQkHaJA8Xi2Wy8z97LSsNiSGrbLbWu17hLSpIP"
    "BB5YZPvEwPdcaNkDcXTantte54yYiHNj2SxByXU05cWMgp9J1OrlCYFVQWuSM8YZXK2/JFEQWSmR"
    "98je8GcN1BiZltqU3hbyJOgFIN9vNyFzAMEH1wGRk0qhnsVYP6RHyBpmyiElZSKBLbECzr1q/9xj"
    "rpnKz45tt8TirvVxPWtflW8Kv0rSl8oGAJSEMlgDvZfq9Lh8htEibCHKIwhjtCswhNEgIBi3MqaA"
    "EHTYUidPjuDTy5Q61Ak6kzRdXb2D9+6hHZsKDKAL8cglR0AG3OnMe6ws8tc963uFdKhjZTtTmeht"
    "uLPEHFVQoCdPDtdcwbBUxjqfAJEiYBH5C8NWoEEjSgCJIAF8hS6AQEBOiMz3Rnc94GkjOHqoYXn9"
    "+duttb7KdM270TxwX3Zx9jJpBuzaR8pnjSqMTMpaA5EDU5DK4PY2xWJU57C8BHoMiYARrMygJlSJ"
    "YGSQDZiwsErpPqYBxcH/wKfZ1VO0eI2kq1hCl6Z2d56lk6Dr6+O1jbZl1LVsLF6DWug1FBCBqyQQ"
    "SeGXjCba5JMEjgLlrLYpmTKYniJTA2Nwy1z/WEufM/1nWloirtqtqrtCiAwZKkvDqRXrnCdrrrJj"
    "Ws5jBib3QGYMMgXK93PUlBmjjXlslFDTIN0HmT6OpHgciiOgczIEDI0iOPPJTN+Gvz5+sTx0NV+X"
    "F9xXkvp9+Spf9GaljygVSEmyW8InuKUerwL9oos8ioDeeU8I5p6ktoPH7vGw071T94ydGhd0pZbu"
    "cVFeHfjPXuvpcukeFtTdIYY6zjxkJRjBvZcaYTSv3n05QnH0QxBMdhB9hCg56tYnGEbviwbgMIgJ"
    "wR6aCIwBR2AMGAJjhAgMgDPgiJwRR9Q5aBw4AGegAxmEBpChwOSgA8YExWS2mHjktl++sXm0Upio"
    "rNWdZ16c3XyTWhXY3sq/553MGHFsBxJpzMSQIaxuUL2OSCwXJ4doa5sYJ92AdpPKmxBLYrafUClf"
    "IRIrxKG6QrfdR+slSJts34AoN+RWzH3wI/j3f6A03XcshSnGje13OyNviTq2jLS0mGWbTuQdgzGR"
    "YOkEUFxusjKQQgAgJcEHCQwhzo2YDskbJO9utg630n+js/cm/C1hvdxiehakr2Qtoe9vSceRDSJi"
    "mPBjQ5idgImDWBwAI0H7pogB1husuo82V6FRoqHdlMwpu0FWi40MQMLEkUFM6nygiOnYhaHEWOPA"
    "VuOFRvuMdbX5/fiTqUSfavnKR/AIXI+jpkygNoDGwAZgKlTCiRA4oYRQtQuacSQCI1AQjB+q0G8B"
    "Y6HGGGwp2SOCd31tB3cdTo7BVTpshW6xgO4vISVB6kaKSGXtHksCd3alYsexdk0Puj67y5I6ROvW"
    "E1Cnshvcaoh72mEA2GMPYWkZg8HOkMewzquRkTBExol1XmLByr7AGGgcdASdSAfkElAhF8r2TV3/"
    "8Qd/+y3/jqtXXzPidXduDVZuoCdx+aJq1AR73GtabtPFVBLbDYrrVOxD3eR7ilICs13aqML2NrQb"
    "WF6HygqYe8hMgoiDLWF9m267HQcS8I2v8ve9W6FP8yu+bfPJcTxwnBI5UA4ZcctxsAKQ0Lzb9QyD"
    "lT4oIm9wD0EAKPAJAt2BFCgAgYwF26ap0GMQKKIK1Wt+IzXal4jFD//DRPW+aq2fJ/+e7HiavBpR"
    "S5iTDjBflokxoBSkhuTwfhrYBdkiHb0TMwn0bBrpIwmsbUN9F92YgUYLmjWqbWMqri6cgTtP8GIe"
    "PEfpOGY63mK9uHvgncOf+Gb5bXuLH6muvTacRKyvXpk5m09m0ffWli6Ba6AhSAAwAMZD8skJNACP"
    "gRtkBQrAR0Ii1Z0+RwWKAVPhEhJAwKI/GYK9siKm1MFyl+kEJkCdVSG6+W7wa5dIY+cUvSl5lIuH"
    "v0GgAoUspMfqukbXORQ7yO6S9c7LXfLeCTDIIohD5OPDQRsKEB+CPtgkmXVgTYHvD6IBY8AZIgDn"
    "xDhwBpyBYCAQOQAHEhwFC5/XALkCndBAJb041z70jl979kLi0oVvifEj7vImbm0SM6i9Bp7POZva"
    "N7zgcWIaHx3Ges0/fgIHitBwNGUpF9R6hQpZ3FzH5VlqlrG1DlWT4ll0LEj3gatgdY0mR/m9D8P0"
    "BjiW2jsIK2uUSJkPHXU/Py435iGZlMKrDRZSwqzusVMgCqbflopxHSQAETFCUigAGQESCQAByCgs"
    "J7EwtwFQMQmKvGSL6gc96VnS981+TV5RxAC1gs8kURsYgDKAc5XOY8KkeBrSeVxZAm0UCjHGPGrZ"
    "VOyDiSLEE/D1r0KjBuQDH8dckWZvKAaYTZGm6vG0abe3Ls65Y7l3m6m/vjkez59wB3G0z9nTvzyu"
    "Jx7KifWlb/zdK39W4W1QnCSgQpCMFKBSIBUgIjACCQCAGgkFSKAIiUgqUApQgUQABK6gs3hK0OKO"
    "BMi7ZIk6RAd6YNulKB1uEnntW9PeLucmCuTaSFQJHbigrq1005Ae1t/DvUIa3pO5dpq1IeL5YYAK"
    "QR9yoQ7cA6BD5PUjx48B7gPEB9bCEBGIcUQGnAEL/uHIOQhOnKFAEgw0RhqCzkGDYH4eGSMG6Ri/"
    "96Gfm00+NAtL6KL/zHfQ8QgVlpdpa46WZ+78xV/Rxyc2vv4K5geh2iRDF6mYnJmG8UmHmfDKGRof"
    "R69FtTLWtqG0SLKFTgNaNdJMbNdYcxvShjJ30eySHB/nI2N4YAQOTNLilirm+H//LfUf/iOtXQcj"
    "VR4eowk7tbkxM6iYL23LJZKgABBRAQCSjGiwRqgBCEDOgBNICtZIVZxpgP0OrPZVE3E3swKklMsy"
    "lMqDR4qbyBBJA6XAaZIQkEhS20a7jcoGpql8DvtMSMahP2WA6/o+mQlo17G8RJoJ1QT0j0MxB9mc"
    "sh1c2vTRTrbr5siYbhr3FIzX1hYv/PW3Su+66+pgIZvLxscyZYP3Df/kp44f+rPv/Yrj+IwZihFw"
    "hgLIV8B84ASCEDhwQknkK2AyTA9AAcgwfyMAYIFtQLioP1CQFQXsJfxgFHToVQfhHUkSozykF7bY"
    "m0hgSMYCOTGcSOj2H4neGLMzCe/JXCOM7+jLiTScaGghtN/e4APhiCaG0/fYrev2RgYK3xDppIwD"
    "48AZchFAnzgHzokhcgaIiJwYxyBQCAGCASNSBD6g1KDRvO3Rn7jg3b7+nVf5epVn8nLiMCzdoGYL"
    "aptU3cwfOGA+/J5XvvKMX65iOi+XpkEnuDSIB6fw5Bn6+LuhkMC3LsD4GJZWqLIJTg3AI6nQccB1"
    "AVENjePmMs1maLuEoyPy9fOwsQUDBSgWaWENxsfxkUfp75chFoPVsqX0XD8fTMTW4hRzhA+xYFYQ"
    "FDCpmEbIQDoSgCRJkMGYczBHguQDuFgHtAX4lr63ZK5l/eRWsTWUVrSM8RSgRgQgDHSaoBSkiqBn"
    "IZ6BVFIlkjyRYOtL1NBoz4S5L8PNnKq03YVtqJSguQ3F3aAQt1eZ56qBIjs4zKwmFQspY6iwsVla"
    "Y35m6J88tvdfPPNqe7khtpvVcvXieLE8Wdxz+9AH7rrvR8v/9E+/9SfIk0guqUDqlIBIjEgQIoEM"
    "pAwJwIPVbEBKRE5KAfrhbAkRogJiwbI3wKJ+oqBliAiRd3fSjoAS7CraccWRWh4RkdBgukAG7MSD"
    "jrATQl500otbDKBXP9oRHaKXo7wFu2WO7luD8NDTGUSKMCoThIaNiAA8qAmzULMMYM0YMAHIADkI"
    "DQCQ8ZBTASNiSIjEATgABynAZ6Rx5AoQyJXp8SOXzgmrdSoBzDJzqtqm6+eguQ2VNVAutMuxg++6"
    "Pr3kXT6H6LKLcwPcHYyB9fWrV1+aorGj+MZl3DsFr7yiNA1qJSwvgtcmAHDq5DSwraE5TEqR1YSz"
    "Z3Fogs68mXv5G7tHB1gqda5J3hMf5e0mDQ2CZkA6L9uWkcy4YwW1aSW0mGd7jFyW0EkSInGNg1IS"
    "FDOUYsR1ZII0gQTKtz3f80kp5ksgchnE26yecFpZckbs2l9WASQlsuA4wHVQimIpDEIo45jvp5Hd"
    "vK8PzBjsH9N0WzLuXp9N3XlMJJjre9Bah+oK5CfIbmFpBaVD13UgR3HpTw2eXq/f3j8wyu2ZG4u3"
    "37H73//Gx//jb/59a2iKOTW32b+8Uqlcv7F8x9THH/mRH2/af/ndv0M00HPAkeADKQTFMBjT8wkl"
    "RXvmISoIp4SVCnxx579AESyhRyQkjESZ3tWriICABdgKWVPIO8KmBKCoQh1iu6O7RDXbaKwXAECE"
    "5rMD1ZFfx0js6U2doeP4oftSp+rQ6U0ITsQ6yS5Hxrs0BhAYQ2QUOHtkgEgogCExBMaBa8AFMI5C"
    "AGMgBAgNuCCGwARoAnSNDAMFI8EBfeQucZ8LLpWjp0Yfriye/e7fz/c/TP17YOk8OhZsL1B1lZJ5"
    "8Brbi/MSTgMCu/b9w0P5YnH44OFDu8fHL5y/+IXzL3rZDMXjyBhsr4DvglUC6QFo6DWptgTUJjMO"
    "y23YtR9KVWq7xUtfOdSfObB74MiBvY/NTP+fL/1Z/bGPQrYPUxkqV9kwj2VsEUfPZLFkIhtnTIKn"
    "ke/5PvlOy3FbUtpKNlzlS0QfM8zXETVCA8hWjKSWAMEE42CaPunWUDbmJezWQNqLtUEYJFIobbJt"
    "MBKkJCiJygWNI3m4tem3EScGMYmQSWo5059Z1oYKsFHjwyNy8Qy0SqgZytNhYwVabao3KGm2T53j"
    "T7zjar28duf+yWp7saX6hP6TP3Ts937762zvXmidU2+7B49NTr947s8s+QuP/OgnJPvSU19i2bRy"
    "fPAQPAKJ5AHYPngKpCLPDcRT8CWgB1IC+EA+AQCqUNbpOPewsbenoa2noNZ1r0HjHUXtR6QiKTFg"
    "O513YxQfumlqV9VHAAIBUWoQBYyu+4+O3On9sXN0yHOwO4yMCFE6CxHLD35mCMiJMYzgHio5TAAT"
    "0Q3yKPHVgXEEDlwHHliICHJe9CUJRh4LswRPIkowBDDOTF35Kp9I/LORcd/byj3yzidPndts11l1"
    "gYwUKQ+UDZ4LAF7dgXIFqhuD2eTQ2D6rWY2ZWv/o4PF48rWzv3/9TI6NHyBPsc05aFbI94gJUAKQ"
    "gXSgXQG3Da6Nmytk5Ni1l4vSsX2cX1ye2L3rXR/72Kb1hT+/eJ4/+G5IZmhhQX9f0hHN1mwNdS5X"
    "vAaS5MqXPvMJkPyqrRyJvkSPmMZ4hqMJGAOeQK5zDsgQTY3FhMZ8L45S74vHDd1XfF2Ry3QUcfA9"
    "4AKJSI9hs0wkgSMqBUyTM9M4NIzVlmMRrDXMJ44nXr9aWuZYTKlGC5HIqoORwXaNkhnU48RjrFan"
    "rU1ZMTDOazfKp149tX5oKL7/8NseeeDEUy+98eoLfGxCbexpjuzPvO3eGKrnF7ZHDj8xeua15ZV1"
    "Fk8oH8BFUAx9BD0o0iMqAl+iJ8n30LHA84AAPAd9F6QP0iclQfmgwuZ2JAUkQSmI1gMnUkhE2Fln"
    "JfTyIZcg6pANinJNQABSIRvqwXbk0rvsRoTiZuj7e3kTRElHxI+iUNJTOe5MDEOHzUM3EHRSFgXE"
    "EUPRlxCQ8WAsNljeGRkjJgIjARTABHIBTADTgAvgGnKNNBOYAMNETQPGyDBRM4AzYARMgWCgMwTv"
    "kwdGV1+9uO3SjauX7ZUrUDQBBG0vgtMAPQlEgBpur0J+NzjVwVwOCHzP6evLx3QxfeN6QkNYugLJ"
    "LDVq5Hi4MQfIEAGAEWpg5AglVrcgmcFmgzJDbPNai3t6LFVV3ub6hqHp+3eN6fUtr7HNVq+iVnJ1"
    "c/vb60gEcQYmJw1BKIYAHoGnkIjpQALAVyRBckQEcMmvKAwWHAOscgBSggnQNJbVTHBES3OWARhR"
    "uwpWi3QDkbCxSdID1CgzCK4NWyUy4pjKqm9/M6NKVNuof3Nc/dhPsLUlHw00TCAHWpsABPkxYhq0"
    "Lba5IsaGXCePy2t+fTN55YUPDHBcEU+9+NqXfupnDt17B/vW0zC5B579vve9V8o//NHWY4cT7Vpp"
    "bSt2/N1s6f+RjyAZeASOJJ/QI/IlKARg4SopMtg6gIGSyDmgAciBGyB9lC4oAlAB7kFJQIVKBovs"
    "BkJq6KaDH0KoKQACDHegRGCAUYk0AD5FYAxrp9QD9hDpnV6gnQkwRM4dIp0pYj+d1wihWwYO3D+y"
    "kHMhD+0h3DAtcPYspPWMExeAjIIcl2vEOAgdkQPjoOvANNAMEjpyAZqBQpDQUZikGcQ5ajrpJgoB"
    "8RgAgN0AlJiIKaUO7epzLp4+f/5SeX2lWlm3PBusOvkOSAXKB88C0IGU3LrI+obBtYxYzmq3HMcZ"
    "HBzY3t7e2Fi1mi1Mj0LLgo0FrJehXSPGQPloJEB5AApYHHwHpFRMEHHiwmltWcksw8T16zeBQSJu"
    "mr7vrsyrpTOEGn3VxQcyGGeU4JBhaCCgBK4UA2grbClquAQAHqGnlAAoMkhw4gpjgFkOMYHIAJlP"
    "wDTur5HXZkwxHEzCDcIEkdtCzimRhdIKSA/JguoqSALbwdwgnD85sXzqwTuO3v7wfa3S5m//u3/t"
    "/PAvoK6B7wBIdOrAdKpAuGRgddlnCoUO24uZt753p1Y9vPfxX/tXP3vqO0+//3//4fXPfMLU/Pba"
    "CiuOQ2MLnn3JW7jGW8sHWuWnB/r58AHfIxQGeABtj3wAxdBXYPvkOuR76HoILhAC+oiSpA8kgQFI"
    "iQjABIKEoF4mZZd/BPQhBJ7qqp4dMtMpq3WTXBXs5RslFNE0PUKnztvJgAFAwI6zBg/WUz8IBVKE"
    "oEYbiTnIQnxDVLsFBj1b0XdMAgNyH2g7XBAyDEgOF8A4IAIXqOlgxBUJYBy0GOgJEDoInWIp0A0y"
    "dDBjqBsgNGCCGAczhq4Fdh0yOTW8B0CCdCGeLLiLZ5/73vT8Neoblah5kkFtDYhAumBXQPmAGjIC"
    "LqC+Cuag4zPXawnOhkeGvvnN76wvLdZdSdyEpgWlRdq6AYTotYgUgI5KQqsOWg6Qg3Qh3sc2Z6SR"
    "w9YSubbNYHnFqVUrsaShIAGzN0D5YMaZo5ijKKdQeIRIigEjqlis7VGKISGQDy5BnEEWeAJVFjHr"
    "g0ACBC7B8agFYAEBKIOhh9BC31JquMFimipZoMdIMWzUSBG4FnEB7TYmcwieatfyV5/tn9jVBq04"
    "OPKRH/n0mcv/9MnvfpO95zPUbhEwkBZ4NjgacA6+Q06dtpcZ1wmgv7kkh4dfPvnq0N8M/PRPfeIn"
    "ztz4w6e+ZzAF5W2VGGBem7ZXxJUX+nLOz//mf/owdz/6Z3MslVK+RwDIGXguEABy0AT4CkgSEwgu"
    "IQdQEIgfHEDqoCSSD0qRIlQ+qID/SJQBL/IhiAMqWnERKFyXJEgxGUQ9QVHRAHhgBiEJwXBRkSCv"
    "6KbDYUJMIiI7XfhH9KVTboh6EzDKOZARMAwS3FDr7AzWsIjiM0AMGD8iA64BMhAaMg6MIxckDOA6"
    "MgShKR/BN4xMMlYsyFRWpfqAaZIL34gT4wRcSa4UB13DuAGcA4LyPXDSICVaPpAiV2mu1Xzz2cV6"
    "zf3Az6oTT6jFBfzS/6LaLAEi+aQsCIKmHgcmsHQdMuZGyUhSe2gwj0jXr1wrb66VWBaYDgtnYPXN"
    "oGcr9BWeF346zhoA53ZVAVEsR1wruXqsWSI/UZNsbnYOAVqbJZh7EfUYIBJKZhLbyylFpJBsBdKn"
    "IpIwURB5EuoMmh4mUBhIKBkhZhjLMVJMuQSOT4Ighsi5rLm0IrFChAiXJK030ffI1sF1QmZMgHaL"
    "WjVKFUESrlxNauBJ2azXAdTywmK2UNTn2u7Fc7g+DRhD0MCtE3CobFIiAUFrdGqAzb5lN6ubG6yQ"
    "zz313Wcfefiedzx04g++e9XnJjQauHgBEjmSLtWWrlaqv/Bv/tPv//ff+JWPf/h/vHBeaJq0XUhr"
    "6ClwJSgCCejY4Fjo2OS00bbAd8D3QClQCqSHvhsgG6UPvoO+CwqJBTV+DkqA8kFKQgmIoAL5s9P9"
    "G/XQYdggSSoSj1SH0ocCUyi7d5Nr7CTBvQznFs+/kxV16ggB51Is0mKDHriealfg75ERMkAecBhg"
    "ehBDGOPABTIOXFOE0PYmHr2v8OBdmMg0XVb1lO15aNseKQkMlGSpmJkvZOIZb83aXm4BQ+a1odmA"
    "dhtsGzyXSGGzDq3azTdftI69Rw2eUK+/isuXoL2GfoM6hQoGgJzcRvjH0lslOSSy/bFYfHNjq7y2"
    "tFyxbDPNrn4X2muYTYOuI/IwPw+DYkDxCIik3CTwiOedTP98fXGQIWOx2dn5TH8/3vw2r636rgMx"
    "zcilU5qIpQUfUGiA6yjPJ09jaKK0feV7kEFcYW7dlWuAhKArWGAqwZjOeE3JNGCclAHUVjrjrB9A"
    "INVRVpkfVA+lA81ZAo7IgOkAEupzkMyBctB3BEPl+41mWyrluk6tXOXxAdiegeYiMBMQQPmcGobR"
    "tBpNYoJSw2A1yS7bjW0A4EJYbfvpp577oY8+0f+Flze3t5ALqJeUU0e/IRW2atWtmSu//u/+58/9"
    "m5//c6JqqQZcAChgOmoxYgJQsJgPUhIB+pKkj44FvguOhXaLrDpYLfI98FxUNqAPTAD5SEDIQBGQ"
    "BAJAFhbGEBFUtJJQCMzgO6GosBT6grCU1qkThKQJomMwrHOFzXChsNOR9SOOFYmavcXe8BQqUj0Z"
    "hFbQkY0omIwI82MhiImoz44jcmI6IGNMSAWpdPqhf/bjW7H0jZcuN+YvK8sFx8F2FdpVcG1UEqSr"
    "OPrpBB7aO/HxJ2575PDJV5adK03m+KQwrAlwg/SkT7yZ2wuvfZ2unsZkBrZmiemYmkBEIBXsLEbt"
    "ysCBQ/od95ZE1lnbtBfnmxKYMC+cPX+j5tSUI2oX4MgD1P8Ei+mkG2jEOQPGUAkNGOfKAwISnIDQ"
    "ainLUZJRoy3Xx9e31vJWdWFmXmu09dvvjU+Mpclyp881tqb1Vlxc8MSIlKbSM35qt/ATBL5SOkgP"
    "JTBKMrcu3S3pbClCKYCrBSV9ydsgOGpF1A+geTtnMe42yd1CeR6dBFfJBNkaSQLpA/lAiqQFIKGx"
    "jLU+wHHFjLbrxZ32RqNVqzdazfrSZsnJj+L1FwgkkAXUBkLUuAbbriV9fRBKqxBPkhaz3XYOXKu+"
    "7Zmp7z39/AeeeNex5s1n23OoZQkFeE3w6krPtWJFY2T0wpmXvv2Xuf1D+09tVnk6o0CRdAOJL+hy"
    "AgRADp4Ddpt8D1wbnDbZTZAeBoumSAm+A74LpFAFEhAFXCgQcwAAkYWNEgyBeDSIHyTKgYKkAt8U"
    "LsNInaJaR97v5rAUFZWjbtBeE+kkIFFNt/O+UPkJkc8IMExtg0yFMUIenCYajw76ARkAB0BkjIQB"
    "wkDBFYBuGHv/4y+fPzW98uW/Ap2DbgApcC3ybPA98BzybQBC02DVduvZxcsvvOl87tMf/uWPf3U0"
    "7l5rgScBERwXPQlMgGOhmcD4AFg18m0VKwJrAIuBMJBc8Fwh1W2f/mEvUZy+vGSvzOLWDdYuN7hu"
    "7x46feZ0bWuZ7X+QEkkFJl6dVq4NwBSGHS2AHIBASQACxkERKi8QtZhvodskorLvXZ+bbd+87i5u"
    "ejOr1v5ju97x2RG6vHr6S7xkuiVfoqdPcmfTZ30+mL6sKelK5aG/Rop5ek4ZQ4AMXctDg/Flwhyx"
    "FNdywIpKNHy17Ysmg03uLAHWkSEnpinlESKAQJDAiBQDUrBxHjwP44PbbUeDNVfFKuXKiobTJV9V"
    "zuL86wAQrWJCfqNSa1QAEA0LnDpYWdD0pjm0VasWM6CArl6/cer1cwNxAvBQVpQCAEmOYP1H5P0f"
    "r0xM+vj177/wbO4BExSnlguE6HvANWACHQd8B5UHjCtCdGzQTUABTAeuA9cJADwHgAPn4NmoJBGB"
    "kih98m1g2CkYQygbRpmA9AMgh0qRUoABNwncvory3HDbMsQd0/Ih1yFAQDPKWYMMOSq/9Wj5oe0E"
    "og8GNhBQHh4msoFJIAemhSmBMAKpBwJFKEgDGAczCchBN8ByEr/62fbFWfXUq5BgUCvvP7D30NR4"
    "QkMWJCG+5zv27Nz866fPAgnRPwik/I360Z/80bt/66f/4kadvbytbAVSQqMJpTVGirmE5SbU68xu"
    "qFaJrCqgBsoHtyVblckf+0Bjqbp56gyaguwWVNehUQarmRssuE7dchxI9Ss9xZSvpAKvHbmNSFzu"
    "7RcJyCgGQzke+BIQwffBrQIQJPuhbxLiSfD5wLvfUdyzYb34f82BLOsjSjFf+q7nYNrnCamk9GoS"
    "GsrflsiVSIC0Qa6TsMBwuJ8FKwUa4wqUrwjjqOscmtzfADkjsG7KlpKuZ3vKI5KkKMgaSZLyARRo"
    "OQA0mJ1NDn30k5/yfPdP//pvmVsj5RALI3+YdGKwkiEAIDEdtThoKfJsg9r9uT7HhY996kfabuMv"
    "/uwPhRGTUhIyQMb0DPVNUmYAc4Ps6gvx/EBjzwmQLnIOIoYEZFugKOjvImSoGwEWyffBdzqd9+R7"
    "4FroO8AQXAt9l5REtw1KkXRBSpQuSI+UAul29xmIRNKQ40ShINB6iBQEUwtRfhxOzQZNFmHKFFCg"
    "bgtDRG8AMBR2QhrT7e+5NfHlyHhElIIGHoEsEvIRCTkhZ2ExC4kbwDXgHDxi73yb1bLob77AxseK"
    "pvjdf/urH3zHvbFA2ex5ENGrr535jd/83edPvsULeS2DF//i/x2+/7bHP3TP93QunqnIRhNbbUYM"
    "hS7SaZEeZI0W1VvgeooAnDbV17z1ldSHH1le3XJOnWEHj6iNjZF8YuLQrqxGTrs6Pz/XbPgtS4KR"
    "Zpyr8saJu6fuO/5DQnDOADCotABnGG2zFuZeyIJ4S4wxxpj0Hd9taEJrufDky2/ML5V5oW/jyW86"
    "P/Se4YMPs7lXFab8iuuT9FpSy4MrEAQwAI2z5LgEn5kEChDj5OYUjoGuM2iRXwa7xiHhew3kAkhI"
    "A1GLMeEBEoGh+UprS7Jcsgk9QE9JqTySUvktkI5DskZrs3PzG1vLYK1AfBiZxpAgiG2AQFL5bohF"
    "6YK0yamDUwUgB2ClZqYz/RfOvaWn+yA9JRIJlBKYIC0O0udMU8OHWHlpQIE5drwxMCUEU0JDYUA8"
    "Ab4kpYAApESSIL3Qs9otkC5Kn6SEdgutJnFBvonKQ2QgdPQdEjp4LvgueHbQzYboEWkALnTSVhUk"
    "dhCmCsCCzWlIqaDNDkNVNMA4h7ASRRAN7CMQAotFQAfqnLqbzga/B0vgBYd1+pyDdgYBEHQ4B1Ve"
    "DpwD04KGNmI6aAZyDYQOJEEYpMdB04E4/Nrn6Hd+j83fZII/8+U/fNs9x5QipVSXggEAEGOcMZRS"
    "/czP/er/+/PPi8Fx8sg8du+nvvq7X0wI65SlnjoPVh3aLbBd5kuhgDWa1K6T4yAheA5ZTSGIf/iB"
    "+p9/nheyrG/0tz773h9/9LZMKoYMrbb9nedenhgZvnz18i/+m/9a2yr9k59++x/8j18g/ioFaX7k"
    "6jtV8iCzCRTk3hI5QIAqA2Df1tb4hz7zU69eqotcn69E8affUTzzx66rSPmeJa1tDwwCIWXT4wbE"
    "ChjP+fEEGLqKZ0gklIfIiLhGSqJqKmsbPQ/I5u1VQA/zgrOK1q4y8pSBDKVwFXNd5oPhouGS5gC6"
    "yEn50C47btv1G+ls3pdKKQHpUZ/rym2ScoMqKiEjIGI6AZDvgpRICpWHnkV+CwhRz6QTmojlK5Rg"
    "jIUroHFTQ8qQ5Mmi1q4eGBjYnjh+RhNMM0nTUfrEOCFDJkhJctvIBSCnYCNd5SPnCESeC7USuHaw"
    "tyRzW+C0ybPBaZPvgfRROiQD1y6DsjGqKBRQhxopUD4SAUgiCDfmUNG+oyRJqbDFIpBHgyEECAvP"
    "0Uhkp6mBIBxJ6Sr6vdWwYGSRhZbXyb7D7z9avyfgReE+vkG/LwfO0XfRbamGjR96gm7Oi2tXfdl+"
    "4ol3vO2eY67nCc45jxbrxehCAL7vc87/9I9++9Kli2+cuaYNj7euXbvy8qWBd902kxKstklXzoPV"
    "BuCKpIuMGXFGigvOkv2Mx7BUEeOp5uIK8zy5sfZTTzz4yx+6L4gtUkoC2Ltnl9W2f/TTH3et9r/+"
    "1z/5m7/5yDr/lyX7FQ566OlBhTVIAAQOwYhamO1EriH8GDjDBFepyeK/+N3/8hP3f+A3lJfBVq20"
    "IvvGbotduyAN08hiLKeU7/qe58c9xlksCZmsEzcdzmRMSIHIBAApDgo4YkbxHOgCZIucQXSqYFo+"
    "GtKNa8rh6DF0sdbGpkIDIMmEhzEXDVsz2oimmSLXbtutkUJSF7GNpmslChah4zu+dIkYaTohJ2GA"
    "niJkyHjoy6yKLv2E9EySHHlfNu+ZyVKpymJJ4AYyjoCCQPhu1qdcfjjfP35TuuRYSndA+j19Lhxd"
    "B6QfriMiJRCC2wbpkgJwGuQ0kSBoeVS+h8ojIEAGPKgdIXIVJqckQXoEhNIFzwIlgQIK6oPyARQq"
    "H5VU0os0/PAbCWN24PWJEaru3AAGSTBBNLHWWyQOG+HCFUdC5xfxNiURGUgfkBPjHVpGiEAMpB9O"
    "uoAHQfTxJPhETAOuoc7h+BH8v3+jDMFt+tWf+3EiYshwZ5dG58E5l1IKIX7sx3/s9Vd/Ufk++O1r"
    "X3pq/7tun9EIdh8AYYKmAdNRKQRSnuTNpiZBgEbNJugJlRn2l64xvwVO/fEju6QiJaUQnDFmmvrU"
    "5HipXG22rcmDkw99eFAlv1x23xQ8Q+HKA9QzchTmRir8jCkKx125TIIrVWXD/ft9tz+4e3/jxqUm"
    "F46cWWgfn8jbN2zHQC7QIOk3CRiQcKq+1yS7bHLCRJoxRlpC6WkPgUlH6ALiaYrFFOo+c5D7aPrM"
    "cAgQSIDvMynBAwUc9RgBY5YiB7gtzKZm1oHrRtJ0XSPlTO3rN3WjdGNVAQdFzEyipgEToMeVnqVE"
    "PzAGjIgx5DoKnayG36oKKQuCIciDu8bW6lXY3EIgROAoBONxxIRmpoQZj8c2fKwyD9t11rDIc5GQ"
    "kKMwASR4LioJwgAK9EwGjAMBCAGJLKZzSERcBChXgOC2EQiUR0qC7wV1A/Rs9OyIySMCI5IYrMVL"
    "MqrYMAAFjAdTpZ2SWbi2YFAiiLICDP8FEU7KBEWicJAxeBcLuox6Ij9RqIwqBB5aGHVmCxQQIeMA"
    "CpRHJIALQIEiRpoJwgAuQBPg+PDoozQ7I65f8pl812MP3n/PHVLK0PcDdG0XwwIeIASR9/HHHxsY"
    "G9yolVm2r/ziSXluKTY4ZMXibGo/xjjZPmeMLEvb3NL0Pt00eduS5KuW7TsuVSskbXBbgiFnQaEE"
    "gAgRTUMv5LMx05xdnZPFchvOKVCE7Z76SFdb7iZMXeH3loIJAoKlVhR7I5lvgGVDSkG17sAAx1w6"
    "0WdXLL/dBi7B4Bp6yBgAKks5Jbe16KX6faEppRzDDHrsQTeZmTB1Pc2Uhi2AJqKFmgLeaGGrrTCm"
    "p9LpTLzZlLWqV4d4Q0u3WF6aCWYKHk9LD/xWrcaJpwUfHqBaSzUtMkyfUkpkIVsU/eN6YcBtNv2t"
    "TQCkZJ48AO6orGwKI+X52ea2dFm1ruKJItd0Bpop4oLAAKlz5mlaTY+VufBIMaHLtg2SAwhwHGAW"
    "6BoiBzNGmoHAQPpgt4EUIIJtMcZRNwgZKBukIgCQCnwXyAVSHY9ImgZCEBfgueh7QBK4AADyXZQq"
    "6IENEnoE2R2X3PGlhD4KQ54SmEdQCcae7xMRgCFCMJCHQBSkAdF6I6GfC6GvCABRESACB4Koj1+E"
    "SQIB+i4BgvLAa4MwwNfQdeH4IfrDP1KaBLv1z3/2xyBKy6Ob7fCf7i0Hl9uza/Cd73z8b/7s8yxb"
    "UOWla3/7deM3fsEyON3cgqSARtN3HKxXuGEoblTLdWh6erOlt2y0JXh+2IpHsnuh0LRR1wUiuJ7T"
    "sJ0mNCUohpF3DwdRo08MIpcQ/hKV1HsUZALWZosubFs+A98G1EFyaoFXrWC+nxcNv9HQLAs99LWE"
    "Ztrcb5hJXY5MpfbtMXaNSDNHPM4ZJ7epuRXeXo5VLtvXb7rrVdSyjh9z6q24543c8zDc+fZWfmJV"
    "z0oS7ba1trqinb7MteLAux9N5+MVZK7QiZA32xvV9ca1y/WlmQZxlYj727XUocN3fvKJ3XuHfE27"
    "TLTWcLe2m96GjLW1PfuSE0OGq7zLrmw6imr1lVoDrtxMvnaWqs1YKpsxE0ngAhQaDDUdhF6TsuZ5"
    "GE9m+rNaNqFlEsSY6ymr1XZLNVVuQtMhz0MdQdeRc+SCHEd6BA4DzwOnCaAAEQWDWByVUL5LtgWO"
    "A74LUgL5gIAaRyCSPhACMkQOKJFpxAQoH8CnQKIN+3OAuvjpVMgAwrH1oEWOiVDWDPt8drS/RdVf"
    "1p246bAUJEKGgMA4MgFMQ8YAgLiGQdcD48ANYhy4AM0AoUEsTS7iu+6lzS0+MyeZ/9B9dzz2tvuV"
    "UpyxqJX1H3sgIKBSxAGe+OAH/vbzX5K2hTFef/oZ86d+FPI5as2hJ4FzbDVI052WryXExO5cX3/C"
    "Y17V96sK4EILQYHnKCkhVIZZzxUAAJSkygY0weGMyTDWsfDzo46TgOhTCuOjitKg7mg2koeNm1Bp"
    "WgjkE+pgWXZ8ZP39P54cm9ybytQb1TWrZKxeEa8+x8147PEPuLuP12RiY9Pyr23bpZon2+Q4gjOt"
    "f68x8fbYbowfWCluv5Y98+3k9Eq5f7z90799Mz11/a3V+vklaCwDcpA2yDrEc/qDtzVmL83+/TVJ"
    "SUjmIZ7AwYHVrIl7bsOpo+z0dTh9nf+Tjxz/6APi3Mw3n3mzUrbcWh2bNQSbEnH+wHFbmae+vVDd"
    "aLiVOjAAQXMZPb5nnP/ME+b8lnbyumo6bsqUggtflhy+OTk4eP/U/YeGWTax2mgtldvORtmv1qXj"
    "0WAWD4xwU+OOUhdmvYszKBXGM9JMw0hieHKwMFpUJq+2GpVG06lZVGpDxVFIeprvLabMlFHx3KrV"
    "dms1tbru3VzytrfASCEp8GwCAOVH36EC4GG1i4iAAcio9z+iOAAQVNPCjFghgOjy18ArYrRgTcfd"
    "h76NIWeB5YUZM9eQcQIMW5cBUehRD7MedPugFgOuodBI6CQEE4LuvxP+63+jmA6N1q/+wk8zhr4v"
    "OedhpQM6t3OrMQTx4MH7Tuw7OHXt2gLvG5QrK+73X8bD7yfPh0aZjY4D6lzne+8Y2jdothx7enph"
    "69JFa21DVbdZZQ2QwG1L3+ueNGoRCa6sCViYgRs23W5ISYHQKwNsu4opCqrwkSYcCm9gCOikRip0"
    "M3S+7Z6zvdpWAgQSAmzO1V58rcb5hpqZKYwhKGS2ecfx4o8cEcm+ldl6/feeVCtr4CtEhQyRcwSQ"
    "DGUs09biZUVgxOcPTPTf+x/Gd7+yeMfHV79ziZ79POQGOHjSagLTAIhVt7BRcp/8isuE6OvHVIH0"
    "FBgmm79MjuvXSpCLsXtuw1/6NI6kn/+5fwtrZSgOADegukGNLSLiUta//806T0BxhOka2E0INhqS"
    "qvHya5CIa3cd9T71cPHsqrZQJjO+sKeQenzfz759P6u7zz1z6sLL5xqzG1BvBp4bfReli6gortGu"
    "MX7kMP/A/bDaVLtH731g37v3Dy2WG1cvz67MrTXWNryNVeLIhkfpgaPvePzO+zRcujp79uJ07eai"
    "3Wopw9DuPpp67AH75kL9uy+Q46EpwFIoFEmffBsDcHOBxIGIfBeCyapAJoJgDM3vGUMLtvIjEfTI"
    "IckwrIQcKoocFLU0B9ltWBfDbnE5MBhSBAyUQvIJOHIEQFSKpI9KAvkAhPU6veNhmr7BZ2Yl2Cfu"
    "u+O973m7UoozDh1mEZEJFmUWPavIoVJysJB61zvece3s/0S/iALoG0/B5MPg2rQ8R46Nh6eSh7Lt"
    "xdXvfHvNrjSgUYXtZahtQbMEXksPiorK75hTx8yCX+NprXod/uKr9IGPsEywMa8ipVBJ3BeDlIDQ"
    "2RNFU83kA71eJguDeVggyUDili9rGbV+ijWumSItpFLgttiFl1kiJ2NJ2l4loTG73v7+NxeP3U61"
    "Ety4JnI5pengtchuEWNAPigJugm1DSCAWFJohj99auVJtvKRj8JLfw/PfpPvnpKbJcmcvAlJzfS5"
    "vuZvKMcSmbTvkl9a1KiaKgw4Nm9trkPbhkROVC118U111zVaWmWNDUjE1OKKlo8Pmqhpbtu219e2"
    "gXSR0P3qnGJuQkjBedtHr24D09FL+V+7WXruGe9jHxsdOLiyv//oxw5/AuBLf/HsyS98A1YWmaEL"
    "DX3fBbsNdoPCYRcCobPVJfnyK5RN08MPFn/ovYdAfP7f/5+bz78OG2sgGANgvs3sBiKqfP+Fbx0/"
    "tVVtnr8IjgXSZUoiY54wW5m48fBDuZ/5ZP3rz/vzi0yPAXJUPnAB0kGpIMwHZJCLEhGCD4AEHDii"
    "QiBCFXDgoJOCRDQ402kHiqS/gEchAclwBZ7AMAhCGTTQUpGHpAiQVLDchwOkSBjhpBJjEJTrGcEd"
    "++GP/gRiGtSq//IXf4pz5vuS8w6tAgBCxhDCztWe3qMuVXnf+977f/74TxyriYk8XbkMly4ik7R4"
    "FSYK5C2WfusvSqKII8OACgRDU+sDITSjstKyy1VQ5UDNvKUoHjxSiXRME6d+Uy3HlVUGr0Hggl9D"
    "jeMf/CqmdJIyCqYRTfQ5/cHfyOkZSgygAmBCxXKQSWFOwKX/rsgq+5IgU0Sdq3hK1TY0qPclB+u2"
    "3doqs3gCLr7ONeEnTb+ykh7M33nP/jsOHZiamBwo5jWBnq+WVzfOXrr20uunZ2dmQUtqBpd//Sek"
    "Ccyn5fy1D378Hb/4Uz+7d2I4bpAvcXGl/Kv/v//04tPfv/3he37+J3/5xPHD6VTW870bs3PffOr7"
    "X/jiP9SbKPqH5flTzDSAc1ae+1e/9NFPfvgnBvvSmkDHcU+fufZPf+XXF1cuffJHP/rpD33wwO5R"
    "wUSjbb114cbffeM7Tz/7IvAUbzr1P/zf05/4Ce/nfql2fuFX/+Of2BfPajEGOnlby8qvDY32H737"
    "8MTwSD6dbrXtleXNS1ev3bh5HdBkTQmf/6vSiy/+uZ6ExTmRS0hSVCopppRmgOuAkrDpbH59FoQw"
    "0llHcbCrym8D18E3QMbsL37JOXNe/Pzn2Be/QwvLqMfBs0H6YZ2LMQACKYExkhIACUW4dqwK2oRC"
    "ySfscQYMCmE9ekc3143Wqwo8MmKwfg2woPMHkXHgHJB33801QA7IgGnEOCIE81ygm2B78LaHYe9u"
    "9tu/o4S667YDrz7zRcY6/dWh+0cEy3KUonjC7OytsJMIQaXhfeCJD7/y0ik+OCklwL1PYN8+XJsm"
    "Q9Krz4pCnx/PgJ586N7bP/nosRN7BoZzCY2zUqly5q1z//N//Ld/8rP/5Kc+91nf9zljnQhASjHO"
    "X3jjuU9+7uMbF8vGUcQxkk1gCtwajB7if/63Whx8Gc5FhPYjFaR1/OX/Kl/+PamPgHIBEHgSiLPs"
    "qPovn3l0b+pzX/7Ki3/y519TRiGW8P/lz372h564P59LOI72V1/42n/673/M8mPStody8M9/5nMf"
    "/tBDk7uyAAzAC9cOAQ7AAOLNpv/d773+H37rf12+sigKgyRdub75mZ8Y/es/+SrAooS6hBYA02Hs"
    "2tzl3/kfX/r93/q9WLwB0Iqa4xMAxRs3Nn/5X/2n7z53VuQK5Hng1P7kj+/57Mf+N8CsBJfAU+Do"
    "cPDr3/uHhcXtX/rcrwHMAlQBEEADiAOkn/7ejV/8V795Y77Ec/2yUmf3v0MtTkNpU+vLeE0f6gvv"
    "fGjvT//YTzxy/519RQtggaAsoS7Brzb6zr+Of/r/nv2Hb78A8RQDAuQspvtbrVi69L7HHr7/7seL"
    "/QUl/eWljS989WuXbyyAnoPq5u7Dxnve9u5D+243DWNmfuXvnvzW3NwGY6YaHdF+/FP+7/8VEYFv"
    "ofTCYhnJoIcUgxYPChbXCFbeU6D8UBslIlBBzTg0gA4ngMgyOsVgjPLTzoRA+Gqn4z/8lAm4BlwH"
    "JsKhXsaBMeQ6JQsoQf3yZ+nP/pLP35S1rS9+/o8+8bH3e74vOI/oOBAR4+zkq28uLa9+6uMflL4M"
    "Rg4wKkkE4Ykx9l9+549+/Vd/jRcnJNchUcSpB6C6SEvXRCrl1xu794z/zr/7pR967O4fTCSazdbG"
    "xuaePZNKKuxkR4hKKc75W1ff+sRPfvzm6zNInJgCFkQvmHpM/NkzBnp2WBcIM2PyFeR1/PU/lk//"
    "U8UYSkWYg9zHYfB+9r6H6Mcm/7+23jPctuyqDhxzrrXDOeeGl0PVq6xSRSUUSiWVAgIJJIGMRAvU"
    "LSFswAILsMHtdkPbbRuM3W6bbGQakxEYoYBACVRFKZdSSSWpcq5XL4eb7wk7rDVH/1h7n3vL9v3q"
    "q/e+c887Ye+5ZhhzzDGvPICXH8b/8VM/+y9/73c+ccedv/ryW8sVfJE2ynX/XnzH//0Lf/JL//av"
    "X/CKm/76j//zZZdfnOCbdbtFah/sXOJaKPIi2z+Qq8fbV7zrH//Cn7//djfcn2dPfvHrb772yOWr"
    "zUOFu4RSgwycQraX/WsqfiM2eaZ7FHl6KeHyYn6T2It+9Cf+jz/8ow8Ll2596/nb/9tPVNXRoE87"
    "LYhASLDVQXZtIcvr4avODqow4d20KBIO5C9ZufDiN//wv7jr7sf84nLcXJW80EEeVusjl05+/d+/"
    "6wff/LPAA1v42Hrz1dpOtFiPshkwc1mxrDftww9+4s+HP/mzv7xWSbaw2F6YvOoN4//8H/75c67/"
    "/gn+rMHThMuxl9uvfv2bfunBx+/5xX/zgn/wg//PYKHZwl0Nzpc4UK++5O0//Ft3fO4RV8f4ljfL"
    "8j5+8CMYOgkNYovYdJHZWsYoANnzhUjQSOvkt7oHDaDfPcOVkvue8yYJ/4G63vqTLTokblMSdNAM"
    "c2aVL8V5uqzTgHA5nUeWYxrw3a/mZOYefdy0uvkFN/69N72OpE8Nkf7908/dX//mZz/7ube99U2a"
    "hut70Yrdtvzd3/3aX/v131zZGOvCHpuu4v6/YVu54UI4f+41r77lz37nl44c2m9kDLGjMpGAGG1h"
    "YbSwcBUTgoUecu3hncXR4vJoGYQ432mYOYLmjR5ao5u/BpKsKwIYIX7QqzTluPJn5blv0psukxcu"
    "YrNaW7MPhfLsld+x9m+vf8vNt9755dnHSz3msUjaOP/MD/zI837511Z/5d+/bv/l/+3+2V+W/lKH"
    "UlTnuqqEiCjgtS3M2uHo8J/9/k9vrp/4xF9/9ZLXNHL4nvPhocY1tZwABTCTxtBst/c5jjI9UCMX"
    "KkQFude9VXO2dI///v/3U6dPPXz733zt2HfjBO/IsUxp0vgIhCbNVntfy1WnC5nslY7Jq6JeMdis"
    "H148dOeH/vh/f8V3//xjT5xzoxEkhFPrN75w66/e97PXXvlTa+HXJ/xKpRdat2k6jqiNDrLQRjnb"
    "fOskvv7K//U7/+bZP/bmt/zBmRNnXvdjW3/8u889gu/4Rn3bjKdSslFFXLH4kX/+H5+z4h/4kRf8"
    "h8fib52u/jxRQmPE0f2XvOd3f+a2Wx++uF7KF+/GP3637D+Idibq2VZgYshF9jB9J7SKNJLcNXN6"
    "d9tdY7+r8gR2SltNCY9o7+ktEgJ1FCfpxqhKN/uiUE8aVCGuSxLUCwPo6LxkgS99AX779zHwXJ/+"
    "03/0I2WRJ4LDjvsHVXVra3z8+MlvfONbT584feUVx6KZ9s2Avj8A0m589jWv+fZvf/+fvl9GSxIb"
    "xtr5LJ49/vKX3/LRP/u14bBMyJLviBWpiweFsxjRzW32KVfvbwEMisHCYBEAqB3YJREIqToKO0/s"
    "aCWpA+nKrqByl8nL3oJbrsBBz0VR+tbZ4BS+dOPzv+3y71x7INzpsj2VrIOrwkx09czgwSMvlHDt"
    "Hzxp6+aXJnI8gXLaKWliTsAFRF2x2X5zkt//G+/5/rs+dddU44ZezOOoQSV00geldGqizBqcFqpT"
    "RwBwitLL3lk4yfzp//LbP/biW+49ieY0njrqFmMiCwD9nHkr4gyTCmOFqHr023hUR1vVk5ccWv/t"
    "3/iB737dv2aRx+1w+fNW3/uxW6898L2nqndX2UOttC0mEXVEbUx7SggBvPfIH5r93RUvfOr3//CN"
    "7/oXf/S6f9esxpWt+JMzPeWxEBEI5Kor9hieffIa/sST8d+dtE9kfgSYgs67E/WZ647+0atf59//"
    "h7WzC7ayIs+6kt96AI5CgzqCYgYIUw2QUOquYOMz+KHSjYtpN0zQlb1Jra+vbxNc3ilSzcEggaio"
    "imRwBRK9KUFHMZCBjJ36Z7GMxf1ogJe+mKfPuHu/bu3suudc94NvfZOZqfYw/C7VoVOnz25sbq+v"
    "b3zuc18EkHQEehvtXDWJMtfv+q7Xiac1M1hQ9TadHbvkwPv++Dd66+/we8zJCkSqsJ8Rceb1LAkg"
    "99losAAgsVlFM2gOeOfFEs9YkgC7REgEIhCRpn1gQHEANx3Tq0vs9eIELUKQWc14ySWzdX8Xkbcy"
    "a1g3qCqZzDDecOPxIh9snoxST7hRYyvKuvqVmK+GfBX5RtStGbcqbs6wNsHZ2k1O1V/ec+lnv//t"
    "N5+/wFVOohsHtAF1QB3QBDRBQkBoUEXMAqYVxw3GNTamPLONh7fdfcfrjx6+4sv/4N0vePBBW40I"
    "UrWo2+4V6paNgUHaFjNBFaWqMWtk1mBSY3uGC/T2WP23z3/Ft9769hfFtYv54va7fn9y04G/93j1"
    "b1ez28e8OOX5Bts1Z5DaZVEyOp/IOjGwyrPiieaJa15z5z/7zzd/8jF8dXpyxd1lyBpUQUIrbSvt"
    "jM3efHlPfuJpfEJl0KJppW2kraSiZGf5xP7rTyNSYHzyOI8eEpJ5CV/0zFB299RlklRF1PdytG6n"
    "su3Hg7WzkR6F75gS7M1CkFrNnXsRCChJuMIahBlCxVAz1EwU+cRgSv8kNqgrhJavfCk/8nEMC26s"
    "/syPv2M4LEOcQzGpSy0iYmZPHT+5cnGlnk0+8fGPAUiA0DO+VY+KvvhFL7rm2ddwvCYWQXI2++X/"
    "9xeOHbukbYPT3vHP7TwdfPaneh7/OhGy7qs75wbDdAAcXUafwedApk4j0BAtpSVasAWDIAChr4kA"
    "+FwODGQo4gASEWglBsgFu6eBtWBgmvRGQGxRXajj6im566TflODdlH58glsfOD75j1+a/OJXJr/9"
    "2PZj1TZl1qIOaFo0DaeQ/By/eOtbpxaxNjHTGLtx8RgTKYzRJGS+GvvxOBuLn0XUEU1A22A65YWZ"
    "rjzBv33z25bcWE5v05QtQpQYJGGWMYgREVl91tWrvoFOA2YBTYu2RVNjTBmc5u1v/4m9Greu+uHV"
    "lz7vppX6W2ezD08Zp1ivZDLjFDp7yprf+mb4D5+Pd5xmLTGArUiD1mn5ZHzwldc3a48tfv583JY8"
    "CFswABESxVpqzFdWiw+1ljcIAWyBALRJT0uY70Gnlrk1wWgIi+IyqKc4EQ9fQL10JahLuQzUUXwa"
    "T5fdurTAXBcIc49IaD9bwG4gTbqEFKYdo1WU4jVJu1ligQoBCYS0cJlYIFtursttt2J93T3+pNGu"
    "vvHad7ztzdEMkGiUZOIiIFV1fWP70cefXLm4Qmu/eNdnV9c29+9bjqmaAWCcUy4BHrv08K0vu+3x"
    "B+933NeuX3jZy1/41u9/Y4zRezePKNJz+XdHG7O50aegsMPwUeeKrOzm+jsdOwKBEmpYTWiXFKeR"
    "C7RgDVjXQIfzyByYGF3zsMIoyEw6PCJ9l0jNGR4/DT7AL/yFDS/F9Xv41IZ88Q4+cYc056GjyEV9"
    "8H/hv3wz8jbppwkgVE5ksvfZbT7E6hptIbaES7/qo51z9uEnZn91V8iW9A0vzl97NBNLe7ySb5O1"
    "sHnZs87ddHh46vwEe32InLfEKVBI6/kH32g/87W4d8l/7y149eUCc/33AVRWeP7Sm09c9+bFK9+4"
    "cTWvOaUfi1RDZWIGqtiKyL/+DXvor0z28Cuvcu5H5MV7rUkaQRIbUy48estycfej2295lvnI2JlY"
    "9w4tqzQC0DP60W9BQWCkzyBORBACixKaiTgAdIpo0jGl0+ft4Zs+0d/hOPdbajzQmUmX2e4kCWlR"
    "aQC0w/67zoBIgkFTemVAooizFnPISmrfkQaELV51G9/3YZQZz2/+zC/8zMLCaDqrnWpaBWw94zKa"
    "nTpz9tTps+PJWGinTp/8yle+8obXvy5G0yScCPRFOmBcGGS3vPTW9733j+N0gmb93T/6v6lqCGFu"
    "2AnbEZG2DSdOnj15+kxZFNc/+1l7lhdCNJl3GjoldgLQ7qj06ryigAEeWjeITb8LVHsuVSBmYJwv"
    "SFehIkS03Nn5nJLDlAZnnhEgJCdn4r75aESFC+/lR0q782Z35lOtfQw4D/SzKl+aYOXvyWGRhuwh"
    "W6nRxqVGFVubKZIg9iUSgdLLw5P6P/5CmNwjOIJHXtoMfya+bH/WtBBJ01MajFV27qarsrUVRFjL"
    "buI/KVWPvH7lfPyDn4tyEU8dslOndc+P2fMW0ERonzaGCCuPX/u2el+5qFKv42zGwiQQjMZhxs/f"
    "y4f+NZ0AR7CyHO8+5W7aj06yASBkFbPrrsTffUWmZJbmTvtEvJ/hTedBQGov+2ZGCs5fTEtoDHkB"
    "KgHEWmItMQCkahptgUUh+sGAKDYXU0lE/e7W7FqUDUBUegVRdghJnzN1CRb6kXnt2sFdiMlF+xWB"
    "4uAcncN4qi99oY0neu89VuDyZ136w2///hAiIJZgqZQvgarS1M2FiysbG1uz6YRsVfWO2+94w+tf"
    "F2OESybUNaWdEwKZlxuue/YVV135+MP3X3rZ1a9//Xd1kwzsE5pEcDX7wpe//pGP3nHm3LnptHr+"
    "857z7nf90KEDe1IOJsklinRbCrpLn/5LJ0EBEScBrC0Vm10KCSJCGrDtD4AAgWjIsNNf6D6KF0yE"
    "XzqBJ05LUeKKA9gY8L5PAxCsyfpv2PqCHR0NXvCSa2583pWHDu6NMaydq06Gi3n9YJNvBe5iI9Ka"
    "nFSdTNkgtuyA6vRuXrC9idntcCuU09ys5AtvsOe/LM5BDoIUmWJy9Bjv3UCN2CZ+TOKRGXOx2QnK"
    "7dACHNvGw3zgrNzwbAs77X9G6Azbexbqst6/gYdriKUtN0QgInjuc9CpOA+cAi7RMqrCKpp0fhZj"
    "YO/h1m3JRs1RJm1PqOrU9/sRJJUYnKwFBMpQMBDcF+Ln7nDwYAQOHpbJDBbQBMYgoWYMqdjtlRUj"
    "+mmYnsRonY5c/3a+v3f9QSC7VoA49HBJXwAroExjX4Rolyp07DcR+KKTAMoKyYd0C/i+N/P336s5"
    "bO3cP/q5dy0tL26PZ96pWcc5khghQkobwvHjp+5/4OGnnnoYsQHw8Y9/5Bf/7S8WubduhQ4oVAjZ"
    "8WQvP3bkxue88PGHv/GSFz5v3769bRtEpAe8hITzevbsxc9+9q57v3XvyVPHV8+f/szfffTqK4/+"
    "yDt/sK4b0U7PQrrONwg47+aRZl47Q9EAFeES0NWLExvFA003fm2ktJSUsAptPjDghJXjn9yFO/4S"
    "8Wx0JZauF4VtfwK5800MN1yz+E9++s0vedPR4vCFiK0GZxvMcgxHuOHp9tTE1rXrtHSsk+ABldmM"
    "LdiAio4/m4owJ+IMbYRuAMd54RwnsGzOW4EQmMJG+212AVOwATQla4IIVkDhlS6yBk8gnMTGNmZd"
    "ftRxp6KxQRzmyri9ic1AgXQVIFW2o/3o977ph2691vy2irpSDlzmL4b3NzjvIJYQGIMuBRjXJzi0"
    "FzV3wstcqjZ3PDGTD30aJ05DRlw+xKWr+MSHirOfXpLljLOI/YfxxBPiBe2MoWZoAZqZpPGxTkfR"
    "OuSnW8SQZoj7HZfcpQohnQeUTvqhS5a6OYB5J6BHJFUAqkKU4uAL8bmQnbStL1lFve0Wbs30W9+y"
    "gR2+/NJ/8M63NW0AEM1650iRtB8Hg7K49ZZvu/zSQ3X148nsnHMxBjNnSVtjThYSqkKBwweWbrzx"
    "po9AbrzpOgAhtM556zbMm0BisFNnzp44efrkieNPPnYvGI3xxFOPAYgx9jaVgACCMJokYtIzxJHE"
    "wApWG7yIpHUNCaAkHRh6VgWJQDZkmA/QAARLz2+c5p1/Ct5LXQEbbH2Ltgaelgbh7//k8/7Nr7z1"
    "dPHph+P7mrZJ/osBFLgcuYhSewXKFJOtFYGibtB0ByD9quN5m6q4PgFbYZywBY3GDs4jgRpCz3om"
    "FRh6yRoAMQ1QlYIcNoPUiBswRSu9E4UBYkADwmlobApruUOJBUjT9orbccUnE3/GwLXIwCiJrd91"
    "dqz2qGYYV2iFTb+9pXfN8IILUX7zPXz8dsuPwh2Ti2ts/nxQ/8VBGQ4gDosjKRf44L1k22uWaCcL"
    "AM4lov+7IkBEseObiG4oPn2kXZMd3QcRTZzn1JFlV0GriFI8E5XAZaJeQFjs4kCCQQm+8uX2J3/m"
    "SxfWV9/9T//54cMHNzbHzukO7ClCWjd0Q73humfddMO12PUzm9VhXgSTImJdFFOhLYwGV19xrBju"
    "P3bJUQDRutwKXbkpIqiqanV19eSJR8yaLBsxTMsiT4dQOsNPzl6j0WzOkd4FIQGtYQbWJqFjkkOl"
    "U9nIdiWQkpRhidDxTQhBUuu470HUn6I+AYsKAMct1T/f947L/tVvveHzza+Op2ulEyc+xVufUz1p"
    "0nbjHTvUpWisAIg0MR2A5BPSdYEA5hJ6JgDRMIMKkGbItI/xGaQiqjFqoFedFRKWjlNG51NpQRgG"
    "JQSogF1bXNAAbcNphQpsCUNfM0pS66piYOplW+dItD8kEslScGoNK0/BRBqy6fDFZIM040Iht3+c"
    "j/8nyxZh52H3oz6d2YUFWc5YlBKA59+K9U1MxjJYQDMFAGk0kCBC3Q9+pLqhs3WwBx7nj3S6QHOi"
    "QVcB7L797P63iwcMICmxUF2SMaLzgMJ5UJCV3Brj1pdyY1PuuTsO9cBlh//hj7y9blqZb73mTkRP"
    "D4QYq6Yhbbd4r/NOOnpSn34KYSJkE23g88suPbS85+DC0h4krNPYr+gEQSciolVV1dUM0CS1nUbP"
    "jOmZSURA0nxwnJPGU7zrE0BTTMDKkMorkV4V0kQ7oXsAoKAhakMA55eNgIFnHwMeRSqUQRVVkkcu"
    "13/2Gy/5VPWeilu59023ABl5ZlOHyiRzLBK3pb8lJFtBLRBlG7UCa9L1kHa6v+LEZw4QlUCvlx60"
    "AsUWm6wHvQhk4FbD8QR177XTDUn5gXjkmatUFWY5r16mwtWMrgeVjWiA7W0ZN6gTQLkT8wBK5sVl"
    "NGW3/E6Fxs7FKpzJhuITf8Xx04gZK0NFaJJrQOedZ+Ddf0S5KOEiCAdk0FIWMzoV9SgX5YXfjjvf"
    "jzyHmaSMPQ2f0KAZxMECaKKRSVQ0qU/Pq6UeKPS76AA78HhvQkleokuEpeeNostHUrdYO4AotvAl"
    "XCEuhzby8lv4wb90pQvrqz/+k//k6NFDa+tbHUY5v1D96/UFHnsFFuzG7zuwXrqTGlOxazRmV15+"
    "6eLCKHZ5XV9YpN3NBud9UeTszkIG8bteuiuG2INg0WwuM5Ni6M7nVFTALDLByNK3RtPd3TkAREtU"
    "RNslFQIYTAzSrKQD7UAHEVWJ7ez7f/pZ032Pr21tDbJsZjFll5nyK2fx+bsxuYDM6VveoJcfCs1c"
    "A4rihY2DOGla1kBDKLrpZQLB4D3apgXKYB6D5o03Xl3bWo2KpqICwogCOL+O8QQNes+YUmBIiFxY"
    "dnANLUbgkpvw6sPfdry5PyAGdq7QiAl47jxrJ7NeqKSDBihe+eSGXKxdBNqYUCp2yugCizIzPPJ1"
    "u/dXWDyXVZAZpY6c6yuQUGUzk60HQHHiPJCJ8/QlXIl8yGmlr387Vs5yZRVFIUm2lS3mJW+XMTBt"
    "VhcFTeF2+D/9PACAfii+K/l2vDz7/dToA8Q8qxWosGNEU2CEdj22NBM8HssLnmuTqXzzq3GU7z28"
    "78d/9IdmVZtaXXPX2L8adsAp6X8zr9q7yq0vPLpNIN0BrWb1pZcePXL08OraOoBoiabfvYKZQfLD"
    "hw6VRSES4QZwmYYOTTFLiuB9+kvEaGbWdQn6t0sRk8CMqAwamfoWCqQJbG+cb0pnRBUxiwhpUDJ5"
    "CnZlFyDQDPAisGAykKvf0DxhJyhSWQRAZeHwxLq891c5/lvDDCht7ZXZoSOoY0dQNMADrUAETZAK"
    "VpFq3ZcQIDR2aFS85Y1X/fnvPZIP8c/+9Xe84PJjn5q8N1dXg13HxmQGPvkQ4xR1d8kFXQbFtube"
    "Pfrz/+K2P/iV4+Vlk3//T74nyOnV0AzVWR+xhdgGzjwktg+bgFBonZ80w7DAk9/gn73HBleQOZ1A"
    "BZoJhTYTnNf6uLX3GBbpL0ETkHp1ndx455LgKvhaQQ8toAW9R1YiG2Bay0vegsOX8DN/KUt7MZuA"
    "NWIgk/oQIU5UaC1cpjSokSpqMO3l4tIGy87VzovgeVNUJPWckrFhTqdJIcOB/bB855YpYrQIr2Bk"
    "qKSp5Hu/E+/9gCt8WDv/Qz/7E5ddfsnFlQ3vXV+hom867Mqy0LcE+kjErurinILWfYy+oqnrds+e"
    "xZtuvP70mbPpo1uX4XWvWtf1sUsPX3f9DR8jMxWXjarqYuKfmlHVkusUgYHO5geAuxTFAIAODVEZ"
    "nABdE6TbV69RQjdjLEbODIUh9PPyEIGhAOAAeGgGKBRsZOEKN770TKjbRjq9Jpog5yOPcvLndOdA"
    "wB8VN7BpYGMpNgpBL2gICEJADdQGnav5gaCea5uf/i+3/YMf/4eLy37Ptet3zn7DRJreyaSa/yLw"
    "2Bc5PIi6E8mUeVUI6LlZ/Zx/svW+H3pHMSzO+a99ffapQl3VuQaJoBesTHD2m+Zv0HNTOShsLS18"
    "FJB1zZc+N//kY/XKl1AsuibNyUVYhbgW0fTX6wr4RbSKylgzwUiSJrAIjqBeFcjgcvgBfC5Gaby+"
    "/ofk2TeHj7xXQ422RjOVZsp21isoht7nzAt77dyiGKi9k+1/2YnjCoBeMB09S2JXcQWIMEIUFqBe"
    "zIAo4iAkFNIJQMB5TCbyypcSKvd8Iy644Z6Fd7/r78+qRoBO9Iop19yBNaR3uH1LdjcA1TnhXjBr"
    "V2IiiNEAvOhFL7j9k3fUdSspO03oUqor6nY0HLzz7W/92Ec+/MgDX2ub9auuuvZNb3rj5vZEBGaE"
    "iJil6Es1M7OUTqV8UTuGGTPUZBXhOtBUtMPJRMi6ndfMUkGmxgD2FBMydj02wEFdtxgU9Ht1y7Wx"
    "YdidbwIHSJ7r8JyotjTyk9pitxSRAJwg8VJDwxpsLDUs+qxLaNE+E3//4IsuYdAL26ecQrpVPBDQ"
    "TMoMj63gwl286m1SQXxX+fZy4zAB7t2696HBvYhoWpQqdUoZhBCJhmKIe7+IyX3IDvGp07p4GdvY"
    "15FAW2lxEP/vL7/q537gGxfPb/U3jABues3yO37gNRefCP/1v9w+bmtfShDMiIYAmRqPAgZi4EQz"
    "D+TIcvGllAfkym+T170eUsUPv1eaGdopmwox0EwAxLqj/XZKWMZuuwyY5ERJwLr9kM8ogjvvunuI"
    "XvrSUzvVg9QESFPwNHZbvRTq4YpuRMZlyEp44xu/h3/6QS19XF975z96+3XXXXP2/GrmvRn70YIe"
    "qgcBcapmZjTO9Ux33Lmoiqpqv39A5rGAgGA6nb30lhe9//0fPHX63MED+9vQcl7BkADWN7afc+O1"
    "7/+LP/293/2d5YXRu971rgOHDm9ubrm0o2nORiLNLIZ5XTC/ZwRARW2ojGodH1A78Ig09J1gElIZ"
    "s7QEupeeQKRQmHKmXVhf3XBlSp8hJMMkFTLZslc8/6rt/3X4t3/92IFDo5/+xVfkiw88uPVk4TSN"
    "9yV6fgDFSRNYpQiwkxWCTPdMT22dUYEX33bqhB2Mz0gb4Ot/Cx4HlqSOiKnO6melOrepGgIgUJWq"
    "k19O34bOcFHw9Q8CWwgrfPABXnap5DbHWURETmw2N3/X2ge+9o/vfP/j37r3UcvrK55/8OWvftYl"
    "z8tOZQ9dhvEvvPqy/+ufPmlCAo2hStu1rQucraHOzeUOkoso91zBW98hz7rKHrkLd38OToSRbY12"
    "htgkoho0o7VgRIxdCwzYGQYAu4ZAsn7unAGPucnMFZ3R8Q6esW2vJ9NRnaSNL1D4XFwG8clZcnuM"
    "l76Ek5Z3f8UW86Ff+pmfetd4UpGMFvv6vrNyVbRN+OuP33H27IXFxUV1HlDnnPdZlmcQNCHUs9na"
    "ysrVVx57y5u+K8aA+Sq0Lj7IZDp71jVX792zdPdXv/Z9b35T3dTogKbuhsaI8xdWr73myt/89V9N"
    "52F9Y9Op65P9eVLFYGZpT9vuMrzLE1kTMxPH1AWbh6duz0P3OoLaxEeaoG8Y9JLdaW40dRJpEKku"
    "8tw52XsF2pZzQClS79OLb/+D7/3hk28s9zQnD3zzy+tPq+gsob8CCNKKFXEIhoqoCU3ukz1sldAu"
    "UQUCrKcDA0QEco8HTsr9v2YQWCG1wYy7kkvpaTS2K1GldSglaMgK+dKXePa/QTLIDE/fwwdv1hsP"
    "M4Yeg4AJ9Gur9z1x7Mkb/+XLXoqbFJxg/HR912cvPjQTBMXNb8i/7Yv6tXOBojVZW4qqnX00RA1q"
    "4eBzqMPNL5S4xk98FvVURkPUU4QIcfBlF9gsdCkgd924eUuXc7Dbdq5Fd2DpE+gzVztIiUha3S7q"
    "ukQIaTKjWxDBVOy6DBCxAAE75cPAV9/Gv/k7nyGsnH3HT/z96667+uTpC967nk6641tVdX1j6667"
    "vnLnnZ/K8zwvBlmee59leZHnhaojzGLYWF+77Nilr/2OV44GuVn/IonKI2LRnHMvftELP/ihD77x"
    "e95Adhs2042zLgvh6uq6mZHivXNOLWmp7mCVIJMsaf8JOzBKuquYoQEqg+s6UXMsWLq41blN1KAj"
    "rMPUAQgNYqkGmOOEKpnyvB5/0C67MhnXvM3ESTP+QPPnB4762IatFeQiIdHhkVZDMOWd8IiQ2ljb"
    "Du8ieS8VocFATeJmPbVXgNzh6ah3/HKs7yEKREMdu430KfB3kSItAiVpMIh1TQU6Ec3kaydw9/9J"
    "rAAO0qI5xfu+gj3fqfvzmGZxUxml4lank9u374CkpeBQh8yLmmbkcTZLL5X4R1IHBkHVvUO6c9KQ"
    "MxHNtCsALjuMR5+EBRmNmFSje6NnkiNJQUCcKLhzH/u0MtGgRECdc+D6G520QTsr789GEvgU19VV"
    "XYWVzMkhTdpTYRECakYRyQpQ5NgxBi9f/0p0cbg4+Mfv/pHtSSWCxMDssZIuXw4hnjp9lqL79x88"
    "9fTDWxvnOmCl/2hdsQI8+ZC/74Efe+XLb5lOpmmSi9aZCwSTyfQ7X/sdv/We93z605959atfMZlM"
    "+xGwDrAgoYkWiw4/ZZcg9SATGElNS5d3xIJkXk4hRyAqwrFPNtihgbJzaghFAxEidsdPBAzJgrpd"
    "hB10Bq+Y+lOfbZ98mVw+kNj2XYoUZ002t4P3qiJRzSitEUpjwvTgBH4o0dBA6tT9krlnECfUDBIl"
    "WEp6oSqqiMAj2/qFPw1rv9P1XSmsDcE6JKDDWUVCRKsYFb3kOAQKQrcCHjrOb/w8mrsEThhpp4jr"
    "sXmffWXZvfBFure0ei47BiPEqROBCVNWPgMTPheDbGawFTStBKDq0+PUwqwNNeBKTRtyORygyKWa"
    "whwsoq3RzDTWTJq4jKT1eS/gfDJOYYRJ34mQntsmna9K8paUHVGbnp0jneYW5s9mkoPlfBGY+mRe"
    "fU7vQEPd8PAR3vuwq7diW73me779phuvPXn6gnOaslDOo5SICqbT6dlzF82Q50U12wYg4oB8Lrub"
    "nu2chjD+zKc/9apXvtzMVHod0r6sq+v6yKHDR44c+3e/9Es33vS+hYXSou1gAP1zE8vK2A3i7DQB"
    "jL0ehnWTbl16pezoTyIeNVBB/DzEMhEfkO2KaqLSAIGdUGUKt9HgCWbo0ki47ptJXt3Z3PtK8y91"
    "Bxdi29IsYSDpXKrSJJPT53V5aIMhQuguoJJq0hrMpDLW1kd7AECWcW2Mh+6VYzfovmUMPEBUARvr"
    "OH6ST3wijt9DaRUglPSo08dDr65JcR5bM/zdB+SSF2LfURRehGxqrG3JyUftwu+Kfc7BSeKacDWG"
    "B5EdxMV74l2N3vwCd2SvWWA0UGCAMXb7tMDOXQgUnM7cU58mZmwNM2BKaF9FEKgNtTIbKuA7VZ+m"
    "wnQTbTp2AbHt6G4WJOUj87TeYq99K12l2uGJRovYQag78969IWZ+d43o6FzdPEHyDOiQuG7MHsKE"
    "CzkIhbGBZLi4KuUATbjhuhtjsBBiEl/YYSn36fnG5nh1fTNEq+pJU88EGenEFUzUurndChCqz3/2"
    "s1ubP6uazjG6bBHdMPt4Orvs8qs/9P4/+E+/8qv/18//fJlr7LJ5m59hAkbLMr+1PT5z5tx1z35W"
    "DKH/QCn4UlSd68hwlLT8BoA2OdcNNdH2KUJ6xWgoktawCCgxctJKRgRL1xuULlJW6dJ2G78FBpRm"
    "j2YbH5rdDXnWzXrkKBxT6Zwo14iipy/gW/+JN/6Iv/p5FisShKJ1OP2kTO8xvFZqw2yH2ggQ0VB7"
    "uf9X+OAVYeFlOtgr4lFVnJ3m7C7j34hMHVRhES6hWwgJBbLuS0kLG8r4S/z65628WTCE5ERA8wjj"
    "34icyZDnQqEKzMAm3N80+1C8ApuP2pc35PKb5PIrMSjAyEgkGmpXWAqoEgVbIk/9Cc//CeVFWN0Q"
    "Ocg6+Sl2ZWJDbDlrSoHL4BSxRbvNagI6WMsYu2LdrJd4SLEjSmK/pXSuS3goNOvGWhLcmS7WvBHW"
    "d4I7zzcfRO3wDgWUIqqugwLS7LxmAu104CBQL6qEhx/SF3CTR594an2rSohPqsbnwH6W+el0urq+"
    "0TRtiPHi+RMA4AYQT593SnLSDeWYRRjuv//BRx559PnPu2k2m+3M7IOqGqOdPnvO5cWBw1f93u/8"
    "ZlkM/+E//NEDe0finFFSXSsiqpJETz/84Y9Op7Nve8HzNjc2JEkydsQ729zezvIcUKh28wAqgNu4"
    "IBenEMc4L4HSZ3Bcnch4I0VIqR8LJx6QS25QaAdnmKKe4cST2HwUgIfLIDkEoBMBQxE/0Yz32b3r"
    "euKI7r+Uo2W4TIyoKqw8hYufMPsknnoeJxlGi1Cn9YRb27L6p8TjjEPWERV750JC0ESJOf2U1We4"
    "sRG3RoADVoQPgE85wsM5wASENxaojEpY3GkTIMItSCkcfxnxPJHRGuCM2gkvlnOQQzLO/WjwCFJ/"
    "riUtexXjKh77Ep9+FAcul32HZbjYkRKEEgLqmpOprF7Ayl+x/a+Gfcj24MlHsFLKocPwvotiaf79"
    "/nM48USJ4YB5geEI7ViaCVwBUizM8RxJm2NSTdjVOgnTDR0Sl3CpVL+zL7O71QHpAPTWj2dIf2IO"
    "KnS4vFn3l45TCKiCUVL2FQgnMhnj0BEzyrC88+9u//QXfuCVL/s2C5WKY3cSAGJja+uJp06OJ1Wk"
    "G4+31y+eFh3BD5ANZLiMhf3IRt2cWD3h9gXnstnmqQ/+5V/fdPPNKnDe982BuD2enDh17tHHnsyL"
    "0WBQWgy/+Wv/7uTp0+/4oXdec8XRpcVRnueqYmaz6fTiyuqTT5+989NfyryeOnNxcehVxQwxxq3x"
    "5PTZ82dWN1dXNgAVl1Md1EMMRZx92Z+9NyweUT+kpokYIUyqbUzOoXki9dUcTuDsB7nxXSgGoiUo"
    "iNucrQFm7ac9spJZIZojIdNpiGlq4c+m7kxceTZXBuIGoiVNJIyJx8DbiXXM7orHNyFp8GgLfJxy"
    "B6CIJWYms667LikTcoAWUAc8KTyLaEQQRge4tGUZEGFAJDSmCEDr4cd+C2MucAKekXAmjQA5wKMs"
    "kJdwhYgDCefQNtAcziM0zeeqcLLxt9FdKfUWnn7Cns6RjcQPIA5QxBZhHc0jhi8Qj0EAZNABpsdt"
    "46KcO4xyv+gA6mAOVWmT31sOjy3L0QH8Aezbj5XzsAYBXbGauG5MFMzUPk36/uykUJKh9gv2II4w"
    "IErK29P5EYDwyZntwkITyqeSGJ2I0mMpSABohy+2QoMonUA8KKIO557AoRvovWSj8Vb1z37u//7p"
    "d7/r5ufc7BS0hjSLNh5XZy5sNK35zG/N7KH7vmoGKReYD7BwhG2L9VMY7IVbYjWBEwz22izKwtE/"
    "/sM/2bPvyKu//VW0CrQYbTpr17em42mzsdleWFk5f/ZJEQe4D7//Dx988IFXvfb7rnv2s/fvW3Kq"
    "FttZ3WxP2tPn1gPc3Z+//df/85Xf/h2vY6wI1E2YVu3GdvX0iae++JlPIRvRF+J8IkvIgtgTC7OP"
    "tLNvj9iAE4GQCgYjJPNo7wXgoYro7MM2YZgsAjnoIQ1EYPeQ9w9leUA/RJZ3jQNrkJLDqYaPztyh"
    "gCssLptlYtFwHnhSuC2A8CMiD0bmYAvZBs4mzj60xMw4IWDSlTECiRh48UNCgNrRFD5H4eEcxEMU"
    "FkmRlnAtPGpKtH5dXsI9I0cq2QIgiiyH5PAFfC6+RD6EOOQjFENsnEe5F9UWrEQzhfP2VNUer8Ox"
    "KFdSD4FLaH2asQcmxAXgKeCkChxTKns6huNsFyljzs7JxIMFZS/MC+7YK5+6DPsXgQxHj0ic8PgT"
    "GAxRN31Ojx7dZ4fOQ0CTDt/jDvzf5799gtMnWj3aItAhhB3lQQTQxG/oM0uZNwFEBJ0MVlqO5OBc"
    "1yxLu69nm3zRD3C8gbMPinPcXJFm+3nPfe51z3/53oOX5nmpKk0b2mAW68n6ua9/4SOP3f91yfey"
    "GKEYYc81WD+H1QeAKSB+6RI5+ux2eCnO3Cei3F7VdvuV3/6Ga25+ic+LLmckp9ubjz345W9+5Y56"
    "NhUZJCqIhbHPB1dc85wrrrl5/6FLFxYW1cnW5voTD9/zyL13TcbbRTF4ySu/59Irrs/yAclZNV05"
    "e/z+r396dWVVlo6wWJCspMtgQazFZBOyqm/ZdpdE1F1hYRGaSbxX7PZuBTIgCFEGNY62GBAKicI1"
    "5bmhLO3DYInloiwd4ZkHZeEgvLKeINRSb7OZYFojplmadGcUcEi0fkM3Mj6/JUKWvOmjevgF2Bqz"
    "awX3Ocz+A+7rPxhXP6JSFJQcvkSWd9W8KEMLa2Ra8dD2kd+wG78D9RT9sKAACIH7jrnjP8/HfjnX"
    "0ZBuwGIoWUlXyGBZDl/NhT345id44QJueq20G9w8g9ii2kas0Taoq07ZriQyQIgAVAJTwMPn6JYz"
    "GCzAWjkUeYBSQjKIVzYlTy9yfFgO7uFoj9YZvv+tfOLT/Is/lIUD7IifvtOr7dJ6xRy1TQfAYme6"
    "ZK8GF7vvl7qfjCCTSFYiw821Qbuz0pHbuniT/qkQIpY2B/TyEkmHSCBUgPAFHvksXv7DmKyx3pKl"
    "vZzIN+/+4jfv/szynv2L+w6pz0izGOrJ1sbFk6ENUh5iPkBRyugwD16L6SaKg9JsiG/0yhuMkH1H"
    "GFpunxMR2+ZnPvmBL3/hk4vL+8SpWQhVNdlebZsJUIhfpmRwSkCyYWjrJx762hMPfdlnhfeFWWjq"
    "KUAgEx3Vdfj8He/LssL5gmRoqxhbYCSLh1COpBixXFJGZgNU2wA5ZvxD4d5t5Ja+KwLiGDIbYThM"
    "G366artp8PhMEAgSDn4ge5YxWOZgQcolHr5+0c5avT058GKZXsB0k+VQppvMK8QGbYMYAIi6HdFV"
    "BSwiNOj0uAzB4GrJWBMTo0s7GgABG8NBJ4sjt4pCigX6gWQF1GOwJK5ANUY9ZhBohFPksYVMCIDW"
    "UwEa437TpVKAAQZLUi7LwgGM9sj+y7i0H80UX/0Qzj2BwWXY3uLNr8bZ+3H+MRQjtBXqiRQztjVC"
    "kCaySkPICifIs7Q4dScziQGx4YUGFwITpRIjlMuytCiHljDcJ9mI1zyXlyzLr/8FsiHbWTJCaCI8"
    "SzeVhQhKUn3DPL2hAEZG2THpbkaj68d3Vm0e8x5MXwmn+nfeE8cOYWd+qhowyUN0vBiKIDRQJ+un"
    "8PCdfP734JsfT6008TlnG5vr65urp3epS3n4BRktsliUwaKY8qbXQkc48yDEk5RiuT13grMtbE9w"
    "yztx3x10KgLJh9V0ozpzEmmWAx5SSH6ALqMfwLk0qk+XSUkJy2xnIdShCoCKXxL1TLqlNNhCG6p2"
    "FiECHUo5QD7iaI/4XA5ey2pix++Sl74T5x6mz+AyFJltl1ib7jjjIue+BeSLIkILcBkAWItQs21A"
    "wnkUIwyWMFgWCK6/Vc6d0GHm8ign78Vtb+PmKTn9qLgCYUYLiEFiy67E6bJbOA8jqgnahoLkOOGD"
    "K60yTADPjpjkgG3Sq9u3xx3HUIZLmi9i+QiW9rMNPHU/pmPsOYKpwbdQlYy1SWWCBKAQItIQLcQN"
    "HWQooz1cvpQLh+ALrJ/Tx7+Si0ixNMuWEBqZrHLlAl74Zll7jI9+FeN1lEtsZ4g1YssYkHSYVSEO"
    "6pH2IJmJz5nIXWGG0MAiSMkKlgtSjlAssFwWN5Aj1/KNr8Wv/Tin28gWYRHikDq2ndxn6lF0woS7"
    "SD7oFrr1LW5AeomsbldSl/SlVYfSY0Nd3ABJ66vpeaeR7PZL9t2crnIKFKAN3Qlzigduhwhe8EY8"
    "eTfXT0E8fSbFApoZYuigSefhMroc+UjcEK/4Pj77lfjMB1BNECpIZL2NagvqcfwuOXAJXvE2fO2j"
    "yIcc1jLag9kYYdYtY4PSOfEFXSmLB5GXqLYxG1MIa9HWkkakrQXEklyMuC4pNCJtZlZlVqAYSbYg"
    "l1/LS56LO/4Ek3NcP4WbXotH74LzKAYol9BMJNakQb3kJfIRfMlyJIM9oGB8kc0EkG6jrcuQj5AP"
    "MFrGTbfw/El/30frIwcUyKYr7affK6/6Qdx2E889KeefxmwMi4htp99dlpqP4AubjTHeQDVGPWV3"
    "DStkdWPWKCpBN+kCQMQyOWFhrA5SsiixfJQrZ/j0t1yYxumaHHwOF/ai3abLQW0N51ehIyR82SBU"
    "CPTRjWbzzDLKPXQZ91+O4/fgqXu0XNDhUshKEXFLe+LmJjZPy5NfRmxw6xvk+a/Ek9/iY9+U9XMI"
    "NaxFbGGx01oWEXXMBjLaj2Ig400MlrF9EbN1xhZIXeICWcF8KPlIhvvk2m/Djdfwt/93PHA3siWx"
    "Fh1E6YBU5moCyfvOifRdhK6t0zlsdg2jFBm6Gay5qyc6LhDIuZ3PKyIw/ZHKA+vUA3oAVcx6kYt0"
    "5ExIBpO8xL1/hfWncMs7cPQ6nn0YG2dRj9lUSNvVQYiHyyQfYM8xvui7ecVz8NlPyONf5drTCKtA"
    "zTahsDW05Nc+AOf0tnfy9KO4+BS2LmC8hmaG2KaWsGSlLOzDpdexIe77hFz5XF77LGxfwOYZVmPE"
    "gBhhQQDJB1jc7wYLrKecbTFGNLXQ4HMUQ9l3FFfeyOWj/PzfYPVRkYL3vA/FELf8L7jwkFx4EpMt"
    "VmO2s+SxJCswWuYlV0m+B597L5eP4YZXI2wiNkJ25PPRIvZdysEI931BPvenNsiaM2eRhqY2HrcP"
    "/kfc8DLc8FLceBtcEJBiaBvULcYTfuNzOHwtbn41Ns9xc0VOP45qjGZMCkyPP22ukPyQ0DNNLVEQ"
    "tuXxR9r2iRLDIV3B5SPaTIqwqoOjsxMb9AMs7MX2RQwjtorq5HRSUQsURztJS2sRzJo1aT65F/sX"
    "4Aa49FJsPyJPi3kfpxvpVgtEHNmscnUqsw1ePIWbXokbX4BLbsJsFZM1TDcx2UY9EwhdJr5AMYII"
    "V07g0a9zfRXPe708/0WYrGC6JqFBWg9cDGX5gBw4xuUlnrmPv/TPceEk/Aih7mRqhWDXz4JmHR83"
    "bczu/LHO2/dIIhQpa4ICTGIkspMPdaez7I6DQES6scwuIEhHLgRSEcyu69jXC+g7YyAsdv0+GkQk"
    "TuhL3PzduOZlyBelnmG2jbamBZAiDoMFDvZKNuJ4gofvlnPf4vQk4kafJu2iJIgDGxy9Xl7+ozh2"
    "PaoJtlcwG6OpEUl1Uo7gclw8xW9+EusPAZVc9kJe+yo5eLn4jDGyqcVaiKMfyHQi99/JK67D5c8D"
    "0vxohM/gM4SIU4/z/ruw9hAwRhdEiatuw8t/APsPoA2YbUs9hQB5jiwHDedO8q6PYe1+ADhwI571"
    "Ehw9Jgt7kLZozrZx7gQe+QpWH4bLmVZxihKECiIRW8gQy5dg7yEMF5F5zMZYPY+1U2IbzA5j6RJk"
    "XjZPshzIs27lhUfRzrB6wf/Uqj3fHNXtSa0zGGEjuPMy+5lLbHhUBkt4wavlsc/LQ3ezGHBtlUee"
    "Ly+4jU9/S6ptXDin152WNwTLgCJpZEIXIYD97n57+phcckiKI/a9b8Af/ys8+RjcYJ5gCNhRjmGQ"
    "HH4Z+X4ZHcGBK3DwGA4c4tKoUxyNgbNtrJ/F+cdx6j6sPAUUUh5GuZ9HrsOx67BvL0YDKUrxGY3S"
    "Tnn+MX7rb/D0fQBESzJ2xS7Ri/FoZxWqHdup6853rnjeF09Zf5e+z3Whe9Z/SpYFUspOE7i3vOR/"
    "u4ekKwx6oVZ03b2UilnXSe/nzbrmqqgwMKXLB5+FA9fI8CCzAdIimdhyNsHmBayfwWwNmIHVbqJS"
    "YhzPP4CowmoC2HMljl6PpUOSDWhEXaMey/Y6105h+zQwSybbfaPyAPZfKctH6AdgQN1gaxXrp1Cf"
    "B1rsuxZ7r4DPO3rJeA0bZxE2gF07lDCHk4Gly3HgKgyXumsAymSDF49j+zTQNxO7a+8hOQAwoh+7"
    "hWoarEi0zQ5cQCLg7pJA3QnO8z/6PxePyivfyae+jtBgc030NN64IYdJhRgEkINwAw2/tSeevlQu"
    "uwTlYX3D6+2//hxOPw2XITouXIk3/hjOPSJrp7F+hudPy3Ad10Ts6SXfpw6PLrI9JEcPydKluPK5"
    "9pKr8PM/hJhQdu0/p6Vu2jM+tTjQAX6+WA3d9Hx8xvfqTDkDBXBwOVwGFbBFO4NV/VXP2GUrc7Sn"
    "PwDp0nRd2t5IxPXpze5cqLP9Hcx0jgX11z8JY80PDzo8OfGSZD5r2ofY7tNJj62m/nOqR6w/GOkl"
    "O4IeGHHxcVx8fPfFeubtTpdGOtk1SCdMvXPSUtTLRICN49w4/t+9wjNejeivFFCt4PQKT/9P3gyA"
    "rD2Gtcf++08i/8OH68ohYusEtk78T54oHQrXXRlBEg6dt1a7e2ZzgrHsuIkOfpTdI8jYISZ25t9l"
    "meMLLBdx5U049xQYcWHK36+5f4YlUEWMDC6sLCM/KIcWxQ159Q1cbHn2JFQlthDD+CzOnsQNt/Le"
    "O2AtYs114J4JEPv8YQH798qR/Vw8JNkCXvJi3P5bCBHquiGhpKRHQdKv7q+RAGTSC27+h0stvaqa"
    "9TYNsH9anO46IOiXD5EWuyOX6MkJFktSVJyvYmMXoiGQ3sGL9B7Qeovto1Y3E4EdKwV957126oL5"
    "LeiGJNE7q/5uS6/6hK731nG8bMelsfdqZKIC9/Gkz7t2TCPZfa+42D+tUx2x2E/PJPi2vwH/4wl6"
    "5gM9UW/X++5+ZtcSn/e6d71C53hVdvzbDvepC8W7LmGHPfTHrgPadn6bHuyNoCNWzV+W/amYfzzu"
    "JJfP+GrsCDz3fQbf+5PYWkFouLeGtljfxkq/KTEfYt8+WdqP4T76Bdz2MvvTfwUzqBIAI2SGr30c"
    "V98k19/KB74AUrKSsy20NczgMxmMuLAfiwekWOQt38nH78YdH4H6jvyTvv8cYgfQXWfSrN+Tgp0E"
    "ob8Q/Vea95rm0U/wjJ8e13fSDdCJ62rf7vfpbjqBdGIenXefF7Eyn3PqPmXv79MUfJ8bSBfVuVMD"
    "dG+wY6TdmF1/DObpUA8V7fho6T83uHOb07yYOGgmorQoABg6Cmuy0Y66BJF+e3ja+p3YrQTng23z"
    "j9ef1e40d54gpr8JAASmEY7u6+zkcumq7fquncLcjp33L9H/kZy1sRcsYe/N5z4cPX2+z1X608H+"
    "WkliFnX/idOOE5IsIKk7c34YurvVj6LMX4oQCBSMfM1Pys238f47sXoGkw3MthFqxAjnpFzAwl6M"
    "9sriQb7u7/Gej+EvfguqsJ1vDWRYvBLf90+xPMLjX8PaaYzXUU1gJnnJ4aIs7JfDV+G6F9q5+/DH"
    "/wZQcZ7qxLlemGNO62XnPK2n3asmYKYzcqPA+IzEuQuDfSKTXlEIiPb0W+e7tl3v6JEQBfYKQ4nM"
    "bJZwFyTQkjtXr/d4thOZ58oE89vLndvXHwCZ+8NdmGh/Hvq8AX1ONrcS6UtyFXHMCrgc4lEs0g20"
    "GGGwJFC2M1gLgqGRdppG16SdstlmrAkRzRMzHxZENeGzhDG2ok59qZq7rHC+FAgs0AItAKBFi3UM"
    "tVkAI63pD4yq8yreSZbcb29UZowq3okTkTTdDpBksDawiWmgLv1KIGKqTlWdN3Fmru8KpvtpsEAz"
    "MFqinoskYclecLGbF3UQp6r0PjWwxSJiEq9su6GyyLndpCPRaVFHQ4iwuFPG3fI2eckbsL2C88ex"
    "eR7VBKGBOAwWcOCoXv0cPusG+8x78Ze/0/UQup5mz5QEICO87Adw062Se1TbGK9LbFEOZXk/l/dx"
    "MuaX/xpf/muIE82YZZLnKDIpCzgP7yUam4AYEInMw3mog88ogAqcwAkEvWZ7BIkQEAytwQwhQgCn"
    "KeGFClzi2wucwmeSF2yBxtC2YsZIxIgYmeTMyO6iW5yHXpghtb3mXOjkjzqXZwL0VOI5Ibovgnvb"
    "7o5q3xXrdcDQO73uWTu4UH8qVNQDCl/AD0QdsgGG+7F4BMtHsLBPsxKMOhuLQS1qM0Uz4XQrTFZt"
    "epHVBmOdFs8ABsZ0lqTTGqPLR75YKsq9Zbk4GC7nPmesQluHtqZFWmzqcVVtNNVmDI1ZLaCTLNOi"
    "9MNcytKVuWYko4VgTbAWIplkDppplg5AsDbSGmtmNqviuGFNUERV1XvNclcMxQ8aPwhUI02cQRBa"
    "VhWaSkOtMUTC4AgvyAEHE/Tzdl6QwTwkB5WptcIoiESAVbAoZKcAmUzUyJZiTlUZyZZsWzQBnUyq"
    "YflSecn34bLrxRGMHSJcDMTn2Dhjd30ATz+YcBJkWZrlhoGht8hkJG4Bl90sBy9DkadgJW1lF57E"
    "E/d0JYF6yQsUBTInZS6DAkUhzrONbGNnfz5DWaJQGTg4QiN8hCMiJViXHbVEE1hDGrI2NAGgOIFX"
    "pO02XpE7qNJ5yTLJS2s9tgOmtUTjrEFTI0bG2J3kNIqaXKrsStY7FpDNfXjnMuYNsp2fLrT6edze"
    "SQCIrhHchwPu+PsuD0v/SwNi3QlREFAa4eAyLZfk6LN57Dq3sOxGi9a0fuNC1taDYlHrKq6eai8+"
    "1ZBtaKK11hhiSOWmoHPHgBMR9YVzgyJfXBzuWd5zZN++owujEWiMwUKoZ5PxeG1rc2WTJjE2tm1i"
    "mRSlGy5lSwM3WtCFoSudqqhGa+tQVXEWacvZ8oIb9gmcC9aM28las84oRIyRJnTqvNOicMMFLB2y"
    "8gCyoVGa0EJ9bM0CsLWG7XXP7cxqg7TIRUfKgpKLZmYZCcdW0Dg0wgBxGShJxpFeKaFTq3ImLhFg"
    "CRO0ghoSBaaIkJaoQCdoI9oWotg8jTveQ+Rc2INiIOJIQwjcXoNNAYjL6BwGuRvlMnDJCq2KiIam"
    "ZRsgQBjj+Jd5/Mu7jAIApCgxHEIFmZfE8vAe3tE7RENoEh2ekqVcgIOARZEFQ2mSBRaBaoIoIdAE"
    "DVCBjUijmAi2FTMvZshURh6lJNUyFB4LpfgMUQkvtTKaTMmmERWqpjQPMXZG2GVKTAS4TuhKMAfQ"
    "pcMYdlVmXc7TJdDpfPg+00Wf6PfoxfyRedM3ZbQdbNEXKP0CpS5JTrWaOBQL2H+5W97rFxZ9DC73"
    "bmnZ19VgsFfG23HxoJttoxojyyUOQ2zNph0WIV4gZOhyLdKpK3y+OFo4fPCSI0ePKdk2k9w7i5hN"
    "BrAQ6lk1zcwXiIGWFa5YzJb2ZHuW3OKCG+4plkqf0WKwWLX1djsODMdGR/bny9FiKhfq2F6crdWs"
    "Kk7r6HI3MAbVTMVy74cjO3xMl465fInQdtaQEiNjExWZD9HaGDWzSMIbFwOXgJLsVLCA2tlMUCsa"
    "R/Gkk2gwYUZoy6xlbnAtciKHmKClzIS1oAVaQ6ucqdSCmCF6iYoYCUKixBnixcROFQIFsJgDy6BD"
    "4aXMtcgkBhmJmHESXeXh1WACE5c8aCSQZj1VRLywVBQL5KIEpSgaw7hFS0DYtF0xk4AY52iKjFJG"
    "KQWF6d4og8CBEYFNSDNGnAG100ZZKTIHhWSCRuEdPVAIFrwJJXPMKd6gXrXkQs5Qc7NGzFi3EEEx"
    "EBKhhVnXZGQL9tsgU6LVS+nMrXmew+8ek91d+e0IY+2OEf0raH9ktANMuqcYAYnWjWym48SISDMT"
    "PxCLUAcax2MBh5k6zXy5kGcFx9sag8sGdJlXH9V160/Eka3SujYZABgsQoIwWqgKn+1dWlwe5rnX"
    "tnFNXWvmPDDdLrdoHuIFVOddMXDDpWLvgl/M6R0QrKlCoNFBiagCs5ir7i0WgoXGWoJexbh4vs6d"
    "+EILM0ZFtOjUWdTQirAdjoJJDNDRck01zTiZWl4m0rS5TFU05EEWo4wIJ8wcAHWgitHBFC4DFeJo"
    "TiLhKgyEhaIkcqgABRhNmpQVCI1ikACEDDOR6JEdhB9pHuG3ZbjOIjAwgdUkxJMF0ACrGUMhPmej"
    "sg6BICcNCIQXXVAdUhcqPwgIUSKgJiqI0AGLo8Te0Kz62dklRG9jGIWThm0EiBDpFExyh0oVZBSX"
    "Rm/NYuDUvNAPY/CMtbAOYomDnZaLOjhhKchEADRA8GwtTV9I7SEFiwWLikZQRzgFjPUUbUDiYqZ9"
    "BqkAgMAiaUzYWjI5doV5b/o7YpcdSLOT8CBN9wp2PbCDZ2AOIO6AqV2EEBFGIpV788HCVLQrLSA2"
    "bvMsTz8qh69y47W4tN8NRmJtnI01GiZbrCZoWwsBFsCgIiYAlQnSsZBimQicG3jnB+VCWRSxrWbj"
    "jUpiXbWxbWMbJ5Pt2WScxkAVWrrSi8/VW6gbcQIfIC2nXr2RIbYtW0Ay52tW4zheyBZCCFWYTZvp"
    "djMxRt+5OCdwTkPmi7LMFxdnLouxDS4zCwi10qGdYTbTGMRMaLQA5BQVa1S2QCfIRVRMHalIEtdm"
    "WmRWlgjGaQQdgtCJzBSNwAtqSgSMyFW8ICqCQ8w1ONIhW6Dugc+Yz/xeZpdUMmriNMYpEcRn8Es2"
    "OAhzk/ETLp7POaHVgpljBcYIenGEj8hMStPFsHxlGCwwzoRTNYF6Gy3bnstFhuHM09tE3qwUUgtz"
    "wBxLjzZIZoQgAFUQmHhSDFTxIBqNUSLtAtoYuyHa0GUcMJNaJNCokuYBGGUwoAkakSJD61CD2zXE"
    "SAd6bEyxNWFVo9vXKDTC5RCFRIiKxTmag07BSvvx4/4vEMFcD33XT2oXSEqBdv3sANi74NfuH/Qb"
    "9gSuez91ECFFXNoZXMAVyBegGcXJxmlU23GwUJ9+oomtywb5wv4iK7Wd2db5MF5FOxNCxDtXwMzE"
    "0wKsUZfPh9PzfMG7zKtabDbXzmysxuFwocjzrY31GEI1nbRtXc22Q6gtRi/qRMjoVNo4c1o6yadW"
    "ScIerGlZZ5oTfqNdm4Xx0A0z8dHazXq80YybOCOiQHIpVJ25KGICa1psb7npU2WxKH7YGDKKBYvT"
    "KdoZNNfBXo2E5VksYigiChETE0TvEXNageEilxY1FKgBzdDOEBRSoqYamBEFGIFIycEQMQVNAZXG"
    "I3hOVSzjwElOiEmubq8fXmP7r5J6XayFRThluVeGBzRUPFM30yqPQQDFYYeNKDNFY4wRajBjpBrz"
    "EpfdjCJDu8UAuiEWFsXnaBtuXoxVWUUiRqce9AZ1qRUgQgQzNYgkxyVtlDbChVTHS6TMRGoRE6Gw"
    "08OPNEhUNIbagUIhtRFRtCYVmRUUD3i0EWZUE+dlYYi8ZKQkKKxpYYYYoKkYaNA1GQzUXokmpSpz"
    "MKjDledwPnYeJtnrdfSpzk5CJDJXksBuWsS8vwwQFumyXjbFAIMXiQ1FWW1JPTZa48tiuEegLJZs"
    "42T0hZdcwjRWG2ynpIk4kWjqxFoA4ksnyZLVOefUZ75wqrPxVu68xRaxHbPDgGOoZ9PN0FSMQYHS"
    "DUbZwsANMkjhMkcXYxtiExhipFf16ktXZOrHzbSSqtJZ7vLA0NCCxIDYWOtERTTCVFSd5F7aqR+v"
    "tEPobJoVy/QDRFgIOplaNGg/FeTMIJABuAQIoY5w9AoncQxMgcY4jphVIBEaIIgzBoHkcBFlLrPa"
    "qoDoYInr7QSeVJiDeUwgrelyKYiIVOr+/TK4RIMnAbHoc2S5rJ9F6WPDGJuI7cAJEKEq8LRgaIhI"
    "56CNYII4wehSkyVmpWgGl7GtOZ1Ks4G4GnwVLBpVJINYp1qYUH/xykzhKUqQnETUhhyJYiObDlFo"
    "pKP5CEIygQlqgyVNvr4/WHjQsY6oZ4hCU6EjAZeniXY4L0LWU8SA0PRKWIRFSQ0+65UPO6hnt0Of"
    "MyL6DEi4OwHCXBWifyBhSh0Ss5MUkSKJfJqQ0/6QAYhGCMQJTLQlIv0IsWVssHBYRX0xcIMlly9K"
    "O5OoVk9CXEczbabr1s4Yg1nDmI6yidBprpqpqqhTMPN5nhVeVWEKDgejLFMRjW1Lgi3bqjGJCldk"
    "S7kWuR/kWjjCa5bBR2gVZjQJ1jYxZk4bNCG2mWimXuma0BCs2mqr3Tajg6+tNTEDlOI1KxeafGQu"
    "94NBNthrQbwbUEsZz1Ds5Wzq6lnmVVoTA2kiQTmxWAo8NWioMqsUBswimxKNyixapvAOInROcrA0"
    "lhly4dRJEjFI3N0oCIAXDhVTqgMRUY2hUy2DbImMWQzMK+txMShUrJU6Zo1gJjalRLNpo5VCAVE4"
    "09yY+g81MJNmTWcrVi2SSluVegx1Ao+tVW03GNbZrkVESAVGiBKtIRKRjBBCosmQICXJJZuD0WgS"
    "BE5kQGuMAmQUE4HSFCJIi9yVaTSfFDHpNqpYGowRgSBEibQ6SlWjrhAiSMTQN98S7hLRrb7raThd"
    "I2wH8+lw0rmRczfeIx0MukNqTuSKedLTzw/31t+/DtvuxJAijmJChSiNiAoK8lFaySSLR93iAV8O"
    "JdQuL1jXnK4lTa+sXDbNLVS0nBZpJqoKUeedOFVn1jiXD8rFLMuFGAxGFsLaZKvw2cJooZpOnKq1"
    "jbVtDDF3Qw838GWphVMd+YUY2pi0y6lecohWrILFTKR0+aIbLGZLStQ2ixYCZI/6bauog9K5QFN4"
    "l3loiJMVy3TvwbC4v9WR0mVawLLYRJmMXTuRzLuQi2auFYXPMaCUCmOkxtyBuUrGZsnCAhtKU3G0"
    "F4VCKohhgVyaACozoDXsLbASULQYCSIkCGaiRFSVxUxcwanFzW1WASWk9bNtHSxHFR0u0qaxncrW"
    "FtaPo7ooYStyJirEUCCCKGxNB0KYc/QlRBgqGV8Ao/qCLqMFwLRtZPui1OcYNkOYisAcRAqIo3nG"
    "GtZK2rdEiERIRhjogczEm0KpiVVMyRJ/OYnBOFhKMJO2o9AoLdkEOiLLWOSSaceyM4U5IooQ6ulz"
    "CbNurNFMbDesKc+A+XsUU2C9pSeVO8jOmC+560TMUaDe43NO19khw/Sr+3p185QK7ezL6Nk+afBH"
    "HUSlWBZrMF2JiLHK2U4DxTFwtqXOqcscg6gXTYvAAmOAgeqjNRHwLqe1Tl0ItcB8MZjNxt5lmcvK"
    "olRxoj7GSIqTfFRkMbTO6DUXaLS4Wl0ww95sn4rmftDEGuIKV47bLbNKLA3zVwt+OMoXt9vt1lpB"
    "0dq0SfU3tUGjocmQl8V+V9VuWheUtvImUs8Y1UIdbdKwUolODbOxtQbmmamDkZmLxQKzyCwX2Yt6"
    "GRciiogje+G9jKecGbMoMMpIJEc2kqamj9wzA0U8IIoKslig8TrzUueWjWREHXnhTDXW58uLj7aT"
    "LdEsiMTQiAqpqKZOS1fs88EpSnG5WAtp1FqgJWNUMYGop8vDdM1ZLb6A5lg+CNfJPrg4KeKSzwpN"
    "o4VmsAAXRJ3GVqwQMSWFQjEhTZwAEWKiZAUYUZt6tUCIgkqCrUor3cokps6Romt7B2kjspwQoSIG"
    "MGMbJEYwiiqKAdqWahICkxxfDN0qtd4Z96YPdn67b/NgF8bZU2bmpu37ubH5kdA+TuwKHjsdZuuZ"
    "P9ypiSl0DuJEPeCSSATbxixqbGgh+kwBZYzWOoiTnG0bqi2YWawttmC/d4hUzQTmXQbnncu9OgEs"
    "BlrehEpzTKdoXFNVUyEmk4mFYJFiUvjFBB+WbpD7wqKVMlDVLCsqzBqpZ2GqyCWqqCtkoPQeOc1C"
    "q6QGxtItmVQiXiUPbKFRRXNmjk4pkzU3bqflXqrLJAulr81Pkcts4poGUUHA1JtfsCiSDViVVgGz"
    "APMmAavb0pDlSNoa422EWgaK3ElColtIULKBU8kLiAkF0Sx4TqEzEOBsLKNSBurMymWNU9esDVxp"
    "o/2Se8kGEdrGxmXOV02G2rlMGdVm8JkiF+80IBpUNbqcvnTlKPeludzaytuW1psol8TlpLlYqTrJ"
    "Cm0rWitOVVQMomk9oBdEsaCaKSVCBBFswUYgIlEki5RoQSR2w4apsY0oUrHDMTNhTFx/RUt6jyBA"
    "1yVEU4kJKehmzjNRSztF0wo0ADSBhS4I7CQ9qRxNp3NXKr8rIGDXj8cugrTMkyZ0jJddPN0564Iw"
    "doyXRG3vSURMeqWkxAaxMleISGjG9IVC6AujGRBmGwI3Z5A5VbMoWkgvbUCLMTTOF2YhRuecI61t"
    "6yIbVM00E9+oC6GZzrabpmEkjKUbtaFVn0cGE6/MBtA6jCdtFWEOXsjWQqGDgRuUmkXThliP0yrM"
    "jHTMnXhRieIba+s4ExVHn4QtEfPpNhfKbOic1pYNXdPE8TZntUwbi42pmM+8SWaaSZOhRaRHHZ0T"
    "DkpCULUCZYRsVpjVmIyRe7SmIVgByZT5wCSi9cwMCNIYasOUaLw0wsVSStVAmLFtOVQdOVeW4sk2"
    "bp4t0AbnK9NMQtGuZXEjE7pYAcE7p0IvEbExpz4b0GeRElQEM5lOm8GyiIqqsNLJtpoZTNsp2qkI"
    "wFbZijm1VhjUoiCKqJgoQ7SqoRkyQg0Z4IQQRJAi6tkSEYiESdodm8pICYndRECgjgJRL4Fom0Rl"
    "FDM0Ad2shIEQi0jb6NJe3Tk3TnQuh9EXA3Nbt52/7kJB5/zQ/gDM3fsON7XLqPqzIrsCQs+OQF8S"
    "pOU4FKT90NFEIsQxVtCpiRNXsJmoZlHV5yO6zGgIjUJEnAM1yyV6iAvtRABDUJHAEJog6pGT1qrL"
    "vYYQGhEx8SG202pcNRNhkmTxNaaqUjALsV2rt2ubOohXbwKhKzAIofHqVV3hR8vF0kJWVk1dSjGw"
    "etJO22jjtq7Ytmgb1KKMhKiLZBNZilrI2+1AeGyjcqjYVAxalDldwyCxQSVsDQYLQgGmLYoBGrMY"
    "ECiTFo2iFdQ1JlOop8sTpRehRaaoQS+yarIFlKXMWnhnyCUQuYMKqoal12ikUaStpd1mNnUIRWiY"
    "a4GsiBbFdHZamy1lFFCFSpeT3c5HMxOxtm41VzZitXOUyZmQDSM8E/UBwVt0PssaVYHLBz6kTY9Q"
    "OJUoCIyNWSQcSEujaAxkS6h1FFEDRRgiBYgOweA0NQaYZghFugXLXX+uEQpUOwOOhhhJihmNUN/T"
    "3biL3Mpe8n/HsHtjnidFu339M49A/6AAxbzf1f1iPh4wX9+y8wqyk1V128tlh4ChDuJFEkvCpcji"
    "sgVRJ2kwGhD1sChQp57WiIj3Q1VnMcZYWWzItlelU+cyp+o0864oiwVaawwOziwaqZCqHgNKiBcp"
    "MCzSdBtjZCBi6QellgWGMCWjibXWeM2WsgWQRis02+uXneRVCGvN9sxmkdaipdAYVdWEWaFu0Goh"
    "kEBDXqo41FZXnIVobWPjum0UbS7Rk5mzvLRAhjaWSp9JkXFSU4dkgbbFbMqmUQAqVKCusOi54DDM"
    "wYBJ3e0jcYBXzChRWGTiQGvFERngTV0rqNygFrRuYCq0CCnFK1kzbko7EQsEVU3Ve9ALfKyJYK5Q"
    "KIuF4H0Fa11uIsGV1IIKxKnE1g1GRTOT0KoFbcdirQYTGmJLQKyhNRERjEYQagiRJBzpDK0ByeuT"
    "KkkcqR9EcZQseUkk8iwTqSBJ7CSxUQBJsVgBB2sR2p5wzq5gQE962+GsMSUmO/XA3GKf0dh6piH3"
    "HYJi/kCy7PlzZZ6UdOyJjhc0z5C6ICDzkZc07Z4LpFPEE4io+sL5ofMlYCIqJCyyrcigmoFRRJzm"
    "AERctFZESRNRFaGZihLwLnOiouIkEQidxbZpp0Y4zRSWST7QYeHKaEHFGa2Js1LKkS43oWlZN2xy"
    "Xyi0dEUT6zR6kiEbyaLXvLZ2ZrPGmsiY5DYKN1B1mjP4mZaW5aKaqKOxauos1wDbnlZNaOtQtUJm"
    "gjLnsAy5MhOOMlYtWkOAxYwhQ1134JgIqimcYjhEoZRa2AKkKLxCBZmCJo1JdHBOBFQi1JSoGmWP"
    "0LUuq4qDrfcQDcXAqRcamw22G2i3wODaDYipeI/gGBL0LuIhjqptPmrUN8Nl+izCab1FtkDLpobP"
    "vMt8NSPpWKtVQqgFmgmDUQSRDJHRYJEKqCIEtIEOApiaCBBJEgqElKgAFNAh0dqIzpfHtP8MvXb8"
    "zqqmRHvuaD8CdvhPUrg3dEMaXdYMoJ9+2U393+3o+/KXvZMnAPz/QrPOi5JaLfwAAAAASUVORK5C"
    "YII="
)
# === BOARD MONSTER (democopy delta, 2026-10-23) ===
# Owner ruling: the header carries the monster FROM HIS BOARD
# (extracted from design-board.jpg by the boardrules build:
# board-monster.png / board-icon.png) -- not the 11.6 master
# above, which stays in the file unused by the header. Both
# pieces were pre-scaled at build time (PIL LANCZOS) to the
# header's display size: the big monster at 165x128 (the
# height faithful's slot gave the square master, aspect
# kept), the small wordmark icon at 42x43.
_BOARD_MONSTER_B64 = (
    "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"
)
_BOARD_ICON_B64 = (
    "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"
    "y6QI/qfLu/8Hdmn1oK6PAwoAAAAASUVORK5CYII="
)

_MONSTER_BANNER_CACHE = []


def _header_mark_image():
    """The header wordmark icon as a tk.PhotoImage, or None.

    Democopy delta (2026-10-23): the BOARD's app icon
    (board-icon.png extraction, pre-scaled to 42x43 -- no
    subsample), per the owner's board ruling."""
    if _MONSTER_BANNER_CACHE:
        return _MONSTER_BANNER_CACHE[0]
    try:
        img = tk.PhotoImage(data=_BOARD_ICON_B64)
    except Exception:
        return None
    _MONSTER_BANNER_CACHE.append(img)
    return img


_MONSTER_BANNER_BIG_CACHE = []


def _header_mark_image_big():
    """The big header art for the header's right side (SS1 slot).

    Democopy delta (2026-10-23): the BOARD monster
    (board-monster.png extraction from the owner's design
    board, pre-scaled to 165x128 with aspect kept -- no
    subsample), per the owner's board ruling."""
    if _MONSTER_BANNER_BIG_CACHE:
        return _MONSTER_BANNER_BIG_CACHE[0]
    try:
        img = tk.PhotoImage(data=_BOARD_MONSTER_B64)
    except Exception:
        return None
    _MONSTER_BANNER_BIG_CACHE.append(img)
    return img


# === CHATGPT SYMBOLS (democopy2, 2026-10-23) ===
# Owner ruling 2026-10-23 04:09 EDT: the glossy ChatGPT
# symbols go into the face AS THEY CAME BACK -- no
# flattening, no restyle. Sliced mechanically from the
# ChatGPT symbol sheet (work/chatgpt-symbols/
# chatgpt-symbol-sheet-1.png, the ONLY symbol source;
# singles in work/symbols-sliced/), pre-scaled at build
# time (PIL LANCZOS, aspect kept, fit-within the slot's
# box) and embedded here -- the same approach as the
# header art above. Keys are "symbol@box".
_SYMBOL_B64 = {
    "bell@18": (
    "iVBORw0KGgoAAAANSUhEUgAAABEAAAASCAYAAAC9+TVUAAADH0lEQVR4nIWU32tcRRTHP2fm7t0k"
    "20jSpJuklabNDypNlVoSS0sxUYuiQrXCPumDiPjkHyCIrIsgWFERwZc+KYi1FYsiClUxikJaJVSo"
    "1WpSkjal3SYxbHb37u7de+f4sNtgNdgDXwaGL9+Z75zzHVivsmoAOLx0+9A7tQwHFzfftH/Lyqpn"
    "DHBgetPIqeDi3UuqAx+W/4STHcYC4996txJonvRFsuPphdeGZlXTUxoMTqt2Hzr3OpxN/fdGKjcJ"
    "CJDce3li7KPKb6OzsQ4tRPXtF6J4+2xUH72guueD6mzbPfkH17eWOW5FBG/372Njn5crw4EqP8Yh"
    "J6KY95r4Mg63Laru+axW80bm9osIZI5bAGmIqsmJaP8b+a94Nv3A/Ndx1VzBJ1A0cA2Sb9R1S7Tl"
    "EZtMHr00efGV/vuzqpITcR5ZNTkjjvZTw/YO/975X3Ayo74rxFAOlbCOqoLvI4Wkd/Un67bsaNkH"
    "b/XnjMxB1nhMThoU5w+ndpRab0vEM9S5FluKJagGQlQHEcXzUW8D+ofvCoOppO3pGojzzJEZkbV2"
    "SbdLl0IDl1BWKlAuQK0KLmrYtgmwMVxJuWBrC/T4neSB65vEwARk1cStdMarwOU6FIpQLENQhkrQ"
    "WMslqBQhX1GtWrSrfeONDhleBnLizGDvaLQCXFsVKqtQC6BeaSCqQliBWhGWl9AiyK7BA+TEMTHR"
    "fPj7zj+RenzbsZXvPcNCXnBFcFVwIbh6068FY0E3QG+/tj9k4uLJX5/ku7GPJZE+cVf6/Uenlje3"
    "euFZnFoEh2gdiwNcDChYA9ZEGCBEE7swfdcLuvTMJ/s8x/me5TM7W8ON3RBH4BRcTNLGsbQYAQWx"
    "xKWIyFlfHYh4uNMJlhbnqfFzb3Pu9x6CjqFGDqqR9dL7u959M0MpEVEMDek2atM/hIWjL7xq6Ft1"
    "eAJxAhZn4NynTb//gAG23jnAi1PKS6oc/qvOEVUee/sMAth/8VnLX8bCuAfjHjuzPoDpe/h5+9Sx"
    "q+a5bwJz8MjpBJ0jjaxk/DUuGfs/f0Ij3m3Q2wa7gRtDKeux/wYF0GxfEYzy/wAAAABJRU5ErkJg"
    "gg=="
),
    "check_circle@48": (
    "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"
),
    "document@48": (
    "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"
),
    "grid@18": (
    "iVBORw0KGgoAAAANSUhEUgAAABIAAAARCAYAAADQWvz5AAADeElEQVR4nDWTS2udVRhG17u//Z1z"
    "knOSksuxppbea7VBiZ1otbRYizMdKI7EmSCIUBz5A+xEnIkgRYQq2IkOaoUObAsGU8ULWBSKodBq"
    "0/QSczuXL+e77P2+DlL/wLMGz1oCwJNXm4+8sftoLeTDqphzCH5Ibv++MV+dffhPgPTN+zM7Hx3a"
    "q2VPJcfSRiKDPC3+ObUwCzOZMLU4vP9069vG4dHj6z1AQQzSGtR7YXD7s39faY6ajr/WPl8103pV"
    "gJqRAPWW0Pt+ee72Oz+/7JtH1p4pprcdv75O5L4awUGlkBCbh/yQTPbeDu1RW9iV1ru/aEHhEoKA"
    "KkyJtZ6YPJI8NfKsd9JrdDqFSaeO3FVHZRAxM1y2BZMir5XVsIVbmNy0RKroCEA0rO8021qoi52G"
    "j2urRqZiXaADVhiiiKkgGUIRYljvJfQRW8MIBhEsACnIqLpYbuADEQ1qrADrBgUQAcXoqxEqjNTI"
    "1FgzLCrEzTGch4dUCZn4eOtuHstUZDsJRWryP00QJhDuLwfKEZhwwlYnFAjxAWwHiZQqtngt83H+"
    "7K98sesihw8epaeGIuCghtlX97rJD9+djo1JT3PsKBOTdbI8IgLOKXeCs7kfL3PvzJyH2T4XXn93"
    "7F52KtbDCBYLS3ziYhgq/7h1brD40QWA1pfjH9QOtl9Uy3NzXgT10gsba1eunoSVnjB1fnL3h0fm"
    "9MTYge4ykYBTjdSGE2t0Kpbe/+2t0YktxfjJ/Wc6zdSqAYIhFtVGxpwbXFj8a+m9i8/7+r7moc50"
    "68DqNQJ/R6EyRQVcjMlzaU326qv9dsraWOrCpVhQ4Qmb761uc5Wfbj+W7JDD3pL1tL9amiykIksm"
    "VgJBQUX0pkEsCVUmLBhy1xyVCVGNCFRegg2MZMX5sr+sySCKdcE6CmUEjRAS6HkkFIlUuZAL1olC"
    "LCEGQQV83ShMCOt4bCAW1egA3RLKEqyCsg6DmkFpSO7IotENYAPQaEQT0iHEoUbuPAvzJYUIjwO+"
    "ZVQPHElRdiJ8s1Qy6DleSoQ9TaVsCkGNoLDPw6DrkjvXB56lT36yT6dn5dgLxywLoAkYiKQJn89n"
    "7tLXH8fhoVQa7RNM7a6xUUAUSEBuBLh4/nLsnZsVgDa0VtnzdIQG1NhMO7gaN26WcI3NrGYqprdD"
    "P4I3sARWcuhcAfL/AMQdA8wQ9kJyAAAAAElFTkSuQmCC"
),
    "info@16": (
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAADIUlEQVR4nFWTXWjVdRyHn+/v/3cv"
    "ttFa7MW5mJss12DN7WIkBLMXRljWlRMCLxK9KCEIgjBYp+iiXZleBAqFLI2gIEiQmYkhE9yWMl3J"
    "3DQ2t6nbGTvtnHnO+b/9ft9uSum5+lx9eG4eeISKmP/2mY0Vh9O9m07nDjZ8t/buxtRyH5yrBkCA"
    "VMrwf1REAPZ4tSeyH7RdT2613lTXclO1+YZq86TqsxPJ3ZpjK5/DDxXw+ERQFQVELldtOdv5U0lX"
    "5c6liwHrowtOF1Yc6qCmQp54vt57+vV6ouu5yaWD47vJ9s0z4IykVM1n0i8NPx7/tWR79UtzgzMB"
    "s3d8ooxprK8iCgqkl9PABsemrUnVR6+WRVPpycKBwRfQIyEAFamZ9xqnVdk3WTQvDlnZcdTW7hqy"
    "y0W1kwt5W94zaKX7Y2u6PrH0/VwsH1H1D40fBvBhT4nXUXUofSGrTF3z1F+CYkEDycvw2Ax/Z9ZI"
    "couARX0PuTvqFc8/p9Je9w7wpU/nW+1JSXlrdOUGJItGwxziYnKreU6dHiOfyxDnc0ipQmIUCQzX"
    "rqrufrmFxoEOn7bKliDvbeDBfCxxxkiSx0WB1NZv5utj+7h/L8PO18aJoxARA2IgPe+IPZ+tDU0+"
    "2RXP5mMIshCuCRpBHGC0yL1MQjpbQDRUbCgIqAgkBShGsJ62ht8vzVJYt5SXeRqFShJAXFSNHhLE"
    "EMSADcBF4CIkDuHJpzyC9Yg/hu8YVk/9KcuLf7GtUwitggUbi2ikxUSInMFoBEmsqIVIHW07YOH2"
    "NPHolEEI9NLZE7S3C3XbrUYh+KLFQl4KSUAQ57FhiHgeRKFoc6/jmSZh5PsjiCSCqkHE5+2TI3T1"
    "9/DNFwEroz7Epq6xmiQq6uqDNYRSp02vWNn7fhkXjp7Ti5/uIqUigMEYh3N10n/yjHa92cPEOExf"
    "sazMKcZAzWbDtl5DaxuMDQ1zfmAvqg8RQf6tSRBRVMvoOPCh9LyxXysamo2UoupQV0jIzN3it2+P"
    "c/+XrzAGnBNA5XGRj0wAKmFLN63dzSRBwuzlGchNADHGA2cFUIB/AJkkqYRLC6HxAAAAAElFTkSu"
    "QmCC"
),
    "layers@16": (
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAPCAYAAADtc08vAAADMUlEQVR4nGWTbUxTdxTGn///Xi6F"
    "tcBiIanbiMMQdYuZ6DaniTIhMWZpYCx2vmZzHZAO3Ytb4rLoUhZNgPke0blEJvVlsXUK6odpFu1Y"
    "2JJBoAhV8aWwMQapWrBQoL33/nv2AUowe76dJ+eX8+E8DzBDNg9JEk9MjaYtjcP20sshByxeMwBw"
    "Bji9XhkAw9OgRyKiKdOpbPmhz37aN3qnbYjI94Tox47Rv7e6Ap8DNSYA4Hzy2OT+NAi8e6R3/YmW"
    "cGd7mMgfJvqjX9Oa+3X15jBRxwjRqT9DAfuRTgeA5ATDAGCF8/bqkgJL5WvzM5alKkB4RNdUDYyB"
    "OMAg4nGSJS5MRlkRAHy3Bm/91vSg0vPNygssb5e/aN+2ly9lpwEPBjRN1cE4ZzwuCASAaOoSA2IC"
    "cYNMtOhFJakrCLy/42ox/+vRROh065PB7nFoz81K4gYpziPROMY0IKoDUZ0QUYHxWBzmFOKZZoW7"
    "70H/+nyge3Tg4X352cB1f3310L0L5phlU+lS/e3lWWyuDvz7OIZwlEHiQJYxjvSMZLSEgJPHWsnn"
    "bpGRPvufNOPjICyFB8oX1BMZ11xRYdooMotrxfZrw8I7RMIXItE2TKIuQOKNfTcFcssEklYLU8nP"
    "2gvHiVJfd9oBWMxYcrg1q3KQcmsimiGvWiDZKnI2fC8qLveLwtougYWfCrCV4pn8o8JSNaoZHe2E"
    "OZ/9DsDECjbWrHrrHav76EFXRm/EyJ+3fcKU2Bj6PLWk93QwkIqUxYVIs1Zg7OEAIg37aWFOirBv"
    "d4x5XC6b3BPwmUguyjx+tgYNdSe0M3UVbCI7n8+p2M1MiopolCM4EETw7G5kqXfFhx9v5sus6xTv"
    "9Sbldpd/6kfpr7y59sv65nO+cWroHKGSsuqYkluqSwXfCbz0lUjPLtYclS7N3amR091Ni9ZVXQJm"
    "vfq/JBrmrdn00d5G/9Ueoottj6h8Z536xbfn9J86JujwtUFaVXroFyC7INELIMHabDO6AEPuive2"
    "7am/cf/XXkGnmoNk23GyCebF1kR0nUQccE7Xblr5+U6ZS1JizMhZuvYDafbyooRBRAw2mzST+Q8Q"
    "Tou4oapKiQAAAABJRU5ErkJggg=="
),
    "magnifier@18": (
    "iVBORw0KGgoAAAANSUhEUgAAABIAAAARCAYAAADQWvz5AAADrklEQVR4nHWUa0ybZRTH/+d5+/ZC"
    "aWlHubkyoAUKlI1MjKhzbvpBMmNmWMbiEBOTzSxOjdPEaIwGjJpojMncEj+QqYkJusFGIm66mCmL"
    "wGCwxJAxbpM57NY5Ir1I19t7OX4oxXnZ+fKcnDz55eSc//kD2ejpkbKpvf1yZVVffLfnO/Ul97H4"
    "bttT077Vfx0scMdozUBM901W3j2U/LJmnqOuoTQ7zsS4+ILO5XO87B1Q+2zN13x3hnGmmL/n4taG"
    "S2rIPpBiau/nmrZexb3jmEKbPlXQdoIdYyp7J7SI65n5zf8LY2YyPXjS47+QCMndV/mBnV8kJ8ev"
    "qGeCqtbax1rhczdU2vCZSjWHkuZTQXafjS/mlJ0sBjMBHaswQURctq/+nYBqcG78ZiQ13P2kbG2o"
    "oP4pHTNzaY6nGeyug73YJ+vvnk5FXZaCvAP+/SBiDHT+DXKWvLYuXerYvnx8jD88sMkwpcn44Gwa"
    "o9OCb9zUkYhpgG6Bce169jqrpNjgDEcqHC0AJGyFtgoyPdJ4bxjG3Apd1W+uKaZDwxqPzwi+8quO"
    "SCgNLU0QVheZbE6qaqgh21KIEmq6FGhyQRADTAAgolapKCrALJv1U5dlHp1gLCwwwqEE1FsJgmwh"
    "2ZEP51oz6uoMsNsIiKcpB9F/DNuQmFr4E4pCi0nQ+XGdgksqYuE49GQKJJlBdivsLoFqP+C2hFlR"
    "7KBAKFyAmfACiWxDEBg6PkYLi4lUda745fwsln9fhB6PgQwWsD0XVhfB5wN23Q/MBWb1qL0c/HX/"
    "0QCQxN4xGQBnQDg3y98O/iBvrBPyXdcUTgCwFYELHDB5ZHiaZDzRbEBwdJj782pJO3eRa8o9Bbrt"
    "cD513aNkxUxgJlDFBnr+yIh152aL+GkypcXyDUa3HeVegQZnhDlwXR+iUmPg5+ugz99Tnn7roBxD"
    "zsTRFzq3E7p+49YeKSMqelsH125DW8dXlpbH83KVCCxKjB1GiZYVIxYVB+Ijg39w72GQrOTLlEy1"
    "v3LQnMgpuXqiq/sx5dLr07RybBKoVwOjEmV7X0XDQ4+KwoISXUvpiISDmJr8HrMfvS95Whp1S30f"
    "B3/UkFxSdrz4sTluXRc4/cmRLbctsENAZLglQA4AL4CySsCUEcqKObge3kX+NzUUNjOk4ltrmrtY"
    "NHbu+fcJC7T2SBACEITMK2XdgbKDhatpG9W/sUT+lxm1++ZRtKX8v26QCcpsFGIlv71zAwDIcK4X"
    "1c/uN5mKKgDgL5XDkcqodCojAAAAAElFTkSuQmCC"
),
    "magnifier@30": (
    "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"
    "+Dr9pwAAAABJRU5ErkJggg=="
),
    "person@16": (
    "iVBORw0KGgoAAAANSUhEUgAAAA4AAAAQCAYAAAAmlE46AAAC5ElEQVR4nHWSXWyTdRTGf+f/9iOO"
    "wrpB2ejGWFlxAzQ4shgzFRJ0fiyiktiFhAtNDF5IIt4ZEk2X7Iq7GYNX6oWJia4YIDFo0GUjLkw6"
    "l00i7Rxq5auEjbKStXRt3/c9XhQiJvpcnfPkPOdJznPgf+A5luvlo8WeWqfy31PxuCGuRlUNqAwk"
    "csOjN2335PVq9cXPbx4RIKZqEVdDXM29ZSoCCOATWL/l483DyYJeWFB3ZlH1yOnFYlfXobVe84CR"
    "qngQUT0w38q6hlWVD6f+WrjUf/vrb7dfX35uV7i44nL6TPLK3NyxIowF+WBzB/nlEiIpaT58cdf7"
    "BzuPt3id1dnFwo3iXc1Mjf24zVcfaLIrtnpXitmep3qv1tX7I5GWQOjKsqfy3tDoa55yZnKbVjtD"
    "be0+HulojHiVyMtPvEppueRYxsIX8LVaflqLDmTzMDd77aGVzHhYgFV0HjwaeezRfdGuaLj78e08"
    "vbXFthw1INyxHT07k7GmJybd+fQfqTtT4wkKE0drV6khCPQFeg6f+SKt7vGLleqJea0OT+RcGvZ8"
    "CnQDlgEQwaAIsRHL8vryliXf9+995VevH1kq4eYKjtvYGJT+N95NGsvMxFXFjcUsVDGAkhhw7UpZ"
    "HGdroLk9vK9kw1LFy1IJbK8h2FR/wHVcMwguiYQDUEsnNmJERIM7X+9ev7GpPV+lOpqc9f08f9mb"
    "v4uuaWnqht5mY8S9/0UGIP52SAB27tmx1782SLaAmT7xWTp1/uyN2zYaatsUiPYNPKkKu3cPWveF"
    "MvTsMzbgaW5rfKkoLqkLf1q3fvrmnewvyU+uLpSN1vlp37HxBYBD44NaE8ZGjOu4BLa81RuIRrtu"
    "WUZTY6cylDM/5CZPfvn79KSWQ+Kui27qA+r2eywHEA+JBAKs5GYr6eR5PL81yLXxU0OqKiKSvvTd"
    "V4k10Q0Dl89N5AEc2xGRfzK8V214HsL7/82xGh5+E+h4kP8b3Zg8AqAi5kkAAAAASUVORK5CYII="
),
    "printer@18": (
    "iVBORw0KGgoAAAANSUhEUgAAABIAAAAQCAYAAAAbBi9cAAADhElEQVR4nGWUS2hdZRDH//N93zn3"
    "ldq8Y5LaW5NYwzU1tbZxI0KRgoIIVZJNEeqjRQtduGihG+ntQtGVDywIWnEhQi8FCVqQFoTgQlsT"
    "a2JaYkulTZvnfZ9z7zn3nPN94+ImUnBgmM1/4Dcz/Ifw/5Ddr198uX1rsksTswXASAsm0qzYUL5K"
    "+bWvP58EchoAAWAAUJvd4+dZZiZOc+742MnDh59/PwGByBAUARoAwLDBqJPAV1v4zI1PM9nx86cp"
    "N0EaAERTw5TJzMsssuaR7sS+9haba2XPN/Va5Lu1MHTcIHTc0K3U/YfikjuTwXNA1hwbBwFMG0RM"
    "IOIsEMSe+WBHtVDsXctrLharEjACD/Izk7GT7FXcbnvvmcf3Ey1sDEQKIE6Mndz20t7+kZk74VkZ"
    "eI+6hXy0vnRPGmYoKcDcVGtthFCSY7qW6e9QU5k3Pjzy44XrU6h8U6bhA6dGsqde+3kkM9BZLFVh"
    "20oLO0lhEDZJ/sMhGGbYlgSZgI3ni7aeNvrp0tXZ42+eOKD6HrafHdg52Fk2tu9b7ValoUnXNYgU"
    "jAEMM4iImZkYgJQCtbqgs78tm0NjKd6e7nsSVnxYse/plUKNa0yy4XtkxVMQwobWAHMTxhhNBIIB"
    "ICBQCwxWdAfdzTNZVDdKASoK6sbxNJWCBlWqNcxNT8GpVplAZJjBmwkCEcGEPjp6+/H26B5YSYH1"
    "tVDE40wKxsd6pYFCIHDt1xlMfvIR0NVHqVQCINFcEFHzdmxQdypgpwT/3fewfXAn4nUPHHqkBEmx"
    "nHf1/ULJ3Lm7SLvGnqDPzn2MuYUV+I0IlhIAM9gYtLZtQU97HEcOvYO15TxrSnBX0kcqJaRaWllu"
    "LJca0g1IOm4D+0d3mKF0DNNXy3D8CFIIsNGIIg1LGOza14OBbW1UrHoi1SOxXnTg5Ber6uaVyR8a"
    "dvfF3sHh0eLCFPa8erR3dsHF/O1VWErAgGApiTAI4NZ9rDtD6OvrbNy6NrWqvH/k6s3ZC1713h/0"
    "gFkT6f7HXjx3+UpOtbaGf98qSIAgiMBEiEKNmCV59+5Wefm779dOvHXwKQBlAP6maenpo1+omS+P"
    "eYn+oZZLv/wpEGuJKWKQkDDMMMZACIKOItxejGHu93m1NZ323ftL/isHv5W53ITeJNqsCcB+AYi1"
    "AMY0PS0lEDAgufkH4gIo/gVgesP0BgD+BTLzv+/2Mcv3AAAAAElFTkSuQmCC"
),
    "printer@20": (
    "iVBORw0KGgoAAAANSUhEUgAAABQAAAARCAYAAADdRIy+AAAD2ElEQVR4nFWU32vWVRzHX59zvs/3"
    "2fY4t9mmY3O5Vf6oxDSDJJNpFxJmEBlChBdC/QPhVRFqZphXXSSFQWR1EQ7SIJSg1HKCKzLwYipo"
    "oZO57Vlzz/N9fn6/33M+XTxT5xvO3fvzOp9zzud9hIekAqIsO9zduWXNoNEkMEEogahiQ1yqSlwj"
    "tU1J/uL4MFd33blfM6dgPkwVpHV756t7tp7dtmXNqqhYw1hLALg5l/GO5lyW08PXr/+4d88mnWJS"
    "5AHU3OcN7rMIkO0bWLOybxWJJBKnqY3j1MdJQq2WUKslrh6n1ml9RX/XE4RmHSKN2nsbAqKqxgx/"
    "mAYi2t5Nd6kQaaFQlSgqy8xsycwWSqZQrJjZQtkWihUpRFVTKZR9W6dfmjGoGT6QHj9+3ALIvAts"
    "bn7hwNve68evv7WtqbWt08zkp/BeCaxBAK8KKK0di6hEkf/hm5OpxX1S/evgIaA2B9zQ/MHnB468"
    "+Gz/1vF8aXGtWsv0LR9wzhupV2uIgBhBfcOtXslksxgcUzdvmaaWUDs7crdOnL509Oj+Nw8FvRvX"
    "bt760vrdPX0ddEV4DK5a9Y0HEoNXj9cHR1EAVcLQYnLtbmxqRjeu7122dmx6Pyz+PmjS2sJCqeKK"
    "tztcsViyznsxxoIKzis6B9HGGAgIqUJrNuDrkZty6lbMsUybd8bUIWkJNK4mUdVZL6lG5UQkyBIn"
    "SaMbFbwq2liiCiqCqqdQSdi0fBkrOyv4sNncLSUWQgKSgkaVlFJckXI55vTQd1y+eAFnMuq9E0Tm"
    "gIAIIoKoI+NjNr6yg+c3b2F8OqJWT4BYAgtMR3X+i0taLM7KyPnz9PQs5qn1z0kYWDyCAEZAxaDe"
    "4X3KH2fP8Of5s3QvX0dLSwVTqjeAnnrmbjn1N8bG0jStWaOx+fSjd+Txtc9w8qdL2DBLYMB7D0Bo"
    "DW/seJpvj+Q4/MXPfnJiymMMS1q8QGzM5Pjk+JWr/xrbvKApqrpMT9cC27O0h3y+QnsupCVrsVYI"
    "M4ZsRlBRZqYd/Uu7yBgXxGpC05Sz/1y7VoFkIijlR4d/PXbw3f7VG7bPTN12qx9tX7doySOLTp24"
    "rJdHb0iYCQAhyBh86kiSlMcGerWjd0BMdHP0xm9fjadxPZ24MvIZMDE/KQAc/vLElZd3vbbizh3S"
    "ejIv64DzjXlc2E6aE7Lv79556JdTQ+/Ns0jjtxkcDPTcOW3r62v7feTvhXnTaYqFUhgEASIGp4p6"
    "30gNiscGmlS4fnvG71U1Qzv3BaNDow6G3PwOZW6GnwRW8XA47L2QNGQNuDJwZi7D92r5H2qP90ox"
    "RXzVAAAAAElFTkSuQmCC"
),
    "refresh@20": (
    "iVBORw0KGgoAAAANSUhEUgAAABQAAAATCAYAAACQjC21AAAEU0lEQVR4nHWUaWzUZRCHn3n/u9td"
    "SltaylGOcjTalqNijAKCCdEPRBDwSNeEGMUPSJCYSjSaAFpiJHggiRFNNBgCajTbEoFC4xGSFomI"
    "pQ22FNIiZ2krpbTbY8vu/o/xw1KLGOfTvJN5n0x++c0Id0dELXlWXNXb75KB8Txm5xEyfhq9Lg7n"
    "tAEqgEbUIixuqlEFRP8DSyWn08d+NrCh+Jd4TUlL8q+iS8n4PRcTdmFLorewLtmQty/2DgXnpw7/"
    "KddyIzIMvQtmvdS2fFbNUMv9SdV8VU2Pe2rFHMcMuHZan+PlJlULXNWZv8dvZr55Y/0IoDptJC9N"
    "wUJlbeuKz9g6WVW5acfp1ltcU6VVlRZVLqrSrnEu2/GMQdWCq6pjXmv7aMo3vV9Nqu4/T/HRaUJE"
    "LQmL63/63IqpWwoOdc31OwOdjie2L8BJG441RrWj9zLquDIuK5+F88bJohCeeo4vy5Bn43PHQ8/5"
    "BM7qnx5BVQUOZ0+M9HbkJNSj1U6YP1RZf3qI7PfeAPLuUDmXrLfX8tzxSxx3XE45Do1ugqvqEOnq"
    "J/DJvQAEX7mwOTeqHld0UJo1yYsNA/DkYgCMgDGgKhgDAqNWHzwYrB1y5Fc3KT8nHWlSlc8vt8GD"
    "Yw1AMiMe7rmO0E66Ho76qfy6DDlwnFmRAJ4KngdLaiw8T8zC/RtN2cqVydyQpWr8BP0OPhwGEz1Q"
    "F/UBeEeqN1FVt5RREjLRq5e8/p17CUcCVIRtIOWt2hoPwOtpPDJY1j2XmTMeYur4QmZOS9PiMUhz"
    "Wy+Q8mRoU2xyTnlsAfyW+R+j/3/4Uvo+tZyCDzaT/nzJ7eILwVBRf23msokFgUdLblnR2IV4p90Q"
    "u5Csjn9YUwml3r83QIXSZj+Vc5Lpa67NDszJnKRDg9du/Sn9ib37AN7NCxy60U2nuqbJ9UKtqhld"
    "qsGdnUqwPB9VgXIz4tkzAQSYUrs0o8rRnHOqWVdU/S/X/5hqCOwpkoM3Y1LnKVVJm2Ma59OoQ+6O"
    "8tRAalC1iKiFNbxZJ6b7tvVckpPqENF+9rseD+x5C8AwPWMsRtLUFVsCfqTbtUxhuphXSx+n8NRS"
    "RAwiLmFxcdf6mXtlle/9OUdZkj2dhqQrQdLlQF2U+l27URWfCSUnS0625TYPWPQOoXMmuLQ7nlmU"
    "P99fOOkHvdzX5B9yz4pnjJ3hny0zRs3yRoFz0k4wJWA40Wk4+O0GpL4TqbCEaTuK5OGSSs42V2rX"
    "YJyN67ZTOA6uExefa0y2FfCHUoawh8DtdhPELGUCQWnuRL78YpN3Y+t2SiMWFWF3WBQZ9pvJ3rJa"
    "Vz3xsS6en4sf6ENxcPAAg48gQkKRY7U35Pv9r3vs2jcMuw1SwVjKM9+lbmFF2A0RmpQo2LZG5923"
    "itysQgKjR2N8MNA3SHtHqzTVVwU7tu4egs47YXfGyGEsjViYkWIaWTN8LJvvY8WCNLKm/9NoBIhY"
    "d4P+BsPwGLQHfjaDAAAAAElFTkSuQmCC"
),
    "shield_check@18": (
    "iVBORw0KGgoAAAANSUhEUgAAABEAAAASCAYAAAC9+TVUAAADuUlEQVR4nHWTW0ycVRSF1z7nnxlw"
    "GJABZspVW8tF7FjuabGWQYyWxFRDxWqNqTaAhuibjY0+8KJ9MZWaNJpoTbwkhrQRitqbVZuUaqCm"
    "amqJENNaBAaYUm7D3P45598+TClq43rc+fbe62EtIClCFwS6GoxWPiIJt5SR/3bjQwDSkxDQwF1G"
    "w9kGA62QN0cgAEREzMyrq6XIK3+luaXAX9zpLfLeO3llcmTy57HDox9/dwQDsfEVjIjAzLT69Jnc"
    "srLNFXXpxe7m9HXuR3VJSuZVcwIzo0GdVeKRhQ4vaDS8xOPmt8tXZ49fPntpCD3jw0kn29Jy6l9t"
    "OZpTlrsl6I3IG0YYM1NBLF4MJvBNhDAMAR9ZeNhuuaqy7GvycuFWLjgDsMzfF8+dP9C707izfO3m"
    "rNo1DefMy3q+bzqB36LAHxAiAAmDwU4NugQhflUi5FnUoeJrFkoMpDZ6RGVluT/DW1RvpNlTXH9Z"
    "QWv+2Jgl309ITmPAbgGZDEgNYg3KklDRKJzRDAqfWZLyqxSOxoPW9LYcssmUFBFXERnVpiATxJlx"
    "CE8C7IpDCBNQJgwAOjSB57a3YPiTM3j6+SegXYsQTKSZhLbiQphL8WgoEgcTADZZxZYASkDFQmwQ"
    "YIYmsXtHGw61HcBd7iI0+fyAChM5gFjYRGxxYVksX5m/Hl0wWdoNYSWWaUvNJlzsPo2WrdvJnA1g"
    "z86XcLD9HZBIxUcXevHy6y9CCBvgkDJyI6yivwQDQAqKHKf9C/b+ekaNoT4436OZWY8sjet3T72n"
    "r5mzeo5ZfzjUq41qp0alXYmtaUqcqGNbT90EgIxkZrp9P8gfGy3xiNt0NxXqvpEBPcWm/pMXdIDj"
    "+vCFY9q28Q5FFQ4lq9MU7ciMi6EHLdp3dy8ACADMA9P9iGlCVRbPTUzhhfanMDjyE1zIwNeDJ9DZ"
    "9iwrlYCw2WCpBNEDHsJYhPhk4NNkUpkJQLbYt3ZGflGrjMe9CdwjtLupSHcc3KvtFekapVLJaqei"
    "UrsS7Z64OL6JaZdnEIAB7hK4WSTAZ9sl3iph+VlFTDS7FdYZGvlQ2OBQ5EtVVGzTYne2Kb+s1tRZ"
    "EIYTvmT9IJJuVg5Vpb4p95ey/Hyjkh15caPGpajUoag2Vck38uOyr4pFZ0ECeXjsn3urBWyFxFFo"
    "3GffK/2e/dSYbVAoAUwsK17vNKywBp+8Psan5vYgjO9v8bdpxRFQS35nv3itMCwPrWfq8Mxgg60b"
    "QPZ/uP/Rv4H74caTAPKx6vu2A38DD4yh3OQeqyYAAAAASUVORK5CYII="
),
    "shield_x@18": (
    "iVBORw0KGgoAAAANSUhEUgAAABEAAAASCAYAAAC9+TVUAAADxUlEQVR4nH2TbUzVZRjGf8/z/Dkv"
    "nAMHDhxADBEIQYhe0FUzdU5nQzcXNs8sa35qKzc3s+aX3s5yTSpz1Wz1pWyNtba20vJtumpzow+I"
    "IksCfJkBoSIC553z8n95+qA4P7h+H+7d1+77ur5dcAehiUgdDisdiRhICcBlCCW3vrd1GG81AFKg"
    "IxFDh8NKgwQEd4dACo2jmacHipo6d71c1NK8x+3z1GVi0euJS1cPXPz1y0PrIX7vUQpwtBDz+hpV"
    "tXLdhrZATfV6Vyj4XKFy1dJ3lqnzZ62KtqUG7cvJaGciOZM4lp2ePRk/9dvgo4z/A2hxAUrqdrz7"
    "k7+2cYWamfYQm4W/h7jx14B5NDUtz6HEMhzd4S1yFjc0FPBIK1QuxAyW56OTN3r//Or9zUbSaGzy"
    "ly9aq0+fYuhcj/VvIuFcJCWvYimfCtDkmIwKQxzITKgFg7eslsELzsOGIZran3QF13Ssst0L22Sy"
    "rNynJ246IwN99seJmDxJzgjUNcqXOrew2o7RQJY1Toztz2+lorZB/o6luixHXhkctPT4qBMrrfYY"
    "c0K6hZmTLqmtdmGJVn8B67q/huYWbi6q5ubBz6l5cw+ht95h2UA/hzdtEkMZUyslhTbz0kELYzaZ"
    "ymazGTxoEdQOZDJc/uUoSxbWUvnaTspWrka1PQYzUc4cOc5kLkcpCq/WZHN5pjPJrBxNj81k0+m8"
    "xyiQJoKUIzmzv4veffuQGnTjUpRlcWzvBxw5+AloN3kt8Ugpc8n03FD8+i15mthYKp6YKnH7hYPQ"
    "URTlQFFZEFuDW0gcLQiUB2kCshgIBEFPoZiNxqe+JzUmz0P82uTEgMtdrL0UOBlDsHL/Z7Ts3IVK"
    "pOk/fgKZM1n1+m427v2IrHSoQtiGK6CvRG/3A2kJ0HNrtNt0hGh3FTOpXDiLGyGe5FDXPna//Qbd"
    "XR/CXB7xUB1RCStdJSJtS3Fieqz7bme0EIiCw8Ut/Z3K3/ptdNjsKw6qyvpa+gZ6WaAC3LYTLG9/"
    "mpHhETaac9Y2b4PrG3Om95Xs+DOaiCYMSgDr8T7V62k2tXep/akqzT+L394uq+3tosJ+UVTZHXjs"
    "77ylee1rdE6qmlQ9tEkgDAruWzZT/MIZucjRvhr9R0l5bocqs7YQtHcWlJl9VZVZXRLSRynNPIG7"
    "437fPSJgADyOa8MPlExor0+nKwP6fH2VZdeUadvn0V9gjBQZxooHBszz4/zBR8WreA+cEsbkJa9b"
    "/4wc34YRIRTy/2/APGFQcl4UFi5YglqL3x+CO84HBfwH61GTL7BHfLwAAAAASUVORK5CYII="
),
    "shield_x@48": (
    "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"
    "RU5ErkJggg=="
),
    "trash@20": (
    "iVBORw0KGgoAAAANSUhEUgAAABIAAAAUCAYAAACAl21KAAAEB0lEQVR4nEWUS4jVdRTHP+f3/997"
    "520+ZmjUyVDSMowWQkWBQw3lItxUg2RCm4pq06ZVoM0qgtaRoEWbFtomiJA0mlGkSNHSMnzkcxyd"
    "O/fOvXfu4//4PU6LmdGzOhzO9/Dl8OUjLJYcfuMNA/BPuSwTU1NuP5vXPLNj9HGXJvR1F1VsLmdO"
    "/XX5Y86Xf2VHPMeQAoxzJAAqACKgyv36euPYYztff/WX4UJYT2VOMCjFoszMLkz/cOz42AfVC5fu"
    "LwugEMPikW/WjT3bv3rVimr1Xj708ND7w53GyI9ffWZvBBelwbM57na7do2vH+rv3X+ovf3AYP/K"
    "UrHVrO9Mfj+97Cg6sfeTg0+/9OLbVBtgHKo5PZr5y3evy4LNQAMDpSJbuvu02XZRHGKkVCAulDh3"
    "9NSh504ffjf+CDY8Oji8uz8V5coVh1ohbeE7LbPVWcg74CxYi2925CHvPYrSyZWNI/GawdL4dpiI"
    "m9DnLl7o4t4c+eVzRrwVsgTxOXmWonkOzqPWItaRZ17EqQT12jNbl9pgVEqgKGzY0PXFreqBbf3d"
    "b617YkvIQzCKw6piUWwIIIoAzjkcUIgM6jWU/7thfm61D37LCx+KMYYQAsde2XN1bO87m+yFs64g"
    "zvikjtoWsc8gS3CdhDg4CIrP8hCtG4m/O3v+4p4zvz0ZiRB77wURjtfyCldvbLJ/nODO7WusHRyi"
    "KJZrt25igueRgQHSJOV6fZ5NcbdGWzpEC607CsK+fWL4dDFGadqcxzrac2U9efU8FRfACz/NzHK0"
    "bTHFXm6lOV82Glou9CgSU02zqoBOTk6aeHJy1ACh2mzMstCkGBdUpEfzYIQso4ceursGIAskHU+/"
    "6adLCpBlzCadMgBTEDO1GNC03S7TqCHBU9ECnVYHvCNTQVyAjqdpFRsV6Q0xNrVU82wGYJKpxWQD"
    "VNuNsjbnKXhlAUOrlYANtFBCCEripe4DbSNStEI9y7iZpuVlfTy5ZKmWNGbTtEHROemALNgcMkgU"
    "4qDgHHUf8FFEZJ2pWUvF5XcBLoKai6AIXA/1aj1ZIMocmYjWnIXck4jgAkLuqAWliwhCkLk84YrP"
    "qsuOzHJzCebmkrpirWmrZaadgHNUNKeVWfCOaXIya5XgTcW6vArzAhwBjbeCgvA3WmtmjTzkrjA6"
    "PKKrin1amZ5hdHiEvlIvN29Ps21wLdrdQ16ua1u1DTSWEKTxBKgBApT/vTvTep6e1W/WRb12pO4t"
    "r9XbNLVJ1XtebmZ0NdOAC+bPVnsGqHtFZAlL7AczAeEpzO7xOPq814WVDkTF0NJAAaEgRlMNOAz3"
    "xEx/r+69Ou7k0nuCPODiMutWrqDohhBRyFiclYBMAYOqkOfTQPJAA/8DXl91hWlU9IUAAAAASUVO"
    "RK5CYII="
),
    "usb@20": (
    "iVBORw0KGgoAAAANSUhEUgAAAA4AAAAUCAYAAAC9BQwsAAADEUlEQVR4nH2Uf0jUZxzH35/n+/3e"
    "nZLij9SoJaU4UYmKDAq0q/xjjdgGgf21Qf2xfhBjQcwxiO5of4wtaBEVGYmNoeKPXDOhYAd3Dl1u"
    "oVZuroVmNH+fnWee5919v8/z2R/XWauj93/PG97P58fz4gHeEBMA6OcDlXCxAMfPb1cLawCQ9d1k"
    "9e6nktfVThwGgOoXfnIxEzMT4M0o9c6PrWKWJd0LQRR2rSUC4GKRNJe4teDHqQv5QWYMyHBekLm4"
    "YbYZTq/ewqwxM7mYRWIcwMW6k1nH1vZ389oCLHol06+WRXdMzry9xMi7VvZ6IYqniZedjXUHsbXw"
    "ANU4K+hi70N1y/d9zuefbMjckLVNkYR8phZGG4aP6ABxztfTFTmbVnzk7494/K7seuwbXA9gB2en"
    "9eHRV1eDeQcfLhamFKtpQKQBoNBG3fjw3uaMqjRPuDzFLtPFCZuzp9SUsXgHFgw4Xbq1JKPmICT8"
    "iGKl1LE4p4RU4yWPHSn2JwNYDNgdFAs9KWClwjABSBM45mZ+OhMWLDVyKEOMzdowMbIkVGf7bdX0"
    "+2+ahlRq+uNP9NX3ICrTKArAtEzsJ2l03L0jUqHor0dz6svT1Uh/7hNAXYD98w1CAxCYuwl45iHN"
    "VI4BGA/lrvjCd8Zx7sBR/tcU6nrnWQQutcHnjuoACOMzi1YIRJXFH2i+s+3WVNigIMPYU1plFeW+"
    "F/nlHxNNHacwVPMtttQaILIQZ9G5kg55RkUXs+1mhI3a0QVqsUyqiyjsbfUB2ze/eO9X6UlQULYW"
    "ziuXUdM/gR/mTNHKTB97+wAAGoDq5LwSKJ7XUbXdfrw7KH5my3b678f23LaCeCVXclbh9epwenX9"
    "m6GfHB5mnLSWbJ3Mhru/F9higP8PuVhud/cuC13H0mVu+s5Iv1KYtfTYXSWt7MxyICcfROrVqvoy"
    "sooJRCEeGp6h8jUZPG2P0jqk0IOxScawH8wEesm0ntgQyC0AxLTG5s+UxfX0TtFqvj/i5xuNR4Hh"
    "53C7BQCVfE4g8U2sQuan7wOO/Nf8Zf0HPnl0tmYIadQAAAAASUVORK5CYII="
),
    "wand@30": (
    "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"
),
    "warning@18": (
    "iVBORw0KGgoAAAANSUhEUgAAABIAAAAQCAYAAAAbBi9cAAADJUlEQVR4nI2TS2jcVRTGv3PvzH8m"
    "SZmm1kykgTiJ9hEoorUNVoqDfVAxWqpldFcjKMRNRKrYUmUolRYfkFJRRHGt/RNwkUUXVRPUbLRC"
    "QBOCmRgK2moybdLJPP6Pe+/nYiwuGtHf5mzO+c75OOcAayMkFAB8P4ojM2N4Lg+kRQQk5F9qbod+"
    "QQOCyxe3nHfBp6S7wNLXD14EkPB9XwP/Q8z3oSEKn5/G/nD5DZJnIhsPB7Rv8asPMy8BCuPjSPyX"
    "jpBUAFLzk4/OkMcd4+0Rg60xedT8MfX40vB2dJJUxWLT+tqW2LQ08UH2JM0wGfSHpe/utvOTPZbV"
    "rSE5yMmPez76J3cNikUoknI2j1x5+mCF8QFTLeXiffe12IHd601w5V7DYHe0PHvQnB9Av4jAL+B2"
    "sVsdpj7b9gX5NHmtN1r5udc+vKPDPpbPmWBus+WV7ohmP6f9zd8CkOZSmigAoA8tatT6Q96hvr33"
    "HEb5lxg1p1MugFYKCU2kbA2u5jSuLcTb8l17Lgy1HpVnRi395lSKgKBQ5AGybedTfSNe63WaxbK4"
    "RgjPNagF0EoEUQQGMWy5Kip5w/UPbDpTAO9AoUgCoibG81rklHv1dPbNnocyvW5hPpa6Uaw1oKJQ"
    "qnWFRgggaoDVBtCIFX79zeR2tWwafL39hMgpNzEOLSKC1/rZd+zcjqlsx5IyV1dEnBUah4Rn8OWP"
    "7UinPOzpW6SJlKiEkIbUXetlcbE9fnto7oGROZlVJNWTg70j2VzNs/O/U9UDQTWE1COYZYuFmVUs"
    "TC/BVaxgNQZXIkHdKFsqu2x3LX3ohY53SULOPdv+xPOvZMcylZIxN6lgATpAK6BSBbpf7sSGDRqz"
    "Z69CGYAA5O9TTG0UXk/eKe+/c3NfoiXjujPJP4GycxIJaAlQEDsio4FLx1cl5Sl4IV0YAQKIozS/"
    "zTls7KppLy13yd42dJ48kRy7fwt3uYqDJACwKUgHtCYdHIGGUVBKQEcQzSjrFH6YkkvH3ouP3Pri"
    "thd36kfWpZAWAa2C0gLnHFi1gIZGWlnRGjAGEjswk4TcWMbqJz/ZbwBEfwFH0KehVjevWAAAAABJ"
    "RU5ErkJggg=="
),
    "warning@48": (
    "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"
    "bb9m2cnPoQAAAABJRU5ErkJggg=="
),
}
_SYMBOL_IMG_CACHE = {}


def _symbol_image(name, box):
    """An embedded ChatGPT symbol picture as a
    tk.PhotoImage, or None (callers fall back to the drawn
    glyph). Cached at module level, like the header art."""
    key = "%s@%d" % (name, box)
    if key in _SYMBOL_IMG_CACHE:
        return _SYMBOL_IMG_CACHE[key]
    data = _SYMBOL_B64.get(key)
    if not data:
        return None
    try:
        img = tk.PhotoImage(data=data)
    except Exception:
        return None
    _SYMBOL_IMG_CACHE[key] = img
    return img

# Drawn-glyph fallbacks for the two composite renderers
# (used only if a picture above ever fails to decode).
_STAT_GLYPHS = {"document": "\U0001F4CB",
                "shield_x": "\U0001F6E1",
                "warning": "\u26a0",
                "check_circle": "\u2713"}
_SUB_GLYPHS = {"magnifier": "\U0001F50D",
               "wand": "\u2728"}

# === DEMOCOPY3 ADDITIONS (2026-10-23) ===
# Height-true variants for the rebuilt stat cards (D3),
# plus -- when ChatGPT's extra transparent sheet had
# landed at patch time -- the clock (D1), gear (D2) and
# white trash (D4) glyphs sliced mechanically from it
# (singles in work/symbols-sliced3/). Keys are
# "name@h<px>" (scaled to an exact height) or the usual
# "name@box" fit-within form.
_SYMBOL_B64.update({
    "check_circle@h84": (
    "iVBORw0KGgoAAAANSUhEUgAAAFUAAABUCAYAAADzqXv/AAAu6UlEQVR4nN29d7wkZZX//z5Phe6b"
    "7507eQaGOBIEJCO4AmbU7+rqDri6rsquqKu45oTugHlXXRdUjKtrlhlUUEDEAAjqyoKS48AkmHRz"
    "6lD1PM/5/fFUVd8hKCrq9/ctXjXdfbu6u+pTJ3zO55wqhP9bF0UAOLt4LJezUYDir/rn3an/Py1r"
    "MaxbE6FrItYRVYD+rkUR1hGxbk1YH+3n/sTLX2YnwsELV2E4Gcc8iwtvRLxUv1D/zU0/6Z+1k3Xb"
    "bMY+siaSujWkzb6ugdmbDvtqw4hR0N3NVRGuImIEZQ0e+fNb858X1LUYTjrRcNLVrjzYyMSsvO2F"
    "e01Pbj+wmc0e7Hy+v+JWgSxG/WLwPeAjQDFiMaZFHM0aZEKdjKk12+ume4NJ0hsX96y89b7Dvnm/"
    "4jtIriP6c4P75wFV1xo4BwQP8FnV5D3XnnJkIx97amZbT3NR9nipyULpS6ErQqIYNTE+jvCxQfEK"
    "AioAIniMc5gsh1aONh3a8GjOrsjHt9Sj+i+7k66fPPlJr/3Fejk1C/tAxHrgVNyf+nD/tKAqpvgV"
    "L8Ae1z1nn9GJnS/Maa1xJj8sHkpT01tDe+qa9yXW1/BEBoikpqn0arekWseIwSBYtWTGakbGnMyq"
    "p6V4C7mDpkoy6RJpZOKncpjIvZH0xojkS/317nW7nvnLXQrBcm9DOSec4D/F8qcBVRHWYzgVJ8Ci"
    "a5523Mz06Gsz33oug2YwWdyLH+q2Wb84EpFu32/2ZTmH6Co5lFWs0kUsl2EWs4BUEiIRQLHqyMnx"
    "WCaYYhuTbGQnv+Febtb79C69T52bVGZFzQgmGssTN50hGVuiWvflvd19X5o4+ef/U4H7JwoLjx2o"
    "4bjDzhZgLrjixKNm85E3W81faIbrSbJg0GfL09x2ORnUQXOSPkGew5EcLvuwQPpo0mKEGbYzySjT"
    "zNKkRYZTL1Y8KESIdkmNIfpZKoMsYwGLGCDViG1+F//jbuV79jqulZs191OeGaPJjnbNz2QwSR5J"
    "8jVJBj7QfvYv7oXO/j5mOPBYgSqAX2u46hzDydgDrv6bZZum7n1bxsxrZFGtVls0YFtLU+cTiQ52"
    "+8iL5USeFh0tA6aXbTKqd/iNbNEdjOsMTXJysVg8HofFikfxeDyKBtPSkqymxNJDN0sY0n1YyUHR"
    "3uzBQsbsBJe4a1kvP2Sj3K3Mpr62SSM72or8rI7HcfqZhQOLPr795KtHH2urfWxALc62QVhw2XEv"
    "mmyO/5sfYs/68iHfXlW3Lm5Gx9iDea2+QI5MVnO/GeE23ciITiECsQqxRKrqmdUWMzRp0JIZbdGS"
    "VgFvWD0ep+EZCCHaGlQNIpGm1Bk2w3Ko7MNxciBLtI9r7S/5uLuAe7hPZbLmog3NxM3lEjXMvfWk"
    "681zz7vxYi1pnvzxsfaPB7UA9Fl3n9n/s9uv+fcmM6+qLenHrF7abgzMRKvdXmatvIK/ig7iFjZw"
    "h24lJaJOYEkZOVM6y6y2mNUGc7R1WpsyS5OWZFixeFUcDosjxxUW6wr7VVQCMzAq1LVOXbpIpEYq"
    "NfYyS/lrOZ4D/Aq+0/4x/+a+yoTu8vG21PnNUzWmIDW18056wlPfdvnqT7S5kpiTsX85UIsdOPAn"
    "L1i1afLur7d7shP6913Znt2rLqJZ9FY9jX+Oni+3yN3cp9tYKUvYh6XM6iz36BZ2MMZOnWJKGzRp"
    "0qDNLG2d05bkWJw4HJ5cA6DBVilADUFBRVFVFEUFDEKqKd3U6aGLGnUwEXvIEk4zT2WpG+T87Gv6"
    "33wbaUQ+uUPJdzaSqGl+NJD0v3zsxb/ZxpXEnIT7Q8PBHw5qAeiiS45/wvjM2DdlODqg+9C9W9OL"
    "2vET89VybvTPGEQu1WvZ2yzjiXI4EYb7dAt36ka2+p2MMsWkzNHQNk3atMnIsGRYrDocGqDUAK7X"
    "4PQlgCXJ13n/AUQixESkmtJFFz3ShUiCMRGHmwN5CU9nS7ZR3+b/nW35GOl9kbV3T9aY5s6I+t/m"
    "Z9xxG58l4QzsHwLsHwZqAWjPuiOf3mxOfy1a3L04eeLKdqNnNn6TeyHvSl4mV/pfs4XtnGQOYSH9"
    "bGGEjbqdTf4BtukoYzLNHE2amtGSjIyMXHNy9YE0qauSUwBTK1CdFrVAcbwPBtWIICJERAFcEmpS"
    "o58+EpNSky5ONc/gWH8A7258lB/KT0h21nN3y1RNJ+yOVNJ/aJ++4Ud/qMX+/qAWgA5959hTJidH"
    "1sVLBnrl+MVt192Kv6Bv5ZnJcfINvZL9WMoRsg8TOslduolN7OB+xhjTSWZoMEeLlma0NSMTiy2s"
    "M3BRj8OFWFoAqgpOg2U69ThVjBhEQMttABOKLsSErCMYIiPEEtOtdXrpod/0g0l4ojmc03kW57c+"
    "z2fib1CfHrb5DSMpm/JWmnS9tPmPt1/IWmLO/v2A/f1AXYvhHPzC7z3pxInxnRdHS/v67DHDth5p"
    "dFHtQyyu9XORvU5OiY9m0Ne5X7dzn9vKBh5gVKYY1xlmpRHcXdu0sSEBlTFTlRyH1TLDd6xTleK1"
    "4n0AUKAAtWOxgmCqijZsICassRoSiaibboZliNR0s8Qs4Z3m77i6dS3vkfM1bSTO/XRnzNasHddr"
    "z2u/ZsOPWEvMOY8+eT16UAtAhy4+4eCpHbuujPfoWagnL8l6NYovNh/CJ5bL/HVymnk6noxtupON"
    "fhub2M6oTDCh00z7kJBaWHIsuVqsKraKmxpee4fXED0DoAVoHrwq6sN7ENycgrl2gDahFilDhBFE"
    "wgkwRhBjSKTGkBmg3/Sz2CzibDmdG+1teqY5i3gk9v4HYzEjbqSn3vWkmTfcd095/I8dqMEAZD89"
    "M7nv/Mt+ZhbXjjHPXNpK6yb5qZyHNZb17ip5YXQiORnb2MUmv53NuotxpplimhmdoTHPOnMtsrp6"
    "nPrisXB3rwWQWrB8LRDyaPmelscnVSmgAlIgKyJF3C1fd56IESQS4ihhMO5lMBpmgGE+YP6RG/Mb"
    "eJM7R5OtqXNXjaeMmmt9X9fTuHaDZd2jKxDMowJ+PQbEbz738g9LX3RM/FdL2lnaTL7FB+g1dVnn"
    "r5a/Nk9mQie5Qzdws9vAHbqJbYywk3FGdSpYqbbJNKflw9r2lrazZM6RO0/uHM56vO+s6j1qPWot"
    "ah3qPDgHzoMtVqfhdV5u6/HO4Yvnmnt8Fh41d2ju8JkjzzMm8mnG7BjjjHGWfo7ja8fzVn2T5Esb"
    "cXRUX0avf1I0Ov0R1uMCDr/bEH87qIqwlkhOxXV99sA3urp9Q/cJK7LWklb8QV7NAcme8lm9hJPM"
    "EYzJJHfqRm5x93C338R2HWVEx5n00zR9k5bPaPuMts+rNfMW6xy5s1hr8dbjna+AU+vBOsR7xD8Y"
    "PAWrYB1Yh+bzQLbFNrmrXqv1qtap5h5vNYCdOWw7ZzqbYtKOMOknOMt+jjVdz+FF0WnkB8xG5rDu"
    "tqZyZm3tXmdwKo61v7sz8dtRVyIEt+DrRx4zuWvsquSooaT9pF6elx0vn4rfKB/Ub3Kg7EWdiM3+"
    "AbbqNkb8OJM6xxwtsiJu5ppjfZnZHbkqrkw4hTtXLl+5uyLFWv1dQ6ZXV/69TFTV/oZ/jOn8IUgF"
    "ICbEXBEUIyYCjEEikDgiTiIGkgGGkkU8zqzmbXoaZ7Rer7fO3eajn6mRX7dn+/Ze9lcTr7rhlt8V"
    "Xx/ZUoN8xxpdm07tGP+4LI263KHdfkV7qXzUvE6+6C8HNSiWO/Ve7tZNbPE7GWGKSZ1j1jVo+qY2"
    "fEvnbKYNZ2k6S8s6Muux1uGsw1qLs8GdxfnK8oJ1ueD2uZv33AdrdR4K65V5oUCL5+IKy7YqWFCr"
    "iFUIn1fNQTOHZg6f5eStjIn2NBP5OLf6O/mG+QkfjN8nadJr9CixfqUZmNmw431rVX9nyHxkS10X"
    "3D792P6vaqetz6RPHW5ne5r4a8nHSONIvuou5choP3bpKDv8KGNMM+MbNHyTpm+TeUuuVp0quQtJ"
    "yCuiqqh3oB7vFPHzExLgtcoF6j3iC4uksMiCTpWWrITkVGWPeYlK5yUnRRUJzLXQzkWk+OJIIRYk"
    "jonqdQbrQwykQ7w5Pp27p2/nP/JzNLmz7uyP55KkXTs1+9CWC1lDxPqHlwwfHnVFWINf9uWjh7O5"
    "ubcne3T5bI/cPE+fyeHpvvJlfykrzQK26y42+x3s0kkmfYMZbdHUjLbLaLuclnM085CIrPXiS2uz"
    "roh3Fp0XO0MickWycR3Lc77axpeW7EIYwIU4TGGZWlqw9+EEeI+oEmMkKkSX2CM4VyUtzTy0HNrK"
    "cK0W09kEU3aCr7vLeF73KRzCsWL3aInZMxXbaL5jv8v2q7GukMkeNahnhxM6tn3nOxkwe+sTuuyg"
    "WWTWpqfLl/wPEBxOc+73OxnXaaZ1jjlt0PQtWi6j7S25d1jrxFknar0EMMNauW8JmOu4beXGmSsS"
    "UQCqzOLiFHFFknIKLlgvHtQFANVTxGuHEXC+Te4nsDIl1o1L7qaJfPH5Kql5yBy+lWGbbebaU9xj"
    "N3B5fD2vTV+JRt6wX5Jrnxy5+bLW3yMoax4ev4f+sQjCfV98wv65da9O9utzdomL3hS9VKbSNtf5"
    "W+mTGvfrLkb9FNN+jjnXou0zssJCc+fJrMM6h3eB3qhzgQqVsdIFS8J5xDukokfzrLR4Td55LwBZ"
    "hA1Xfp5gtR7wIXOpemKNcdksi80C3r34zaxf/ik+t/xDnNh1JDafJPIm7EO5T5mDVo5vtMlnG7Ra"
    "E6yzl7KgZyXHx08TNzAn0Yqaujx/y6J1B/WyHv9wTCB+CKgHh41aO6deKoNRT/74uL2P7pesSZ7B"
    "B903MOIY12km/BQzvkmjiJ+Z5uTOYQt39C4QdZwL8c+HAw0lUvlYVEKqiBLA8UV0rN4rtq/iqj4M"
    "+y5oQHl4qqSSkrUnOLznUL6776dZla6otn7l0Gm8acs5fHz0M6TxYnLnwokTwBmwGc5Cw8/SSrZy"
    "YffPOL3nDH5Rv8rovup0MwdM/WzqFGA9ZxPD7iXsgy1VOBW3aN2Jva6RrYn37lVdYswr9HncJTu5"
    "Te9G1DPpp5jyDWZ8i4bPaLiMZpaTZQ6bOWxu8bkLXU7rICt2OteKU+o8V5fCtbXI2mI9Yks390UY"
    "mGetlRXr7qsPoCekZPk4J/QczRX7f5mV6Qp2uil2uWl22EkmXYP/2HMtZw6fTtbYRpILkgNtD22H"
    "Ni2+kWHn2shMm2vyX9HdO8QJw0/FLZ9TszQib8ydWpRp/sG2ujuo68LrqQ33P8Wk8Wq3utsO61Jz"
    "fHIc6/3PgIymNpm0c0y7BnO2RTNr085ybO5wucXngQKRO8iK57bj/h0wXQVY5eYukPqyKiIvqVYA"
    "rSL8lfsXnys8AfUkJGTtCZ7ZexKXPe5LDCb9jLkpDFEQsCXG4ZlxTc5b9QHOHH4V2ewuorw4ce1g"
    "BNq2aG6xrTYT7RGu5CbWdK+B7tTIksiTcFLtjMV7cQ6eC4geGdTbUEHws/lp8eIuY5fk/pn+BKYl"
    "40ZuxqDMuDnmtE3T57RtXlhlCWbBKTPXATYvElGZDPJ5PLTgn1IlLQfOFo8d7qplLPXz1up1CBmK"
    "JyUlyyZ4xuDJfGf/z9AldabcXNHH0opmCUKGY8rNcd7+7+eVy16KzSaINOpw38whzRzfytBWix/n"
    "P2cwWc7i+p5iV+SWHrMwn5s7pcBNHh5UDQmq67OPW+by7ETdO/bUjHlydBw/8ddrrtNYn9H0bZo+"
    "o21zXO7QPEdzC8Uq81bNLZIX7l+6egleQYtK63xIIqrIe6e+F6+70SV8oUKpUqNGuz3GKQMn8539"
    "zyeShGltgpiiINNKsAm6rNDE0SDnQ/u+iyX1xbhmG9MG2g7JPL7l8I0MP9Pi/vZ93B7v4Jj0iTDg"
    "iYZjNOb5a3RdBLsnrA6oV4Xn7funjqMuy7P943yxLpP+aIjr5GZqkmjL58zZjEaWYzOLz3I0s/is"
    "4Hq5L6qU4m+la89f3XwAfceS3Tzrc4EWqZ9vob7DGIokp2EjUklptUd41vDJfPvgT5NIzIw2UNAA"
    "oFenofniAEuQG40IDdemJ+1jJcvQ6TbSAtoKmUcyjzQtvtUib8/xv/5GDqsdD73dRveseTVyxPfe"
    "+c69OQdfiC3zQA2TcmGZbT89WlIX7Vc9wj5eJmSWEXYhKszlbWbbbfIsR9s52nb4gu6Uyg+5rZJP"
    "6dZSWF5FmyoxZPf353PXMlmpm2fB5WfLkICSSkK7Ncpzh57BhQd8DlzEpG+gAg4vGsxIEILgrR4v"
    "4dGqJ8YwZhvsGBmBdgg94rQT0zOLZo4od9yZ30lfuoTBrqW4ZS6XhGG7beKQB4eAjqWegztSz0i8"
    "1SPN8i5AzBFyEPewGUdO22XM5m3N8hxt5WjLBlDbIaiLtSrOqc478PmVj5ZgzCf4pXXaQoUqanPN"
    "O8lKHMU2rgoNJe1KSWlnY/zN4udy4SGfI5KYKW0GQLVoYqsXRAJDk1K4Bm/AeUdX1M36nVfxwAN3"
    "EUcR6ix4h7ji93IPTYuZc4y0dzIXW/ZJVkNPrtKTiG/mh/GgpQRVAL3to1csJ5VVfjj2cd4r+0R7"
    "cqduRNQy3W7QyjI0s9CykPkQS62DAswShKr0dBoALaW8MmPPDwulJVpClvd0ZL6izKxCQOnyQE1T"
    "2o1R/m7RC1l/6GdQgRnfRCRMQ/igNVTPXdUYLAivdwwmfVwwcQ3vu/BtRC5A4X257yC5R9seGhZm"
    "Mmx7hvvYzh61A4Saiuk2qHBIRa2KJZD/szGA9xPNx0vEYtvr8pWyyPSYXjbxANZnzGVtbDuHZl5w"
    "TlfRmdBAKuJeaMeLKMV7IKVaUgj2giJlXCRk45LoS7FNkPCpBBItwRAhJabVHOG0lS/ka4d9krZ3"
    "zJF1+lJFCxsCsB27KVovzrEgGeD7U9dz5mdeyvTcAyQrB/G5InG5jQcDYgEVNMmQVsp9uoUD0z2h"
    "r0sYbINzBy74ytH94y+9brr8gd0olZ/NV0t3LPTlfq9kJW2TM64TZFkuWSsTWk7IHFJmc+eRUuDI"
    "3e4xUsF4g/FgNCLSuNBEO4kGpSL4WorNpQxYhpGSQhVLKint5hh/t8epfO3wT9NwGdPa7FhlCT6V"
    "BIuXTgNbvWcwGeCy6Rt53adfxvTOrSSD/Xhb6Ai5hjUrCoGWK4oCizQzJvwkw7IMSbvFL4i8RNGy"
    "2Ru3rARgbfjl3cpUN5OtivaoQ92wt1kuu6Jp5nyTOM9xmcVntqRHqs6JzDvgKjOjGBOpt7loNg2a"
    "BACNEqcDKNIpV8vPqxSP5dnVqrcUunUCRkmikJRessff8ZUjPknT5czSBhGcOlQFEaWkUEFE1E48"
    "9ZahpJ/LJ2/gNZ98KWM77yFZ1h/mstSE2r+ya8FHgkRAHAzGZJZddhc+qdNluqXRM+4E6XMPZCuA"
    "23d3/9tREYHIL5ceAxGywixl1M+S+RyTebRdZELrtLBIDVVSEaYK5T4iwuZNepI6r1n9Jk4YPIqG"
    "a3LZrp/y9W3rSKQLVcE7F8QPF9R8KSbEQq0vRa9Pq6ifakJ7doRX7PVyvnjUeUy7JrO0EUw1bKFo"
    "ETWq6FmFDfGOoWSQH4z+L2d+/MWM7dpEunwAbzScNC2SYfFBBYgMpHQ8KHPM5VNoLaFfemjEziOS"
    "qHcrCxznWepBKEZQ0X6JAIlJ4wE2mFHyvEXUzNEsDxy07BuVtXrhzl6V2MTYrMGi+iAXHf9Vjh88"
    "sjrzL172NxwzcBj/cuvbiVwPkksoXeepI1r28EsPDqyJRFPacyOc/riX819Hn0fDt2mSYzBFhteC"
    "PHW+ToMmjUooGvqTfr6z85e88T//nqmRLSSLe3GRR0wUQHRUMqJqOJkCQSqxEmhV25L5WaaNo+56"
    "wVrECCgD8z0+dAfPRtU6IXepGgUvYkUY8zOQW3w7ZH0teBtZEEWkiD2aO2JvsPkcS/qGuPzJ6+X4"
    "wSMZyafYaafZYacYs7O8fq9/4vzHn4dvNxCXI152E0OCjFfZFyJC4lOy6RH+cfUr+K/jzmPKBTG8"
    "4KFhMqCIoV4oCL6G56JEThlKBrhg5zW8/mMvZnpkK8lwH94ARgIjsR7JijhaiTZaiNgetSCZD9cX"
    "uCajTGNygZYrmUTXfFBjytilZwttDcKA90QSkflA5jWzQWjIi5jqNFCngsAbNTg/x6LehfzwuAs5"
    "rPdAxu0sGhmshomoFp6GneQ1e72EbhFOv/6fEdeDqEGdrdopUsRPjBDHMdnsGK859FWcf+xHGHdz"
    "NMgwhcuHNowUk3+dxFQNUTjHgnQB68d+yVv+42XMjT1AsrAHH2twbS2OoejXlAMYIYYUXygCuUPz"
    "qAJ+mhaaS8BEInCPVPtzttJGcAZcORPqwZXtj1BZkPtwRqtsH36026asP/7LHNZ3oOyy02SxkldD"
    "ZoVUKZ5tdpKXrXoxXzr6szjfRiINUyN+XrNOITExWXOU1x/6z5x/7EcYszPMaRsVilmrYnpFtIwS"
    "lAbiCcJ4X9rPN0d+xhs//FIa2x8gGazjRNEonDi1iuS+kiV9KUnmvsNoCgFISgv20CZcv4HTop1r"
    "/ENBVSA2ihdHM1AJrx7EhHPn5lU7bSeBaoTkFbsI15zhlQe9Qk5ceLTcne1kVnJtu1xdRdUDN40Q"
    "1MCIneYf9jyNzx/zSaydARyiEsrczJF4QzYzypsPfCPnHvEhJl2Dptgiy2s1qRrEkSLTSycxRQ4G"
    "0n7Wbf0Jbzn775nbuoV4oCuwcwFVF6omnSfMWB84aa6QKZqDlvQq1w5bwWCJsDYXNFAt2n43UGNA"
    "ORsjiKoxczQ8TDew1lPvqkPkq7hTWalVkVDtKCYCJ3L8wqPxBCtCy0Gx0oWKxEEoF1vieCCf4J/2"
    "eRGpdbz8p6/GRDWiKCJyEdnELt5wzFv56FHvY8LO0ZAchcI6Q2LqLA5UMBKsL7LQnw7yha2Xc/Y5"
    "/0R7YhfRkhrOqGIMogg2JDYRqTw9MA9fNRHwQAQSaehkeCUSIEpQEqzNQsWYe8QkjYfG1NsR9Qo5"
    "O7WlgNMxN05CPcSessLIfJDyivIzlBoespztjREMkBCRiBGDqGoQMkpnCI4anMMaZYud4B9WvwQj"
    "wsuuOQNjUrLGJK8/8i18/LgPMmJnaRIA9eorawQ6wIYSEY8ndspgOshnNl3C2g+cgZ0bJV6a4mJU"
    "YgmtGIeKhP3SijvN48jlvpbdGdupCtWASerq8LTa4zDnDS3Fx/7+h7r/rsKEMr+RlgcrOulGtYck"
    "bKKh2ggxL7hIqdars0DEl27/JttpMWh6glviJWTjTj/OS3GVSWG1TmBzPs7f7/9ivv2Mb5EmOWf9"
    "1Xs494QPsc1OMCWtSqarirB5w2i+ANkSeGRvMsDntv6Ate99JW56lHi4phqjEhXidNn3KjXbqosQ"
    "eHa5Uj4PoUVNEV00QaO4Di6nPTWpzBFr004Rabh8aH04Nbsr/zWzkVkHTS95NsferAzZrfRhpKrx"
    "xYPkgm1bImrceNOVvPqHb2M6NtQ1Javm8ynEDACp6vPwjYI3wv12kuevfC7XPvsa3n/4exjzczTE"
    "huRWnIRiwj9YbfFd4cQEhauv1s/nN13Ku886HTcxhgymweKiknAWGV6rnap4cKnfljssRSMyPA/O"
    "iAo+giQaRNuObHpWySMh1zG6+7fPM/IC1NcWx9wV7fAzmaMZcdfcPTQQorgPjSlGlEvdTKoYa9oe"
    "nbMkpofvXfAJ3njxO8mSiH5fD8pKeTydurM6yHJiPxfPZjvOwUNPYJebYUqbBW0KLuoftFYnRpTY"
    "wVA6yFfv/QHvfecr0bExoqEURNVLWQZrBaR6is5t2VgEtR2Q1ZcdXEoBSBQRNYLWI9J0IVPTD+Dn"
    "ppFmBDkP8I0nTVCpNQ+y1HSwtl3n8ikmIrN9dovm1tMT9+FrBokjxJigLhU7E4Tk0MN3XkmGu7hk"
    "/bm84dK3oUnCsO8CNFwGKdIROMoBNcqZVCUXZZMdZUrbeA1ZvtOM1t3BVXASsvxQOsjX7/kh57z7"
    "DOzcGLI4RWPVUHoSKqRS4K6ahVrlBSk0i47mWypoleEFG0gR7YlI4qU0JjdD7pQxhUzuI7rQzR+s"
    "CE9uC58efuXxm/B+s9nh4tnGTh1pjjCcrIAuDVpepfCG8Ub1YVpPBEjA9QrJHl18/4Lzee0P30We"
    "JCx0XUVE7GibHXApa6Iq8QRH0EDoK0gFr1J4q2AlqFh9aR/n3/od3nXWK2g3x4iGA6BFCYMpXLuM"
    "nVUeKEcMveJ3ayh6SkFLKx2NkKzrgvT2ipghpsd/Ay2BMTBpdANeQ17aDdRz8Kwh2n70pQ1VfwP3"
    "N0Xnpv2m2btYlhwIdRPEYqVIWtXsYwlDOIIIXF2Jl9a4+Kv/yasufQtzKfS4Gi21leu6Yu3ESV89"
    "r2r5qkKSqrApY2hiYbA2wCdvuoD3vuOV2MYE0WAt1P8GKcOLlonJ75acBKuiuUplsVYRryoqqvOb"
    "i2hAKInRvohoYE/EptIauRtG0khHXeYHar8E4KSOSL17olLFpPIT3ZHBzky2jN5MH3tDTz9aKyxS"
    "0JLcSXnIStXaVRv+mgykXPzZT3DGd99CM43o9gkZBbDqw1pZItXkSRkeSlpTZn0KC06s0F8b5Nxb"
    "v8kH3/FaJJ/DDCThtJh50ytlTHQITkUsAcxy/qrsMqAqqqrzWt5lsgLQJIKaQQdTkv4DcWM7cTt3"
    "eXZEEZnfyDP3uqMwzOqnO6CGKTbSRb0/15l8p9kcpWMjt+DblqGeA9EBQsKKTSi0ihkcLSsNC+Qg"
    "uaK54lSIh1Iu/cyn+ZeL/xWfdtPnUzyeirzScXmVQvssrNmjoVoSVETUiZI4GKgNcO7NX+bf334m"
    "xjVgQYwaLXw9jA5hERyiDqlAogNYR8MtXpdSY/G6zPaYIpd0C7Kgj97kYNpbfgPjucoOB8jPefst"
    "c/BIwxSFl7XOH79f4H9lhxM/ucOPj97N6tqJMJxgaqpEBi8RGmQixKG7lXOuaIBHiu+GZFnKJZ/+"
    "GGdd/n66kh4WuFqQ44qrSiruqaXbF2GgeFRVrHjqzjCQDvHx67/IR952JpFrwMIISTzEVBdRlK7e"
    "aXlTZf6QZAX1qKqqelX1snu2LyKpAhIZJIrQXk+8aCWJH6R976+UnSK6y0JXelEh0j+SoAKswSCi"
    "kkTfdtszGEM27LqCblYSD69U7QtZXMSAGrSQ7sShIVBqZ8AhAmLF9yjJypgLPvd+3vTj96FpNwOu"
    "Rq62KAo8TuZzUK2KBYC2OEkt0pX28cGff5qPnPUGjMnQBQZKtanD0qoQv5tVevCu5JtokBxlnrVq"
    "VTWVzFGMCFEk1CJ0UUoyeATNbXdq/sB9XnYmMS29lRP2/2kB6MMIKg8KAX5l+n0m3SazMYmmtt/m"
    "Z6e2sbjnGNywQApiTFUeBh8tT3NxUBLkOKIgoPiakAwmfOPc9/O6S/+VPE3pd3UyHK6gWq6ouCgn"
    "oAUsnro1dNX6ee+V5/GJs95EnFgYMMHlI0NgkUXFWVZEVSNSK/5Zzq3uBmJ5n6FyLR8E0dig9QQW"
    "RJiVy9BoH2Z/8z0YU9UHvGDMf/Oxm+c4kajz6YcDNQyyRnxqZgxvvqH35cK23G+65xK649UwNIj2"
    "KZoAUegdaWTmj2SoyLyGSBGb1IM3kPTGfPfjH+bM770NrdUY9N1karEVCwgnSlRweHpcRF9tkPf+"
    "9BN87j3vIOkCegrLjExwVlUtaFFxQXWHOuj82StfyqRatcrL90Ur0EOZFhukliD9NaLlKbLiWLL7"
    "t5DffB26JUkY9bvYa+CbgHB1VZc9TKIql4PCm+nKnq/p9lZTNhKPbvylZlPjdC8+Al2coN0GagYS"
    "06m0inpCKzWfzqMH7xWXQDqY8P3//AT/ctG78WmdBb4eLliTTrvaizJka3TX+nn3FR/lv856O3G3"
    "4LuLgiAqNq5iZgBH52XvisQXz9WXo0RIWIP7l0RfvYT8aQTSCO1LkcWCrFoOXatxV30HGXOOTV6I"
    "onV8f3wbIcj5B0P4UFDDpSwm/8bkHVKLr+CeWaNTbTd25w/p6ToWs3JPZGGEdBmIizAg82JTOfxg"
    "C0ZQVCxBy1Vsl5IsSvjep/6Dt3xnLWnax3LXS+4sLc1pa86CPKW31sd7rvgwX/nXs0i6DNpD2fzp"
    "AFjGTxXUC6WCoyHbFUPEhC6rloIKGC9IuPMC1TVDJaCxge4EFsWwKkL2OQnuvB25/SZlZy1iXOfY"
    "e/jTqAprdnf7RwYVYA2izpMesPBcHc29udeZua2/xo1N0b/sWcievTAYQyIhDBSLFgpQZTHltERR"
    "/EskkCi+S6ktTrjoC//GOy97H0mtl4PTPViRDLEqWYitd/OOH32EL59zNnF/hBtQNNJOP9+rlIKH"
    "zp//L383eIdq5ZidEqm8zJJAtzvAGglXqNQSZKiGWaHIvoeh7I3+5BJkInJ6Rx4xWPsWl+y8HTCs"
    "f6iVArtTgd2WtRg9WzX6Pz3rvMv+Njqlq20O3i/uf8obmJ28iPym68RvaMNohsy4MGyQhQMsQS0l"
    "S1Sl5KblZTuiYXrZTlqOesrzee6zXsx+C1ewbXaEdZdfwPXfvICoB7SLoPpKuFiHkopJmDora8oy"
    "+5eYaSndlnmsqMhCHi0ymwGJCGVtYoTuCBbWiPaJkcOXwMGvw1/9I/WXXqRcnxjd5sf4m72O58P3"
    "3ssazCNd8vPQmf/5iItQ//A+b259e9Nx+gu3wnZtsM2FPzbdhz5HpvfYApP3QysqXD1CjQsHUtzw"
    "jPLy2PlOUiaRgtnHvQnXX3YR1198EdLTg841IfNECwyaUpD6AshiPIjS0FRBRCtiz4N/q9wybFVe"
    "F6AU1WFghkhioC6qfZHIYoMsi9H9nwubHkCvugR2pF7vy2L26H4zH753AxCz/pEvVX/kq9fOwXMi"
    "Uesd922JlnSf6e9pKLeKNn71Q3THKF17vQBZNYAMp9ATQZeBNILIIFFIorsBWlQs6qQawPAoXlST"
    "RSnJcIzRJnGvIV6a4NPCJU0IpPPnrXajQU6lHA/SUlie9354Pb+CK+M7oQGYCKQGeiLM4hSWRbjH"
    "PxXsStz6z6vuUqc32ZQ4+iy/aH6VYIi/9T5Wv/2SwKtwnEjsLmtcJD3p5/VXM6nszN30VV9E7Apq"
    "+z0V9qjBcIr2xGHnEhOAkEoZCLGvCGri/fz6WlUUi1MbKb5HcHXFGx+uwisSU3DtYNllT6n8jqqk"
    "DK2FeYBqGQ6CZFHETSn6/cQm7G8tQnsiZFEEyy0cfAzRkpPRb3wRto54vcmkzOqdPGvJWXg1PEy2"
    "//1AFZST8Hhv9ORl76AhN+nVs6lu2umaV3yRtPc4agcci9mzCzOcQm8EiUFNIP3lLTeK+i8cqREt"
    "+xpCuAJPKLY1IEbDCoWlFbG46qfQyfhVEppnweUJoEwYlaIQvL+yTkFSg/TGyJIEVnk47Aii/Z6P"
    "//Z63M03Kfekho22wdKeM/jUtjHKKP0gsv/g5bfGVKCSBTln82TyT8v+0f7vzqvl2na3NTe4Vi0y"
    "6dNPwx3sUXtdUANdFuaqBDop2BSV1/yrY+TBMbLaV60yNPOa3PMPRx6UnCrRPQDeSWYFVQJiCRpB"
    "HAVhKBHojmBpLLqnKocdQbT/S9DLLsVd/SNle83rHVnCovR1/GL2Gh6F2z96UCGUrycR51/YfkO0"
    "ZsHL/S3j35S022T8yjsREz/tRfjHG4RfFiqThxkNN+ESEwYWvKdSgwoAK4CrsbyOCVTVDxRuXwJe"
    "3OpMOt9V5PIiEWkHSBPm7ig8J7i8IDVBuyNkWYTu7ZGDT5B4nxfgrvgh/vLvISNdTv+nnTIQf4ib"
    "sy8RSP6jvofKowM1hEYLRG79+IWc3GO4ee7LQj1x2c8ss+04ef5pkCT46BqIFI1zZFrB+A5xy4N8"
    "34mRHZpTTudVD2VcnG/NlNvrbk6oJUuScCKlTEJSwBGHQkUTg0kj6E9gOei+ijn82SSLnoP93rdw"
    "V/wAJhPLta0UST7Bnfm7CsL1O+Po7w9qZ3GcSMyVc+t4Spfqzc2viq0lLvuV0+mZKH7RKzBHL0Jr"
    "P4DaGOzyMOmClRgprMcXo+jMa7SFdCJaWHdZ6JTgV9hRpZ0CYcoGvaISFDTQWCEqgI0NJBESF+yk"
    "P8WscLjVXZijXkTSfTT2y+dhf/UrZazmuS5LSZNPsjl/Pa5KTL81hj54eWTy/0iLIhxFzA2SR08d"
    "eJ6/d+q/2a82qIdrLnsuj5I1Z2CWCPaOi9ANm2G7RSdymC6G3DJFMx9CgqUYVigoUZGUxM+jQb4s"
    "e+gwexA18yy6jJ0iiNHC1UMyIonQWoT0xMgQyJIW5qBD4PCXEW3zZF85F79lo5fNddGb2hE98cfY"
    "aN+Cqyz09wL0DwP1QcDGzx54sr1t6lsyHC+To9NMlyVx+uznEx99HHb8OvT2X+C2jqIjFp320FTI"
    "tLhUsRz8Cl1NnUeVKppUmmqhMqloRVvLK/i0yOpiBI3oUKZaBD0JLBBkcY4s68Ic8gyiZc/E//Rq"
    "8gu/is5ay11pyr0ZDCZvZWP+UbyWct7v5fZ/HKhllD2KmBvIk39Ycaj9xY6vA4+Xo3uc36Pto4MO"
    "NPEpf41fDG7TL+Ceu9EdM8KUwqxCQzugVlcDanE7j84haVGHltdVFHEh3NErCiFFo3BLJEmk4/Jd"
    "EfQLulCQZX3I6kMw+56MbG3hL7oAf8ttXsdT5UafMOl3sqr7Nfx69rt0lKff20L/WFDDoggnEXE1"
    "duD8Q4amP3nX+3Uqf7XsVzfsn7dZmkbmiccLJx6H9rRg869FNm6AkQZ+ysEc4SKFzENLO0O3uXYu"
    "olCCKRY1frXXEoAMMTNURVIzaK/AkEOGDGZRH+xxKCw/Fp3pQX/wY/w1VyhttbK5VtPbcojMRTxx"
    "6C1cNHIvPPQy8z9k+eNALb/hb4v7iRiBY7ufwqbGB+gxx5n9Y8eq3OmiwcgcdSjmmEOF4QQmN8MD"
    "9+FHR9HpObShMAs0gaaHlgu9+hJEXw5WSCeIGgk2VTNQN9DrYEhhWRfRHvsQLT0G6dkHOzGLv/bn"
    "6NXXKltnnY5GRjZIzLTfpMPpWja3v4JVeIwALSH54xdFOJvwP0O4Gstlz6rxxp++mVn7bhkyXexr"
    "rA55Hw10RXLwAcKTjkT2WYaJ2/jGFvz4NhgZR8cnYGIGGnkYNC4ply/oQCQhi+2mfXbDYD+yeDGy"
    "ZE9Y8DhElyL3bkOvvxJ3+/XKaNOxyxjuNrHsBHriz+nJfWv58sgOOirtoyL2j2Z5bEAtlwBuxNk4"
    "jCjPX3I0d03+K1P5c+gzIisMZqFkDIn4PYeNHHSgxPvvAysWQ1eC+gaaTeGbU5DNYfI5sC1EbUhG"
    "cYJJ6kitC9I+NB3EmUFwPbhJj2wegdtux99+q7Jru6eFymyUst2gYx7pqf3UrB78kLt8+49xlXW6"
    "au8fo+WxBRUearWJIT5l8ZPdnVNn6Ez2HKmbQRYbWOzQIWvpjtX09gvDwyLLV4guW4YuGCIa6sP0"
    "plALSpVKcduQ3CAtB5Nz+LFx3JbtsHGr6rYHVHfNqMwgOk3MVAQzgrR0jK7ocrN68L/dtWM/pu2A"
    "qlk3T0N77JbHHtT5S7h3U8jjRqi/etWq1i/H/5rJ1gsl90dpKj3SLVBXtJYj3eQMofRFaH+MdMWi"
    "SaG0VHeNsEqruIdAG6FBxBxGZgxMGpgBmkxqJDfQH3+XQxdczMXb7q/6879FXH6slj8tqOUS7iAE"
    "Je9LInjBktXmztmjdVv7KJ3LjyWSgySVAXoN9CvapcE5y5azEiZgMtC2ILlBM8B5K8ounLmHxFyv"
    "g+ZX7Nl/PVfu2lgkIADDGuRPDWa5/HlA7SymWEuKH5JPJPDMRXtHW7KD1Om+2myvxLolOBkg1268"
    "SQjyQI5zsyi7NI0eIDFbSPQujl68me9u3dGZQXiE3/p/egl3aIs4kZgTQweq82ah9idRqNXTKFRG"
    "tTg8plHI+kYqCQAI3gAxa4iK539ug5l/BH/hpVQAT8VUM56zCL0oVz+sICyciFTbAJyE5+xOo+Ev"
    "vfzlQX3w8jvuTfqIy/8lgAL8fwUHNUSo4Pe6AAAAAElFTkSuQmCC"
),
    "clock_history@26": (
    "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"
    "TkSuQmCC"
),
    "document@h84": (
    "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"
    "/teuf5Zb/T+StdI7SjgVewAAAABJRU5ErkJggg=="
),
    "gear_settings@26": (
    "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"
    "+/roQ2YAAAAASUVORK5CYII="
),
    "shield_x@h84": (
    "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"
    "K2rMyg5AxwAAAABJRU5ErkJggg=="
),
    "trash_white@h21": (
    "iVBORw0KGgoAAAANSUhEUgAAABQAAAAVCAYAAABG1c6oAAAFAUlEQVR4nFWUW2ycVxHHf3POt7ux"
    "Q+00sbuNAoXWLRVRLk6pjZRCZQQSlz4VFKQg+gA8gBAIiZtAKtlsIqVC8FQhoOGJCgWphJYX1PQB"
    "YkttKVCp2NA2xNfY6+vuer273t3v+853zvDgAOX/MvMyP81oZv7CO1QqlcyFcjkM3P+ZL3/tK5+7"
    "MHLP8EH1ISgICGhArMjMjaW1Z56+/B23/bcXtFQylMuB/1fJHD1Tyuv161F06PTDl3/zJ6+qWuup"
    "bvRUN+O9WOmoVruq26nqE9/9ZbtQKN77+uvP5I6eOZOHM/a/XZl3oIdPfuHrO7upvjbbSk5/6RfL"
    "pz576drY2Z+8NP75H1879tj5F7/x1NXNeqxJ+dk3FI49/p862YOZqFwuB3h47MSnPvpoJMEUIiba"
    "nVhvrTdzyzN/nt1H55pIZK1RzZq7Ya0YDgf/+LA1Gu770ENnDx549H6HYfql669SLr/Ce0498dVn"
    "X3hFt9tOqzuxVnd62uqmvtlJfK3Z02rLabWVarXldKuZarUZa2M39dVmz6/XO7pa6+pGI9Gnf31d"
    "h0Y+8S35/o+uNJ763tnBbhrS1CPOB0mdNyGoGGuDQvBeUYWA4py3WeYlKBhjfaYoqppqPv/tcz/t"
    "RM5n/RlIEkzkFfEYJIpUfdDEB6MByQISwh40C5aAJfOBLA3WB9Dgda7akWYvRNFzV/9QTu1A6d2H"
    "h6yGDEUBI2mWkXlQRRAIqoSgZAFUFUVIM72d53jr5nJ8869/fFIACu/75KUrly/9oDhYSLtpFnUT"
    "jzFCkjiMtSQuEHSv2DmP2Ihe7IgiC0j2xkIz//NLFy7SePmcKZVK5o6Bg9MPHR/hkfGjDB66i07P"
    "cWhomI9/bIz3jozQSwNi8oyOHmds/IOo7UdUKd59Nx8+Pc6dQ0VsoX+6VCoZc7FcDrWZ6crbN5cI"
    "YG7cmGdi/EFm3lyk046Z/sccHzlxhHwuYm1lhY1qgyjZ5tMTJ5ibW6Lb7dj5hVv4jbeWL14oB2OM"
    "AG+uVtarqQG7f3+fJt4g1pJlnr5CDrV5OqlSyFmc8wwPHWC1kZLP5dSpsfV6vQeVVUQwGAGoblQb"
    "dUCCQuoyAgaXeRTBZR4fAoohTlJykaXZjukrWO0k0NxpVYE6CMY5L0BnfauxCmCMCWnqQAxx4kCE"
    "zO8tQ0VIkpR8Psd2q0dfIa/NbkaztVMBEu+9GMAAbGzWbjkgivIaJykASeL2bi/zOB+APWAURbTa"
    "Xfr7ClprJbR2GksAE+cnrTl/flIAKqubiztdJVfI0Y1TxFh68R44dZ7s9rc4lyHW0t6N2de3j41a"
    "m2Zjex6AyUnM5OQkAAtL64sb1RaFfIFuL8HaiE6cEVRxt0d2XskyDxKx242xuQLrW3V6tdoCwBST"
    "mCkmEaA+u7C4srpF//4+Wa/tsrId04tTNCiVrV3WtruAkiQps2ttWp0YiXJmbW0LavNLAjB1lxqm"
    "JoIxAunM3Gt/n+NwcVhAddB0OFIcZHjoTirrWzxQzDNwx7sYHBxgbn6JR44Vtd4zsrJSCfh/ze9d"
    "y2/VQDk86YOBdO653734/O9fXY7uGXk/Y2OnZH03J51QkGMnT8p9D35AZjedaP9BOTE6StMMy/NT"
    "i3b5n3/5FbBy7ofBAEH+Z7gKyIFDo1/82ZEHjj9mDHljEEFwWZAQVI0giKjzQpy6bm1++mr77Svf"
    "BO3d9mz9N/ZuD8ecCyZ2AAAAAElFTkSuQmCC"
),
    "warning@h84": (
    "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"
    "+8oAAAAASUVORK5CYII="
),
})


def _symbol_image_h(name, height):
    """An embedded symbol picture pre-scaled to an exact
    pixel height, as a tk.PhotoImage (or None). Cached in
    the same module cache as _symbol_image."""
    key = "%s@h%d" % (name, height)
    if key in _SYMBOL_IMG_CACHE:
        return _SYMBOL_IMG_CACHE[key]
    data = _SYMBOL_B64.get(key)
    if not data:
        return None
    try:
        img = tk.PhotoImage(data=data)
    except Exception:
        return None
    _SYMBOL_IMG_CACHE[key] = img
    return img

# Stat-card geometry (board law, owner correction
# 2026-10-23 04:26/04:28): glyph height, number font
# size, and the pad that puts the glyph's top on the
# number's cap line.


# === DEMOCOPY4 ADDITIONS (2026-10-23) ===
# Sectional duplication pass (owner order 2026-10-23
# 04:44): more build-time scales of the SAME ChatGPT
# singles and of the board-icon extraction -- no new
# art, nothing redrawn. Box keys are fit-within scales;
# @h keys are exact-height scales (pill glyphs).
_SYMBOL_B64.update({
    "bell@22": (
        "iVBORw0KGgoAAAANSUhEUgAAABUAAAAWCAYAAAAvg9c4AAAEMElEQVR4nJ2VXWwUVRTHf+fObJct"
        "tKW1VZDIh1JAaiEGCNSoW4XEGGOiJFWRECNGfdAYo4nGF4uJJvJgYkg0xgfQ+IFSJcHgq0I0RBJR"
        "FFI+y2eFLi3QbXdnd2fm3uPDbGl5KIn+k5v/zOTc/5xz5n/PwA2hknBfA08Vl8ORuuuf/1dk1c92"
        "q9+wof/uFbuDE6vP2krbN6WjjR0X78p2q09W/f8m2LXDMya5nLppYPeiQNUcsMG8i6q1z/Z+B2BM"
        "Ejd5dRPRrYlcw8W5Lc/k3lv8bWGk7bxGy34K47aTNmrfmhu55ench9T1L7guflJ0qxGAlaeeXPlF"
        "+WrnsOrCK7FrPmVtw3Frm3pj23pB3f1Dqiu2lYtmeW6DMFnGAF3qCcDSY490fF/S5VYdB22ZH2LL"
        "9tiyLbZsjS1fRZY9caW9qG7lTqssOb1WqvvHpGSsD6og0jNl9rudf9S/0bLo8D4bmjP4BKCBQgVQ"
        "RVKiZETcDOyCNV4q2tzfd3rzjnbV18oiAlDtRxfGiCh3zn6ofnXToqPHiOQkvg4p7oJFc5HqYFl1"
        "sKwuF+IGYuSken1/EWU6W+7wGuc+KCJK1w4DkIheQhSYtrDu3lKzp/Exp1xSNGfhagmGC5AfhfwI"
        "5AtwpQRDDtuLDjeldUrr1FWJTosAJF57CWUvSL3MvRoinFPhsoN8AOUiRKHgLKiC54OfVq2IcM5j"
        "eIknrtmfBcDNnTou2oUDiDO22Y4AOYF8CIUClAOII1Bb/QoeeJFQIyAZqRQ8JJ1qrOpAz1j5nlEU"
        "cWmZHg8CuVh0tAjFAIISlEtQKSdcCqBUSiq4XEGHQetrG5Hx5Ax0G6wzyPo62zRtlu0HLleEQhGC"
        "MoQViMJxjkKoVEVHRw0DwMymVnR+OnGTiiHbaRBxmVVvPVfbfluz/T2OCPNCuQRRBeIQ4jEOwVa5"
        "EoC7Im5/ENUsnXNrZlnP84g4snsSv5t7jqxv2jhnW+FsWsq/hoIpClEFNASNwcYJA4iAGJAU+GkI"
        "67Um26CZ+QXyWw6+yN/3bRV4debsT948VN44Y/rQb8TGx7gYxSEontPqMdHqEkBQBAsgBtEA19KB"
        "3/jl2cLxlze1+3AoM3Dg6DRb0+hpPvCsZ8C6JKly3qUU1DiUxE7iLDY1xUPSnqpDNYVnhPx5n/z+"
        "A3VwuLZ6TB9Yi9f8GM4hOJ+UOA3z9Tet2/hw3aMdnhuM1fg1hM5pOgXnujefsbnefSKNPvhWcQIK"
        "emoXHOoZnwATV3U0mBe+PsePGrO+WGHdQMzrGvB5RWXeE+9ci504Rar3ifm1y0ucW8W8X3xObAnd"
        "9OxHprHtfVqXeO6fAGmxGfn0g8HU6V2fVbI/++zdLrDGXes5PUCP5QYwgDGZFa+Y1W//KY9/3GcW"
        "bthZA4tJptH//E9V92XBvx0akldNGEST4F+UJBd8Gk5JYAAAAABJRU5ErkJggg=="
    ),
    "check_circle@h18": (
        "iVBORw0KGgoAAAANSUhEUgAAABIAAAASCAYAAABWzo5XAAAED0lEQVR4nFXUS2xUZRjG8f97zpmZ"
        "FixQGDq0xVYCNsEgLVruKobEBg0s5KYLQtANVE2MYhQxoCRGE4IiibrgGghB0kEwDQQEA0FiJUow"
        "UC7FkkK5VAv0NtO5nvN9rwvSUN/Vu3l+u+eBwdewxHWQh/+XFHMuNte5WPumc2nqCs6Vz2UNxQCC"
        "QAPu4Kj8D1kaN3YLYyN1U1e/GJu9sDxSUiGFIXwCMul+7ifu37rcefHA/Z/OfiUb6NAGXJZiHkED"
        "yMEhdc9PX7Z3ZdmS0T100RRcMK3aoQnNICISC5W4pYym9UZz5/lfG5fLitzxAUweIgeM3T10zvy6"
        "VcfrxywOnwhO5w4Hv3sPTL/kTIAfBBhrUAn0sXBRML2oNpK6849/dt8PL8lH5rQ2qCuqKrJSRtWs"
        "fu3C8qpFZY2Zn/3zQZvr+4Z8LoAggLwBo6go1iagIBTMqpwX7j537U7LZ0cn62HtdUREi+dXvzel"
        "qqZsV/5Qrind4qZ7MuS7+qE7hXalkL48pi9JOGXZMHI1E5PjvKaWI/lozfixwxY88baIqEMpQyrG"
        "TVx6lXZtvtfq0plDulLQnUZ707h9PqYnwZCsEK/8hvWj64lP+JaCtpxzvfumRqsmLAVCHq97k72i"
        "gnEt91qVjpTkU/3g+2A9whohn0sxJFxAvGYbLxTPpIeAYy0n8W/3OX3Fd6VwxOMTmMl4JxQbVZGN"
        "WLf/9j0rd7tYPmKRHqreTdQvIt/5L0W5MA3P7mL2qJlkge1nd/JBvB7tNfjtXSarppAKt8KRPmvz"
        "6RzBnQeUpkvYOOVzmRerY/+MHUwqfJLdz21jRmwWGZRtZ3bw4Z5VeBKGBz62J0MmmVG6jHHyl3tu"
        "Z/vSJhRE3HvXr8vGU5vpxWf8yKdoXHiC6lgtOYSdp3awdnu9euGwasKg/XkVN+TkEtk0f3DToTG4"
        "lOxItIeKh2Nygf06vo7NRzcRdoeSsHlCXhE7f9nKJ9+/hRcJiSataNoo/WqkLEpwq7+FBDcdIJVp"
        "unVQS6OC6wShcIFu3LuWzYc3Eo2MYeuR71i35R28oZ5qWrEZgyYsEg2pDhsm/rEbewAjqApRKQ1t"
        "qr2oY/2Rdt8FX/A8kw14unwaza1/4oQEEVFrQVRFPes7b1RH9Ezyiv2ibRr6aUZYgktcDLWhl733"
        "axptYcLjyLWcdKtr0jhOgYMYsIFVwEqZa+XVSRFtDrrtx5fn4Mgl1qnzsLRLcIljqOQV992anUwk"
        "pm2dSHvS2u6sRYHhEU+qRkFJCZxJXrGbry1D5C/Wq8MG7KMZGcCgVBaXrJFpoxcwzKtkqHXEgPZJ"
        "Vh8Erfpbx35O9m4BSYG6MHhGBmM/isEqQBEek3hmeDm9eZ+/M23AVSDAEbDqAHYg+h+QHA8jZf2W"
        "/wAAAABJRU5ErkJggg=="
    ),
    "check_circle@h20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAEyUlEQVR4nG2Ub2ydZRnGf/fzvOf0"
        "dGen7dqNDdfyz20Mh9kcdUw2AwJaGR0u0cMQMiO6L3NKlhHjB81GNYYQMmZimAGdyJ9g0k1IFMwE"
        "xzQqmiWbE2FshXU9bN0pbfH87Tnved/3eW4/VMlErs/X/buuL/clfFCat0YOOo/Ct8mxKVhOsLiX"
        "QBzh+SL7k1P8nJpB8KoWwV18Lv8L222MDHn/BMtZu2r7p3r6N/S2Lbws0zY3cDiaYS2ZqE2888bk"
        "6y9UXz32qHyLEdXdBhny/w/UvBU54PQPl+9c/7GBH9674AuZkAavuzP+LEVf1aYYEem2PaabHCfP"
        "vdY4evzw99g0uRfNW+TARU2H89YAvLz0oW3uR/pH/bvbFT/a6g+3JIsbt7uu+q0uU7nJ2co6J5W1"
        "ybzGQGtAv+M/H+7U1HN9D8t/GLMNh/PW3HnQ+eEFW79yx46fbmj7ZPR0+Bt7XE/LTJIQxgneJWjk"
        "wHmMGBJxqI20f+E611knffjJp7bKfTP7dVitqKrIN6R31Y47T96+7LPtL4SH9UxYNEnkiaMIjR2S"
        "OIgd4oVEI7AWKymcqfg1Vw9K9ehI/dSuQ9foIZ0wRkSzt6zY/vFlK+f+qvWyO10bN2E5JC7VodSA"
        "UhMthUjVkdTq5KKAF/v28VLvT7i0Os8ce/OI61m5pDPzuUVfFxE1CunFl310cIx3dWRq1LjJBkzX"
        "kVKIVkKohdhaQlKtkotTPL/kcW7MruXm3PVs6/wq7uRbZjIuaffSKwcBCfgiS7MdHVeNVsbwxRnx"
        "zVBpJYJLMD6F9ZY4qpPLZHn+2idY07maOhEnpkfY/6fHENLyXmFcct3zltLNRwx9XJqkpb1UnPRS"
        "rLBoZi4vfeJZHr76AXylSlwq05m089yap+nvXk2NiDPTBTY/volC8TRMqzQvTGukPscVLAqYQqNm"
        "hFYa6Plphgb2yGfmr+f6+TdA6Hjk6IM8edMzrJq/miotRqcKfPmRjRSjMVLZDuLyDK7WoulD5T18"
        "wAkutOphwyRmDhV1T/35F9zYdwvpIMXmZXdz2+W3kW3rok7M2XcL3PPgRoqtMU21Z8VVQkicEqRM"
        "VG5WKDBueIPR8rmpgs11qCRW//La7/javruJPTQlwdk21Aa8PTHKPbsHKZbHNEVGXLUJTa9EeBZ0"
        "a3y2PAJMGqA187fCbyXXIZoSlw7m8uo/fs/WvXcRJ9DTdgmnzo+w5bsbKVYKmrJpcfUIWqJad8jC"
        "Oaqkxb3yzvDsp6gKvbIkvWfNP/2iyLhfnpBUMMdEkw3W9w9w1w338v2f3c9kaZxUR1qTKEFAwKCa"
        "OLPtusAfKU/oD86sQLUs5LEcEGcG5uwMdq3bk5x9s6WHzgU2SEtSi5QZhHYIggAXe0BUREWt92bz"
        "EtVyR8o/cHyQC/IiX1I7uzZ5LAdwckfXXvPNlTsoF9W/8nZsprwRb0QTRJ1XVcDi6QvUDqxI63Qb"
        "7qHj9/GW+zF5nWVcvIXIkOe6zP12y/IhvcZm+VcZLZShHDpEoCNj5ar5kO2CI6Vxv+/0Dpoc/G+h"
        "DxlYDIIHlsuGnu3Sf8mtzEtfQRcZiUErWtFCc0SPFX/NX+uPAVMXwz5ceSzyfk4bcC2d3Ax8Grjy"
        "fZ+RWe8H9G95IHPfqcpMtQAAAABJRU5ErkJggg=="
    ),
    "clock_history@22": (
        "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"
        "fzL9D8RLHpHYwHYGAAAAAElFTkSuQmCC"
    ),
    "document@20": (
        "iVBORw0KGgoAAAANSUhEUgAAABIAAAAUCAYAAACAl21KAAADhElEQVR4nE2U34tVdRTFP/t7vt5f"
        "M+MYZKPNQ2WUkSFZPURvCZFIEURa9AcI2i+qJ4N66ale6yUQS7SQphKEsh8iIr3YUxQZRCTk6Kg5"
        "znjvnXvPPed89+rh3Mm+8H3arLX3XmuxDWRggoud6RO3PWbt1MEwUoI1maeIUeIEQu9SuM7uxo9I"
        "hkGNq180TO0P+w/O7mgeGTXilnwYWa1KkAGobrd1k7hwvHx3yeydXVI2Z/JVsqg7zrfWP5oduhHi"
        "lqsH+iXdbsCrGp4c3OvuuSvbfzsbd3be5uBwes7stf+TRZ6fuqs3Ge+9/mXh/Dqfma6CJySZKYEc"
        "AWFlYL0r67Q80ynufq71KgyyObOXV8kijbw1GE4byzkUi5L3wEtQMqF6PwkVfUIqLL9A/LOditln"
        "2y9Vnoc5s31IFinlIQF5CaM+sGKURS0MAiXAUTEkxYgZVH9bnHeK2ReaexsaVIt2+o3AsFCVzClL"
        "SEPCcEDLnGZINC3RjNAgQb9L+dVP2LBPCAPSfD8uXMkrf6T9Crs3b4soZSrJLI1Q74Zt3PMQbL+f"
        "slsSgoFDaAeuf3CC/PNT2PdnkDkWmpS3bA1Le59xNtOJtc2GygI8Z2HhH/zcPPSqcQaASeDaZZhs"
        "IsAqk1xGZ5ow0Qh+LSeyUuIjh7KCJvLDZ6xx+FtECXIg1bX2JEyuhaqkSmbWnoBOB5kgz4kkSQ5m"
        "jno9Zvc9iT+xjVG3xKIhF+ZgBp6cbDJj8NkpVo6dxbyqJ26ssYhXZjI8OfiIy0td0l/L0K1qNEBS"
        "HWAXTGbY0hJGgZLLKqCQIl4ZSZCPoJGRPvmGePBoLagnJL8ZBUCV4dbCZjZAVRiVw8pQkUGBJAiC"
        "Xo/1e3aixx+m6lfIQGZ1KAElwUSk+OKkRsfPArJafRQhJBLCHVSyVCSqxQTLCbJQkzgQgEowJUKR"
        "DC+EHEOogkhKgQCUDq01VIeOwcefAo7Jx86B0FjxgGctmJg2igocoTJGzt3ogjsbZ5yfp2SdylRN"
        "GVWBPIEJWz06Y/EtNtFoSmy4EzeP/H5+2QDjrT+OsuOe3Xx9CRavgo/A01hfq6cyu+miMpi+FZ7e"
        "BCd/+473HnjK6pO1fx2vv/i+3TezndJbyEzu440CmInkwsxw1b+pgl/On+bAR29iRxbHs/7n7hTs"
        "atVtF4CRw9rxXl2gY9A2SAY/5EB3jLV/ASj7FtTnLHwYAAAAAElFTkSuQmCC"
    ),
    "gear_settings@22": (
        "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"
    ),
    "grid@22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAAUCAYAAACJfM0wAAAEgElEQVR4nE2VTaxdVRXHf2uffe67"
        "9300rx88Ci2UCE/aNBpCQ1USidGBTl4iGhKjjozGkTghMcIAJ04k6oAOoDAy0ZEJqTRGE00M0RBF"
        "BatNBIq1TX2v7Wv7vPfcc889H3v9HZxXYbQna639+6+1/nsbyMDEIxcPxqPLh/O6MgAyjMysKgY1"
        "Z+48BzgAvJjzxOePj6zOSY1sjnKgWVm06sx4k+rYJsjMgOVnr371wY19P+xWWC3nKZgggAGM8szH"
        "f2vf+Nfzk8fJtnT/k0df3Xs8f7huWktJ5kJZZhrlgeqWja/89PJ3J6fXX47i7N6DJ4fPbZ3I1zbf"
        "9UTMgjog9XxxKfiRL+aPjn536cnltf0afmH0sbf+Q5O2Q5Tv6lCQJfd9J8OB/PLKj3T61NkIOlAs"
        "snTt30gXhDXIWiAhgG4hcckyJxQPVsvLurCDd+ccKyWrgU5gDmA3PXg2shy6tQjb+KwjlFgaAw3Q"
        "/p/YGICXBLVt14wrU0lgLKPYjXUDgSSzKaayM5hYhG3qeWMqgULQgGqwhBEMchNzoGmUZtNMFTAB"
        "FUCHzGVyQEJToOkCzC3CTJ0klcC0p7Ua5GAmkYPmDl0rVyNrBQVQCjqZXKBdhWMgdYKbCnC1a0oZ"
        "+0hkuDJzRXMyc5mJpSyxFJz/3hI7RcuSJRYtkZkTgmOhP3NLdhC3ojY4V0d48Ur7ysab4Z5Dn+Ro"
        "zJi9v7EkYJVoZ6/AW3/6ped7gv3i4a/Y8f1ZT0dPC7AANgW9+offw+sXrV/XtTUOP/M99q8+hLfC"
        "vSMfZtDklGXFu789DWd+BkD42jd44LEvM5gP6JITY28weWTzvb+w89zToCKC4HNvHlnfyD/E6nTP"
        "3BHIk3cWsiwOGw1vvr7x4Z2Xnh/Be+2hrx86svqJfF9JFyyE5Fhw71iAyNbGfZde+tJ97UU7F+HZ"
        "xXs/6z/xbx44unXxAKnqJUq9zNEaLH+cjxbnfzVZvOvues/T689sZlDd+EC7BMFg7+McWyiLY+33"
        "v30iwh13F+uDwzvn3fmzO41Bg3AgKDRD64rHsmiHdXJ+p4V3clL6dddSEOlMfWEZSczGOdn9C/dA"
        "c2+Eq9m8ahV2QvCxy1qMRigJMCwn6CaZ0lypncl2yKywpELBGknJ+wE6ZtuYl3UL14lwVe287Q0y"
        "AbUOTYLkgKEsYlUGaqK1ZUYDmmAUCbWNkRJg4DmaDrC2M7hlEW6k1LaiAipB10HdgHdgAWxRzASp"
        "Qj4zq4GZYN5CV4NLoP6CZrHPoyTC9RiM4CGJKkFyUTu4wAQDN1bM6eaythILOPMOaomWvrAc3LGh"
        "Y/OAuBYi/GPbX3t7qm89sMSjmVERaJb6aQfgLtBWCvb38xdYXsi49kTgM0Nna5jhK/2DBdgI1xEC"
        "r/x1Apc2I0xu2c9PfceuT36gO1ZXVDcBiwZgmURnbn/8zRuLl0/9eAoxPBU/zYlPfUSpTSSHZCLD"
        "iMguX9mx1154Stg160ePlsRaCWu7nNw29gC6Bv6J9T8W0gBY3427bf7bOVsYNxD2P7Z6nB0XzglD"
        "AAAAAElFTkSuQmCC"
    ),
    "info@18": (
        "iVBORw0KGgoAAAANSUhEUgAAABIAAAASCAYAAABWzo5XAAADx0lEQVR4nG2UX2jVdRjGP+/3d86Z"
        "k7mteTDNmZvH+SfTaRMqEookUMkgdVBi4EWJUNEfoYsiZYMySaQou4okihquvOgmEWtMhcJY/kvc"
        "lmfaWSd125nb2XbO+f2+v9/37eJIDOyBF96b532f5+J5hOnYp0baxakCHE3w7GMPVrXEGo1KLN8f"
        "ZPiq6zK8kBdAW9WjUyLuQutRr7ycmZX8bPLt5Wft5WW9YbB0QHVpWjX1h42WnQ0Gkh+PHIQT95U5"
        "6v3/kQ39j6S6Cn3Lc6pzTqomDgw580bayqt9NrZ3MJp9rKCLsqoLTkzd8p68tHk6V/6z89SVlqa2"
        "hT/Z2sqa64cHfdIZj+KQYaoEGsIMQBNKfUOYfKWlwgQ2HGq78IycfvRH3aae7FM1bdI5c97363vM"
        "0rol2Xcv+CafjuPGqPQStO9eR250nA8/7yIyJSCmLt4UVb6zIcHNsZvFnV+vRPfkTJuIS7z2wC5p"
        "rluSPdTvy/D5mAR/40ZusKqxkje3NrD3pWbm1ynu9hCUhkUme7ziJ11+1HTvXLN97cuIaAwwFatr"
        "doyeC5QrFw16S1xpEpFIf+85L7s/qmZi9DaDV3sRD7SgkJgB137zgp61Ks1ztvIN78Wo2N8Q1c1a"
        "HPySEYoZUR1TsVOCc4hUY0ctdjxAnQNXBERRCxoKF3tF1zQshtZUjEWz6kslqlz2RoQdEXHjYpxP"
        "VPBlybIGDrZv4tZoSNepbkaGi5iYoM5DsOjNrEObKqmtnxsjn/XcVCT4RfDHgSlQC6GPhgXSw5Ab"
        "zoOzivMFJ6IYRUMIAyj5SinjDNnTWSYnCsysNFhfiXwIixAWVcMiQQTWCbgAnAVnVZxFwhC5p86Q"
        "H5+gdHLQwJm0ZK6lJZWCKK6qTtWFEJUVTZYcU34EzofIlkdDIOE0tUIZuNIH438ZINKfj3dQP1eY"
        "t0qJrAiAiwRxVFQbZtbUIGrBRYoY0TAUbVynUlstdH93BNAYqoLIYT3Vsovndy7kUF/g9M8YMyr0"
        "+kBGjnX8wORYTsdyeSQRR51TqppD2fJihZ44fInBzi9QNUCrhzHA6sd5vavA+2PKivYSyactdU+E"
        "JJojEitDatdZZm+0rDlQYn9e5bkvhyG+sszdZ+ROaj3ojOD+9bLjgyM0b1qg6etw9Zx6+SGnxuBq"
        "kh6pNTBnNvLrt5f0+Fs7ELmI7jXQ5mRaBXhIZ4SSJLV9jzy8YYsmGxolXhXXKIRwosA//b10d3SQ"
        "6/4UkSK67Y6Au0vpjk2gnPeH8BZvhvkbgeVA+bHxAMx05r/ESQMmcDECyQAAAABJRU5ErkJggg=="
    ),
    "layers@20": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAATCAYAAACQjC21AAAEhUlEQVR4nG2Ue1CUZRTGn/f9dhe5"
        "6C4koyzCmiFDomEhkenGkMKU9xndGa9Jat6dFB2mMWTLCmeMklTGy5SjJoprmmYabjqoiZc2SVEz"
        "FUxFNJHV1lUWdr/znf5gMXJ4/jgz78x7fu8575zzAB3I5nAozCyDR2n54m5mQnFjFrAgBAAURcDm"
        "YKWj3P/LzrIdCH3yr40qPPLwlPNGgCvqiVf94qkeuPzSNAASAJhZ2GyODsB2u3Twfy/Gz68e+tEB"
        "9+GK28zXm5nPNahq1T1VrWliPtPAXHTonit14elxbfeZWcJulwAgABYCghmAbuzZAbkTYvOsKZG2"
        "xDgDHnk09XGzxgJQmAEN0EINko1dpP7vRg3HXTcrtn5/pfCv7W8fDqKFEAB4YKVl2kxLflaqKadv"
        "QrjO69HosU/TEKyaGWAWABitYNZCQxSYTIquvr4JzsobP2za/MfSpkrbJYGMih5rP+5b+dagrvH1"
        "DRo1+TSNNVYgBEjjIAxgIBgAKREEg8JCFdHfInWl5XX3cyfsTNOBfTF1naLifRpUoxIQPgjFRxIC"
        "DNJaE59WCYaAgEYCDCA6XFO6R2h8qlHS3pvc1aA8DhUAgDHOgn6ZLxXMGtmNrV0hW7wtuO0RaAoI"
        "yNZOwWCABYiBqDBGrEmgLqDHxjPQnE4X/BUnpuFq7re6bt0mh1NYeO8LG34VCx1XePC7kzBpSAzS"
        "zMATrx91HoGWAAAhEBkK9OgCuIUBReeBPbuOwLd/h4ApS3R+/dUR3quj90PXaUJGyjY/x630kjQX"
        "EPTZFDK0iEaWPqDtN5ku/sN09k4zXbzvpxONTHOPMXVecJwQP46AFNI9v4zMa1jrWeJh6DIGwwij"
        "CQmf7otedocTd3DA/N5vBNN0gt5KXYavpSl7PbS+lmnxaSbz0vOE3jkEJJEuZg5FL7pG5k0cCJt0"
        "VEPE7C0AQgVgl0NmxK68fKF+8d3mSLXXO7OlYgyBe98+uJ1bAL0HnZL7o9l9D6ipghKZis5jl8CQ"
        "ngK1+iIelK3WEhKNSuqAuOKdX+3JA3Tpg8tONnBZ1UN/UuZcFXorhWTuoN4bmBLXMZmyy1RETSdp"
        "nk/GiYep+0am5z64RbDkEgxplDrifXV3tddfUn6LActAAFE9hs1bU7P7MvPJu0wffu30x70ynhA+"
        "iiJGl1P/75gGHWRK3c0UW+gl2XcFQZ9OSW/kqJ9tO9NysJZ5+YEGfnH0MheAKKB1cGLirdNLZnz+"
        "k/9YPfOR6xzIKdgciHxhJCF+DumzSgl9VhAMGWRJm0j53xz1H6plLjn6iK2z1jfKnsPsAExtuy1a"
        "FxAAMKDPiMV78re62OVmPvhni3983sZAr9emUvKbM9VFq/b6y68ylVYFePiSbd6I5DFfAohrhbR5"
        "QxBqcziUp2AlOjtz6ien1/18g2v8zL83snrOzVxey5xT+KMakz5lC4BEABBSIiPDrmsPay/ZzjiF"
        "oXs/2+S81WeLdrl4QfGhJ0nZ83YCeLkNFPTCDkHPyKZI5ak96oAIK4Dk4P/A5nAoCJrss/oXuSdB"
        "FoU+HAUAAAAASUVORK5CYII="
    ),
    "person@20": (
        "iVBORw0KGgoAAAANSUhEUgAAABIAAAAUCAYAAACAl21KAAAEHElEQVR4nH2UX1DUVRTHv+fe38IC"
        "SwSuICJ/dhUwUPxDYjnJ1maR2ORMujPRWC/14NRMjfXSNNWPGXvppemlmZiptInaWsVyRhkTShGD"
        "acRQRCNyUFDWZEGE/b/7+93TwwKaM3oe7j1zz/1+Zs659xzgPkbzTsNEIVzj9vvde4AxMTOh5kaW"
        "2zvz+ZeXkxOfDSf9a/cF9gI+qessHiiGzgK6Llw6awSgrHlY/z3G/G+YlT/M/OM15odfO7uLALj0"
        "Exp0FvCxBDMtQMRcKgIAMxMzi0c/6uk8PcvG9/2x+A8DicihcTZLd//aOheneTXdYRArnLCyfrtO"
        "NfxVRtScQUSqz3eoe1/XLXnNTOehsEXubx+h0YPeLiJiogN2fnWgJu1j/1Z+5lw+QEx47Fjei3tq"
        "f36pzr45MBkJBaZjN4O3oyNjQ6O42H/GXVJTjVgkismhIXPjpk2nChxLs3LzcxyL7Wn2ZUtsmrfj"
        "xt9fvfWtW0NgcMNGp3vzs2WITeVlZkiZudwgLDcai6AitebUxC1Kt0jOtm+TsIgtAgAUoICENQfR"
        "PJusRHK4hmwotGdu/6Bry46GqgpnAZyFNi7ORUKGlTRMJkuahFKgRNyAxaqZQQm+MmGmXbgcwNm+"
        "AQwePdSbcb6lcb5my4DVr8O5zr2odOm64urVtqZdz6v1BVmIxE2AAUu6hqMXrqHDe1iMDvZfj18d"
        "6Ubo/HFgpg1AEACIiCAp9WpWoBTI/3D3F33q+Dgb352Lma39UaPdz2rrO1/PAtj5ApAtAAgBgATm"
        "V2ZmMtmlKZ21uJCjORve71n5iJOmQlCRJCFsCMyEgHUbN1kyivWeI0IEVW2LRSmXBlYEYOGXMtBl"
        "uHASrEyUry57ZWlpLiZnDRVngbhJdCuMZGmF05rrsDUppchl8zPQZaS0qWzmjU7vdRtAZfaqtWVb"
        "EgyEE5BDgaQaDyoVDJuAzYKKNcsbAPDJk83q7t64A/L4hFIMWbzzcWf1siJ/QCUTWRod9u7XevrO"
        "aHEp5XSIUbKypA5YVSAlKWChPe6APB4PGMCap9fvyC5ahJmoMMYm4/J6h7dzpPfE5WmCCIYoUVpV"
        "npOxYtsTSgFwNct7QdTWJEwAtorqJVtDcUZEg/ZnezvzzT/euNnb0TJ21U9RBVPLewgVdY5GAPC8"
        "2cz/B3l8QpmM7Kr33LkrVxTfmKLYRDipDR1r6yRK/GMEun2XOn+ZnZWwTAdNrqytfApYbGtrkuZ8"
        "36ZAExcJANIzw/WyMB9pFeDhnlMUufTTp0oxEWFs9LeDR4LRpMYOacQ1qwMwHGAFQF+oEwBdEABo"
        "5fVl2z8J1L7dyuklz33DDILHJzk1c6rs9XuurHnXy1lVLx8FYJ2bRXeDUnWa2x0AnrznnJCaQAVz"
        "Me0eDf4D+B3e6i5xaNEAAAAASUVORK5CYII="
    ),
    "printer@22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAATCAYAAACUef2IAAAElElEQVR4nG2UW2hcVRSGv7XPnpnM"
        "ZEzHaKOxrSmNbVqLrUah1luqIK23CmpqQcUb3sALiKDow1gFHxTxAoIXpFCsSIsXhPqgRUwFixot"
        "CkUNLQaDbdMkZ5KZycyZOWfv5cPE2qjrae+Xfy/W+vYn/LcEUJa/soqzF/UgsZJOCUkCqaziVGnM"
        "Ahb+jP5g5O5f/ycDmXcb3BXI7i2u47rtg7fec/X25Wd0tFeihJQNCFRJMCiK8Z62lDA6Fdd27th3"
        "/8zHN+/UwV0Bu7e4v6PMybnFcxfKFQNFe86KhfdeuX5Re8Zmml2nZN2p2bTryGVcZzZITsvapDOf"
        "cblUpnlx/+m5JUtyj1wxULTFXYN6ctZcsMpAsWg3bNjA0NC2JOXryeQEOjFZkVJYkTCsSBhWmQqr"
        "MhlWZSqsMFWqSDiJUinJ0NC25Hkb+IFi0Z48ChHQv58785rXHu/syj9+2313dB8dPaLgxDmPEcEY"
        "watiBBTRs85eLDveen9menzqtWN7n3gOUBFBVbGAKoOdNz167ZWVmYn+P+u5pxeYOq5a9rXSuDjv"
        "UOexqQD1oKoYI8ROpVDIUzDVAvnssyu2Ptedbu/8dO+7D38BxAJrCy9sf/XL224auKA828DHUSxB"
        "YMRmJIkdegIT5p1BSVsLPtaMUeeCTFok4eXXP3rvnedvv8uyaOn5a1f3XFBFmpONNM6nbRJ5nPcY"
        "saiCU0UVxIiq1xMkiRFE0/LZgRG7IJdt3r1xme1ZUrgeON2iVTtdrurRKYLJUh31LVRFDOoVP9em"
        "quIVEW0txQNiU0SlGd4eS3GaawYbz/OmHmsTsJZGzUexykwNSpWGmFQalRTOJQgGr3PheiIcldZA"
        "VJtk8wWePDdL4GPGI0MU+wDAEoW+FsUk5UjKdcfoLyN8/sEOqvWGKl7m2m3NVRVFEDGgHk1qFBYu"
        "4sY77yWdaeN4KU+SxABiAxKqkVKbqBBFDb79+hsODw9TWLVWcvkOAhG8GARtLU4Mqh5Rx2xZOLR/"
        "iAMr++lZtQZjp6lFsQBiLUhYrevE5HFNNJHpcpnla3r54JM3GJusMx1Oo8ZiTYsEQRCUM8/qIpkN"
        "ueW624liz7Fj48RJE2JVQGySTGupJlJOvKvPzjJbq5nLV3abpV3w/fAo3/80Slt7O84leOcwRmg2"
        "EzZdtZb1a7pZ0pUnLJWdZvK+vbNL6uVqADSsa0wd2Pvhzh9XXra537mYRvgHl2y9wY+VISZF//nL"
        "aCQt3Kw1BCj1ZkIzgZqHxYsXysjMsVTQ1cGRkR84vO/T3cBxC8yM7ntz0+j+TzaaAJPN2PW9q595"
        "oDzt3fDPv5uwVCFtA8QYRAT1jlq9yaUXrdDVq7vMir7e8ucvFJ86vr8jqs0cCYE9gFpARMyEuPH3"
        "fKwMbH6sr7uvTyoJ7qEHrzZiaCE2JxOd47heh2aA9izvWwDVPVGlOibS0s8/rlAvvb2b0ocO1d3B"
        "g8PxSy++ow6bajQaxoggJmjx7N08a+Xy7Yx899UYbW3m8nXr7NDQkIAmgM4X/T8qvRDI/UsRAa0P"
        "d3IJ8BtwdJ5GgL8AFcRqqmh3TtQAAAAASUVORK5CYII="
    ),
    "refresh@22": (
        "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"
    ),
    "shield_x@22": (
        "iVBORw0KGgoAAAANSUhEUgAAABQAAAAWCAYAAADAQbwGAAAE5UlEQVR4nIWVaWyURRiAn5n59tst"
        "3W6hu91tKVhFgVIVrRc2amoMXhhivBC8ABFNTED8YYz+sIlyiPEAE01UEo2JaEgwGKMQNCkIatQS"
        "EdFFAa9SoEBbyt7f9833+oNSjxB9k0kmM3mfuZ+B04SAlo5OB60B6GVSy0HOaQVAK6Sj0xHQp8s9"
        "BVBdHR2OdHY6IqJQJ9u7IZW74eGV5RVv58rPvFnov/HBV7bDWAAUiIiSjk6nq6PDEU5mqVOdyF8D"
        "7IdJtVfPnR27uO2h6rENY9m+FYIKtE8j3zfQX/wh++qhT9evu5DC7pGkYYYC2EM8VXfx9Gv1Gc1T"
        "I+n6KyJj4pdWxeMxslnYss37qrfHoEKm1adC2i+L0DKFfMXz/UrY7fX1f+5n9+46kN26uZ1Cn+oE"
        "d9Hdi7ckr5/ZTs8B6P0DfsrCrh+9/cf6zMdSUV+jMCimAjegpLU6bmmZGGHqhYrMODh3Cr0bN+14"
        "dO1LVzkpSKnMhCls3W4H168NDuaP698CX3+HOHupEDejuMB6KOCgjrA6zKlMwXdad3wjLTu+suMd"
        "1yZvnePoZKalFRodF6qCoaJmX9a8cfwwu1RUxQlodgw3TWzBz+7EaBeNMCHMEz3vIr7P7qPLWnlf"
        "x3RbUFJP/LzHhFPjWIhqH2JUyi7lAnGladM+N1ZrHnz5OW7v2sy02bNJhx6Noc9lc+cx45NNzH9x"
        "OdOrhVZ8qcIBvwKVsgEcZwDCMLQhgS8ZCfFtiabkeJLXXYc9OsiElS8Qr3ioiEvymeXY/kFS10zH"
        "JMaoVOEQCWJCEGKtDYfA6j1QrBTyPkqrCELERDnyx690zb8fYzR2KEdq6bPUPb0UGRzCeB5rFjzA"
        "3kO9OCZGFAtoSsWi1w0FvRGOl/K5HI5LBMhZRWBi7N3WxYb5CxBrsYUScqKALZd45f6F7P56O6NN"
        "nHxoiIKgNN6J3MCXcEwPwlC+f7BHTIwajJTQ5MQhBWQa0oRao9TJEhqHhoY0k4GKOBTR1GFEnAhH"
        "+/t7gIIG2Hfwt29VINLkVIdFbfDDMufeeRftq1ZjQoXKFzFlj5gT5baXV3PRzFsIwhJKQbOKipKI"
        "7D96uBuGH/gXR37/YDCfU+MT9VqHFSJnTGTy0mexJ0oY32fZI4tZtmQJBD5hwad92UpUZjyjwzLN"
        "NRndU8yrT479/uFJMYgowF2fOv9HGXd1+KVp9BZHEvazJU9a/4uddkXblfZ6HHsT2q5qv9YGn++0"
        "m+Ytsgt1ld3tNnhSd3m4puasbwEjiFKd4DwNwb2MmbM8ec7aplK58nqpJ7JFhFgiweETAzTpOEJI"
        "X1gkPTrJ4eNHuSMSZZ47Ltglgbuo+MuMbXgbbwcDwLrhylNO47qgqk38UWeXn3dTdiZ1dq4Za+8j"
        "be9RaXu3abA3k7BvVSet1E4oD5hJssAk1vydMSKfYWHWrtDpbs9MFEk0ld+NJ+0C6uwsUnYWyWAh"
        "o+1H9elA0pnykErLI6pmMxAdhql/e3bYzyQfU2O29auMSG0i2NNY562qTQavJuuDA2dnKpKsCX/C"
        "lTkqtgEYpf+y4WnjFDR6ixr1/HvErERdkTOTIs0pkagrb2IK07T7+MgV+Q/YyPJHPgun6pKHib7z"
        "NurIG3BoFuY1XHcyjMj5f2Ej0H9scirVSDqdOTWrfx/A3+NPWr4mgwCaP00AAAAASUVORK5CYII="
    ),
    "shield_x@h18": (
        "iVBORw0KGgoAAAANSUhEUgAAABEAAAASCAYAAAC9+TVUAAADxUlEQVR4nH2TbUzVZRjGf8/z/Dkv"
        "nAMHDhxADBEIQYhe0FUzdU5nQzcXNs8sa35qKzc3s+aX3s5yTSpz1Wz1pWyNtba20vJtumpzow+I"
        "IksCfJkBoSIC553z8n95+qA4P7h+H+7d1+77ur5dcAehiUgdDisdiRhICcBlCCW3vrd1GG81AFKg"
        "IxFDh8NKgwQEd4dACo2jmacHipo6d71c1NK8x+3z1GVi0euJS1cPXPz1y0PrIX7vUQpwtBDz+hpV"
        "tXLdhrZATfV6Vyj4XKFy1dJ3lqnzZ62KtqUG7cvJaGciOZM4lp2ePRk/9dvgo4z/A2hxAUrqdrz7"
        "k7+2cYWamfYQm4W/h7jx14B5NDUtz6HEMhzd4S1yFjc0FPBIK1QuxAyW56OTN3r//Or9zUbSaGzy"
        "ly9aq0+fYuhcj/VvIuFcJCWvYimfCtDkmIwKQxzITKgFg7eslsELzsOGIZran3QF13Ssst0L22Sy"
        "rNynJ246IwN99seJmDxJzgjUNcqXOrew2o7RQJY1Toztz2+lorZB/o6luixHXhkctPT4qBMrrfYY"
        "c0K6hZmTLqmtdmGJVn8B67q/huYWbi6q5ubBz6l5cw+ht95h2UA/hzdtEkMZUyslhTbz0kELYzaZ"
        "ymazGTxoEdQOZDJc/uUoSxbWUvnaTspWrka1PQYzUc4cOc5kLkcpCq/WZHN5pjPJrBxNj81k0+m8"
        "xyiQJoKUIzmzv4veffuQGnTjUpRlcWzvBxw5+AloN3kt8Ugpc8n03FD8+i15mthYKp6YKnH7hYPQ"
        "URTlQFFZEFuDW0gcLQiUB2kCshgIBEFPoZiNxqe+JzUmz0P82uTEgMtdrL0UOBlDsHL/Z7Ts3IVK"
        "pOk/fgKZM1n1+m427v2IrHSoQtiGK6CvRG/3A2kJ0HNrtNt0hGh3FTOpXDiLGyGe5FDXPna//Qbd"
        "XR/CXB7xUB1RCStdJSJtS3Fieqz7bme0EIiCw8Ut/Z3K3/ptdNjsKw6qyvpa+gZ6WaAC3LYTLG9/"
        "mpHhETaac9Y2b4PrG3Om95Xs+DOaiCYMSgDr8T7V62k2tXep/akqzT+L394uq+3tosJ+UVTZHXjs"
        "77ylee1rdE6qmlQ9tEkgDAruWzZT/MIZucjRvhr9R0l5bocqs7YQtHcWlJl9VZVZXRLSRynNPIG7"
        "437fPSJgADyOa8MPlExor0+nKwP6fH2VZdeUadvn0V9gjBQZxooHBszz4/zBR8WreA+cEsbkJa9b"
        "/4wc34YRIRTy/2/APGFQcl4UFi5YglqL3x+CO84HBfwH61GTL7BHfLwAAAAASUVORK5CYII="
    ),
    "shield_x@h20": (
        "iVBORw0KGgoAAAANSUhEUgAAABMAAAAUCAYAAABvVQZ0AAAEV0lEQVR4nHWUfWiVdRTHP7/f89x7"
        "t/uyuet2tzlXptWm0dKspaj5llniGGK3pTKjcLOCQFhBi2BMRUjCiCgyQrTl0NGwsjCXgWbpsP1h"
        "+TJr3uVIc6726t19fZ7n9IdOhuUHDhwO3/PlnD/OgXEIKKFBy8IGE0MD0A5ZQ3M3LD8LQQC0RhY2"
        "mEKDFlDcjoTDhogYaH2r1gDmQHlVdbz+w/POjn0yWvdupHd+VW0DZNwSaY2IaAmHDbjNuRZcb7lK"
        "Sn1L5j/tKi1dFwjllXH+HJxqt5n5gEHJDIaHBjtjXT3Ng8dPftMS6zzXCKmxfgXQO69yrX/O/CrR"
        "7vvcLnW/GzG4GIETJ9Ptly+pI9h6MVrmhUIOD89yMXUaCb9f0o75u5NIRgY6OlqmtrfuUc2Qv+K1"
        "7ZHsont8HG2D7i4Z+KMnfTY6rH9EdEQJPiCBpliEciynzOVzCouLTCbfrVlZQd+V3nTTe/XTTAVB"
        "SZhYez+193UccSJ49ACWaZEkiEO5uPFqIeVAPykOYegDaXSwu0tKuk9b1b1XUY8/YQO5pkV2JtGo"
        "O52M6rPKjdZKzc5wsWTrNnQiRmd9PSlHCGhNyfZ3SDjw/eZGORNXnHYCuspKKxWPSYos0xxFtG2l"
        "FOmEzBDw2oM8UrGOyTU18M8AXk8GfVs3U9i4BV/lKnQgQNmJn1T8i1aELFFpSzmpFA6I2cNILB2P"
        "Wy6lPW4sydQeLnz9FcYnuyiurCSwfAWB8seQYC46keTX5v0cbjtMrs5AOylcKBVPJKwIIzF9AgYS"
        "0etR03QrA2FETGLROAc3vcpv+/ZjKI3l9mI6ws9Ne9n5Rh2euENM3BggWhskh6PD30KfPgZ/D/cP"
        "XhGXj0y0jCgXSYS7MjPwBHNwbAePaeI4gntikAc9HtzicB2TLBTiyqB/oP/Pq9CvATvy16UOJaZM"
        "MnzOIDaBUD6LdjcxZdlT6FiS3jPn0Gmbh1ZWsPqjj/HnBkkoi2nK4yidIV19vacA0QDHrkX2D8Vj"
        "qiQQ0rYTwz13Ef5FyyAa49DuXVQ/v5bvdu+BeJq8xcvJmDkHr3OdGYECfSUeU18OdLfcPO4GDRjN"
        "E6Z3SMEC+cEoSNUon922sc5uXf+y/STaXm9MtCsw7IM1m+wD1a/Ya3Dbpz2FKckul/e9dx0DtNCg"
        "VRiMz8FegX9Bo3/K0dmOsptTV/VnVlRZaCbpLAyxSSlFnzOCgUWNN8dZRYg2e1Q2Ji892gO/PAMG"
        "AC03kxd0Tt1FV6mI995UayA/vUGH7Oe4Ec+Sa9UaufbRvIKUBIrT7apIlmrPiwDhMaPxLwdgNf43"
        "21WRiDckkdyc5DZv0Ko1cuwdE3LT1ybnJSUrSw7glwXa89L4vv8wNmG5kRneif/yqMsjkh+QoemF"
        "jhRNkGG3S97G6PQZxtLx+jtyS+Anbw2ZW5owuo9jJD6AC8swXycvz/+/q92JMGNPG8jJycbrnUVZ"
        "vg9uONzJ6F+71OhoRbMWGAAAAABJRU5ErkJggg=="
    ),
    "usb@22": (
        "iVBORw0KGgoAAAANSUhEUgAAABAAAAAWCAYAAADJqhx8AAADZElEQVR4nI1UW2xUVRRd+9x72ykO"
        "bW1jhQoVCiSS8RFsP9AYH6FJiX9+FBNlvgAlUUkgGGMiTtLGlA/6IY1GazTBzAdOJDDBoFVhmFpC"
        "qVVrtYMFhk47jQPThy1M53HnnLP9uKUdwgiuv32y9zpr773OAYqBmUAA2pObFuP/jQAbAFD98fU3"
        "mqJ5WdMR3154fnf4WBAR8MxQ/WO98zfXMavHQ6kZeMKrmZngY3GPeidhXdfEqbU3mRGR6YfnmNcf"
        "GjsGAA0DbCHABgJs3EnmC5kAUL5ncPeGSWa6zDkRlopibK+9xrzM2+8tdql5qz9fC3RrG8FO3aiK"
        "ffj7JK+ocOP5NSaOx/TY1PVJU6fqat69tkW50u5S13LOJTOJ6Y66nwvJCiVV4v1fe2mUWezr6wdQ"
        "afpG9tePMddFNK+PM6/8ZlpiY9AjAGBVe3LnE32Z4Q3d6X73rvHnyMAslrttKIDd7jQMmlUiu+Jq"
        "Cno8RpkrUeQTigmcKzfxSPejxubSroTHRTkNqL9LuvgzeIgkgwEoCSgmSKWNNISeyBtUawFSsL6R"
        "IAF7onJsXlLyD+TnLkJnJqerAQhWWsEGICUQYMGj8SkdnQbVWornMhYGLwlMRWYFru64YHzRc0TY"
        "2qK/Zhj+cDsAG6msRRIgKfPYRgr+cK8Zic5TDVz0ebBbt33wNPxbRpyRPXRws/m91GbnaAqoKocB"
        "4L3+MA0wkzd0ruzFo29VfJWIlw0z4/W+LCq8m0AA0LLgzpWtDfhyhunbdF684N8LwKL958MixFx6"
        "OJpz9zIbPzDj1dPjKN++FQDQ8KnlFDvuK6FXjg/gDLN1VrKr4/Kw2TY0RcdYiiArvP2njY0HDwOo"
        "XnBd4cpvBY312HokiAMRLb5jNk4rJj8rsS/yD9Dc5DhFFMi+Hc7zBQA0NaL2wCf0TiQvgqzFrp8u"
        "LSktXrykhJ0nW/ZmOHDfiVmmTs4uO5nh0p09RwEYC+3+B1oCDvuzgZfMHzXjI85jb06hk/Pm1/MM"
        "z6Hm2/IWsMSYfMBpwm2vkRnSuKIlbAAxSJktYViy3skbpuIE4bMaBODcqR4auiioUbhQVaLwJFzi"
        "t18UBkNnQASEoe8yBmcjom7Pa7S7O0GtIzZ2nIzjfu/Li3O6NxY/0AeB5qdQfPeL+BcMJalsb+F1"
        "dwAAAABJRU5ErkJggg=="
    ),
    "warning@22": (
        "iVBORw0KGgoAAAANSUhEUgAAABYAAAATCAYAAACUef2IAAAEH0lEQVR4nJWVW2xVRRSG/zWzT29Q"
        "Sq1CoOUilx4oBkUFIVpEEijeqEW3kOiDQSVqDAkk8KAkp8FEBHlQ0sQ3E0lI4FDw8gAJBCUhJjSa"
        "EAsSIcqltJRqWzltz9ln7z0zvw8bjBoVmJdJZmZ9Wfn/tdYAt1giyX60DY91fIomAKWAgIDcKvY/"
        "mdmsrwHoU4dr94z8+h6j3Me8dKLh5IctGEdmVCYDdcdUEhpQ+KoNm8hdJA9F5O6Q3MOO3WP2Awqk"
        "r+8ImslAkZStPtK9nU8Nk21RmFtgoqEGQ7shHOlZy882ogmikM3i9uFJJoKOvRMPkTto840R7YOW"
        "8XxjhxoicrP78cv6c3VAOZlRuB29mU0k2LsJL0W/vUqGq0I7OMt+m51gOw5OsBxIW44sDJlfxy+2"
        "lL0LyI2Y/4MCQlI1A2Mvfj3vCvmKZW5mdPbYFDt3gmcfnlZhLp6cYdk/3dC2xN3HHylsSiNNUv5p"
        "5N9dpa9ElFu/fewHUxc/UGf6OyxiT+cDC1ZWQ1feDRNpIFZi+zpdbePk8uY3anaKCFtbfflXcNaH"
        "FnXA7nqajfNWLlgH0xVzKNAIIozyLJxTgAhGeQWgUASHYg/DF+KHVt73zCcteEFUu/2rkTfB4md9"
        "gK5k6ZppbdX1FbBXz0NiAsWAZRIBFFAUSmCAMIYYwvb2SlmtYuNzk3Y0kKN9P8ObRioA+CYDLdJu"
        "D24o2zzn2fRc9JyOJW+1FAMgiKQMESACT4mUuojIR0BQBApOofuXeM6Kife2vlaaEdnqmE2Yihmo"
        "Ja20b07h7AUrZ70D12dM36BmEAFBBBRCVIjBcF6hEApKXSiuEALFEFIMYa/lNMygXdQ86e21NUzr"
        "NWJ9H1pIX4vst8e2jT+y9K36ZfanzhixaJgI4hzoCK0dDp+6CxXlFXi8vpvWACIiUJKMjJRyavaM"
        "1NGPuo4sf/96E7O+9kTa7Y4V6uVFq6Yvw5WzMXMFLQTgHGgBkLCOiK8OoljSD1frBBZkUp8iWugA"
        "rbouxY82j1veenxotbzYvk/NB2ueWD19W3lpD+2FAVGBheQNZMTBFQhtie86NZp3VuPJ7eNw/rKG"
        "DilmBHB5wOUpCADz85BUVOfYtLp6awM42lt8PxbOnMU6nLlszO+iAMCZpFsA0gIyqYp4fomgqtLD"
        "PSVAfhB0ybVAhKIIoSh1ZsDVTa6un1qJud6Fa7jcc66XVfWeVzpgLDTECQWQJJpE7Rgr7a/3J4VU"
        "tIg8gYCggwAQKFAsqWo83fd9kLsyjC7v8z6cSe8O1q9q0VvGKD2WhgKlBBDAEULQOsAlqkJEi1IC"
        "IUECTN7RK4PrPYGrB/aFG08D3cLkkyCA8bOBiak/50ZKpVKAjWMbI4X4xnn5jQYgIDEAg5hVgBjA"
        "/QBcAnAdgPwBjmQuH2vKARcAAAAASUVORK5CYII="
    ),
    "warning@h18": (
        "iVBORw0KGgoAAAANSUhEUgAAABUAAAASCAYAAAC0EpUuAAAD2klEQVR4nJVUS2yUZRQ99/v/6Uyp"
        "ffFoo9L6ABVaIialKKKCNBI0BILkt2oxAiYaUKM8FiRoBtBITCH4wAQTV0ZDnGBYlJiAJDXuXGiC"
        "IhgePiihtEg7ZToz/+P77nExBN1g4Gxv7rnnnntygf9BNgsDCHatRssvB9HdtwOzAYBZmP/ruy5y"
        "OXiAwf5eLBw6/dyQRvuZP7cu/P5TrAPM1fpNgICQNMsmofbsD4/+SR6ljd8Nya85/OsKu6cbM0nK"
        "TSkmKyr7P6vdS91FW1oZxWNtLhnvjMj3eOzgHYcBgLngxtTmAngiBvvWYt7o789b2lcShm2WSYdj"
        "sd0yWhInl17kl2+iBzDgDdggZOAB8E/2zfiJfIMstsU/Hmp1m7ur3c9HWhzHpsVkjzt7uHNgMTCR"
        "pCEg1187Bw8Q9L2V2cTSKiajcyKOznCbV9e7+lSde2fDVMt8m0uGZ0aMunlkW/0ngKC/H/5/ea4Z"
        "nc3CIKBueYjTO5c/uB2py07zlzwkiuraNCY01rKuvkoQhdB80YMdsB0r2l/evZhzF3WJzQX/2nCN"
        "dNu2QESEK9e0fNw8p6lGL/6mEhtBWMIET1GOPFT7FojKkBiiF85xYluNv+Dp2/dSKUEQAFdtMEAl"
        "kyIH3BdrzQuzl85cguETMQuxx7AMJCGrUw5WjWR8AuUEjGJwXD0M/pE88NTUzs9XmVflmQOOuQqf"
        "yQImCLJcATbND9p7U7Vj6i5cNBImQDkGypF4qhgvCKoQE6UQKIWQKIYbHBEvU9CHl7XuWAQ2I6Bm"
        "AeMv7IcR2W4PbZ3Ue+e8xmY9czxGSJ82gjgCzqJjegpLu9KYNbUguBLSJCmhjQGK0dMDbtpjdzdu"
        "3NiwU0TWkjACEbw9n10bPpp7tLFmILHnR4wQAqeAEgIFEuDk+Wq0t4RQkCQEAkBAQOC1NvDy3w3+"
        "ztfPPr77hHxnppC3PNlz14eNTaOwZwbFlKzIeAwpOriCwjhiy740Zq2vxvtfpWGoYq8QLBAsUFCi"
        "uFOXOam1iOVrJveCTPvrH/EWtnek2vXYKat5MUqF2ooIVVAjSvNkD8231qF5soWOlBiHAiOsBN4Q"
        "BuKljw+7e+6bOKenBXP9oTEZC4cGUZcxflVMB0M4QEiBp4RGwKauIl5acAENfowoBKqMgkTl86iQ"
        "jjBp4+UHyrwyjhEBIB886+1c/IT3Wia2GVUY8QRUEWilVZXwhUhUxFTOACigIoCSqRQ0n5jiN4e4"
        "feu3do9IZSBuA+69f4rfJAAtAOPDGECdBZMUEFmwhjDwAR9AYiHWgikfyPhA36A9D+AvAPIPMpsS"
        "DHixMAAAAAAASUVORK5CYII="
    ),
    "warning@h20": (
        "iVBORw0KGgoAAAANSUhEUgAAABcAAAAUCAYAAABmvqYOAAAEeklEQVR4nJ2Ua4jUZRTGf+f9z0y7"
        "XtbLiLK2ruWlkpVcXdTY0FS8oMFi1nhDLKIEMSFIoe3C7AoZgUJtRhqU+aVwKKhIog9iBkW0YIhm"
        "maujIt7SXWdnduZ/e9/Th12IDUvpwPn0cp7n8Bx+L9yhslkMCFtmk+78iCWfbmUyCJrF3Gn2PyuX"
        "wwPhk10suXxqycVK927X3bW69+heXgQz8P4/KpvFqKpZ18SYfOcj11Q7NY4Phqo/aqHrSd33DM0i"
        "gw0U5K7EVfHAcPjD6v2qe9QGW/yoNMvG5aWB6nvuxJf1P0HG01zG425FYSAOMXQ8x6JCfp2qvhrG"
        "vQ1W/bnWFqbFGq0OXWGz5l7mBTDov8Rzu6MIZKhTV72oZWpHzX3T1JYOiRcZrp66jokSuNIxkRq1"
        "TYua2jeMc2PJqMvezYGPHCEBhkM7TKtWNmlcXOhrYZrt2F5jHx7r2Q92jLJ6a5qNexoDjTfpN21D"
        "D4DcdvtBbtksZsECtdsb3dSZS5tfoeqm1eIFj7LSeVrokTQnz9UosaC9BQ+Xj+a0NG18Y77OkzXG"
        "5jKDDQaJt7VlRMToE5vG7amd+8Awd/2EI0gYXEhNTQqrKR1ZI0JURgMRd/UMoxtHs/zp2ndQl8pk"
        "MgOx/kNcc3gin9sDa3R9U8ucpZR+D7UUegQBhD4pz+FHhqqkgzCAMET7rEf32bBxecPMj9ebLbL6"
        "M3sk+/f2BiALhkxWV+LSzese3JUaGzl75byR0EIQKHGo1UlHGBmpSgJ+BEGMhI748g1PRpbtvJX1"
        "rz87UicuaMu67ICuAWjLISI73KbXhr85ZemUWnfhpKXsDBUf54dCEEhKFD80VHmR4gdoxUcrPiaw"
        "wvlzdtLicaNaNlTvFGl3bbn+aEwug2fWiG1t1MeaHn/oeYoXIu0uGfFDpRxAJYRKxL1pJVmdYnwa"
        "oS9AghAJfPB9ja+XEvRei5tXTVzb2sCjZq3YXAZPVLNGpN374d26zuaN9TPsyeMR1vOIQ3AOnCLq"
        "MJ7HxZtp6scUcL6vGAOCAKqIkPScN31y4uj7V44vaOuerZq1RmSH61iVemluy8QZnP010qLvSakP"
        "KYdQjnF9FmMdXxxybN3Zw+HvAoxTsUUrWrRo0Qp9MfQGhq581Lxq9IzdKxKbRdqdWVyt4+c/df82"
        "L8prfLFgTAW07NA+hQr9XYK3vx3KV8fHsff7ERAqcR/YMrhKf2tFiC+WJZns0fkrRm6rh1GJyWNo"
        "qKsL0py+Gsc3MRinGoM6QBRrgYTSujKkboJj68KY4E80jEEUUVUQwXiKWGTI6VsuPWbE+FqYlPjl"
        "Br+dOXatmF6YGF5VCB2CQfv/GLUgqqoqsmx6hWWzLoGvxDE6VEBUBe1nRkEFUVObMOe+ruT/gK7E"
        "zxUu7d1X2VguJd9KD/PGa6TGeIKKoBYxqHMOrIJzijFGPAExAlZxiKAoqHpV4vIHbX7//mBzDxRk"
        "AFcFhqRgwvABfAOQJJgY4n7eUhRBhw2wcQ8hClIaAHw0SDfEIeTpn5G/AOuxZb4xNfIbAAAAAElF"
        "TkSuQmCC"
    ),
})
# The header mark at the BOARD's size: the same
# board-icon extraction the 42x43 slot uses, scaled
# from its 67x68 master to fit a 66 px box instead of
# being shrunk to 42. Overrides the democopy3 slot
# function above (its only caller is the header).
_HEADER_MARK_LG_CACHE = []
_BOARD_ICON_LG_B64 = (
        "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"
        "/aYWMQeSDpHuqDRw4IbtsUigKZ8+ccpZ3zkk1lYuEfQkL+TTpQuXp4WqBORqYU1zm7KbTPlsW5E7"
        "pZxxg2HN6g0mHx2CzEX6rYC/10CKrJQmCwVP8nn4fQkPkVRIaJoqCc+QTaklz5m57NGsP2s101pM"
        "UL1Ynbs4DRciozvkEcsfuaFuOlsc05fWZH9KViwp2oHV6VekCJbboytuoCarFrK0briTdcJHZWqN"
        "rtFu5cC1O+JfOX5y2Kk78dyr+rbf0jU+Bu6noOVXlLzldNa//eRy85vfmWr92od2B39w7IKjOYZx"
        "y017wl86fdK/YbTTdfojpZdfvpDrqFt+WyaRSMc3BW3JH2tWSl217FOt3rgZ7RqYX1zNzNQrR4/B"
        "uCNXE5vVkL697cphWw0Q9Gl1yfYfF17zKat5rtlaei5o2/Pt0Wt39I7vuft201odWyuujQSabid2"
        "h4QpFbJLGc8QfjvUOSZfPnGqtWpY5obB9UnTNGLlsikJW6UmC1rLM5ht3dKF5LZxxOQbEXgDEJ54"
        "ddZnoVo0n/vaN74fNStedb4uLX79+3M9jXqXkV+ZK1STKyMXvGislDfs3njqsuFyStSayaptT/gl"
        "KYoaqMZc2ekCR0VdKpYzTxRWjry8I3Ti4kT9JefzzsQpp7LnKYjrJjqmLEyc+iocWh6kaBoJ5LU1"
        "lIZ62jw/rY1Vm1WzVTcznk3ZMoRsN8Q5e9UpE1QbZaVTrWadnFOpNTp3bNg+O7c8eur487rd6KIq"
        "Z3l6eslr+YRlZ91pBcqfAuf33gTE61f2iG0QyMC2Iuzuh5klWPChhIIK1lbbbl1AiRWQ/VHd5zbc"
        "ZmGdZa0Ngn8Fehrg11/N61aLsDqPPwiuD9pZoAEwAfIaKEt0SrANOO/Cks1PLlcWQAiVfiS6sNHw"
        "COPSB8wDsxo0NJDq0EiAlVYDnWtuOxFwHKX9w4tVAQdcP1RaMAsUeIsw+lqRgXgYRnZDAvD1gd8D"
        "nwfap8APBF5tB3RejTQK4J+AwIde/U378fGJH22N8EY34UftzW6S1v3q9ULjEO+HkTj0Trx6TH0Q"
        "tOte7Vs6APoPxxUEgtsg+F4IdkNgEHz8ghtrvHZ7gtcP9mcp8LMU+0Xlx5trvLrfxI/emH/Wf1/f"
        "3lL+Xx6Yot1wl57DAAAAAElFTkSuQmCC"
    )

def _header_mark_image():
    if _HEADER_MARK_LG_CACHE:
        return _HEADER_MARK_LG_CACHE[0]
    try:
        img = tk.PhotoImage(data=_BOARD_ICON_LG_B64)
    except Exception:
        return None
    _HEADER_MARK_LG_CACHE.append(img)
    return img

_STAT_GLYPH_H = 84
_STAT_NUM_SIZE = 38
_STAT_CAP_TOP_PAD = 15
_STAT_CARD_PADY = 2
_STAT_CAPTION_LIFT = -15


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

# ---- Desktop redesign tokens (2026-10-22 candidate, REDESIGN-SPEC) --
# Board palette deltas live HERE, in the one token block -- no
# scattered literals in the layout code (spec SS12 step 1).
ACTION_SCAN = ACTION_CLEAN            # board: SCAN PHONE is green
ACTION_SCAN_HOVER = ACTION_CLEAN_HOVER
ACTION_GUIDE = ACTION_BLUE            # board: GUIDED CLEAN is blue
ACTION_GUIDE_HOVER = ACTION_BLUE_HOVER
CARD_BG = BG_PANEL                    # stat / device card panel tint
CHIP_BG = ACTION_NEUTRAL              # filter chip, resting
CHIP_BG_ACTIVE = SELECTION_BG         # filter chip, active view
TITLE_GREEN = VERDICT_KEEP            # board wordmark: Trapper green
# Faithful-face stat cards (board section 3): tinted panels.
STAT_REVIEWED_BG = "#0E2742"
STAT_REVIEWED_BD = "#1D4E79"
STAT_REVIEWED_FG = "#35A6FF"
STAT_REMOVE_BG = "#2C1216"
STAT_REMOVE_BD = "#7A2733"
STAT_ASK_BG = "#2C2310"
STAT_ASK_BD = "#7A5E18"
STAT_KEEP_BG = "#0F2C1B"
STAT_KEEP_BD = "#1F7A44"
# Risk pill tints for the results table (board section 7): dark
# family tints, never a solid verdict color -- the pill carries
# the verdict WORD as colored text (owner verdict-display law).
PILL_BG = {"remove": "#33141A", "review": "#33290F",
           "clean": "#12301D"}

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
SHELF_BG = "#0B1424"               # FAITHFUL FACE: board table navy
SHELF_INK = "#F5F8FC"              # body text on the dark shelf
SHELF_SECONDARY = "#9DB0C6"        # supporting text on dark
SHELF_MUTED = "#7186A0"            # package metadata on dark
SHELF_BORDER = "#1E2C47"           # dividers on dark
SHELF_SELECTION = "#234562"        # checkbox selectcolor on dark
SHELF_VERDICT_COLORS = {"remove": VERDICT_REMOVE,
                        "review": VERDICT_ASK,
                        "clean": VERDICT_KEEP}
# Boom on white (SHELF-SPEC §7.3): the reason BODY renders in dark
# ink; only the single loud phrase takes the verdict color.
SHELF_BOOM_BODY = SHELF_INK
PANEL_BG = "#0E1930"                  # detail panel: board panel tint
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


class _SubButton(tk.Button):
    """Board-style action button (faithful face): icon + bold
    title + small sub-line, as ONE real tk.Button. set_busy()
    and friends keep configuring it with text/state/bg exactly
    like a plain button; the overrides route those onto the
    inner labels. Child widgets forward their clicks here."""

    def __init__(self, master, title, sub, icon, bg, hover,
                 command):
        super().__init__(master, bg=bg, relief="flat", bd=0,
                         cursor="hand2", command=command,
                         activebackground=hover,
                         highlightthickness=0)
        self._bb_bg = bg
        self._bb_hover = hover
        self._bb_title = title
        # Democopy2 (2026-10-23): the door's icon is the
        # ChatGPT symbol picture (`icon` is a symbol key);
        # the drawn glyph (_SUB_GLYPHS) is the fallback.
        _simg = _symbol_image(icon, 30)
        if _simg is not None:
            self._icon_lbl = tk.Label(self, image=_simg, bg=bg)
        else:
            self._icon_lbl = tk.Label(
                self, text=_SUB_GLYPHS.get(icon, icon),
                font=(DFONT, 17), fg="white", bg=bg)
        self._icon_lbl.pack(side="left", padx=(10, 0))
        _col = tk.Frame(self, bg=bg)
        _col.pack(side="left", padx=(8, 0), pady=(0, 0))
        self._title_lbl = tk.Label(_col, text=title,
                                   font=(DFONT, 16, "bold"),
                                   fg="white", bg=bg, anchor="w")
        self._title_lbl.pack(fill="x")
        self._sub_lbl = tk.Label(_col, text=sub,
                                 font=(DFONT, 10), fg="#D7E6F5",
                                 bg=bg, anchor="w")
        self._sub_lbl.pack(fill="x")
        self._bb_parts = [self._icon_lbl, _col, self._title_lbl,
                          self._sub_lbl]
        for w in self._bb_parts:
            w.bind("<Button-1>", lambda e: self.invoke())
            w.bind("<Enter>", self._bb_enter)
            w.bind("<Leave>",
                   lambda e: self._bb_paint(self._bb_bg))

    def _bb_enter(self, _e=None):
        try:
            if str(self.cget("state")) == "disabled":
                return
        except Exception:
            pass
        self._bb_paint(self._bb_hover)

    def _bb_paint(self, bg):
        try:
            super().configure(bg=bg)
            for w in self._bb_parts:
                w.configure(bg=bg)
        except Exception:
            pass

    def configure(self, cnf=None, **kw):
        if cnf:
            kw.update(cnf)
        text = kw.pop("text", None)
        bg = kw.pop("bg", None)
        if bg is None:
            bg = kw.pop("background", None)
        state = kw.get("state")
        if text is not None:
            try:
                self._title_lbl.configure(text=text)
                if text == self._bb_title:
                    if not self._sub_lbl.winfo_ismapped():
                        self._sub_lbl.pack(fill="x")
                else:
                    self._sub_lbl.pack_forget()
            except Exception:
                pass
        if bg is not None:
            self._bb_bg = bg
            self._bb_paint(bg)
        if state is not None:
            try:
                fg = (DISABLED_TEXT if state == "disabled"
                      else "white")
                sub_fg = (DISABLED_TEXT if state == "disabled"
                          else "#D7E6F5")
                self._icon_lbl.configure(fg=fg)
                self._title_lbl.configure(fg=fg)
                self._sub_lbl.configure(fg=sub_fg)
            except Exception:
                pass
        if kw:
            super().configure(**kw)
        return None

    config = configure


class PopupBlockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AdTrapper v%s -- Malware & Adware Scanner" % VERSION)
        self.root.minsize(1024, 700)
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
        self._dev_model = ""         # device card: model (redesign)
        self._dev_android = ""       # device card: Android release
        self._selected_pkg = None    # detail-panel selection
        self._row_by_pkg = {}        # pkg -> scan row, current render
        self._row_frames = {}        # pkg -> row Frame (selection)
        self._det_img = None         # detail-panel icon image ref
        self.search_var = tk.StringVar(value="")
        self.chip_btns = {}          # view value -> filter chip
        self._tick_overrides = {}    # pkg -> tech's manual tick
        self.source_var = tk.StringVar(value="All sources")

        # ---------- header ----------
        # Desktop redesign (2026-10-22 candidate, REDESIGN-SPEC SS1):
        # the small embedded master stays beside the wordmark AND the
        # same master rides large at the header's right (256 px
        # source ceiling; SS0.3). History moves up here. No DEMO
        # badge (the real app never fakes demo data). Settings
        # gear: restored by the owner's board ruling (faithful
        # face, 2026-10-22) -- it opens a REAL settings panel
        # (show_settings), never a dead button.
        head = tk.Frame(root, bg=DBG)
        head.pack(fill="x", padx=22, pady=(8, 0))
        _mark_img = _header_mark_image()
        if _mark_img is not None:
            self._header_mark_img = _mark_img
            tk.Label(head, image=_mark_img, bg=DBG,
                     bd=0).pack(side="left", padx=(0, 10),
                                pady=(0, 52))
        else:
            _mark = tk.Canvas(head, width=30, height=40, bg=DBG,
                              highlightthickness=0, bd=0)
            _mark.create_rectangle(4, 2, 26, 38,
                                   outline=ACCENT_CYAN, width=2)
            _mark.create_rectangle(7, 6, 23, 30, outline=BORDER,
                                   width=1)
            _mark.create_polygon(15, 10, 21, 12.5, 21, 18, 15, 24,
                                 9, 18, 9, 12.5, fill=ACCENT_CYAN,
                                 outline=ACCENT_CYAN)
            _mark.create_line(11.8, 16.8, 14.2, 19.4, fill=BG_APP,
                              width=2)
            _mark.create_line(14.2, 19.4, 18.4, 13.8, fill=BG_APP,
                              width=2)
            _mark.pack(side="left", padx=(0, 10))
        _htxt = tk.Frame(head, bg=DBG)
        _htxt.pack(side="left", pady=(0, 29))
        _wm = tk.Frame(_htxt, bg=DBG)
        _wm.pack(fill="x")
        tk.Label(_wm, text="Ad", font=(DFONT, 26, "bold"),
                 fg=TEXT_PRIMARY, bg=DBG).pack(side="left")
        tk.Label(_wm, text="Trapper", font=(DFONT, 26, "bold"),
                 fg=TITLE_GREEN, bg=DBG).pack(side="left")
        tk.Label(_htxt, text="MALWARE & ADWARE SCANNER",
                 font=(DFONT, 10, "bold"), fg=TEXT_SECONDARY, bg=DBG,
                 anchor="w").pack(fill="x")
        tk.Label(_htxt, text="iFixx Phone Repairs",
                 font=(DFONT, 9), fg=DGRAY, bg=DBG,
                 anchor="w").pack(fill="x")
        _big_img = _header_mark_image_big()
        if _big_img is not None:
            self._header_big_img = _big_img
            tk.Label(head, image=_big_img, bg=DBG,
                     bd=0).pack(side="right", padx=(10, 0))
        _hbtns = tk.Frame(head, bg=DBG)
        _hbtns.pack(side="right", anchor="n", pady=(13, 0))
        self.settings_btn = tk.Button(
            _hbtns, text="Settings",
            image=_symbol_image("gear_settings", 22),
            compound="left", font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=8, pady=7, cursor="hand2",
            command=self.show_settings)
        self.settings_btn.pack(side="right")
        self.history_btn = tk.Button(
            _hbtns, text="History",
            image=_symbol_image("clock_history", 22),
            compound="left", font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=15, pady=7, cursor="hand2",
            command=self.show_removal_history)
        self.history_btn.pack(side="right", padx=(0, 10))
        tk.Label(_hbtns, text="v%s" % VERSION, font=(DFONT, 10),
                 fg=DGRAY, bg=DBG).pack(side="right", padx=(0, 10))

        # ---------- device card + stat cards ----------
        # SS2: the status bar trio (dot / status / helper line) moves
        # INTO the device card, same widgets, same honest states --
        # never a hard-coded "connected". SS3: four stat cards --
        # the faithful face follows the BOARD: tinted cards, family
        # icons, board captions (verdict words stay in list/panel).
        toprow = tk.Frame(root, bg=DBG)
        toprow.pack(fill="x", padx=22, pady=(8, 10))
        devcard = tk.Frame(toprow, bg=CARD_BG, highlightthickness=1,
                           highlightbackground=BORDER)
        devcard.pack(side="left", fill="y", padx=(0, 12))
        # Board SS2: a phone-picture area at the card's left. No
        # stock photo of a phone we did not identify -- a simple
        # drawn phone glyph (outline + two-tone screen), the same
        # simple-shapes language as the header fallback mark.
        _pic = tk.Canvas(devcard, width=64, height=92, bg=CARD_BG,
                         highlightthickness=0, bd=0)
        _pic.pack(side="left", padx=(12, 4), pady=(8, 8))
        _pic.create_rectangle(7, 3, 57, 89, outline=BORDER,
                              width=2)
        _pic.create_rectangle(13, 12, 51, 68, fill="#123A5C",
                              outline="")
        _pic.create_polygon(13, 68, 51, 34, 51, 68,
                            fill="#3E2A6E", outline="")
        _pic.create_oval(29, 79, 34, 84, fill=TEXT_MUTED,
                         outline="")
        self.dev_glyph = _pic
        _dcol = tk.Frame(devcard, bg=CARD_BG)
        _dcol.pack(side="left", fill="both", expand=True,
                   padx=(4, 12), pady=(4, 8))
        self.dev_model = tk.Label(
            _dcol, text="No phone", font=(DFONT, 19, "bold"),
            fg=TEXT_PRIMARY, bg=CARD_BG, anchor="w")
        self.dev_model.pack(fill="x")
        self.dev_android = tk.Label(
            _dcol, text="", font=(DFONT, 17), fg=TEXT_SECONDARY,
            bg=CARD_BG, anchor="w")
        self.dev_android.pack(fill="x", pady=(1, 0))
        _srow = tk.Frame(_dcol, bg=CARD_BG)
        _srow.pack(fill="x", pady=(2, 0))
        self.dot = tk.Label(_srow, text="\u25cf", font=(DFONT, 13),
                            fg=DGRAY, bg=CARD_BG)
        self.dot.pack(side="left", padx=(0, 6))
        self.status = tk.Label(_srow, text="Checking for phone \u2026",
                               font=(DFONT, 14), fg=DTEXT, bg=CARD_BG,
                               wraplength=205, justify="left")
        self.status.pack(side="left")
        _hrow = tk.Frame(_dcol, bg=CARD_BG)
        _hrow.pack(fill="x", pady=(2, 0))
        self.helper_status = tk.Label(
            _hrow, text="Phone helper: not checked",
            font=(DFONT, 12), fg=DGRAY, bg=CARD_BG,
            wraplength=205, justify="left", anchor="w")
        self.helper_status.pack(side="left")
        self.helper_btn = tk.Button(
            _hrow, text="INSTALL PHONE HELPER",
            font=(DFONT, 10, "bold"), fg=DTEXT, bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=12, pady=6, cursor="hand2", state="disabled",
            command=self.on_helper_install)
        # packed only when an install offer actually exists
        # (companion absent AND a companion APK beside the program).

        stats = tk.Frame(toprow, bg=DBG)
        stats.pack(side="left", fill="both", expand=True)

        def _stat_card(glyph, caption, bg, bd, fg):
            # Board SS3: tinted card, family icon chip at the
            # left, big colored count, caption under it. The
            # captions are the OWNER's words (democopy delta,
            # 2026-10-23): Items reviewed / Remove / Ask first /
            # No flags found -- a RELABEL of the board's "High
            # risk" / "Needs review" cards; the buckets and the
            # counts under them are unchanged.
            card = tk.Frame(stats, bg=bg, highlightthickness=1,
                            highlightbackground=bd)
            card.pack(side="left", fill="both", expand=True,
                      padx=(0, 10))
            # Democopy3 (2026-10-23): BOARD GEOMETRY -- the
            # glyph stands at the card's left with its TOP on
            # the number's cap line and its height ~1.9x the
            # number's cap height, hanging BELOW the caption
            # line (owner correction 2026-10-23 04:26/04:28).
            # DEMOCOPY2 pack-centered a 52 px chip in the
            # card, which dropped the glyph ~57 render px
            # under the number line; that shift is what this
            # rebuild kills. Both pieces anchor to the card's
            # top now; _STAT_CAP_TOP_PAD nudges the picture's
            # top onto the number font's cap top inside its
            # label. The drawn glyph (_STAT_GLYPHS) remains
            # the fallback if the picture fails to load.
            _simg = _symbol_image_h(glyph, _STAT_GLYPH_H)
            if _simg is not None:
                tk.Label(card, image=_simg, bg=bg).pack(
                    side="left", anchor="n", padx=(10, 8),
                    pady=(_STAT_CARD_PADY + _STAT_CAP_TOP_PAD, 0))
            else:
                tk.Label(card, text=_STAT_GLYPHS.get(glyph, ""),
                         font=(DFONT, 40, "bold"), fg=fg,
                         bg=bg).pack(
                             side="left", anchor="n",
                             padx=(10, 8),
                             pady=(_STAT_CARD_PADY
                                   + _STAT_CAP_TOP_PAD, 0))
            _col = tk.Frame(card, bg=bg)
            _col.pack(side="left", anchor="n", padx=(0, 6),
                      pady=(_STAT_CARD_PADY, 0))
            num = tk.Label(_col, text="0",
                           font=(DFONT, _STAT_NUM_SIZE, "bold"),
                           fg=fg, bg=bg, anchor="w")
            num.pack(fill="x")
            _cap = tk.Label(_col, text=caption,
                            font=(DFONT, 12, "bold"),
                            fg=fg, bg=bg, anchor="w")
            _cap.place(x=0, y=num.winfo_reqheight()
                       + _STAT_CAPTION_LIFT)
            _col.configure(
                width=max(num.winfo_reqwidth(),
                          _cap.winfo_reqwidth()),
                height=(num.winfo_reqheight()
                        + _STAT_CAPTION_LIFT
                        + _cap.winfo_reqheight()))
            _col.pack_propagate(False)
            return num

        self.stat_reviewed_num = _stat_card(
            "document", "Items reviewed", STAT_REVIEWED_BG,
            STAT_REVIEWED_BD, STAT_REVIEWED_FG)
        self.stat_remove_num = _stat_card(
            "shield_x", "Remove", STAT_REMOVE_BG,
            STAT_REMOVE_BD, VERDICT_REMOVE)
        self.stat_ask_num = _stat_card(
            "warning", "Ask first", STAT_ASK_BG, STAT_ASK_BD,
            VERDICT_ASK)
        self.stat_keep_num = _stat_card(
            "check_circle", "No flags found", STAT_KEEP_BG,
            STAT_KEEP_BD, VERDICT_KEEP)

        # ---------- conviction counter ----------
        # Owner idea 2026-10-20: the tallies on the home screen --
        # live bad-list count, this shop's own convictions, and
        # the suspects this machine has parked undecided.
        # Refreshed at startup and after every render. SS3: the
        # board omits this line; SS0.4 keeps it, under the cards.
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

        # ---------- action row ----------
        bwrap = tk.Frame(root, bg=DBG)
        bwrap.pack(fill="x", padx=22, pady=(0, 34))
        btnrow = tk.Frame(bwrap, bg=DBG)
        btnrow.pack(fill="x")
        # Board SS5: the two big doors carry an icon and a
        # sub-line. The DISCLAIMER door is NOT in this row (the
        # board has none) -- it lives in the Settings panel now;
        # the feature itself is untouched (show_settings).
        _hscan = tk.Frame(btnrow, bg=DBG, width=357,
                          height=60)
        _hscan.pack(side="left")
        _hscan.pack_propagate(False)
        self.scan_btn = _SubButton(
            _hscan, "SCAN PHONE",
            "Scan for malware, adware and unwanted apps",
            "magnifier", ACTION_SCAN, ACTION_SCAN_HOVER,
            self.start_scan)
        self.scan_btn.pack(fill="both", expand=True)
        _hguided = tk.Frame(btnrow, bg=DBG, width=299,
                            height=60)
        _hguided.pack(side="left", padx=(12, 0))
        _hguided.pack_propagate(False)
        self.guided_btn = _SubButton(
            _hguided, "GUIDED CLEAN",
            "Step-by-step removal help",
            "wand", ACTION_GUIDE, ACTION_GUIDE_HOVER,
            self.guided_clean)
        self.guided_btn.pack(fill="both", expand=True)
        _husb = tk.Frame(btnrow, bg=DBG, width=138,
                         height=60)
        _husb.pack(side="left", padx=(12, 0))
        _husb.pack_propagate(False)
        self.usb_btn = tk.Button(
            _husb, text="USB GUIDE",
            image=_symbol_image("usb", 22), compound="left",
            font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.show_usb_guide)
        self.usb_btn.pack(fill="both", expand=True)
        _hupd = tk.Frame(btnrow, bg=DBG, width=128,
                         height=60)
        _hupd.pack(side="left", padx=(12, 0))
        _hupd.pack_propagate(False)
        self.update_btn = tk.Button(
            _hupd, text="UPDATES",
            image=_symbol_image("refresh", 22), compound="left",
            font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self.on_update_click)
        self.update_btn.pack(fill="both", expand=True)
        _hprint = tk.Frame(btnrow, bg=DBG, width=266,
                           height=60)
        _hprint.pack(side="left", padx=(12, 0))
        _hprint.pack_propagate(False)
        self.print_btn = tk.Button(
            _hprint, text="PRINT REPORT",
            image=_symbol_image("printer", 22), compound="left",
            font=(DFONT, 11, "bold"),
            fg="white", bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self._print_report)
        self.print_btn.pack(fill="both", expand=True)
        self.update_info = None  # manifest dict when an update is known

        # ---------- filter chips + source + search ----------
        # SS6: the chips are a re-skin of the same show_var radios --
        # one view at a time, one variable, render() still the only
        # renderer. Counts are filled by _refresh_chrome().
        frow = tk.Frame(root, bg=DBG)
        frow.pack(fill="x", padx=22, pady=(0, 6))
        self.chip_btns = {}
        _CHIP_W = {"flagged": 223, "all": 204,
                   "sites": 228, "badlist": 189}
        for val, txt in (("flagged", "Flagged only"),
                         ("all", "All applications"),
                         ("sites", "Notification sites"),
                         ("badlist", "Bad list")):
            _chold = tk.Frame(frow, bg=DBG,
                              width=_CHIP_W[val], height=56)
            _chold.pack(side="left", padx=(8, 0))
            _chold.pack_propagate(False)
            _chip = tk.Button(
                _chold, text=txt,
                image=_symbol_image(
                    {"flagged": "warning", "all": "grid",
                     "sites": "bell",
                     "badlist": "shield_x"}[val], 22),
                compound="left", font=(DFONT, 12, "bold"),
                fg=TEXT_PRIMARY, bg=CHIP_BG,
                activebackground=CHIP_BG_ACTIVE,
                activeforeground=TEXT_PRIMARY, relief="flat", bd=0,
                padx=14, pady=6, cursor="hand2",
                command=lambda v=val: self._set_view(v))
            _chip.pack(fill="both", expand=True)
            self.chip_btns[val] = _chip
        # Compat shim: the scan-done handler still updates the
        # flagged view's label through this name (it is the chip).
        self.flagged_radio = self.chip_btns["flagged"]
        # Board SS6: the Source dropdown rides at the RIGHT of
        # the chips row, its caption above it.
        _srcbox = tk.Frame(frow, bg=DBG)
        _srcbox.pack(side="right")
        tk.Label(_srcbox, text="Source", font=(DFONT, 10),
                 fg=TEXT_MUTED, bg=DBG, anchor="w").pack(fill="x")
        self.source_menu = tk.OptionMenu(_srcbox, self.source_var,
                                         "All sources")
        self.source_menu.configure(font=(DFONT, 11), fg=DTEXT,
                                   bg=DBAR, activebackground=DBAR,
                                   activeforeground=DTEXT,
                                   relief="flat", bd=0,
                                   highlightthickness=0, width=22, pady=10)
        self.source_menu.pack(fill="x")
        try:
            self.source_menu["menu"].configure(
                bg=DBAR, fg=DTEXT, activebackground=SELECTION_BG)
        except Exception:
            pass

        # ---------- results header (board SS7) ----------
        hrow = tk.Frame(root, bg=DBG)
        hrow.pack(fill="x", padx=22, pady=(0, 4))
        self.results_title = tk.Label(
            hrow, text="Scan results", font=(DFONT, 17, "bold"),
            fg=TEXT_PRIMARY, bg=DBG, anchor="w")
        self.results_title.pack(side="left")
        self.results_note = tk.Label(
            hrow, text="", font=(DFONT, 10), fg=TEXT_MUTED,
            bg=DBG, anchor="w")
        self.results_note.pack(side="left", padx=(12, 0))
        # Democopy4 (2026-10-23): the board's search field --
        # a bordered box in the header row with the magnifier
        # INSIDE its left edge and the board's placeholder
        # words showing while the field is empty. The
        # placeholder is a display-only label laid over the
        # entry; the search variable is never touched by it.
        _sbox = tk.Frame(hrow, bg=BG_PANEL_DEEP,
                         highlightthickness=1,
                         highlightbackground=BORDER,
                         highlightcolor=FOCUS_RING,
                         width=236, height=36)
        _sbox.place(x=403, y=0)
        _sbox.pack_propagate(False)
        _simg = _symbol_image("magnifier", 18)
        if _simg is not None:
            tk.Label(_sbox, image=_simg,
                     bg=BG_PANEL_DEEP).pack(side="left",
                                             padx=(10, 4))
        else:
            tk.Label(_sbox, text="\U0001F50D",
                     font=(DFONT, 11), fg=TEXT_MUTED,
                     bg=BG_PANEL_DEEP).pack(side="left",
                                             padx=(10, 4))
        self.search_entry = tk.Entry(
            _sbox, textvariable=self.search_var,
            font=(DFONT, 11), fg=TEXT_PRIMARY, bg=BG_PANEL_DEEP,
            insertbackground=TEXT_PRIMARY, relief="flat", bd=0,
            highlightthickness=0)
        self.search_entry.pack(side="left", fill="both",
                               expand=True, padx=(0, 8))
        self._search_ph = tk.Label(
            _sbox, text="Search apps or sites...",
            font=(DFONT, 11), fg=TEXT_MUTED, bg=BG_PANEL_DEEP,
            anchor="w")
        self._search_ph.place(x=42, y=0, height=36)
        self._search_ph.bind(
            "<Button-1>",
            lambda _e: self.search_entry.focus_set())

        def _ph_sync(*_a):
            try:
                if self.search_var.get() or \
                        self.focus_get() is self.search_entry:
                    self._search_ph.place_forget()
                else:
                    self._search_ph.place(x=42, y=0, height=36)
            except Exception:
                pass
        self.search_var.trace_add("write", _ph_sync)
        self.search_entry.bind("<FocusIn>", _ph_sync)
        self.search_entry.bind("<FocusOut>", _ph_sync)
        self.search_var.trace_add("write",
                                  lambda *_a: self.render())

        # ---------- results + detail panel ----------
        mid = tk.Frame(root, bg=DBG)
        mid.pack(fill="both", expand=True, padx=22, pady=(0, 8))
        pane_wrap = tk.Frame(mid, bg=DBG)
        pane_wrap.pack(side="left", fill="both", expand=True)
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

        # SS8: the persistent detail panel. It rides the WHITE shelf
        # like the Background Check dialog (the shelf precedent), so
        # _add_reason_lines renders into it with its shelf colors
        # unchanged and the verdict stays colored TEXT (SS0.1).
        detail = tk.Frame(mid, bg=PANEL_BG, width=397,
                          highlightthickness=1,
                          highlightbackground=SHELF_BORDER, bd=0)
        detail.pack(side="right", fill="y", padx=(12, 0))
        detail.pack_propagate(False)
        tk.Label(detail, text="Selected item",
                 font=(DFONT, 16, "bold"),
                 fg=SHELF_INK, bg=PANEL_BG, anchor="w").pack(
                     fill="x", padx=12, pady=(10, 4))
        _dbtns = tk.Frame(detail, bg=PANEL_BG)
        _dbtns.pack(side="bottom", fill="x", padx=12, pady=(6, 12))
        self.det_remove_btn = tk.Button(
            _dbtns, text="MARK FOR REMOVAL",
            image=_symbol_image_h("trash_white", 21),
            compound="left",
            font=(DFONT, 12, "bold"),
            fg="white", bg=ACTION_REMOVE,
            activebackground=ACTION_REMOVE_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=10, pady=7, cursor="hand2", state="disabled",
            command=self._panel_mark_removal)
        _dbtns.grid_columnconfigure(0, weight=63)
        _dbtns.grid_columnconfigure(1, weight=37)
        self.det_remove_btn.grid(row=0, column=0, sticky="ew")
        self.det_keep_btn = tk.Button(
            _dbtns, text="KEEP ITEM",
            image=_symbol_image("shield_check", 18),
            compound="left",
            font=(DFONT, 12, "bold"),
            fg=TEXT_PRIMARY, bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=10, pady=7, cursor="hand2", state="disabled",
            command=self._panel_keep)
        self.det_keep_btn.grid(row=0, column=1, sticky="ew",
                               padx=(8, 0))
        self.det_bg_btn = tk.Button(
            _dbtns, text="\U0001f50d BACKGROUND CHECK",
            font=(DFONT, 11, "bold"), fg=TEXT_PRIMARY,
            bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=12, pady=8, cursor="hand2", state="disabled",
            command=self._panel_bg_check)
        self.det_bg_btn.grid(row=1, column=0, columnspan=2,
                             sticky="ew", pady=(8, 0))
        self.det_canvas = tk.Canvas(detail, bg=PANEL_BG,
                                    highlightthickness=0, bd=0)
        _dvsb = tk.Scrollbar(detail, orient="vertical",
                             command=self.det_canvas.yview)
        self.det_canvas.configure(yscrollcommand=_dvsb.set)
        _dvsb.pack(side="right", fill="y")
        self.det_canvas.pack(side="left", fill="both", expand=True)
        _det_body = tk.Frame(self.det_canvas, bg=PANEL_BG)
        self._det_win = self.det_canvas.create_window(
            (0, 0), window=_det_body, anchor="nw")
        _det_body.bind("<Configure>",
                       lambda e: self.det_canvas.configure(
                           scrollregion=self.det_canvas.bbox("all")))
        self.det_canvas.bind("<Configure>",
                             lambda e: self.det_canvas.itemconfig(
                                 self._det_win, width=e.width))
        self._mousewheel(self.det_canvas)
        _dbody = tk.Frame(_det_body, bg=PANEL_BG)
        _dbody.pack(fill="x", padx=12, pady=(2, 8))
        _irow = tk.Frame(_dbody, bg=PANEL_BG)
        _irow.pack(fill="x")
        self.det_icon = tk.Label(_irow, bg=PANEL_BG)
        self.det_icon.pack(side="left", padx=(0, 10))
        _ntxt = tk.Frame(_irow, bg=PANEL_BG)
        _ntxt.pack(side="left", fill="x", expand=True)
        self.det_name = tk.Label(
            _ntxt, text="Nothing selected", font=(DFONT, 15, "bold"),
            fg=SHELF_INK, bg=PANEL_BG, anchor="w", justify="left",
            wraplength=205)
        self.det_name.pack(fill="x")
        self.det_pkg = tk.Label(
            _ntxt, text="", font=(DMONO, 10), fg=SHELF_MUTED,
            bg=PANEL_BG, anchor="w", justify="left", wraplength=205)
        self.det_pkg.pack(fill="x")
        # Board SS8: the verdict rides as a pill beside the
        # item name -- a dark family tint carrying the verdict
        # WORD in its token color (never a solid verdict block).
        self.det_pill = tk.Frame(_irow, bg=PANEL_BG)
        self.det_pill.pack(side="right", padx=(8, 0))
        self.det_pill_icon = tk.Label(self.det_pill,
                                      bg=PANEL_BG)
        self.det_pill_icon.pack(side="left", padx=(4, 0))
        self.det_verdict = tk.Label(
            self.det_pill, text="", font=(DFONT, 12, "bold"),
            fg=SHELF_INK, bg=PANEL_BG, anchor="w", padx=5, pady=4)
        self.det_verdict.pack(side="left", padx=(0, 2))
        tk.Frame(_dbody, bg=SHELF_BORDER, height=1).pack(
            fill="x", pady=(6, 6))
        tk.Label(_dbody, text="Why it was flagged",
                 font=(DFONT, 13, "bold"), fg=SHELF_SECONDARY,
                 bg=PANEL_BG, anchor="w").pack(fill="x")
        self.det_why = tk.Frame(_dbody, bg=PANEL_BG)
        self.det_why.pack(fill="x", pady=(2, 4))
        self.det_facts = tk.Frame(_dbody, bg=PANEL_BG)
        self.det_facts.pack(fill="x", pady=(0, 4))
        tk.Label(_dbody, text="Install source",
                 font=(DFONT, 13, "bold"), fg=SHELF_SECONDARY,
                 bg=PANEL_BG, anchor="w").pack(fill="x")
        self.det_source = tk.Label(
            _dbody, text="", font=(DFONT, 11), fg=SHELF_INK,
            bg=PANEL_BG, anchor="w", justify="left",
            wraplength=345)
        self.det_source.pack(fill="x", pady=(2, 4))
        tk.Label(_dbody, text="Permissions to review",
                 font=(DFONT, 13, "bold"), fg=SHELF_SECONDARY,
                 bg=PANEL_BG, anchor="w").pack(fill="x")
        self.det_perms = tk.Frame(_dbody, bg=PANEL_BG)
        self.det_perms.pack(fill="x", pady=(2, 4))
        tk.Label(_dbody, text="Recommended action",
                 font=(DFONT, 13, "bold"), fg=SHELF_SECONDARY,
                 bg=PANEL_BG, anchor="w").pack(fill="x")
        _abox = tk.Frame(_dbody, bg=BG_PANEL_DEEP,
                         highlightthickness=1,
                         highlightbackground=BORDER)
        _abox.pack(fill="x", pady=(2, 0))
        self.det_action = tk.Label(
            _abox, text="", font=(DFONT, 12), fg=SHELF_INK,
            bg=BG_PANEL_DEEP, anchor="w", justify="left",
            wraplength=340)
        self.det_action.pack(fill="x", padx=8, pady=6)

        # ---------- bottom action bar ----------
        rrow = tk.Frame(root, bg=DBG)
        rrow.pack(fill="x", padx=22, pady=(0, 10))
        self.remove_btn = tk.Button(
            rrow, text="REMOVE SELECTED (0)",
            image=_symbol_image_h("trash_white", 21),
            compound="left",
            font=(DFONT, 11, "bold"),
            fg="white", bg=DRED, activebackground=ACTION_REMOVE_HOVER,
            activeforeground="white", relief="flat", bd=0,
            padx=31, pady=11, cursor="hand2", command=self.remove_all)
        self.remove_btn.pack(side="left")
        tk.Label(rrow, text="Review selections before removal",
                 image=_symbol_image("info", 18), compound="left",
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     side="left", padx=(20, 0))
        self.autoprint_var = tk.BooleanVar(value=True)
        tk.Checkbutton(rrow, text="Auto-print report",
                       variable=self.autoprint_var,
                       font=(DFONT, 11, "bold"), fg=DTEXT, bg=DBG,
                       activebackground=DBG, activeforeground=DTEXT,
                       selectcolor=SELECTION_BG).pack(
                           side="left", padx=(14, 0))
        _undoh = tk.Frame(rrow, bg=DBG, width=165, height=48)
        _undoh.pack(side="right")
        _undoh.pack_propagate(False)
        self.undo_btn = tk.Button(
            _undoh, text="\u21a9 UNDO", font=(DFONT, 10, "bold"),
            fg=DTEXT, bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground=DTEXT, relief="flat", bd=0,
            padx=18, pady=7, cursor="hand2", command=self.undo_last,
            state="disabled")
        self.undo_btn.pack(fill="both", expand=True)
        # Board SS9: a PRINT door rides the bottom bar too --
        # the same one handler as the action row's PRINT REPORT.
        self.footer_print_btn = tk.Button(
            rrow, text="PRINT",
            image=_symbol_image("printer", 18), compound="left",
            font=(DFONT, 10, "bold"),
            fg=DTEXT, bg=ACTION_NEUTRAL,
            activebackground=ACTION_NEUTRAL_HOVER,
            activeforeground=DTEXT, relief="flat", bd=0,
            padx=18, pady=12, cursor="hand2",
            command=self._print_report)
        self.footer_print_btn.pack(side="right", padx=(0, 10))

        # ---------- activity ----------
        # Board SS10: one strip -- "Activity log" at the left,
        # the live status and the version at the right.
        arow = tk.Frame(root, bg=DBG)
        arow.pack(fill="x", padx=22)
        tk.Label(arow, text="Activity log",
                 image=_symbol_image("document", 20),
                 compound="left",
                 font=(DFONT, 20, "bold"),
                 fg=DTEXT, bg=DBG, anchor="w").pack(side="left")
        tk.Label(arow, text="AdTrapper v%s" % VERSION,
                 font=(DFONT, 10), fg=DGRAY, bg=DBG).pack(
                     side="right")
        self.prog = tk.Label(arow, text="", font=(DFONT, 10),
                             fg=TEXT_SECONDARY, bg=DBG)
        self.prog.pack(side="right", padx=(0, 14))
        log_wrap = tk.Frame(root, bg=DBG)
        log_wrap.pack(fill="x", padx=22, pady=(2, 12))
        self.logbox = tk.Text(log_wrap, height=2, font=(DMONO, 10),
                              fg=TEXT_SECONDARY, bg=BG_PANEL_DEEP,
                              relief="flat",
                              bd=0, wrap="word", state="disabled")
        lsb = tk.Scrollbar(log_wrap, orient="vertical",
                           command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=lsb.set)
        lsb.pack(side="right", fill="y")
        self.logbox.pack(side="left", fill="x", expand=True)

        self._show_detail(None)
        try:
            self._refresh_chrome()
        except Exception:
            pass

        # v10.1 window sizing: ~1100x720, centered; height hugs the
        # content (clamped 720-800) so nothing is clipped by default.
        self.root.update_idletasks()
        try:
            _w = 1280
            # Faithful face: the board's proportions need real
            # height (tall device card + table + full detail
            # panel). Aim for the full board height when the
            # screen allows it; hug the content when it does not.
            _h = min(max(self.root.winfo_reqheight(), 1020),
                     max(620, self.root.winfo_screenheight() - 30))
            _h = min(_h, max(620, self.root.winfo_screenheight() - 30))
            _x = max(0, (self.root.winfo_screenwidth() - _w) // 2)
            _y = max(0, (self.root.winfo_screenheight() - _h) // 2)
            self.root.geometry("%dx%d+%d+%d" % (_w, _h, _x, _y))
        except Exception:
            self.root.geometry("1280x760")
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
        try:
            self._refresh_chrome()
        except Exception:
            pass

    def log(self, text):
        try:
            self.logbox.configure(state="normal")
            self.logbox.insert(
                "end", "%s  %s\n" % (
                    datetime.now().strftime("%H:%M:%S"), text))
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
                bg=DISABLED_BG if busy else ACTION_SCAN)
            self.remove_btn.configure(state="disabled" if busy else "normal")
        except Exception:
            pass

        try:
            self._refresh_device_card()
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
            try:
                aver = adb_cmd("shell", "getprop",
                               "ro.build.version.release").strip()
                if aver:
                    self.q.put(("phone_android", aver))
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
            aver = adb_cmd("shell", "getprop",
                           "ro.build.version.release").strip()
            if aver:
                self.q.put(("phone_android", aver))
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

    # ------------------------------------------- redesign chrome ---
    def _search_text(self):
        """The search box's current text, normalized (spec SS6)."""
        try:
            return self.search_var.get().strip().lower()
        except Exception:
            return ""

    def _set_view(self, val):
        """Filter-chip door into the one view variable (spec SS6):
        chips re-skin the radios; show_var + render() still rule."""
        self.show_var.set(val)
        self.render()

    def _verdict_counts(self):
        n_rm = n_rv = n_cl = 0
        for r in self.scan_data:
            if len(r) < 5:
                continue
            if r[4] == "remove":
                n_rm += 1
            elif r[4] == "review":
                n_rv += 1
            elif r[4] == "clean":
                n_cl += 1
        return n_rm, n_rv, n_cl

    def _refresh_chrome(self):
        """Stat cards, chip counts, REMOVE SELECTED count, device
        card -- one refresh for the redesign chrome (spec SS3/SS6/
        SS9). Called from _after_render() and once at startup.
        Never raises into the UI."""
        n_rm, n_rv, n_cl = self._verdict_counts()
        try:
            self.stat_reviewed_num.configure(
                text=str(len(self.scan_data)))
            self.stat_remove_num.configure(text=str(n_rm))
            self.stat_ask_num.configure(text=str(n_rv))
            self.stat_keep_num.configure(text=str(n_cl))
        except Exception:
            pass
        try:
            labels = {"flagged": "Flagged only (%d)"
                      % (n_rm + n_rv),
                      "all": "All applications (%d)"
                      % len(self.scan_data),
                      "sites": "Notification sites (%d)"
                      % len(self.sites),
                      "badlist": "Bad list (%d)"
                      % len(KNOWN_BAD)}
            active = self.show_var.get()
            for val, btn in self.chip_btns.items():
                _cbg = CHIP_BG
                if val == active:
                    _cbg = (STAT_ASK_BG if val == "flagged"
                            else CHIP_BG_ACTIVE)
                btn.configure(text=labels.get(val, val), bg=_cbg)
        except Exception:
            pass
        try:
            _titles = {"flagged": ("Scan results",
                                   "%d flagged items"
                                   % (n_rm + n_rv)),
                       "all": ("Scan results",
                               "%d applications"
                               % len(self.scan_data)),
                       "sites": ("Notification sites",
                                 "%d sites" % len(self.sites)),
                       "badlist": ("Bad list",
                                   "%d known bad apps"
                                   % len(KNOWN_BAD))}
            _t, _n = _titles.get(self.show_var.get(),
                                 ("Scan results", ""))
            self.results_title.configure(text=_t)
            self.results_note.configure(text=_n)
        except Exception:
            pass
        self._refresh_remove_count()
        self._refresh_device_card()

    def _on_row_toggle(self, pkg, var):
        """A row checkbox changed (by hand, or via the panel's
        MARK FOR REMOVAL door): remember the tech's tick so search
        re-renders preserve it (SS6), and refresh the live
        REMOVE SELECTED count (SS9)."""
        try:
            self._tick_overrides[pkg] = bool(var.get())
        except Exception:
            pass
        self._refresh_remove_count()

    def _refresh_remove_count(self):
        """REMOVE SELECTED (N) -- the live checked count (SS9)."""
        try:
            self.remove_btn.configure(
                text="REMOVE SELECTED (%d)"
                % len(self._checked()))
        except Exception:
            pass

    def _refresh_device_card(self):
        """Device card model/Android lines follow the honest status
        state: the card shows a model only while the dot is green
        (connected); otherwise it says what the status bar says --
        No phone (spec SS2)."""
        try:
            connected = _face_norm_color(
                self.dot.cget("fg")) == _face_norm_color(DGREEN)
        except Exception:
            connected = False
        try:
            if connected:
                self.dev_model.configure(
                    text=self._dev_model or "Phone connected")
                self.dev_android.configure(
                    text=("Android %s" % self._dev_android)
                    if self._dev_android else "")
            else:
                self.dev_model.configure(text="No phone")
                self.dev_android.configure(text="")
        except Exception:
            pass

    # ------------------------------------------ detail panel (SS8) --
    def _panel_reset(self):
        for w in self.det_why.winfo_children():
            w.destroy()
        for w in self.det_facts.winfo_children():
            w.destroy()
        for w in self.det_perms.winfo_children():
            w.destroy()
        try:
            self.det_source.configure(text="")
            self.det_verdict.configure(bg=PANEL_BG)
            self.det_pill.configure(bg=PANEL_BG)
            self.det_pill_icon.configure(image="", bg=PANEL_BG)
        except Exception:
            pass
        for b in (self.det_remove_btn, self.det_keep_btn,
                  self.det_bg_btn):
            try:
                b.configure(state="disabled")
            except Exception:
                pass
        self._det_img = None
        try:
            self.det_icon.configure(image="")
        except Exception:
            pass

    def _fact(self, text, bold=False, color=SHELF_SECONDARY):
        tk.Label(self.det_facts, text=text,
                 font=(DFONT, 11, "bold") if bold else (DFONT, 11),
                 fg=color, bg=PANEL_BG, anchor="w", justify="left",
                 wraplength=340).pack(fill="x", pady=1)

    def _show_detail(self, row, site=None):
        """Fill the persistent detail panel (spec SS8). row is a
        scan 9-tuple (or None); site is a (date_str, host) pair.
        Content is the row's own data only -- reason lines verbatim
        with boom phrasing intact, facts the scan established; the
        panel never invents findings."""
        self._panel_reset()
        if site is not None:
            dstr, host = site
            self._selected_pkg = None
            self.det_name.configure(text=host)
            self.det_pkg.configure(text="Notification site")
            self.det_verdict.configure(text="", fg=SHELF_INK)
            self.det_source.configure(
                text="Browser notification site")
            tk.Label(self.det_perms, text="Managed in the browser.",
                     font=(DFONT, 10), fg=SHELF_MUTED, bg=PANEL_BG,
                     anchor="w").pack(fill="x")
            self._fact("Allowed since %s" % dstr)
            self.det_action.configure(
                text="Notification sites are managed in the "
                     "browser that allowed them.")
            return
        if not row:
            self.det_name.configure(text="Nothing selected")
            self.det_pkg.configure(text="")
            self.det_verdict.configure(text="", fg=SHELF_INK)
            tk.Label(self.det_why,
                     text="Run a scan, then click any row to see "
                          "why it was flagged.",
                     font=(DFONT, 11), fg=SHELF_SECONDARY,
                     bg=PANEL_BG, anchor="w", justify="left",
                     wraplength=340).pack(fill="x")
            self.det_action.configure(text="")
            return
        (pkg, label, _score, reasons, verdict, src, privacy,
         _ttype, _boot) = (list(row) + [""] * 9)[:9]
        self.det_name.configure(text=label or pkg)
        self.det_pkg.configure(text=pkg)
        self.det_verdict.configure(
            text=VERDICT_WORDS.get(verdict, ""),
            fg=VERDICT_COLORS.get(verdict, SHELF_INK))
        _pill_bg = PILL_BG.get(verdict, PANEL_BG)
        _dpimg = _symbol_image_h(
            {"remove": "shield_x", "review": "warning",
             "clean": "check_circle"}.get(verdict), 20)
        try:
            self.det_verdict.configure(bg=_pill_bg)
            self.det_pill.configure(bg=_pill_bg)
            self.det_pill_icon.configure(
                image=_dpimg if _dpimg is not None else "",
                bg=_pill_bg)
        except Exception:
            pass
        img = self._icon_imgs.get(pkg) or self._badge_imgs.get(pkg)
        if img is None:
            img = self._generic_photo()
        if img is not None:
            self._det_img = img
            self.det_icon.configure(image=img)
        if reasons:
            self._add_reason_lines(self.det_why, reasons, verdict,
                                   wrap_px=330)
        else:
            tk.Label(self.det_why, text="No findings recorded.",
                     font=(DFONT, 11), fg=SHELF_SECONDARY,
                     bg=PANEL_BG, anchor="w").pack(fill="x")
        self.det_source.configure(text=src or "Unknown")
        # Permissions to review (board SS8): chips are cut ONLY
        # from the row's own privacy facts -- never invented.
        _perms = [p.strip() for p in
                  str(privacy or "").replace(";", ",").split(",")
                  if p.strip()]
        if _perms:
            for _p in _perms[:4]:
                # Democopy2 (2026-10-23): the two permissions
                # the owner named carry their ChatGPT symbol
                # pictures -- layers for "Display over apps",
                # the person for "Accessibility". Any other
                # permission keeps a plain text chip (no symbol
                # was assigned to it).
                _plow = _p.lower()
                _psym = ("layers" if _plow.startswith(
                    "display over apps") else
                    "person" if _plow.startswith(
                        "accessibility") else None)
                tk.Label(self.det_perms, text=_p[:44],
                         image=(_symbol_image(_psym, 20)
                                if _psym else None),
                         compound="left",
                         font=(DFONT, 12), fg=TEXT_SECONDARY,
                         bg=BG_PANEL_DEEP, padx=10, pady=6,
                         highlightthickness=1,
                         highlightbackground=BORDER).pack(
                             side="left", padx=(0, 6))
        else:
            tk.Label(self.det_perms,
                     text="None recorded by the scan.",
                     font=(DFONT, 10), fg=SHELF_MUTED,
                     bg=PANEL_BG, anchor="w").pack(fill="x")
        if privacy:
            self._fact(str(privacy))
        factory = _row_is_factory(reasons)
        if factory:
            self._fact("Factory app: came preinstalled on this "
                       "phone. It cannot be removed.")
        vault = is_photo_vault(pkg, label or "")
        if vault:
            self._fact("Photo vault: the customer's hidden photos "
                       "may live inside this app.",
                       bold=True, color=VERDICT_REMOVE)
        if pkg in self._bg_keep:
            self._fact("KEPT AFTER BACKGROUND CHECK", bold=True,
                       color=VERDICT_KEEP)
        elif pkg in self._bg_results:
            _omap = {"confirmed": ("BACKGROUND CHECK: CONFIRMED "
                                   "BAD", VERDICT_REMOVE),
                     "not_sure": ("BACKGROUND CHECK: STILL NOT "
                                  "SURE", VERDICT_ASK),
                     "cleared": ("BACKGROUND CHECK: CLEARED",
                                 VERDICT_KEEP)}
            _o = self._bg_results[pkg].get("outcome")
            if _o in _omap:
                self._fact(_omap[_o][0], bold=True,
                           color=_omap[_o][1])
        if factory:
            action = ("Factory app -- ask first. A factory app "
                      "cannot be removed from this phone.")
        elif vault:
            action = ("Ask the customer first -- their hidden "
                      "photos may live inside this app. Never "
                      "remove a vault without asking.")
        elif verdict == "remove":
            action = "Recommended action: mark for removal."
        elif verdict == "review":
            action = ("Recommended action: review this app "
                      "before removing it.")
        else:
            action = "No action needed -- no flags found."
        self.det_action.configure(text=action)
        self.det_keep_btn.configure(state="normal")
        self.det_bg_btn.configure(state="normal")
        if factory or vault:
            # Same law as the Background Check dialog: the Remove
            # door is OFF for factory apps and photo vaults.
            self.det_remove_btn.configure(state="disabled")
        else:
            self.det_remove_btn.configure(state="normal")
        try:
            self.det_canvas.yview_moveto(0)
        except Exception:
            pass

    def _paint_selection(self):
        """Board SS7: the selected row wears a blue outline."""
        try:
            for p, fr in self._row_frames.items():
                fr.configure(
                    highlightbackground=FOCUS_RING
                    if p == self._selected_pkg else SHELF_BORDER)
        except Exception:
            pass

    def _select_row(self, pkg):
        self._selected_pkg = pkg
        self._show_detail(self._row_by_pkg.get(pkg))
        self._paint_selection()

    def _select_site(self, host, dstr):
        self._selected_pkg = None
        self._show_detail(None, site=(dstr, host))

    def _select_badlist(self, pkg):
        self._selected_pkg = None
        self._panel_reset()
        e = (self._faces_entries or {}).get(pkg) or {}
        self.det_name.configure(text=e.get("name") or pkg)
        self.det_pkg.configure(text=pkg)
        self.det_verdict.configure(text="", fg=SHELF_INK)
        if self._faces_ok and e.get("status") == "not_found":
            self._fact(FACES_BADGE_TEXT, bold=True,
                       color=VERDICT_ASK)
        self._fact("On the shop bad list.")
        self.det_action.configure(
            text="The bad list is reference only -- nothing to "
                 "remove from here.")

    def _panel_var(self, pkg):
        for var, p, _l in self.row_vars:
            if p == pkg:
                return var
        return None

    def _panel_mark_removal(self):
        """MARK FOR REMOVAL = ticking the row's own checkbox; one
        state, two doors (spec SS8)."""
        pkg = self._selected_pkg
        if not pkg:
            return
        var = self._panel_var(pkg)
        if var is not None:
            var.set(True)
        self._refresh_remove_count()

    def _panel_keep(self):
        """KEEP ITEM = the dialog's _keep(): untick + record in
        _bg_keep so re-renders respect it (spec SS8)."""
        pkg = self._selected_pkg
        if not pkg:
            return
        self._bg_keep.add(pkg)
        row = self._row_by_pkg.get(pkg)
        self.log("Detail panel: %s kept by the tech."
                 % ((row[1] if row else None) or pkg))
        self.render()

    def _panel_bg_check(self):
        pkg = self._selected_pkg
        if not pkg:
            return
        row = self._row_by_pkg.get(pkg)
        self.start_background_check(pkg,
                                    (row[1] if row else None)
                                    or pkg)

    def render(self):
        for w in self.inner.winfo_children():
            w.destroy()
        self.row_vars = []
        self._row_icon_labels = {}
        self._row_face_labels = {}
        self._current_icon_rows = []
        self._row_by_pkg = {}
        self._row_frames = {}
        mode = self.show_var.get()
        _q = self._search_text()

        if mode == "sites":
            if not self.sites:
                tk.Label(self.inner,
                         text="No notification sites found."
                              if self.scan_data else
                              "Run a scan to list sites allowed to send "
                              "browser notifications.",
                         font=(DFONT, 12), fg=SHELF_SECONDARY,
                         bg=SHELF_BG).pack(padx=16, pady=24, anchor="w")
            _sites = self.sites
            if _q:
                _sites = [(d, h) for d, h in self.sites
                          if _q in h.lower()]
                if not _sites:
                    tk.Label(self.inner,
                             text="No notification sites match "
                                  "\"%s\"." % _q,
                             font=(DFONT, 12), fg=SHELF_SECONDARY,
                             bg=SHELF_BG).pack(padx=16, pady=24,
                                               anchor="w")
            for dstr, host in _sites:
                f = tk.Frame(self.inner, bg=SHELF_BG)
                f.pack(fill="x", padx=12, pady=5)
                _gl = tk.Label(f, text="🌐", font=(DFONT, 14),
                               bg=SHELF_BG)
                _gl.pack(side="left", padx=(0, 8))
                _hl = tk.Label(f, text=host, font=(DFONT, 13, "bold"),
                               fg=SHELF_INK, bg=SHELF_BG)
                _hl.pack(side="left")
                _dl = tk.Label(f, text="  allowed since %s" % dstr,
                               font=(DFONT, 11), fg=SHELF_SECONDARY,
                               bg=SHELF_BG)
                _dl.pack(side="left")
                for _sw in (f, _gl, _hl, _dl):
                    _sw.bind("<Button-1>",
                             lambda e, h=host, d=dstr:
                                 self._select_site(h, d))
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
        if _q:
            rows = [r for r in rows
                    if _q in (r[1] or "").lower()
                    or _q in r[0].lower()]
        if not rows:
            tk.Label(self.inner,
                     text=("No matches for \"%s\"." % _q) if _q
                     else ("Nothing flagged." if self.scan_data else
                           "Run a scan to check the phone for "
                           "adware."),
                     font=(DFONT, 12), fg=SHELF_SECONDARY,
                     bg=SHELF_BG).pack(padx=16, pady=24, anchor="w")
            self._show_detail(None)
            self._after_render()
            return

        # Faithful face (board SS7): the results take the
        # board's table form -- a column header over
        # grid-aligned rows (real widget rows, as always).
        _hdr = tk.Frame(self.inner, bg=SHELF_BG)
        _hdr.pack(fill="x", padx=8, pady=(5, 2))
        for _c, _w in ((0, 26), (1, 30), (2, 52), (3, 225),
                       (4, 118), (5, 128)):
            _hdr.grid_columnconfigure(_c, minsize=_w)
        _hdr.grid_columnconfigure(6, weight=1)
        _hdr.grid_columnconfigure(7, minsize=28)
        for _c, _t in ((3, "Application / Site"), (4, "Source"),
                       (5, "Risk"), (6, "Finding")):
            tk.Label(_hdr, text=_t, font=(DFONT, 12, "bold"),
                     fg=SHELF_MUTED, bg=SHELF_BG,
                     anchor="w").grid(row=0, column=_c,
                                      sticky="w")
        _hcb = tk.Frame(_hdr, bg=SHELF_BG, width=20, height=20,
                        highlightthickness=1,
                        highlightbackground=SHELF_BORDER)
        _hcb.grid(row=0, column=1, padx=(5, 5))
        _hcb.pack_propagate(False)
        tk.Frame(self.inner, bg=SHELF_BORDER, height=1).pack(
            fill="x", padx=8, pady=(2, 4))

        icon_pkgs = []
        _nums = getattr(self, "_original_numbers", None) or \
            original_numbers(self.scan_data)
        for _idx, (pkg, label, score, reasons, verdict, src, privacy,
                   ttype, boot) in enumerate(rows, 1):
            var = tk.BooleanVar(value=row_default_checked(pkg, verdict, reasons)
                                and pkg not in self._bg_keep)
            if pkg in self._tick_overrides and pkg not in self._bg_keep:
                # SS6: filtering/search re-renders must not lose
                # the tech's manual ticks.
                var.set(self._tick_overrides[pkg])
            f = tk.Frame(self.inner, bg=SHELF_BG,
                         highlightthickness=1,
                         highlightbackground=SHELF_BORDER)
            f.pack(fill="x", padx=8, pady=3)
            for _c, _w in ((0, 26), (1, 30), (2, 52), (3, 225),
                           (4, 118), (5, 128)):
                f.grid_columnconfigure(_c, minsize=_w)
            f.grid_columnconfigure(6, weight=1)
            f.grid_columnconfigure(7, minsize=28)
            self._row_frames[pkg] = f
            # Owner board ruling (2026-10-22; democopy delta,
            # 2026-10-23): NO row numbers on the face -- the
            # board shows none. The original scan numbers (AT-2)
            # still appear in Guided Clean and the printed
            # report, and _nums above still computes them; only
            # the face label is gone. Column 0 stays as the
            # row's left inset so the grid matches the header.
            cb = tk.Checkbutton(f, variable=var, bg=SHELF_BG,
                                activebackground=SHELF_BG,
                                selectcolor=SHELF_SELECTION)
            cb.grid(row=0, column=1, sticky="w", padx=(4, 6))
            _iholder = tk.Frame(f, bg=SHELF_BG, width=_ICON_BOX,
                                height=_ICON_BOX)
            _iholder.grid(row=0, column=2, sticky="w",
                          padx=(0, 6))
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
            txt.grid(row=0, column=3, sticky="w")
            _nlbl = tk.Label(txt, text=label or pkg, font=(DFONT, 16, "bold"),
                     fg=SHELF_INK, bg=SHELF_BG, anchor="w")
            _nlbl.pack(fill="x")
            _plbl = tk.Label(txt, text=pkg, font=(DMONO, 11),
                     fg=SHELF_MUTED, bg=SHELF_BG, anchor="w")
            _plbl.pack(fill="x")
            # Board SS7: the row carries the one-line Finding
            # (below, in its column); the FULL reason lines live
            # in the detail panel, rendered there verbatim.
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
                    txt, text="\U0001F50D BACKGROUND CHECK"
                    + (" \u2713" if pkg in self._bg_results else ""),
                    font=(DFONT, 10, "bold"), fg=TEXT_PRIMARY,
                    bg=ACTION_NEUTRAL,
                    activebackground=ACTION_NEUTRAL_HOVER,
                    activeforeground="white", relief="flat", bd=0,
                    padx=12, pady=6, cursor="hand2",
                    command=lambda p=pkg, l=label or pkg:
                        self.start_background_check(p, l))
                _bbtn.pack(anchor="w", pady=(4, 0))
                for _w in (txt, _nlbl, _plbl):
                    _w.bind("<Double-Button-1>",
                            lambda e, p=pkg, l=label or pkg:
                                self.start_background_check(p, l))
            _src_lbl = tk.Label(f, text=src or "",
                                font=(DFONT, 11),
                                fg=SHELF_SECONDARY, bg=SHELF_BG,
                                anchor="w")
            _src_lbl.grid(row=0, column=4, sticky="w",
                          padx=(8, 4))
            # Board SS7 Risk column: a dark family-tint pill
            # carrying the verdict WORD in its token color.
            _pill_bg = PILL_BG.get(verdict, SHELF_BG)
            _pill = tk.Frame(f, bg=_pill_bg, highlightthickness=1,
                             highlightbackground=VERDICT_COLORS.get(
                                 verdict, SHELF_BORDER))
            _pill.grid(row=0, column=5, sticky="w")
            _pimg = _symbol_image_h(
                {"remove": "shield_x", "review": "warning",
                 "clean": "check_circle"}.get(verdict), 18)
            tk.Label(_pill, text=VERDICT_WORDS.get(verdict,
                                                   "KEEP"),
                     image=_pimg, compound="left",
                     font=(DFONT, 11, "bold"),
                     fg=VERDICT_COLORS.get(verdict, VERDICT_KEEP),
                     bg=_pill_bg, padx=7, pady=2).pack()
            _find = tk.Frame(f, bg=SHELF_BG)
            _find.grid(row=0, column=6, sticky="w", padx=(4, 6))
            if reasons:
                self._add_finding_line(_find, reasons, verdict)
            elif privacy:
                tk.Label(_find, text=str(privacy),
                         font=(DFONT, 11), fg=SHELF_MUTED,
                         bg=SHELF_BG, anchor="w", wraplength=320,
                         justify="left").pack(fill="x")
            else:
                tk.Label(_find, text="No current flags",
                         font=(DFONT, 11), fg=SHELF_MUTED,
                         bg=SHELF_BG, anchor="w").pack(fill="x")
            _chev = tk.Label(f, text="\u203a",
                             font=(DFONT, 14, "bold"),
                             fg=SHELF_MUTED, bg=SHELF_BG,
                             highlightthickness=1,
                             highlightbackground=SHELF_BORDER,
                             padx=5, pady=4)
            _chev.grid(row=0, column=7, padx=(2, 2))
            self._row_by_pkg[pkg] = (pkg, label, score, reasons,
                                     verdict, src, privacy, ttype,
                                     boot)
            var.trace_add("write",
                          lambda *_a, p=pkg, v=var:
                              self._on_row_toggle(p, v))
            _binds = [f, txt, _nlbl, _plbl, _ilbl, _src_lbl,
                      _pill, _find, _chev]
            for _fr in _find.winfo_children():
                _binds.append(_fr)
                _binds.extend(_fr.winfo_children())
            for _sw in _binds:
                _sw.bind("<Button-1>",
                         lambda e, p=pkg: self._select_row(p))
            self.row_vars.append((var, pkg, label or pkg))
            icon_pkgs.append(pkg)
        self._current_icon_rows = list(icon_pkgs)
        self._kick_icons(icon_pkgs)
        if self._selected_pkg not in self._row_by_pkg:
            self._selected_pkg = rows[0][0] if rows else None
        self._show_detail(self._row_by_pkg.get(self._selected_pkg))
        self._paint_selection()
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

    def _add_finding_line(self, parent, reasons, verdict):
        """Table Finding cell (board SS7): the FIRST reason only,
        with its boom phrase loud + bold -- the same boom
        segmentation as the full reason renderer. Nothing is
        reworded; the full reason text lives in the detail
        panel, exactly as the board's panel carries it."""
        if isinstance(reasons, (list, tuple)):
            first = str(reasons[0]) if reasons else ""
        else:
            first = str(reasons)
        if not first:
            return
        loud_col = SHELF_VERDICT_COLORS.get(verdict, SHELF_INK)
        segs = boom_segments(first, verdict)
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
            if cur and cur_w + add > 185:
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
                tk.Label(lf, text=w if i == len(line) - 1
                         else w + " ",
                         font=(DFONT, 13, "bold") if loud
                         else (DFONT, 12),
                         fg=loud_col if loud else SHELF_SECONDARY,
                         bg=SHELF_BG, anchor="w", padx=0,
                         pady=0).pack(side="left")

    def _add_reason_lines(self, parent, reasons, verdict,
                          wrap_px=640):
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
            if cur and cur_w + add > wrap_px:
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
        _q = self._search_text()
        if _q:
            order = [p for p in order
                     if _q in p.lower() or _q in str(
                         (entries.get(p) or {}).get("name")
                         or "").lower()]
            if not order:
                tk.Label(self.inner,
                         text="No bad-list matches for \"%s\"."
                         % _q,
                         font=(DFONT, 12), fg=SHELF_SECONDARY,
                         bg=SHELF_BG).pack(padx=16, pady=24,
                                           anchor="w")
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
            _nl = tk.Label(txt, text=name, font=(DFONT, 15, "bold"),
                           fg=SHELF_INK, bg=SHELF_BG, anchor="w")
            _nl.pack(fill="x")
            _pl = tk.Label(txt, text=pkg, font=(DMONO, 12),
                           fg=SHELF_MUTED, bg=SHELF_BG, anchor="w")
            _pl.pack(fill="x")
            for _sw in (f, txt, _nl, _pl):
                _sw.bind("<Button-1>",
                         lambda e, p=pkg: self._select_badlist(p))
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
            self._refresh_device_card()
        elif kind == "phone_model":
            self.status.configure(
                text="Phone connected -- %s" % payload, fg=DTEXT)
            self._dev_model = payload
            self._refresh_device_card()
        elif kind == "phone_android":
            self._dev_android = payload
            self._refresh_device_card()
        elif kind == "phone_bad":
            self.dot.configure(fg=DGRAY)
            self._dev_model = ""
            self._dev_android = ""
            self._refresh_device_card()
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
            # Report-integrity (2026-10-23 spec): a rescan that
            # still flags an app the last cleanup VERIFIED as
            # removed means the report and the phone disagree --
            # log it as the bug it is, never silently.
            for _row in self.scan_data:
                if (getattr(self, "_removal_outcomes", {})
                        .get(_row[0]) == "verified"):
                    self.log("REPORT BUG: %s was verified removed "
                             "in the last cleanup but this rescan "
                             "still flags it -- the earlier report "
                             "and this scan disagree." % _row[0])
            self._tick_overrides = {}
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
                    text="Flagged only (%d)" % (n_rm + n_rv))
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
            if len(payload) == 3:
                removed, failed, unknown = payload
            else:
                removed, failed = payload
                unknown = []
            self._cleanup_time_str = datetime.now().strftime(
                "%B %d, %Y - %I:%M %p")
            self.set_busy(False)
            pdf_path = self._make_customer_report(removed, failed,
                                                  unknown)
            if pdf_path:
                self.last_report_path = pdf_path
                self.print_btn.configure(state="normal")
                if self.autoprint_var.get():
                    self._print_report(pdf_path)
            _parts = []
            if failed:
                # The device's actual per-app reasons -- never a
                # guessed cause (report-integrity spec, 2026-10-23).
                _parts.append(
                    "Removal finished, but these are still on the "
                    "phone:\n\n"
                    + "\n".join("%s - %s" % (f["label"], f["reason"])
                                  for f in failed)
                    + "\n\nNext step for those: on the phone, "
                      "open Settings > Security and privacy > "
                      "Device admin apps and turn the app off "
                      "there, then uninstall it from Settings > "
                      "Apps.")
            if unknown:
                _parts.append(
                    "The phone disconnected during cleanup, so "
                    "these could NOT be checked:\n\n"
                    + "\n".join(u["label"] for u in unknown)
                    + "\n\nReconnect the phone and scan again "
                      "to finish checking them.")
            if _parts:
                msg = "\n\n".join(_parts)
                if pdf_path:
                    msg += "\n\nCustomer report saved:\n%s" % pdf_path
                messagebox.showwarning("AdTrapper", msg)
            else:
                msg = ("Removal finished.\n\nReboot the phone "
                       "and check the popups are gone.\n")
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
        # Report-integrity (2026-10-23, REMOVAL-REPORT-INTEGRITY
        # -SPEC): every attempt is VERIFIED against a fresh
        # package-list query. Outcomes: verified (gone on the
        # re-query), failed (still present, with the device's
        # reason), unknown (phone gone before the check -- never
        # upgraded). Only verified apps enter `removed`, the
        # Removal History, the learned-bad store and the undo
        # manifest. On a disconnect the batch STOPS: apps not
        # yet attempted are marked unknown, untouched.
        failed, removed, unknown = [], [], []
        outcomes = {}
        bdir = self._backup_dir()
        disconnected = False
        for pkg, label in targets:
            if disconnected:
                unknown.append({"pkg": pkg, "label": label})
                outcomes[pkg] = "unknown"
                continue
            self.q.put(("log", "Backing up %s ..." % label))
            apk = backup_apk(pkg, bdir)
            if not apk:
                self.q.put(("log", "  [!] Warning: Backup failed for %s (APK pull failed; undo will not be available)" % label))
            self.q.put(("log", "Removing %s ..." % label))
            result = uninstall_core(pkg)
            self.q.put(("log", "  %s: %s" % (label, result)))
            outcome = _verify_removal(pkg)
            if outcome == "unknown":
                disconnected = True
                unknown.append({"pkg": pkg, "label": label})
                outcomes[pkg] = "unknown"
                self.q.put(("log", "  [!] The phone disconnected "
                                   "during cleanup -- stopping. "
                                   "%s could not be checked."
                                   % label))
                continue
            if outcome == "verified":
                outcomes[pkg] = "verified"
                removed.append({"pkg": pkg, "label": label, "apk": apk,
                                "result": result})
                _save_local_bad(
                    [pkg],
                    ticket=getattr(self, "report_ticket", "") or None)
                self._log_removal(pkg, label)
            else:
                outcomes[pkg] = "failed"
                if result.startswith("COULD NOT REMOVE"):
                    reason = (result[len("COULD NOT REMOVE"):]
                              .lstrip(" -").strip()
                              or "reason not confirmed")
                elif result.startswith("disabled"):
                    reason = result
                elif result.startswith("uninstalled"):
                    reason = ("still on the phone after the "
                              "uninstall attempt")
                else:
                    reason = "reason not confirmed"
                failed.append({"pkg": pkg, "label": label,
                               "reason": reason})
        self._removal_outcomes = outcomes
        if removed:
            self._write_undo_manifest(removed)
        self.q.put(("remove_done", (removed, failed, unknown)))

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
    def show_settings(self):
        """The header Settings door (board SS1, restored by the
        owner's board ruling, faithful face 2026-10-22). A REAL
        panel, never a dead button: every control here is an
        existing control of the app -- the auto-print default,
        the update check, the threat-list refresh, the
        report-details prompt and the DISCLAIMER door (the
        board's action row has no Disclaimer button; the
        feature lives here now, unchanged)."""
        win = tk.Toplevel(self.root)
        win.title("AdTrapper -- Settings")
        win.configure(bg=DBG)
        try:
            win.minsize(520, 430)
        except Exception:
            pass
        tk.Label(win, text="Settings", font=(DFONT, 15, "bold"),
                 fg=DTEXT, bg=DBG, anchor="w").pack(
                     fill="x", padx=18, pady=(16, 4))
        tk.Label(win, text="AdTrapper v%s -- Malware & Adware "
                           "Scanner\niFixx Phone Repairs"
                 % VERSION,
                 font=(DFONT, 10), fg=DGRAY, bg=DBG, anchor="w",
                 justify="left").pack(fill="x", padx=18,
                                      pady=(0, 10))
        tk.Checkbutton(win, text="Auto-print report after a "
                                 "cleanup",
                       variable=self.autoprint_var,
                       font=(DFONT, 11), fg=DTEXT, bg=DBG,
                       activebackground=DBG,
                       activeforeground=DTEXT,
                       selectcolor=DBAR).pack(anchor="w", padx=18,
                                              pady=(2, 10))

        def _btn(text, cmd):
            tk.Button(win, text=text, font=(DFONT, 11, "bold"),
                      fg="white", bg=ACTION_NEUTRAL,
                      activebackground=ACTION_NEUTRAL_HOVER,
                      activeforeground="white", relief="flat",
                      bd=0, padx=16, pady=9, cursor="hand2",
                      command=cmd).pack(fill="x", padx=18,
                                        pady=(0, 8))

        _btn("CHECK FOR UPDATES", self.on_update_click)
        _btn("UPDATE THREAT LIST", self._settings_refresh_feed)
        _btn("REPORT DETAILS", self._ask_report_details)
        _btn("DISCLAIMER",
             lambda: self.show_disclaimer(first_run=False))
        tk.Button(win, text="CLOSE", font=(DFONT, 11, "bold"),
                  fg="white", bg=DCYAN,
                  activebackground=ACTION_BLUE_HOVER,
                  activeforeground="white", relief="flat", bd=0,
                  padx=16, pady=9, cursor="hand2",
                  command=win.destroy).pack(fill="x", padx=18,
                                            pady=(6, 16))
        try:
            win.transient(self.root)
        except Exception:
            pass

    def _settings_refresh_feed(self):
        """Settings door: refresh the threat list now (the same
        silent feed the app checks on its own), then refresh the
        counter and chips so the new size shows."""
        try:
            self._kick_silent_feed()
        except Exception:
            pass
        try:
            self.root.after(1500, self._refresh_chrome)
        except Exception:
            pass

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
    def _make_customer_report(self, removed, failed, unknown=None):
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
            for f in (failed or []):
                pkg, label = f["pkg"], f["label"]
                if pkg in pkg_to_threat:
                    threats.append(pkg_to_threat[pkg])
                else:
                    threats.append((label, pkg, "flagged by scan",
                                    "remove"))
                actions.append((label, "COULD NOT REMOVE - "
                                        + (f.get("reason")
                                           or "reason not confirmed")))
            for u in (unknown or []):
                pkg, label = u["pkg"], u["label"]
                if pkg in pkg_to_threat:
                    threats.append(pkg_to_threat[pkg])
                else:
                    threats.append((label, pkg, "flagged by scan",
                                    "remove"))
                actions.append((label, "COULD NOT VERIFY - the "
                                       "phone disconnected before "
                                       "the check"))
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
