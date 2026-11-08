"""PrintMyTexts v1.6 — standalone Windows transcript tool (Python 3.10+).

v1.6 is the owner's fix pass on v1.5 (owner order, 2026-11-08): the paper
transcript is laid out like the on-screen chat — the other person on the
LEFT, the phone owner on the RIGHT, in tinted bubbles — instead of flat
full-width lines; opening a conversation lands on the bubble view;
documents no longer carry the shop name/address/phone letterhead and say
the times are the phone's time; 'Import XML File' is renamed 'Import
from a Backup File'; a finished import lands straight on the messages;
the phone page always says in plain words what it is waiting for; and
Settings explains every button in one plain line each. The v1.5 Light
Professional face (owner order, 2026-10-26) is unchanged: white and very
light gray surfaces, thin light borders, dark navy text, plain text
labels, no decorative glyph icons, 1200x700 default window with
remembered size/position.

No third-party modules. ADB is an external USB-only executable. Importing this
file does not start the GUI; parsers/layout are independently testable.
"""
from __future__ import annotations

import atexit
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, replace
from datetime import datetime, date
import hashlib
import html
import json
import os
from pathlib import Path
import queue
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unicodedata
import urllib.request
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import zlib

VERSION = '1.6'
UPDATE_MANIFEST_URL = ('https://raw.githubusercontent.com/ifixrepairs/'
                       'popup-blocker/main/printmytexts-version.json')
UPDATE_ALIVE_SECONDS = 10
UPDATE_STABLE_ALIAS = 'PrintMyTexts-PC.pyw'

SHOP = 'iFixx Repairs'
ADDRESS = '2828 S McCall Rd Unit 346, Englewood, FL 34224'
PHONE = '(941) 875-7511'
NOTICE = 'Processed locally on this computer — nothing leaves this computer.'
COPYRIGHT_LINE = '© 2026 iFixx Repairs. All rights reserved.'
COPYRIGHT_PRIVATE = '© 2026 PrintMyTexts. All rights reserved.'
# Light Professional palette (v1.5 restyle, owner order 2026-10-26).
# Screen-only theme: printed pages stay black on white, exactly as shipped.
# Token values mirror AdTrapper's owner-crowned Light Professional face:
# white / very light gray surfaces, thin light borders, dark navy text,
# soft meaning-colors only, no decorative glyph icons.
LP_BG = '#F2F4F7'            # app ground
LP_SURFACE = '#FFFFFF'       # sidebar, cards, panels
LP_BORDER = '#D8DEE7'        # thin light borders / dividers
LP_INK = '#152A44'           # dark navy text
LP_SECONDARY = '#48596C'     # supporting text
LP_MUTED = '#8593A5'         # metadata / captions
LP_DOOR_BG = '#E9EDF2'       # neutral buttons / doors
LP_DOOR_HOVER = '#D9E1EA'
LP_PANEL_BG = '#EEF1F5'      # inset panels, fields, status bar
LP_SEL_BG = '#EAF2FD'        # selected-row calm tint
# Legacy constant names (kept for the existing code, token-driven):
BG_APP = LP_BG              # root window
BG_SIDEBAR = LP_SURFACE     # navigation sidebar
BG_TOPBAR = LP_PANEL_BG     # header / status bar
BG_PANEL = LP_SURFACE       # standard panel
BG_PANEL_ALT = LP_DOOR_BG   # neutral buttons / inset panels
BG_INPUT = LP_PANEL_BG      # input fields
BG_HOVER = LP_DOOR_HOVER    # hovered rows/cards
NAV_SELECTED = LP_SEL_BG    # selected navigation row
BORDER = LP_BORDER
BORDER_STRONG = '#B7C2CF'
TEXT_PRIMARY = LP_INK
TEXT_SECONDARY = LP_SECONDARY
TEXT_MUTED = LP_MUTED
TEXT_DISABLED = '#A9B4C0'
ACCENT = '#1F5FA6'          # primary buttons (professional navy blue)
ACCENT_HOVER = '#2B74C2'
ACCENT_PRESSED = '#17497F'
FOCUS_RING = '#7FB3E0'
NAV_INDICATOR = ACCENT      # selected-row accent
TOOL_PHONE = '#2E86AB'      # Import from Phone accent (muted steel blue)
TOOL_XML = '#4A6FA5'        # Import from a Backup File accent (muted slate blue)
TOOL_XML_PRIMARY = '#3D5A80'
TOOL_TRANSCRIPT = ACCENT    # Message Transcript accent
TOOL_EXPORT = '#2E7D4F'     # Print / Export accent (muted green)
EXPORT_CONFIRM = '#256B43'
CLEAR_RED = '#B42318'
STATUS_OK = '#1E8E4F'
STATUS_WORK = ACCENT
STATUS_WARN = '#B25E09'
STATUS_ERROR = '#B42318'
# On-screen chat (light timeline in the light shell).
CHAT_BG = '#FFFFFF'
BUBBLE_CUSTOMER = '#E7EDF3'        # contact, LEFT
BUBBLE_CUSTOMER_TEXT = LP_INK
BUBBLE_CUSTOMER_META = LP_SECONDARY
BUBBLE_CUSTOMER_TIME = LP_MUTED
BUBBLE_OWNER = ACCENT               # phone owner, RIGHT — strong blue (owner 2026-10-26:
                                    # the two sides must be unmistakably different colors)
BUBBLE_OWNER_TEXT = '#FFFFFF'       # white on the strong-blue sent bubble
BUBBLE_OWNER_META = '#2E5A88'
BUBBLE_OWNER_TIME = LP_SECONDARY
BUBBLE_UNKNOWN = '#E2E8EF'
DATE_SEP_BG = '#E2E8EF'
DATE_SEP_FG = LP_SECONDARY
PREVIEW_BG = '#D9E1EA'             # paper preview surround
COLORS = {
    'bg_app': BG_APP, 'bg_sidebar': BG_SIDEBAR, 'bg_topbar': BG_TOPBAR,
    'bg_panel': BG_PANEL, 'bg_panel_alt': BG_PANEL_ALT, 'bg_input': BG_INPUT,
    'bg_hover': BG_HOVER, 'border': BORDER, 'border_strong': BORDER_STRONG,
    'text_primary': TEXT_PRIMARY, 'text_secondary': TEXT_SECONDARY,
    'text_muted': TEXT_MUTED, 'text_disabled': TEXT_DISABLED,
    'primary': ACCENT, 'primary_hover': ACCENT_HOVER,
    'primary_pressed': ACCENT_PRESSED, 'focus': FOCUS_RING,
    'phone': TOOL_PHONE, 'xml': TOOL_XML, 'transcript': TOOL_TRANSCRIPT,
    'export': TOOL_EXPORT, 'success': STATUS_OK, 'warning': STATUS_WARN,
    'error': STATUS_ERROR, 'chat_background': CHAT_BG,
    'bubble_customer': BUBBLE_CUSTOMER, 'bubble_owner': BUBBLE_OWNER,
    'bubble_text': BUBBLE_CUSTOMER_TEXT,
    'pdf_customer': '#F0F2F5', 'pdf_owner': '#E9F1F9',
}
PRIVATE_NOTICE = 'Processed locally — no data leaves this computer.'
FONT_FACE = 'Verdana'  # wide, high-legibility print face (owner readability request)
BODY_FONT_SIZE = 18
UI_NOTICE = 'Processed locally at iFixx Repairs — nothing leaves this computer.'
# Settings help (v1.6, owner order 2026-11-08): every sidebar item and
# button explained in ONE plain line — simple words, no jargon.
HELP_LINES = (
    ('Home', 'The start page. Pick how you want to bring your messages in.'),
    ('Import from Phone', 'Reads messages from an Android phone plugged in with a cable.'),
    ('Import from a Backup File', 'Opens a backup file you saved earlier from a phone.'),
    ('Import from iPhone', 'An iPhone cannot be read with a cable. Save a backup of its messages first, then open it with Import from a Backup File.'),
    ('Message Transcript', 'Shows your conversations. Tap one to read it like a text chat.'),
    ('Print', 'Prints the conversation you have open, on paper.'),
    ('Export', 'Saves the conversation you have open as a PDF file you can keep.'),
    ('Settings', 'This page — app information, update checks, and this help.'),
    ('Update', 'The UPDATE button gets the newest PrintMyTexts when one is ready. Nothing about your messages is ever sent anywhere.'),
    ('Connect phone', 'Takes you to the Import from Phone page.'),
    ('Choose backup file', 'Opens the file picker so you can pick a backup file straight away.'),
    ('Open transcript', 'Takes you to the Message Transcript page.'),
    ('Read USB phone', 'Starts reading the messages from the phone plugged in with a cable.'),
    ('Browse Files', 'Opens the file picker so you can pick the backup file on this computer.'),
    ('Back', 'Goes back to the Home page.'),
    ('View Transcript', 'Takes you to the Message Transcript page to read the conversations.'),
    ('Chat view', 'Shows the conversation as text-message bubbles.'),
    ('Paper view', 'Shows the conversation the way the printed page will look.'),
    ('Previous page (◀)', 'Shows the page before this one.'),
    ('Next page (▶)', 'Shows the page after this one.'),
    ('Apply / preview', 'Puts the name and dates you typed onto the conversation and shows it again.'),
    ('Hide the phone number (private print)', 'When this is ticked, the phone number is left off the print and the PDF.'),
    ('Check for updates', 'Checks if a newer PrintMyTexts is ready — the same check as the UPDATE button.'),
)
PICTURE = '[Picture message]'
UNREADABLE = '[Unreadable message]'
PAGE_W, PAGE_H = 850, 1100  # fixed US Letter layout at 100 pixels/inch
MARGIN, BODY_TOP, BODY_BOTTOM = 45, 170, 1010
LINE_HEIGHT = 20


@dataclass(frozen=True)
class Message:
    address: str
    timestamp: int | None  # epoch milliseconds; None is explicitly unreadable
    direction: str         # received, sent, unreadable
    body: str
    thread_id: str = ''
    contact_name: str = ''
    kind: str = 'sms'


@dataclass
class ReadResult:
    messages: list[Message]
    warnings: list[str]


def timestamp(value, seconds=False):
    try:
        result = int(value) * (1000 if seconds else 1)
        datetime.fromtimestamp(result / 1000)
        return result
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def clean(value):
    return '' if value is None or value == 'null' else str(value)


def parse_content_rows(output, columns):
    """Decode Android's unescaped display format, preserving commas/newlines.

    Use projections with free text LAST. Metadata delimiters are then consumed
    only before that field. Arbitrary default-order body output is inherently
    ambiguous; reject an ambiguous row rather than guess a message's contents.
    Returns (rows, warnings), including partial rows so they remain visible.
    """
    rows, warnings = [], []
    starts = list(re.finditer(r'(?m)^Row: \d+\s+', output))
    if not starts:
        if output.strip() and 'No result found' not in output:
            warnings.append('Provider output was unreadable; import from a backup file instead.')
        return rows, warnings
    for index, start in enumerate(starts):
        raw = output[start.end():starts[index + 1].start() if index + 1 < len(starts) else len(output)]
        raw = raw.removesuffix('\n').removesuffix('\r')
        row, pos, bad = {}, 0, False
        for field in columns[:-1]:
            match = re.match(re.escape(field) + r'=(.*?), (?=' + re.escape(columns[len(row) + 1]) + r'=)', raw[pos:], re.S)
            if not match:
                bad = True
                break
            row[field] = match.group(1)
            pos += match.end()
        final = columns[-1] + '='
        if not bad and raw[pos:].startswith(final):
            row[columns[-1]] = raw[pos + len(final):]
        else:
            warnings.append(f'Row {index + 1} has unreadable fields; retained as unreadable.')
            # Recover only individually unambiguous metadata, never body text.
            for field in columns[:-1]:
                found = re.findall(r'(?:^|, )' + re.escape(field) + r'=([^,\n]*)', raw)
                if len(found) == 1:
                    row[field] = found[0]
            row[columns[-1]] = None
        rows.append(row)
    return rows, warnings


SMS_COLUMNS = ('_id', 'thread_id', 'address', 'date', 'type', 'body')
MMS_COLUMNS = ('_id', 'thread_id', 'date', 'msg_box')
PART_COLUMNS = ('_id', 'ct', 'text')
ADDR_COLUMNS = ('type', 'address')
CONTACT_COLUMNS = ('data1', 'display_name')


def parse_sms(output):
    rows, warnings = parse_content_rows(output, SMS_COLUMNS)
    messages = []
    for row in rows:
        stamp = timestamp(row.get('date'))
        direction = {'1': 'received', '2': 'sent'}.get(row.get('type'), 'unreadable')
        if stamp is None or direction == 'unreadable':
            warnings.append('An SMS has an unreadable date or direction; not guessed.')
        messages.append(Message(clean(row.get('address')) or '[Unreadable number]', stamp,
                                direction, UNREADABLE if row.get('body') is None or row.get('body') == 'null' else row['body'],
                                clean(row.get('thread_id'))))
    return ReadResult(messages, warnings)


def mms_body(parts):
    texts = [clean(p.get('text')) for p in parts if p.get('ct') == 'text/plain' and clean(p.get('text'))]
    pictures = any(clean(p.get('ct')).startswith(('image/', 'video/', 'audio/')) for p in parts)
    unreadable = any(p.get('ct') == 'text/plain' and not clean(p.get('text')) for p in parts)
    if pictures or not parts:
        texts.append(PICTURE)
    if unreadable or (parts and not texts):
        texts.append(UNREADABLE)
    return '\n'.join(texts)


def parse_mms(output, parts_by_id, addresses_by_id):
    rows, warnings = parse_content_rows(output, MMS_COLUMNS)
    messages = []
    for row in rows:
        ident = clean(row.get('_id'))
        direction = {'1': 'received', '2': 'sent'}.get(row.get('msg_box'), 'unreadable')
        addr_rows, addr_warnings = parse_content_rows(addresses_by_id.get(ident, ''), ADDR_COLUMNS)
        parts, part_warnings = parse_content_rows(parts_by_id.get(ident, ''), PART_COLUMNS)
        warnings.extend(addr_warnings + part_warnings)
        addr_type = '137' if direction == 'received' else '151'
        addresses = list(dict.fromkeys(clean(a.get('address')) for a in addr_rows
                                       if a.get('type') == addr_type and clean(a.get('address'))
                                       and a.get('address') != 'insert-address-token'))
        address = '; '.join(addresses) or '[Unreadable number]'
        stamp = timestamp(row.get('date'), seconds=True)
        if stamp is None or direction == 'unreadable' or not addresses:
            warnings.append('An MMS has unreadable metadata; use a backup file to verify completeness.')
        messages.append(Message(address, stamp, direction, mms_body(parts),
                                clean(row.get('thread_id')), kind='mms'))
    return ReadResult(messages, warnings)


def parse_xml(path):
    """SMS Backup & Restore SMS/MMS -> the same Message shape as ADB.

    DTD/entity declarations are rejected; binary MMS data is never decoded.
    Source files are read only and are not copied into the working directory.
    """
    if Path(path).stat().st_size > 128 * 1024 * 1024:
        raise ValueError('Backup exceeds the 128 MB import limit.')
    data = Path(path).read_bytes()
    # Reject declarations even in UTF-16/32 inputs.
    if re.search(br'<!\s*(?:DOCTYPE|ENTITY)\b', data.replace(b'\0', b''), re.I):
        raise ValueError('Declarations inside the backup file are not supported.')
    root = ET.fromstring(data)
    if root.tag != 'smses':
        raise ValueError('Choose a backup file from the SMS Backup & Restore app.')
    messages, warnings = [], []
    for node in root:
        if node.tag not in ('sms', 'mms'):
            warnings.append('Unsupported backup record was not imported.')
            continue
        attrs = node.attrib
        direction = {'1': 'received', '2': 'sent'}.get(attrs.get('type' if node.tag == 'sms' else 'msg_box'), 'unreadable')
        # SMS Backup & Restore writes SMS dates in milliseconds, MMS dates in seconds.
        stamp = timestamp(attrs.get('date'), seconds=node.tag == 'mms')
        address = clean(attrs.get('address')) or '[Unreadable number]'
        if node.tag == 'sms':
            body = attrs.get('body')
            body = UNREADABLE if body is None or body == 'null' else body
        else:
            body = mms_body([p.attrib for p in node.findall('./parts/part')])
            addr_type = '137' if direction == 'received' else '151'
            addresses = list(dict.fromkeys(clean(a.get('address')) for a in node.findall('./addrs/addr')
                                           if a.get('type') == addr_type and clean(a.get('address'))
                                           and a.get('address') != 'insert-address-token'))
            if addresses:
                address = '; '.join(addresses)
        if stamp is None or direction == 'unreadable' or address == '[Unreadable number]':
            warnings.append('A backup message has unreadable metadata; not guessed.')
        name = clean(attrs.get('contact_name'))
        if name == '(Unknown)':
            name = ''
        messages.append(Message(address, stamp, direction, body, clean(attrs.get('thread_id')), name, node.tag))
    return ReadResult(messages, warnings)


def number_key(number):
    # Do not equate different country codes or group recipients by last digits.
    return re.sub(r'[\s().-]', '', number)


def conversation_key(message):
    # XML has no reliable thread IDs. Prefer the actual participant address.
    if message.address == '[Unreadable number]' and message.thread_id:
        return 'unreadable-thread:' + message.thread_id
    return number_key(message.address)


def conversations(messages):
    grouped = {}
    for message in messages:
        grouped.setdefault(conversation_key(message), []).append(message)
    return grouped


def ordered(messages):
    # Unknown timestamps go last and stay explicitly unknown, stable on ties.
    return sorted(messages, key=lambda m: (m.timestamp is None, m.timestamp or 0))


def filter_dates(messages, start='', end=''):
    low = date.fromisoformat(start) if start else None
    high = date.fromisoformat(end) if end else None
    if low and high and low > high:
        raise ValueError('Start date must not be after end date.')
    result = []
    for m in messages:
        if m.timestamp is None:
            result.append(m)  # cannot safely exclude an unknown date
        else:
            day = datetime.fromtimestamp(m.timestamp / 1000).date()
            if (low is None or day >= low) and (high is None or day <= high):
                result.append(m)
    return ordered(result)


def format_date(stamp):
    if stamp is None:
        return '[Unreadable date/time]'
    dt = datetime.fromtimestamp(stamp / 1000)
    weekdays = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
    months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
    return f'{weekdays[dt.weekday()]}, {months[dt.month-1]} {dt.day}, {dt.year}, {dt.hour % 12 or 12}:{dt.minute:02d} {"AM" if dt.hour < 12 else "PM"}'


def format_time(stamp):
    """Time of day only — the chat timeline shows the date on separators."""
    if stamp is None:
        return '[Unreadable date/time]'
    dt = datetime.fromtimestamp(stamp / 1000)
    return f'{dt.hour % 12 or 12}:{dt.minute:02d} {"AM" if dt.hour < 12 else "PM"}'


def format_day(stamp):
    """Long date for chat date separators, e.g. 'October 12, 2026'."""
    if stamp is None:
        return '[Unreadable date/time]'
    dt = datetime.fromtimestamp(stamp / 1000)
    months = ('January', 'February', 'March', 'April', 'May', 'June', 'July',
              'August', 'September', 'October', 'November', 'December')
    return f'{months[dt.month - 1]} {dt.day}, {dt.year}'


def message_text(message, name):
    label = {'sent': 'YOU', 'received': name.strip() or 'THEM'}.get(message.direction, '[Unreadable direction]')
    stamp = format_date(message.timestamp)
    return f'{stamp if message.timestamp is None else "[" + stamp + "]"} {label}: {message.body}'


def transcript_header(messages, name, number, printed, private=False):
    dates = [m.timestamp for m in ordered(messages) if m.timestamp is not None]
    covered = f'{format_date(dates[0])} — {format_date(dates[-1])}' if dates else '[Unreadable date range]'
    if any(m.timestamp is None for m in messages):
        covered += ' (also contains unreadable dates)'
    if private:
        # Owner-requested privacy mode: phone number hidden.
        # Message text itself is never altered — a transcript is a record.
        return ['PrintMyTexts', f'Text message conversation with: {name.strip() or "THEM"} (number hidden)',
                'Date range covered: ' + covered, 'Printed ' + printed.strftime('%Y-%m-%d') + " • Times shown are the phone's time"]
    # v1.6 (owner order 2026-11-08): no shop name/address/phone letterhead
    # on documents — the transcript carries the conversation, not the shop.
    return ['PrintMyTexts', f'Text message conversation with: {name.strip() or "THEM"} ({number})',
            'Date range covered: ' + covered, 'Printed ' + printed.strftime('%Y-%m-%d') + " • Times shown are the phone's time"]


def render_html(messages, name, number, printed=None, private=False):
    """Escaped, offline HTML representation, also useful for renderer tests.

    v1.6: the body is bubble-style like the paper layout — the other
    person on the LEFT, the phone owner on the RIGHT — not flat lines."""
    printed = printed or datetime.now()
    header = ''.join('<div>' + html.escape(t) + '</div>' for t in transcript_header(messages, name, number, printed, private))
    display = name.strip() or 'THEM'
    blocks = []
    for m in ordered(messages):
        if m.direction == 'sent':
            side, label = 'sent', 'YOU'
        elif m.direction == 'received':
            side, label = 'received', display
        else:
            side, label = 'unknown', ''
        meta = (label + ' · ' if label else '— ') + format_date(m.timestamp) + ('' if label else ' —')
        blocks.append('<div class="msg ' + side + '"><div class="meta">' + html.escape(meta)
                      + '</div><div class="bubble">' + html.escape(m.body) + '</div></div>')
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<style>@page {size:letter; margin:0.5in; @bottom-center {content:"Page " counter(page) " of " counter(pages)}}'
            '.msg {margin:0 0 10px; break-inside:avoid} .msg.sent {text-align:right} .msg.unknown {text-align:center}'
            '.meta {font-size:12px; color:#555; margin-bottom:2px}'
            '.bubble {display:inline-block; max-width:70%; padding:8px 12px; border-radius:14px;'
            ' white-space:pre-wrap; overflow-wrap:anywhere; text-align:left}'
            '.received .bubble {background:#F0F2F5} .sent .bubble {background:#E9F1F9}'
            ' .unknown .bubble {background:#E2E8EF} footer {position:fixed;bottom:0}</style>'
            '</head><body><header>' + header + '</header>' + ''.join(blocks)
            + '<footer>' + html.escape(PRIVATE_NOTICE if private else NOTICE) + '</footer></body></html>')


def find_adb():
    found = shutil.which('adb')
    if found:
        return found
    home = Path.home()
    candidates = [Path(__file__).resolve().parent / 'platform-tools/adb.exe', Path.cwd() / 'platform-tools/adb.exe',
                  home / 'Downloads/platform-tools-latest-windows/platform-tools/adb.exe',
                  home / 'Downloads/platform-tools/adb.exe', home / 'platform-tools/adb.exe',
                  Path('C:/platform-tools/adb.exe'), home / 'AppData/Local/Android/Sdk/platform-tools/adb.exe']
    return next((str(p) for p in candidates if p.is_file()), None)


class AdbReader:
    def __init__(self, executable=None, cancelled=None, on_stage=None):
        self.cancelled = cancelled or threading.Event()
        # Optional progress callback (v1.6): called with 'reading' once
        # the phone has answered, so the UI can say plainly what it is
        # doing instead of sitting on one vague status.
        self.on_stage = on_stage
        self.executable = executable or find_adb()
        self.serial = None
        if not self.executable:
            raise ValueError('ADB was not found. Install Android platform-tools on PATH or place platform-tools beside PrintMyTexts. You can import from a backup file instead — that works without ADB.')

    def run(self, *args):
        if self.cancelled.is_set():
            raise ValueError('Read cancelled while closing.')
        # Select USB transports only; never use adb connect, tcpip or downloads.
        selection = ['-s', self.serial] if self.serial else ['-d']
        command = [self.executable, *selection, *args]
        result = subprocess.run(command, capture_output=True, encoding='utf-8', errors='replace', timeout=60,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        output = result.stdout
        if result.returncode or re.search(r'SecurityException|Permission Denial|Error while accessing provider|Exception occurred', output + result.stderr, re.I):
            raise ValueError('Android denied or failed the read. Unlock the phone, authorize USB debugging, or import a backup file from the SMS Backup & Restore app.')
        return output

    def query(self, uri, columns):
        return self.run('shell', 'content', 'query', '--uri', uri, '--projection', ':'.join(columns))

    def read(self):
        # '-d' rejects multiple USB phones and does not select a Wi-Fi device.
        self.serial = self.run('get-serialno').strip()
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+', self.serial) or self.serial in ('unknown', 'error'):
            raise ValueError('Connect exactly one authorized USB Android phone, then retry.')
        if self.on_stage:
            self.on_stage('reading')
        messages, warnings = [], []
        try:
            sms = parse_sms(self.query('content://sms', SMS_COLUMNS))
            messages.extend(sms.messages)
            warnings.extend(sms.warnings)
        except ValueError:
            # Plain words only (fix 7): the warning is shown on screen,
            # so it must not carry the raw tool error with it.
            warnings.append('Text messages were denied by the phone; use a backup file to verify completeness.')
        try:
            output = self.query('content://mms', MMS_COLUMNS)
            rows, row_warnings = parse_content_rows(output, MMS_COLUMNS)
            warnings.extend(row_warnings)
            parts, addresses = {}, {}
            for row in rows:
                ident = row.get('_id', '')
                if not re.fullmatch(r'\d+', ident):
                    warnings.append('An MMS ID is unreadable; its content cannot be queried.')
                    continue
                for target, uri, columns in ((parts, f'content://mms/{ident}/part', PART_COLUMNS),
                                             (addresses, f'content://mms/{ident}/addr', ADDR_COLUMNS)):
                    try:
                        target[ident] = self.query(uri, columns)
                    except ValueError:
                        warnings.append('Some MMS parts/addresses were denied; use a backup file to verify completeness.')
            mms = parse_mms(output, parts, addresses)
            messages.extend(mms.messages)
            warnings.extend(mms.warnings)
        except ValueError:
            warnings.append('MMS provider was denied; MMS completeness requires a backup-file import or phone verification.')
        try:
            contacts, errors = parse_content_rows(self.query('content://com.android.contacts/data/phones', CONTACT_COLUMNS), CONTACT_COLUMNS)
            warnings.extend(errors)
            names = {}
            for row in contacts:
                key, name = number_key(clean(row.get('data1'))), clean(row.get('display_name'))
                if key and name:
                    names.setdefault(key, set()).add(name)
            messages = [replace(m, contact_name=next(iter(names[number_key(m.address)])))
                        if len(names.get(number_key(m.address), ())) == 1 else m for m in messages]
        except ValueError:
            warnings.append('Contact names are unavailable; type the customer-confirmed name if needed.')
        if not messages:
            raise ValueError('No readable SMS/MMS returned. Import a backup file from SMS Backup & Restore instead.')
        return ReadResult(messages, list(dict.fromkeys(warnings)))


def plain_phone_error(text):
    """Translate a phone-read failure into one plain sentence (fix 7).

    AdbReader and the subprocess layer speak in tool names ('ADB',
    'platform-tools', 'PATH', 'USB debugging', timeout dumps). Those
    strings stay in the exceptions for anyone debugging, but the phone
    page and the status bar only ever show the plain versions made
    here. Text that is already plain passes through unchanged.
    """
    raw = str(text)
    lowered = raw.lower()
    if 'timed out' in lowered:
        # A timeout dump quotes the tool's own file path, which would
        # otherwise trip the missing-tools wording below.
        return ('Something went wrong reading the phone. Check the cable '
                'and that the phone is unlocked, then try again.')
    if 'adb was not found' in lowered or 'platform-tools' in lowered:
        return ('The phone tools are missing on this computer. You can import '
                'from a backup file instead — that works without them.')
    if 'denied or failed the read' in lowered or 'usb debugging' in lowered:
        return ('The phone would not let the computer read it. Unlock the '
                'phone, and tap Allow on the phone if it asks, then try again.')
    if 'exactly one' in lowered:
        return ('The phone did not answer. Connect just one phone with a '
                'cable, unlock it, and tap Allow on the phone if it asks, '
                'then try again.')
    if 'no readable' in lowered:
        return ('No messages could be read from the phone. Import a backup '
                'file from the SMS Backup & Restore app instead.')
    jargon = ('adb', 'platform-tools', 'path', 'usb debugging', 'winerror',
              'errno', '.exe', 'timed out', 'traceback', 'subprocess')
    if not raw.strip() or any(token in lowered for token in jargon):
        return ('Something went wrong reading the phone. Check the cable '
                'and that the phone is unlocked, then try again.')
    return raw


@dataclass(frozen=True)
class DrawLine:
    x: int
    y: int
    text: str
    size: int = BODY_FONT_SIZE


@dataclass(frozen=True)
class DrawRect:
    """A filled rectangle behind text — the paper chat bubbles (v1.6)."""
    x: int
    y: int
    width: int
    height: int
    color: str = '#F0F2F5'


BUBBLE_MAX_W = 500   # widest paper bubble, padding included
BUBBLE_PAD_X = 12    # text inset inside a paper bubble


def safe_display(text):
    # GDI is not a markup renderer. Replace controls it cannot display visibly.
    return ''.join(c if c in '\n\t' or unicodedata.category(c) != 'Cc' else '\uFFFD' for c in text)


def wrap_text(text, measure, width):
    """Pixel-based wrapping, preserves explicit blank lines and long words."""
    lines = []
    for paragraph in safe_display(text).expandtabs(4).split('\n'):
        if not paragraph:
            lines.append('')
            continue
        while paragraph:
            low, high = 1, len(paragraph)
            while low < high:
                mid = (low + high + 1) // 2
                if measure(paragraph[:mid]) <= width:
                    low = mid
                else:
                    high = mid - 1
            count = low
            if count < len(paragraph):
                space = paragraph.rfind(' ', 0, count + 1)
                if space > 0:
                    count = space + 1
            lines.append(paragraph[:count])
            paragraph = paragraph[count:]
    return lines


def layout_pages(messages, name, number, measure, printed=None, private=False):
    """One shared layout for bitmap preview, Windows printing and PDF.

    v1.6 (owner order 2026-11-08): the body is laid out like the
    on-screen chat — the other person on the LEFT, the phone owner on
    the RIGHT — each message a tinted bubble (DrawRect + its text
    lines) with a small name-and-date line above it, instead of flat
    full-width lines."""
    header = transcript_header(messages, name, number, printed or datetime.now(), private)
    header_lines = []
    for index, text in enumerate(header):
        header_lines.extend((line, 22 if index == 0 else 14) for line in wrap_text(text, measure, PAGE_W - 2 * MARGIN))
    body_top = max(BODY_TOP, MARGIN + len(header_lines) * LINE_HEIGHT + 15)
    if body_top > BODY_BOTTOM - LINE_HEIGHT * 3:
        raise ValueError('The contact name/number is too long to fit the page header. Shorten the display name.')
    capacity = (BODY_BOTTOM - body_top) // LINE_HEIGHT
    display = name.strip() or 'THEM'
    pages, current, y = [], [], body_top

    def new_page():
        nonlocal current, y
        pages.append(current)
        current, y = [], body_top

    for message in ordered(messages):
        if message.direction == 'sent':
            label, tint = 'YOU', COLORS['pdf_owner']
        elif message.direction == 'received':
            label, tint = display, COLORS['pdf_customer']
        else:
            label, tint = '', BUBBLE_UNKNOWN
        meta = (label + ' · ' if label else '— ') + format_date(message.timestamp) + ('' if label else ' —')
        body_lines = wrap_text(message.body, measure, BUBBLE_MAX_W - 2 * BUBBLE_PAD_X)
        widest = max([measure(line) for line in body_lines] + [1])
        bubble_w = min(BUBBLE_MAX_W, widest + 2 * BUBBLE_PAD_X)
        if message.direction == 'sent':
            bubble_x = PAGE_W - MARGIN - bubble_w
            meta_x = PAGE_W - MARGIN - measure(meta)
        elif message.direction == 'received':
            bubble_x, meta_x = MARGIN, MARGIN
        else:
            bubble_x = (PAGE_W - bubble_w) // 2
            meta_x = (PAGE_W - measure(meta)) // 2
        # meta line + body lines + one trailing gap line (bubble padding
        # is absorbed by the gap).
        block_lines = 1 + len(body_lines) + 1
        if block_lines <= capacity and block_lines > (BODY_BOTTOM - y) // LINE_HEIGHT and current:
            new_page()
        current.append(DrawLine(meta_x, y, meta, 14))
        y += LINE_HEIGHT
        pending = list(body_lines)
        seg_first_y = y
        seg = []

        def emit_segment():
            if not seg:
                return
            top = seg_first_y - 6
            current.append(DrawRect(bubble_x, top, bubble_w,
                                    seg[-1][0] + LINE_HEIGHT + 4 - top, tint))
            for line_y, line_text in seg:
                current.append(DrawLine(bubble_x + BUBBLE_PAD_X, line_y, line_text))

        while pending:
            if y + LINE_HEIGHT > BODY_BOTTOM:
                emit_segment()
                seg = []
                new_page()
                current.append(DrawLine(MARGIN, y, '[Message continued]', 14))
                y += LINE_HEIGHT
                seg_first_y = y
            seg.append((y, pending.pop(0)))
            y += LINE_HEIGHT
        emit_segment()
        y += LINE_HEIGHT
    pages.append(current)
    result = []
    for index, body in enumerate(pages, 1):
        top = [DrawLine(MARGIN, MARGIN + i * LINE_HEIGHT, text, size) for i, (text, size) in enumerate(header_lines)]
        footer = [DrawLine(MARGIN, 1028, f'PrintMyTexts — Page {index} of {len(pages)}', 14), DrawLine(MARGIN, 1048, PRIVATE_NOTICE if private else NOTICE, 14), DrawLine(MARGIN, 1066, COPYRIGHT_PRIVATE if private else COPYRIGHT_LINE, 12)]
        result.append(top + body + footer)
    return result


class WindowsPages:
    """Offline GDI rasterization. The identical RGB page is previewed/exported/printed.

    No browser, HTML handler, network library, or external PDF process is used.
    """
    def __init__(self):
        if os.name != 'nt':
            raise ValueError('Printing and PDF export require Windows. Backup-file parsing tests run on any OS.')
        self.gdi = ctypes.WinDLL('gdi32', use_last_error=True)
        # Explicit pointer-sized handles are essential on 64-bit Windows.
        self.gdi.GdiFlush.argtypes, self.gdi.GdiFlush.restype = [], wintypes.BOOL
        signatures = {
            'CreateCompatibleDC': (wintypes.HDC, [wintypes.HDC]),
            'CreateDIBSection': (wintypes.HBITMAP, [wintypes.HDC, ctypes.c_void_p, wintypes.UINT, ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.DWORD]),
            'SelectObject': (wintypes.HANDLE, [wintypes.HDC, wintypes.HANDLE]),
            'CreateFontW': (wintypes.HANDLE, [ctypes.c_int] * 5 + [wintypes.DWORD] * 8 + [wintypes.LPCWSTR]),
            'DeleteObject': (wintypes.BOOL, [wintypes.HANDLE]), 'DeleteDC': (wintypes.BOOL, [wintypes.HDC]),
            'TextOutW': (wintypes.BOOL, [wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.LPCWSTR, ctypes.c_int]),
            'GetTextExtentPoint32W': (wintypes.BOOL, [wintypes.HDC, wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p]),
            'SetBkMode': (ctypes.c_int, [wintypes.HDC, ctypes.c_int]),
            'SetTextColor': (wintypes.DWORD, [wintypes.HDC, wintypes.DWORD]),
            'GetDeviceCaps': (ctypes.c_int, [wintypes.HDC, ctypes.c_int]),
            'StretchDIBits': (ctypes.c_int, [wintypes.HDC] + [ctypes.c_int] * 8 + [ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT, wintypes.DWORD]),
            'StartDocW': (ctypes.c_int, [wintypes.HDC, ctypes.c_void_p]),
            'StartPage': (ctypes.c_int, [wintypes.HDC]), 'EndPage': (ctypes.c_int, [wintypes.HDC]),
            'EndDoc': (ctypes.c_int, [wintypes.HDC]), 'AbortDoc': (ctypes.c_int, [wintypes.HDC])}
        for name, (restype, argtypes) in signatures.items():
            fn = getattr(self.gdi, name)
            fn.restype, fn.argtypes = restype, argtypes
        self.dc = self.gdi.CreateCompatibleDC(None)
        if not self.dc:
            raise OSError('Cannot create Windows drawing context.')
        self.fonts = {}
        self.old_font = self.gdi.SelectObject(self.dc, self.font(BODY_FONT_SIZE))
        self.gdi.SetBkMode(self.dc, 1)
        self.gdi.SetTextColor(self.dc, 0)

    def font(self, size):
        if size not in self.fonts:
            handle = self.gdi.CreateFontW(-size, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, FONT_FACE)
            if not handle:
                raise OSError('Cannot create Windows transcript font.')
            self.fonts[size] = handle
        return self.fonts[size]

    def measure(self, text):
        self.gdi.SelectObject(self.dc, self.font(BODY_FONT_SIZE))
        size = (ctypes.c_long * 2)()
        if not self.gdi.GetTextExtentPoint32W(self.dc, text, len(text.encode('utf-16-le')) // 2, size):
            raise OSError('Cannot measure transcript text.')
        return size[0]

    @staticmethod
    def bitmap_info():
        return struct.pack('<IiiHHIIiiII', 40, PAGE_W, -PAGE_H, 1, 32, 0, PAGE_W * PAGE_H * 4, 0, 0, 0, 0)

    def raster(self, page):  # page bitmap stays black-on-white: it is a paper page

        info = ctypes.create_string_buffer(self.bitmap_info())
        bits = ctypes.c_void_p()
        bitmap = self.gdi.CreateDIBSection(self.dc, info, 0, ctypes.byref(bits), None, 0)
        if not bitmap:
            raise OSError('Cannot allocate transcript page.')
        old = self.gdi.SelectObject(self.dc, bitmap)
        try:
            ctypes.memset(bits, 255, PAGE_W * PAGE_H * 4)
            rects = [item for item in page if isinstance(item, DrawRect)]
            if rects:
                # Paper chat bubbles (v1.6): fill the tint rectangles in
                # the BGRA buffer before any text is drawn over them.
                raw = bytearray(ctypes.string_at(bits, PAGE_W * PAGE_H * 4))
                for rect in rects:
                    red, green, blue = (int(rect.color[i:i + 2], 16) for i in (1, 3, 5))
                    x0, x1 = max(0, rect.x), min(PAGE_W, rect.x + rect.width)
                    if x1 <= x0:
                        continue
                    fill = bytes((blue, green, red, 255)) * (x1 - x0)
                    for row_y in range(max(0, rect.y), min(PAGE_H, rect.y + rect.height)):
                        start = (row_y * PAGE_W + x0) * 4
                        raw[start:start + len(fill)] = fill
                ctypes.memmove(bits, bytes(raw), len(raw))
            for line in page:
                if isinstance(line, DrawRect):
                    continue
                self.gdi.SelectObject(self.dc, self.font(line.size))
                if not self.gdi.TextOutW(self.dc, line.x, line.y, line.text, len(line.text.encode('utf-16-le')) // 2):
                    raise OSError('Cannot draw transcript text.')
            self.gdi.GdiFlush()
            raw = ctypes.string_at(bits, PAGE_W * PAGE_H * 4)
            rgb = bytearray(PAGE_W * PAGE_H * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = raw[2::4], raw[1::4], raw[0::4]
            return bytes(rgb)
        finally:
            self.gdi.SelectObject(self.dc, old)
            self.gdi.DeleteObject(bitmap)

    def close(self):
        if self.dc:
            self.gdi.SelectObject(self.dc, self.old_font)
            for font in self.fonts.values():
                self.gdi.DeleteObject(font)
            self.gdi.DeleteDC(self.dc)
            self.dc = None

    def print_pages(self, pages):
        class PRINTDLG(ctypes.Structure):
            if ctypes.sizeof(ctypes.c_void_p) == 4:
                _pack_ = 1  # commdlg.h packs PRINTDLG on 32-bit Windows
            _fields_ = [('lStructSize', wintypes.DWORD), ('hwndOwner', wintypes.HWND),
                        ('hDevMode', wintypes.HGLOBAL), ('hDevNames', wintypes.HGLOBAL), ('hDC', wintypes.HDC),
                        ('Flags', wintypes.DWORD), ('nFromPage', wintypes.WORD), ('nToPage', wintypes.WORD),
                        ('nMinPage', wintypes.WORD), ('nMaxPage', wintypes.WORD), ('nCopies', wintypes.WORD),
                        ('hInstance', wintypes.HINSTANCE), ('lCustData', ctypes.c_ssize_t),
                        ('lpfnPrintHook', ctypes.c_void_p), ('lpfnSetupHook', ctypes.c_void_p),
                        ('lpPrintTemplateName', wintypes.LPCWSTR), ('lpSetupTemplateName', wintypes.LPCWSTR),
                        ('hPrintTemplate', wintypes.HGLOBAL), ('hSetupTemplate', wintypes.HGLOBAL)]
        class DOCINFO(ctypes.Structure):
            _fields_ = [('cbSize', ctypes.c_int), ('lpszDocName', wintypes.LPCWSTR),
                        ('lpszOutput', wintypes.LPCWSTR), ('lpszDatatype', wintypes.LPCWSTR), ('fwType', wintypes.DWORD)]
        dialog = PRINTDLG()
        dialog.lStructSize, dialog.Flags, dialog.nCopies = ctypes.sizeof(dialog), 0x100 | 0x4 | 0x8, 1  # RETURNDC, no selection/page subset
        dialog.nMinPage, dialog.nMaxPage = 1, len(pages)
        comdlg = ctypes.WinDLL('comdlg32', use_last_error=True)
        comdlg.PrintDlgW.argtypes, comdlg.PrintDlgW.restype = [ctypes.POINTER(PRINTDLG)], wintypes.BOOL
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GlobalFree.argtypes, kernel.GlobalFree.restype = [wintypes.HGLOBAL], wintypes.HGLOBAL
        started = False
        try:
            if not comdlg.PrintDlgW(ctypes.byref(dialog)):
                if comdlg.CommDlgExtendedError():
                    raise OSError('Windows could not open the print dialog.')
                return False
            dc = dialog.hDC
            doc = DOCINFO(ctypes.sizeof(DOCINFO), 'iFixx Repairs PrintMyTexts', None, None, 0)
            if self.gdi.StartDocW(dc, ctypes.byref(doc)) <= 0:
                raise OSError('Printer did not start the job.')
            started = True
            width, height = self.gdi.GetDeviceCaps(dc, 8), self.gdi.GetDeviceCaps(dc, 10)
            scale = min(width / PAGE_W, height / PAGE_H)
            dest_w, dest_h = int(PAGE_W * scale), int(PAGE_H * scale)
            info = ctypes.create_string_buffer(self.bitmap_info())
            for _ in range(max(1, dialog.nCopies)):
                for page in pages:
                    if self.gdi.StartPage(dc) <= 0:
                        raise OSError('Printer could not start a page.')
                    rgb = self.raster(page)
                    bgra = bytearray(PAGE_W * PAGE_H * 4)
                    bgra[0::4], bgra[1::4], bgra[2::4] = rgb[2::3], rgb[1::3], rgb[0::3]
                    pixels = ctypes.create_string_buffer(bytes(bgra))
                    if self.gdi.StretchDIBits(dc, (width-dest_w)//2, (height-dest_h)//2, dest_w, dest_h,
                                             0, 0, PAGE_W, PAGE_H, pixels, info, 0, 0x00CC0020) <= 0:
                        raise OSError('Printer rejected a page image.')
                    if self.gdi.EndPage(dc) <= 0:
                        raise OSError('Printer did not finish a page.')
            if self.gdi.EndDoc(dc) <= 0:
                raise OSError('Printer did not finish the job.')
            started = False
            return True
        finally:
            if started:
                self.gdi.AbortDoc(dialog.hDC)
            if dialog.hDC:
                self.gdi.DeleteDC(dialog.hDC)
            for handle in (dialog.hDevMode, dialog.hDevNames):
                if handle:
                    kernel.GlobalFree(handle)


def png_bytes(rgb):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    stride = PAGE_W * 3
    raw = b''.join(b'\0' + rgb[y*stride:(y+1)*stride] for y in range(PAGE_H))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', PAGE_W, PAGE_H, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


def write_pdf(path, pages, raster):
    """Self-contained image PDF preserves the exact preview, including Unicode.

    Explicit user-saved output is retained; no customer data enters metadata.
    Stream pages to disk so long threads do not require all bitmaps in memory.
    """
    count = len(pages)
    offsets = [0] * (3 + 3 * count)
    with open(path, 'wb') as stream:
        stream.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        def obj(number, data):
            offsets[number] = stream.tell()
            stream.write(f'{number} 0 obj\n'.encode() + data + b'\nendobj\n')
        obj(1, b'<< /Type /Catalog /Pages 2 0 R >>')
        kids = ' '.join(f'{3+3*i} 0 R' for i in range(count))
        obj(2, f'<< /Type /Pages /Count {count} /Kids [{kids}] >>'.encode())
        for i, page in enumerate(pages):
            p, image_id, content_id = 3 + 3 * i, 4 + 3 * i, 5 + 3 * i
            obj(p, f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 {image_id} 0 R >> >> /Contents {content_id} 0 R >>'.encode())
            data = zlib.compress(raster(page))
            obj(image_id, f'<< /Type /XObject /Subtype /Image /Width {PAGE_W} /Height {PAGE_H} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length {len(data)} >>\nstream\n'.encode() + data + b'\nendstream')
            commands = b'q 612 0 0 792 0 0 cm /Im0 Do Q\n'
            obj(content_id, f'<< /Length {len(commands)} >>\nstream\n'.encode() + commands + b'endstream')
        position = stream.tell()
        stream.write(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
        for offset in offsets[1:]:
            stream.write(f'{offset:010d} 00000 n \n'.encode())
        stream.write(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{position}\n%%EOF\n'.encode())


class WorkingData:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ifixx-printmytexts-')
        self.path = Path(self.temp.name)
        atexit.register(self.close)

    def close(self):
        # Logical deletion, not a claim of secure erasure on SSDs/OS spoolers.
        self.temp.cleanup()


UPDATE_HELPER_SRC = """import json, os, shutil, subprocess, sys, time

def pid_alive(pid):
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def main():
    (wait_pid, current, downloaded, backup, result_path,
     python_exe, alive_secs, from_v, to_v) = sys.argv[1:10]
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
        os.replace(downloaded, current)
        proc = subprocess.Popen([python_exe, current])
        time.sleep(alive_secs)
        if proc.poll() is not None:
            outcome = "rolled_back"
            try:
                os.remove(current)
            except OSError:
                pass
            shutil.copy2(backup, current)
            subprocess.Popen([python_exe, current])
    except Exception:
        outcome = "rolled_back"
        try:
            if not os.path.exists(current) and os.path.exists(backup):
                shutil.copy2(backup, current)
                subprocess.Popen([python_exe, current])
        except Exception:
            pass
    try:
        temp_result = result_path + ".tmp"
        with open(temp_result, "w") as result:
            json.dump({"outcome": outcome, "from_version": from_v,
                       "to_version": to_v}, result)
        os.replace(temp_result, result_path)
    except Exception:
        pass

main()
"""


def _version_tuple(value):
    return tuple(int(part) for part in str(value).split('.'))


def _version_newer(remote, local):
    remote_parts, local_parts = _version_tuple(remote), _version_tuple(local)
    width = max(len(remote_parts), len(local_parts))
    return (remote_parts + (0,) * (width - len(remote_parts))
            > local_parts + (0,) * (width - len(local_parts)))


def _default_fetch_bytes(url, timeout=20):
    request = urllib.request.Request(
        url, headers={'User-Agent': 'PrintMyTexts-PC-Updater'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def parse_update_manifest(raw):
    try:
        data = json.loads(raw.decode('utf-8'))
        version = str(data['version']).strip()
        url = str(data['url']).strip()
        sha256 = str(data['sha256']).strip().lower()
        size = int(data['size'])
        notes = str(data.get('notes', ''))
    except Exception:
        return None
    if (not re.fullmatch(r'\d+(?:\.\d+)*', version)
            or len(sha256) != 64
            or not re.fullmatch(r'[0-9a-f]{64}', sha256)
            or size <= 0):
        return None
    parsed_url = urlparse(url)
    if (parsed_url.scheme != 'https'
            or not (parsed_url.hostname == 'github.com'
                    or (parsed_url.hostname or '').endswith('.githubusercontent.com'))):
        return None
    return {'version': version, 'url': url, 'sha256': sha256,
            'size': size, 'notes': notes}


def check_for_update(fetch_bytes=None):
    fetch = fetch_bytes or _default_fetch_bytes
    try:
        info = parse_update_manifest(fetch(UPDATE_MANIFEST_URL))
    except Exception:
        return None
    return info if info and _version_newer(info['version'], VERSION) else None


def verify_update_file(path, expected_size, expected_sha256):
    try:
        file_path = Path(path)
        if file_path.stat().st_size != int(expected_size):
            return False
        digest = hashlib.sha256()
        with file_path.open('rb') as update_file:
            for chunk in iter(lambda: update_file.read(65536), b''):
                digest.update(chunk)
        return digest.hexdigest() == str(expected_sha256).lower()
    except Exception:
        return False


def download_update(manifest, dest_dir, fetch_bytes=None):
    fetch = fetch_bytes or _default_fetch_bytes
    dest = Path(dest_dir) / ('PrintMyTexts-PC-v%s.download'
                             % manifest['version'])
    try:
        dest.write_bytes(fetch(manifest['url'], timeout=120))
    except Exception as exc:
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return None, 'download failed (%s)' % exc
    if not verify_update_file(dest, manifest['size'], manifest['sha256']):
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return None, 'the downloaded file failed its safety check ' \
                     '(size/hash mismatch) and was discarded'
    return dest, None


def updater_guard_reason(busy, messages_loaded=False):
    if messages_loaded:
        return ('Messages are loaded — print/save them, then close and reopen '
                'before updating.')
    if busy:
        return 'a phone read or import is in progress — finish it before updating'
    return None


def ensure_stable_alias(script_path=None):
    script = Path(script_path or sys.argv[0]).resolve()
    alias = script.parent / UPDATE_STABLE_ALIAS
    if script != alias and not alias.exists():
        try:
            shutil.copy2(script, alias)
        except OSError:
            try:
                alias.unlink(missing_ok=True)
            except OSError:
                pass
            return script
    return alias


WINDOW_DEFAULT_W, WINDOW_DEFAULT_H = 1200, 700
WINDOW_MIN_W, WINDOW_MIN_H = 1000, 620
WINDOW_SMALL_DEFAULT_W, WINDOW_SMALL_DEFAULT_H = 880, 600
WINDOW_SMALL_MIN_W, WINDOW_SMALL_MIN_H = 860, 560
SETTINGS_FILENAME = 'printmytexts-settings.json'
_GEOMETRY_RE = re.compile(r'^(\d+)x(\d+)\+(-?\d+)\+(-?\d+)$')


def _settings_path():
    return Path(__file__).resolve().parent / SETTINGS_FILENAME


def load_window_geometry():
    """The remembered window geometry string, or None on first run."""
    try:
        data = json.loads(_settings_path().read_text(encoding='utf-8'))
        value = data.get('window_geometry')
        return value if isinstance(value, str) else None
    except Exception:
        return None


def save_window_geometry(value):
    """Persist the window geometry beside the app (best effort)."""
    try:
        path = _settings_path()
        data = {}
        try:
            existing = json.loads(path.read_text(encoding='utf-8'))
            if isinstance(existing, dict):
                data = existing
        except Exception:
            pass
        data['window_geometry'] = value
        path.write_text(json.dumps(data, indent=1), encoding='utf-8')
    except OSError:
        pass


def _small_screen(screen_w, screen_h):
    """A small screen: the window gets the compact size class — an
    880x600 default and an 860x560 minimum — instead of the full-size
    default that spans a laptop display edge to edge (owner finding
    on the 1152x720 MacBook Pro, 2026-10-26: the screen-fit clamp
    still read as "too big", wall to wall)."""
    return screen_w < 1400 or screen_h < 900


def _window_default(screen_w, screen_h):
    """The first-run window size for this screen's size class."""
    if _small_screen(screen_w, screen_h):
        return WINDOW_SMALL_DEFAULT_W, WINDOW_SMALL_DEFAULT_H
    return WINDOW_DEFAULT_W, WINDOW_DEFAULT_H


def _window_plan(screen_w, screen_h):
    """The (min_w, min_h, max_w, max_h) a window may take on this screen.

    Normally the window keeps its class minimum (1000x620, or
    860x560 on a small screen) and stays inside the screen with a
    40px width / 80px height margin. A screen smaller than the
    minimum plus margin cannot honor either, so the window — and
    the minimum, which must never exceed the window — fit the
    screen itself (-20/-60) instead of spanning it edge to edge."""
    if _small_screen(screen_w, screen_h):
        min_w, min_h = WINDOW_SMALL_MIN_W, WINDOW_SMALL_MIN_H
    else:
        min_w, min_h = WINDOW_MIN_W, WINDOW_MIN_H
    if screen_w < min_w + 40 or screen_h < min_h + 80:
        fit_w, fit_h = max(1, screen_w - 20), max(1, screen_h - 60)
        return fit_w, fit_h, fit_w, fit_h
    return min_w, min_h, screen_w - 40, screen_h - 80


def clamp_window_geometry(value, screen_w, screen_h):
    """A valid on-screen geometry: the remembered one shrunk to fit
    this screen and re-centered when it no longer fits, or the
    class default — 1200x700, 880x600 on a small screen — clamped
    the same way, centered when there is none. A remembered size
    beyond 85% of the screen width or 88% of its height is a
    legacy full-bleed save, not a real choice, so it is replaced
    by the class default, centered."""
    min_w, min_h, max_w, max_h = _window_plan(screen_w, screen_h)
    def_w, def_h = _window_default(screen_w, screen_h)
    match = _GEOMETRY_RE.match(value or '')
    if match:
        w, h, x, y = (int(part) for part in match.groups())
        if w > 0.85 * screen_w or h > 0.88 * screen_h:
            w = max(min_w, min(def_w, max_w))
            h = max(min_h, min(def_h, max_h))
            return '%dx%d+%d+%d' % (w, h, max(0, (screen_w - w) // 2),
                                    max(0, (screen_h - h) // 3))
        oversize = w > max_w or h > max_h
        w = max(min_w, min(w, max_w))
        h = max(min_h, min(h, max_h))
        if oversize:
            x = max(0, (screen_w - w) // 2)
            y = max(0, (screen_h - h) // 3)
        else:
            x = min(max(x, -w + 160), max(0, screen_w - 80))
            y = min(max(y, 0), max(0, screen_h - 48))
        return '%dx%d+%d+%d' % (w, h, x, y)
    w = max(min_w, min(def_w, max_w))
    h = max(min_h, min(def_h, max_h))
    return '%dx%d+%d+%d' % (w, h, max(0, (screen_w - w) // 2),
                            max(0, (screen_h - h) // 3))


def begin_update(current_path, downloaded_path, new_version, from_version,
                 wait_pid=None, alive_seconds=UPDATE_ALIVE_SECONDS):
    current = Path(current_path).resolve()
    folder = current.parent
    backup = folder / ('PrintMyTexts-PC-v%s-backup.pyw' % from_version)
    result_path = folder / 'update_result.json'
    helper = folder / 'printmytexts_update_helper.py'
    helper.write_text(UPDATE_HELPER_SRC, encoding='utf-8')
    if wait_pid is None:
        wait_pid = os.getpid()
    args = [sys.executable, str(helper), str(wait_pid), str(current),
            str(Path(downloaded_path).resolve()), str(backup),
            str(result_path), sys.executable, str(alive_seconds),
            str(from_version), str(new_version)]
    kwargs = {'creationflags': 0x00000008 | 0x00000200} if os.name == 'nt' \
        else {'start_new_session': True}
    return subprocess.Popen(args, **kwargs)


class PrintMyTextsApp:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk, self.root = tk, ttk, root
        self.work = WorkingData()
        self.messages, self.groups, self.pages = [], {}, []
        self.engine, self.photo, self.worker = None, None, None
        self.results = queue.Queue()
        self.stages = queue.Queue()
        self._import_source = None
        self.update_results = queue.Queue()
        self.update_worker = None
        self.update_info = None
        self.update_busy = False
        self.update_installing = False
        self.update_path = ensure_stable_alias()
        self.update_result_reported = False
        self.closing = False
        self.cancelled = threading.Event()
        self.page_index = 0
        self.view = 'chat'
        self._chat_summary = 'Select a conversation'
        root.title('PrintMyTexts v%s — iFixx Repairs' % VERSION)
        self.apply_theme(root)
        root.protocol('WM_DELETE_WINDOW', self.close)
        self._saved_geometry = None
        self._geometry_after = None
        self._restore_window_geometry()
        self.status = tk.StringVar(value='Ready — import from a phone or a backup file to begin.')
        # The phone page has its own plain-language status (fix 7): it
        # always says what the app is waiting for or doing.
        self.phone_status = tk.StringVar(
            value='Plug in the phone with a cable and unlock it, then tap Read USB phone below.')
        self.xml_name = tk.StringVar(value='No file selected')
        # ---- bottom status bar (present on every screen) ----
        statusbar = tk.Frame(root, background=BG_TOPBAR, height=36)
        statusbar.pack(side='bottom', fill='x')
        statusbar.pack_propagate(False)
        self.status_label = tk.Label(statusbar, textvariable=self.status, wraplength=1050,
                                     background=BG_TOPBAR, foreground=TEXT_SECONDARY,
                                     font=('Segoe UI', 10), anchor='w', justify='left')
        self.status_label.pack(side='left', fill='x', expand=True, padx=12)
        tk.Label(statusbar, text='Local-only processing', background=BG_TOPBAR,
                 foreground=STATUS_OK, font=('Segoe UI', 10, 'bold')).pack(side='right', padx=12)
        self._wrap_w = 0
        root.bind('<Configure>', self._fit_status)
        root.bind('<Configure>', self._track_geometry, add='+')
        # ---- body: navigation sidebar + content ----
        body = tk.Frame(root, background=BG_APP)
        body.pack(fill='both', expand=True)
        sidebar = tk.Frame(body, background=BG_SIDEBAR, width=248)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        self.content = tk.Frame(body, background=BG_APP)
        self.content.pack(side='left', fill='both', expand=True)
        tk.Label(sidebar, text='PrintMyTexts', background=BG_SIDEBAR,
                 foreground=TEXT_PRIMARY, font=('Segoe UI', 20, 'bold')).pack(anchor='w', padx=16, pady=(18, 0))
        tk.Label(sidebar, text='Text message transcripts', background=BG_SIDEBAR,
                 foreground=TEXT_MUTED, font=('Segoe UI', 10)).pack(anchor='w', padx=16, pady=(0, 14))
        self.nav_buttons = {}
        self.nav_rows = {}
        self._nav_accents = {}
        self._nav_key = 'home'
        self._screen = 'home'

        def nav_hover(btn, key, on):
            if key == self._nav_key or str(btn.cget('state')) == 'disabled':
                return
            btn.configure(background=BG_HOVER if on else BG_SIDEBAR)

        for key, label, accent in (
                ('home', 'Home', TEXT_SECONDARY),
                ('phone', 'Import from Phone', TOOL_PHONE),
                ('xml', 'Import from a Backup File', TOOL_XML),
                ('transcript', 'Message Transcript', TOOL_TRANSCRIPT),
                ('print', 'Print / Export', TOOL_EXPORT),
                ('settings', 'Settings', TEXT_SECONDARY)):
            rowf = tk.Frame(sidebar, background=BG_SIDEBAR)
            rowf.pack(fill='x', padx=8, pady=2)
            bar = tk.Label(rowf, text='', background=accent, width=1)
            bar.pack(side='left', fill='y')
            btn = tk.Button(rowf, text=label,
                            command=lambda k=key: self.show_screen(k),
                            background=BG_SIDEBAR, foreground=TEXT_SECONDARY,
                            activebackground=BG_HOVER, activeforeground=TEXT_PRIMARY,
                            disabledforeground=TEXT_DISABLED, relief='flat', bd=0,
                            anchor='w', font=('Segoe UI', 12, 'bold'),
                            padx=14, pady=10, highlightthickness=0)
            btn.pack(side='left', fill='x', expand=True)
            btn.bind('<Enter>', lambda e, b=btn, k=key: nav_hover(b, k, True))
            btn.bind('<Leave>', lambda e, b=btn, k=key: nav_hover(b, k, False))
            self.nav_buttons[key] = btn
            self.nav_rows[key] = (rowf, bar)
            self._nav_accents[key] = accent
        # Transcript / Print need loaded messages first (design spec s.1).
        self.nav_buttons['transcript'].configure(state='disabled')
        self.nav_buttons['print'].configure(state='disabled')
        bottom = tk.Frame(sidebar, background=BG_SIDEBAR)
        bottom.pack(side='bottom', fill='x', padx=8, pady=10)
        self.update_button = ttk.Button(bottom, text='UPDATE', style='Update.TButton',
                                        command=self.start_update)
        self.update_button.pack(fill='x')
        tk.Label(bottom, text='Local-only processing', background=BG_SIDEBAR,
                 foreground=STATUS_OK, font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(10, 0))
        tk.Label(bottom, text='Version %s — iFixx Repairs' % VERSION, background=BG_SIDEBAR,
                 foreground=TEXT_MUTED, font=('Segoe UI', 9)).pack(anchor='w')
        # ---- screens ----
        self.screens = {}
        for key in ('home', 'phone', 'xml', 'transcript', 'settings'):
            self.screens[key] = tk.Frame(self.content, background=BG_APP)
        self._build_home(self.screens['home'])
        self._build_phone_screen(self.screens['phone'])
        self._build_xml_screen(self.screens['xml'])
        self._build_workspace(self.screens['transcript'])
        self._build_settings(self.screens['settings'])
        self._paint_nav()
        self.screens['home'].pack(fill='both', expand=True)
        self._report_update_result()
        root.after(100, self.poll)
        root.after(1500, self._quiet_update_check)

    # ---------- window geometry: calm default + remembered size ------
    def _restore_window_geometry(self):
        root = self.root
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        min_w, min_h, _max_w, _max_h = _window_plan(sw, sh)
        root.minsize(min_w, min_h)
        root.geometry(clamp_window_geometry(load_window_geometry(), sw, sh))

    def _track_geometry(self, event):
        if event.widget is not self.root or self.closing:
            return
        if self._geometry_after is not None:
            try:
                self.root.after_cancel(self._geometry_after)
            except Exception:
                pass
            self._geometry_after = None
        self._geometry_after = self.root.after(500, self._save_geometry)

    def _save_geometry(self):
        self._geometry_after = None
        try:
            current = self.root.geometry()
        except Exception:
            return
        if current and current != self._saved_geometry:
            self._saved_geometry = current
            save_window_geometry(current)

    # ---------- Light Professional shell: navigation + screens -------

    def _paint_nav(self):
        for name, btn in self.nav_buttons.items():
            _rowf, bar = self.nav_rows[name]
            if str(btn.cget('state')) == 'disabled':
                btn.configure(background=BG_SIDEBAR, foreground=TEXT_DISABLED)
            elif name == self._nav_key:
                btn.configure(background=NAV_SELECTED, foreground=TEXT_PRIMARY)
            else:
                btn.configure(background=BG_SIDEBAR, foreground=TEXT_SECONDARY)
            bar.configure(background=NAV_INDICATOR if name == self._nav_key
                          else self._nav_accents[name])

    def show_screen(self, key):
        if key == 'print':
            # Print / Export is the same workspace in paper view — the preview
            # is the exact page the PDF/print pipeline produces (no second
            # renderer), with the settings column beside it.
            self.set_view('paper')
            target = 'transcript'
        elif key == 'transcript':
            # Opening the Message Transcript area always lands on the
            # bubble chat view (fix 2) — never the flat paper text.
            self.set_view('chat')
            target = key
        else:
            target = key
        for name, frame in self.screens.items():
            if name == target:
                frame.pack(fill='both', expand=True)
            else:
                frame.pack_forget()
        self._screen = target
        self._nav_key = key
        self._paint_nav()

    def _enable_workspace(self):
        for key in ('transcript', 'print'):
            self.nav_buttons[key].configure(state='normal')
        self._paint_nav()

    def _fit_wrap(self, host, label, inset):
        """Glue `label`'s wraplength to the real inner width of `host`
        (host width minus `inset` for padding/border/margin) and keep it
        glued on every resize. A fixed wraplength wider than the box the
        label actually gets makes Tk center the unwrapped line and clip
        BOTH edges in any font; a bound wraplength wraps the text inside
        the box instead, so it can never clip."""
        def _apply(event):
            if event.widget is not host:
                return
            width = event.width - inset
            if width >= 40 and int(label.cget('wraplength')) != width:
                label.configure(wraplength=width)
        host.bind('<Configure>', _apply, add='+')

    def _screen_banner(self, parent, title, subtitle):
        tk = self.tk
        banner = tk.Frame(parent, background=BG_PANEL, highlightbackground=BORDER,
                          highlightthickness=1)
        banner.pack(fill='x', padx=28, pady=(24, 12))
        texts = tk.Frame(banner, background=BG_PANEL)
        texts.pack(side='left', fill='x', expand=True, padx=16, pady=10)
        title_label = tk.Label(texts, text=title, background=BG_PANEL,
                               foreground=TEXT_PRIMARY, font=('Segoe UI', 18, 'bold'),
                               wraplength=400, justify='left')
        title_label.pack(anchor='w', fill='x')
        subtitle_label = tk.Label(texts, text=subtitle, background=BG_PANEL,
                                  foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                  wraplength=400, justify='left')
        subtitle_label.pack(anchor='w', fill='x')
        self._fit_wrap(texts, title_label, 8)
        self._fit_wrap(texts, subtitle_label, 8)
        return banner

    def _action_button(self, parent, text, command, background):
        if background == BG_PANEL_ALT:
            # Neutral door on the light face: dark text on light gray.
            foreground = TEXT_PRIMARY
            active_bg, active_fg = BG_HOVER, TEXT_PRIMARY
        else:
            foreground = '#FFFFFF'
            active_bg, active_fg = ACCENT_HOVER, '#FFFFFF'
        btn = self.tk.Button(parent, text=text, command=command, background=background,
                             foreground=foreground, activebackground=active_bg,
                             activeforeground=active_fg, disabledforeground=TEXT_DISABLED,
                             relief='flat', bd=0, font=('Segoe UI', 12, 'bold'),
                             padx=16, pady=9, highlightthickness=0)
        return btn

    def _build_home(self, parent):
        tk = self.tk
        hero = tk.Frame(parent, background=BG_APP)
        hero.pack(fill='x', padx=28, pady=(26, 4))
        tk.Label(hero, text='PrintMyTexts', background=BG_APP, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 30, 'bold')).pack(anchor='w')
        tk.Label(hero, text='Turn text messages into a clean, printable transcript.',
                 background=BG_APP, foreground=TEXT_SECONDARY,
                 font=('Segoe UI', 13)).pack(anchor='w', pady=(2, 0))
        tk.Label(hero, text=UI_NOTICE, background=BG_APP, foreground=TEXT_MUTED,
                 font=('Segoe UI', 10)).pack(anchor='w', pady=(2, 0))
        cards = tk.Frame(parent, background=BG_APP)
        cards.pack(fill='x', padx=20, pady=14)
        for col in range(3):
            cards.columnconfigure(col, weight=1)
        self._action_card(cards, 0, TOOL_PHONE, 'Import from Phone',
                          'Read messages straight from a connected Android phone.',
                          'Connect phone', lambda: self.show_screen('phone'))
        self._action_card(cards, 1, TOOL_XML, 'Import from a Backup File',
                          'Open a backup file saved by the SMS Backup & Restore app, from any phone.',
                          'Choose backup file', self.import_xml)
        self._action_card(cards, 2, TOOL_EXPORT, 'View & Print',
                          'Open the transcript, check it, then print or save a PDF.',
                          'Open transcript', lambda: self.show_screen('transcript'))
        info = tk.Frame(parent, background=BG_APP)
        info.pack(fill='x', padx=20, pady=6)
        for col in range(3):
            info.columnconfigure(col, weight=1)
        self._info_panel(info, 0, 'Local processing', 'No internet connection required.')
        self._info_panel(info, 1, 'Automatic cleanup', 'Session data is removed when the app closes.')
        self._info_panel(info, 2, 'Professional PDF', 'Clean transcripts, ready to print or save.')
        home_status = tk.Label(parent, textvariable=self.status, background=BG_APP,
                               foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                               wraplength=640, justify='left')
        home_status.pack(anchor='w', fill='x', padx=28, pady=12)
        self._fit_wrap(parent, home_status, 62)

    def _action_card(self, parent, col, accent, title, helper, action_text, command):
        tk = self.tk
        card = tk.Frame(parent, background=BG_PANEL, highlightbackground=BORDER,
                        highlightthickness=1, padx=18, pady=16)
        card.grid(row=0, column=col, sticky='nsew', padx=8)
        title_label = tk.Label(card, text=title, background=BG_PANEL,
                               foreground=TEXT_PRIMARY, font=('Segoe UI', 16, 'bold'),
                               wraplength=140, justify='left')
        title_label.pack(anchor='w', fill='x', pady=(6, 2))
        helper_label = tk.Label(card, text=helper, background=BG_PANEL,
                                foreground=TEXT_SECONDARY, font=('Segoe UI', 10),
                                wraplength=140, justify='left')
        helper_label.pack(anchor='w', fill='x')
        # Card inner width = card width - 2*18 frame padding - 2*1 border;
        # wraplength stays 6 px under that, glued on every resize, so the
        # helper text wraps inside the card in any font at any size.
        self._fit_wrap(card, title_label, 44)
        self._fit_wrap(card, helper_label, 44)
        self._action_button(card, action_text, command, accent).pack(anchor='w', pady=(12, 0))
        return card

    def _info_panel(self, parent, col, title, text):
        tk = self.tk
        panel = tk.Frame(parent, background=BG_PANEL_ALT, padx=14, pady=10,
                       highlightbackground=BORDER, highlightthickness=1)
        panel.grid(row=0, column=col, sticky='nsew', padx=8)
        title_label = tk.Label(panel, text=title, background=BG_PANEL_ALT,
                               foreground=TEXT_PRIMARY, font=('Segoe UI', 12, 'bold'),
                               wraplength=140, justify='left')
        title_label.pack(anchor='w', fill='x')
        text_label = tk.Label(panel, text=text, background=BG_PANEL_ALT,
                              foreground=TEXT_SECONDARY, font=('Segoe UI', 10),
                              wraplength=140, justify='left')
        text_label.pack(anchor='w', fill='x')
        # Same treatment as the action cards: panel inner width = panel
        # width - 2*14 padding - 2*1 border; wraplength rides 6 px under.
        self._fit_wrap(panel, title_label, 36)
        self._fit_wrap(panel, text_label, 36)

    def _build_phone_screen(self, parent):
        tk = self.tk
        self._screen_banner(parent, 'Import from Phone',
                            'Connect one unlocked Android phone with a cable.')
        panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill='x', padx=28, pady=6)
        tk.Label(panel, text='Device connection', background=BG_PANEL,
                 foreground=TEXT_PRIMARY, font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        phone_status = tk.Label(panel, textvariable=self.phone_status, background=BG_PANEL,
                                foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                wraplength=640, justify='left')
        phone_status.pack(anchor='w', fill='x', pady=(4, 10))
        self._fit_wrap(panel, phone_status, 48)
        self.read_button = self._action_button(panel, 'Read USB phone', self.read_phone, ACCENT)
        self.read_button.pack(anchor='w')
        nav = tk.Frame(parent, background=BG_APP)
        nav.pack(fill='x', padx=28, pady=14)
        self._action_button(nav, 'Back', lambda: self.show_screen('home'), BG_PANEL_ALT).pack(side='left')
        self._action_button(nav, 'View Transcript', lambda: self.show_screen('transcript'),
                            TOOL_TRANSCRIPT).pack(side='right')

    def _build_xml_screen(self, parent):
        tk = self.tk
        self._screen_banner(parent, 'Import from a Backup File',
                            'Select a backup file from the SMS Backup & Restore app.')
        panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill='x', padx=28, pady=6)
        tk.Label(panel, text='File', background=BG_PANEL, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        row = tk.Frame(panel, background=BG_PANEL)
        row.pack(fill='x', pady=(6, 4))
        tk.Label(row, textvariable=self.xml_name, background=BG_INPUT,
                 foreground=TEXT_PRIMARY, font=('Segoe UI', 11),
                 anchor='w', padx=10, pady=8).pack(side='left', fill='x', expand=True)
        self.import_button = self._action_button(row, 'Browse Files', self.import_xml,
                                                 TOOL_XML_PRIMARY)
        self.import_button.pack(side='right', padx=(10, 0))
        for label, value in (('Type', 'Backup file (SMS Backup & Restore)'),):
            tk.Label(panel, text='%s:  %s' % (label, value), background=BG_PANEL,
                     foreground=TEXT_SECONDARY, font=('Segoe UI', 11)).pack(anchor='w', pady=2)
        xml_status = tk.Label(panel, textvariable=self.status, background=BG_PANEL,
                              foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                              wraplength=640, justify='left')
        xml_status.pack(anchor='w', fill='x', pady=(6, 0))
        self._fit_wrap(panel, xml_status, 48)
        nav = tk.Frame(parent, background=BG_APP)
        nav.pack(fill='x', padx=28, pady=14)
        self._action_button(nav, 'Back', lambda: self.show_screen('home'), BG_PANEL_ALT).pack(side='left')
        self._action_button(nav, 'View Transcript', lambda: self.show_screen('transcript'),
                            TOOL_TRANSCRIPT).pack(side='right')

    def _build_workspace(self, parent):
        tk, ttk = self.tk, self.ttk
        split = tk.PanedWindow(parent, orient='horizontal', background=BG_APP,
                               sashwidth=6, bd=0, opaqueresize=True)
        split.pack(fill='both', expand=True, padx=12, pady=12)
        self.split = split
        left, right = ttk.Frame(split), ttk.Frame(split)
        # On a small screen the panes narrow with the window's size
        # class, so the compact window never squeezes them past
        # their minimums.
        if _small_screen(parent.winfo_screenwidth(),
                         parent.winfo_screenheight()):
            side_min, content_min = 270, 460
        else:
            side_min, content_min = 320, 520
        split.add(left, minsize=side_min, stretch='always')
        split.add(right, minsize=content_min, stretch='always')
        tk.Label(left, text='Conversations', background=BG_APP, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 14, 'bold')).pack(anchor='w', pady=(0, 6))
        self.tree = ttk.Treeview(left, columns=('count', 'recent'), show='tree headings', height=10)
        self.tree.heading('#0', text='Contact / number')
        self.tree.heading('count', text='Count')
        self.tree.heading('recent', text='Latest date')
        self.tree.column('#0', width=240, minwidth=180, stretch=True)
        self.tree.column('count', width=64, stretch=False)
        self.tree.column('recent', width=105, stretch=False)
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.select)
        self.name, self.start, self.end = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, variable in (('Contact name (editable)', self.name), ('From YYYY-MM-DD (optional)', self.start), ('Through YYYY-MM-DD (optional)', self.end)):
            ttk.Label(left, text=label).pack(anchor='w', pady=(8, 0))
            ttk.Entry(left, textvariable=variable).pack(fill='x')
            variable.trace_add('write', self.invalidate)
        ttk.Button(left, text='Apply / preview', command=self.preview).pack(fill='x', pady=8)
        self.private = tk.BooleanVar(value=False)
        self.private.trace_add('write', self.invalidate)
        ttk.Checkbutton(left, text='Hide the phone number (private print)', variable=self.private).pack(anchor='w', pady=(0, 8))
        ttk.Label(left, text='Transcripts never carry shop information. Private print also hides the phone number. Message text is never changed.', wraplength=300).pack(anchor='w')
        action = tk.Frame(right, background=BG_APP)
        action.pack(fill='x', pady=(0, 8))
        self.chat_btn = self._action_button(action, 'Chat view', lambda: self.set_view('chat'), BG_PANEL_ALT)
        self.chat_btn.pack(side='left')
        self.paper_btn = self._action_button(action, 'Paper view', lambda: self.set_view('paper'), BG_PANEL_ALT)
        self.paper_btn.pack(side='left', padx=(6, 10))
        self._action_button(action, '\u25C0', lambda: self.show_page(-1), BG_PANEL_ALT).pack(side='left')
        self._action_button(action, '\u25B6', lambda: self.show_page(1), BG_PANEL_ALT).pack(side='left', padx=(4, 0))
        self.page_label = tk.Label(action, text='Select a conversation', background=BG_APP,
                                   foreground=TEXT_SECONDARY, font=('Segoe UI', 11))
        self.page_label.pack(side='left', padx=8)
        self.print_button = self._action_button(action, 'PRINT', self.print_transcript, ACCENT)
        self.print_button.configure(state='disabled')
        self.print_button.pack(side='right')
        self.pdf_button = self._action_button(action, 'Save PDF', self.save_pdf, EXPORT_CONFIRM)
        self.pdf_button.configure(state='disabled')
        self.pdf_button.pack(side='right', padx=8)
        self.paper_frame = tk.Frame(right, background=PREVIEW_BG)
        self.canvas = tk.Canvas(self.paper_frame, background=PREVIEW_BG, highlightthickness=0)
        scroll = ttk.Scrollbar(self.paper_frame, orient='vertical', command=self.canvas.yview)
        scroll.pack(side='right', fill='y')
        horizontal = ttk.Scrollbar(self.paper_frame, orient='horizontal', command=self.canvas.xview)
        horizontal.pack(side='bottom', fill='x')
        self.canvas.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        self.canvas.pack(fill='both', expand=True)
        self.chat_frame = tk.Frame(right, background=CHAT_BG)
        self.chat_canvas = tk.Canvas(self.chat_frame, background=CHAT_BG, highlightthickness=0)
        chat_scroll = ttk.Scrollbar(self.chat_frame, orient='vertical', command=self.chat_canvas.yview)
        chat_scroll.pack(side='right', fill='y')
        self.chat_canvas.configure(yscrollcommand=chat_scroll.set)
        self.chat_canvas.pack(fill='both', expand=True)
        self.chat_inner = tk.Frame(self.chat_canvas, background=CHAT_BG)
        self.chat_window = self.chat_canvas.create_window((0, 0), window=self.chat_inner, anchor='nw')
        self.chat_inner.bind('<Configure>', lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox('all')))
        self.chat_canvas.bind('<Configure>', lambda e: self.chat_canvas.itemconfigure(self.chat_window, width=e.width))
        self.set_view('chat')

    def _build_settings(self, parent):
        tk = self.tk
        # The stacked settings panels — the full help list above all —
        # outgrow the window height, so the page scrolls (same canvas
        # pattern as the transcript panes); otherwise the last help
        # lines are packed past the bottom edge and can never be read.
        outer = parent
        canvas = tk.Canvas(outer, background=BG_APP, highlightthickness=0)
        vscroll = self.ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        vscroll.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        canvas.configure(yscrollcommand=vscroll.set)
        parent = tk.Frame(canvas, background=BG_APP)
        window = canvas.create_window((0, 0), window=parent, anchor='nw')
        parent.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfigure(window, width=e.width))
        self.settings_canvas = canvas
        tk.Label(parent, text='Settings', background=BG_APP, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 24, 'bold')).pack(anchor='w', padx=28, pady=(24, 8))
        panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        panel.pack(fill='x', padx=28, pady=6)
        tk.Label(panel, text='Version', background=BG_PANEL, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        tk.Label(panel, text='PrintMyTexts v%s — iFixx Repairs' % VERSION, background=BG_PANEL,
                 foreground=TEXT_SECONDARY, font=('Segoe UI', 11)).pack(anchor='w', pady=(2, 10))
        self.settings_update_button = self._action_button(panel, 'Check for updates',
                                                          self.start_update, ACCENT)
        self.settings_update_button.pack(anchor='w')
        privacy = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                 highlightbackground=BORDER, highlightthickness=1)
        privacy.pack(fill='x', padx=28, pady=6)
        tk.Label(privacy, text='Privacy', background=BG_PANEL, foreground=TEXT_PRIMARY,
                 font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        notice_label = tk.Label(privacy, text=UI_NOTICE, background=BG_PANEL,
                                foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                wraplength=640, justify='left')
        notice_label.pack(anchor='w', fill='x', pady=(2, 0))
        times_label = tk.Label(privacy, text='Times are shown the way the phone recorded them. Only received/sent are labeled YOU/THEM; other directions stay unreadable. Session data is removed when the app closes.',
                               background=BG_PANEL, foreground=TEXT_SECONDARY,
                               font=('Segoe UI', 11), wraplength=640, justify='left')
        times_label.pack(anchor='w', fill='x', pady=(2, 0))
        self._fit_wrap(privacy, notice_label, 48)
        self._fit_wrap(privacy, times_label, 48)
        # Plain-language help (fix 8): what every button does, one line each.
        help_panel = tk.Frame(parent, background=BG_PANEL, padx=20, pady=16,
                      highlightbackground=BORDER, highlightthickness=1)
        help_panel.pack(fill='x', padx=28, pady=6)
        tk.Label(help_panel, text='What everything does', background=BG_PANEL,
                 foreground=TEXT_PRIMARY, font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        for help_title, help_line in HELP_LINES:
            row = tk.Frame(help_panel, background=BG_PANEL)
            row.pack(fill='x', pady=(8, 0))
            tk.Label(row, text=help_title, background=BG_PANEL, foreground=TEXT_PRIMARY,
                     font=('Segoe UI', 11, 'bold')).pack(anchor='w')
            line_label = tk.Label(row, text=help_line, background=BG_PANEL,
                                  foreground=TEXT_SECONDARY, font=('Segoe UI', 11),
                                  wraplength=640, justify='left')
            line_label.pack(anchor='w', fill='x')
            self._fit_wrap(row, line_label, 8)

    def apply_theme(self, root):
        # Light Professional shell + large, wide screen fonts (owner
        # readability). Printed pages are unaffected (paper stays black on
        # white, rendered by the unchanged layout pipeline).
        tk, ttk = self.tk, self.ttk
        root.configure(background=BG_APP)
        root.option_add('*Font', ('Segoe UI', 12))
        style = ttk.Style(root)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
        style.configure('.', background=BG_APP, foreground=TEXT_PRIMARY, font=('Segoe UI', 12))
        style.configure('TFrame', background=BG_APP)
        style.configure('TLabelframe', background=BG_APP, foreground=TEXT_PRIMARY)
        style.configure('TLabel', background=BG_APP, foreground=TEXT_PRIMARY, font=('Segoe UI', 12))
        style.configure('TButton', background=BG_PANEL_ALT, foreground=TEXT_PRIMARY,
                        font=('Segoe UI', 12, 'bold'), padding=6)
        style.map('TButton', background=[('active', BG_HOVER), ('disabled', '#C3CEDA')],
                  foreground=[('disabled', TEXT_DISABLED)])
        style.configure('Update.TButton', background=ACCENT, foreground='#ffffff',
                        font=('Segoe UI', 12, 'bold'), padding=6)
        style.map('Update.TButton', background=[('active', ACCENT_HOVER), ('disabled', '#C3CEDA')],
                  foreground=[('disabled', TEXT_DISABLED)])
        style.configure('TCheckbutton', background=BG_APP, foreground=TEXT_PRIMARY, font=('Segoe UI', 12))
        style.configure('TEntry', fieldbackground=BG_INPUT, foreground=TEXT_PRIMARY,
                        font=('Verdana', 12), padding=4)
        style.configure('Treeview', background=LP_SURFACE, fieldbackground=LP_SURFACE,
                        foreground=TEXT_PRIMARY, font=('Verdana', 12), rowheight=32)
        style.configure('Treeview.Heading', background=BG_PANEL_ALT, foreground=TEXT_PRIMARY,
                        font=('Segoe UI', 12, 'bold'))
        style.map('Treeview', background=[('selected', NAV_SELECTED)],
                  foreground=[('selected', TEXT_PRIMARY)])
        style.configure('TScrollbar', background=BG_PANEL_ALT, troughcolor=BG_PANEL)
        style.configure('TPanedwindow', background=BG_APP)

    def set_view(self, view):
        self.view = view
        if view == 'chat':
            self.paper_frame.pack_forget()
            self.chat_frame.pack(fill='both', expand=True)
            self.page_label.configure(text=self._chat_summary)
        else:
            self.chat_frame.pack_forget()
            self.paper_frame.pack(fill='both', expand=True)
            if self.pages:
                self.show_page()
            else:
                self.page_label.configure(text='Select a conversation')
        self._paint_view_buttons()

    def _paint_view_buttons(self):
        if not hasattr(self, 'chat_btn'):
            return
        for btn, active in ((self.chat_btn, self.view == 'chat'),
                            (self.paper_btn, self.view == 'paper')):
            btn.configure(background=ACCENT if active else BG_PANEL_ALT,
                          foreground='#FFFFFF' if active else TEXT_SECONDARY)

    def _chat_bubble(self, row, body, fill, foreground, anchor, padx, justify):
        """One rounded chat bubble (screen only): the wrapped message text on
        a small canvas, over a rounded rectangle built from corner ovals and
        cross rectangles — primitive shapes only, so the corners draw
        identically on Windows Tk and Aqua Tk. Padding matches the old flat
        labels (12 x 8); the wrap width is 430 wherever the pane leaves
        room for it (see below)."""
        tk = self.tk
        pad_x, pad_y, radius = 12, 8, 14
        # Wrap at 430 like the old flat labels, but never wider than the
        # row leaves room for: in a narrow pane the packer would shrink a
        # max-width bubble and clip its text at the bubble's edge. The
        # update_idletasks settles the pack layout first, so the row width
        # is real even when a render is triggered before the window's
        # first full update.
        row.update_idletasks()
        wrap = 430
        row_width = row.winfo_width()
        if row_width > 1:
            wrap = max(160, min(430, row_width - (padx[0] + padx[1]) - 2 * pad_x))
        canvas = tk.Canvas(row, background=CHAT_BG, highlightthickness=0,
                           borderwidth=0)
        text_id = canvas.create_text(pad_x, pad_y, text=body,
                                     font=('Verdana', 12), fill=foreground,
                                     width=wrap, anchor='nw', justify=justify)
        canvas.update_idletasks()
        box = canvas.bbox(text_id) or (pad_x, pad_y, pad_x + 10, pad_y + 10)
        x0, y0 = box[0] - pad_x, box[1] - pad_y
        x1, y1 = box[2] + pad_x, box[3] + pad_y
        r = max(2, min(radius, (x1 - x0) // 2, (y1 - y0) // 2))
        shapes = [
            canvas.create_rectangle(x0 + r, y0, x1 - r, y1,
                                    fill=fill, outline=fill),
            canvas.create_rectangle(x0, y0 + r, x1, y1 - r,
                                    fill=fill, outline=fill),
        ]
        for cx, cy in ((x0, y0), (x1 - 2 * r, y0),
                       (x0, y1 - 2 * r), (x1 - 2 * r, y1 - 2 * r)):
            shapes.append(canvas.create_oval(cx, cy, cx + 2 * r, cy + 2 * r,
                                             fill=fill, outline=fill))
        for shape in shapes:
            canvas.tag_lower(shape, text_id)
        canvas.configure(width=x1 - x0, height=y1 - y0)
        canvas.pack(anchor=anchor, padx=padx)

    def render_chat(self, messages, name):
        """Phone-style bubble view (screen only): rounded bubbles — contact
        on the LEFT in light #E7EDF3, the phone owner (sent) on the RIGHT in
        strong ACCENT blue with white text (owner 2026-10-26: one side one
        color, the other side a different color), on a light timeline, with
        date separators. Message text is shown exactly as stored; the paper
        transcript remains the labeled record (YOU / contact name / THEM,
        unchanged)."""
        tk = self.tk
        for child in self.chat_inner.winfo_children():
            child.destroy()
        display = (name or '').strip() or 'THEM'
        count = 0
        last_day = None
        for message in ordered(messages):
            count += 1
            day = format_day(message.timestamp)
            if day != last_day:
                last_day = day
                sep = tk.Frame(self.chat_inner, background=CHAT_BG)
                sep.pack(fill='x', pady=(12, 2))
                tk.Label(sep, text=day, font=('Segoe UI', 9, 'bold'),
                         foreground=DATE_SEP_FG, background=DATE_SEP_BG,
                         padx=12, pady=3).pack(anchor='center')
            row = tk.Frame(self.chat_inner, background=CHAT_BG)
            row.pack(fill='x', padx=10, pady=(5, 0))
            body = safe_display(message.body or '')
            if message.direction == 'sent':
                tk.Label(row, text='YOU · ' + format_time(message.timestamp), font=('Verdana', 9),
                         foreground=BUBBLE_OWNER_META, background=CHAT_BG).pack(anchor='e')
                self._chat_bubble(row, body, BUBBLE_OWNER, BUBBLE_OWNER_TEXT,
                                  'e', (140, 0), 'left')
            elif message.direction == 'received':
                tk.Label(row, text=display + ' · ' + format_time(message.timestamp), font=('Verdana', 9),
                         foreground=BUBBLE_CUSTOMER_META, background=CHAT_BG).pack(anchor='w')
                self._chat_bubble(row, body, BUBBLE_CUSTOMER, BUBBLE_CUSTOMER_TEXT,
                                  'w', (0, 140), 'left')
            else:
                tk.Label(row, text='— ' + format_date(message.timestamp) + ' —', font=('Verdana', 9),
                         foreground=BUBBLE_CUSTOMER_META, background=CHAT_BG).pack(anchor='center')
                self._chat_bubble(row, body, BUBBLE_UNKNOWN, BUBBLE_CUSTOMER_TEXT,
                                  'center', (0, 0), 'center')
        self._chat_summary = '%s — %d messages' % (display, count)
        if self.view == 'chat':
            self.page_label.configure(text=self._chat_summary)
        self.chat_canvas.yview_moveto(0)

    def _fit_status(self, event):
        # The status line wraps to the real window width, not a fixed 1050.
        if event.widget is not self.root:
            return
        width = max(420, event.width - 40)
        if abs(width - self._wrap_w) > 8:
            self._wrap_w = width
            self.status_label.configure(wraplength=width)

    def invalidate(self, *_):
        self.pages.clear()
        self.photo = None
        self.canvas.delete('all')
        for child in self.chat_inner.winfo_children():
            child.destroy()
        self._chat_summary = 'Apply / preview to refresh'
        self.print_button.configure(state='disabled')
        self.pdf_button.configure(state='disabled')
        self.page_label.configure(text='Apply / preview to refresh')

    def busy(self, value):
        state = 'disabled' if value else 'normal'
        self.read_button.configure(state=state)
        self.import_button.configure(state=state)
        if hasattr(self, 'settings_update_button'):
            self.settings_update_button.configure(state=state)
        if hasattr(self, 'update_button'):
            self.update_button.configure(
                state='disabled' if value or self.update_busy else 'normal')

    def load_async(self, loader, working_text='Reading your messages…'):
        if self.worker and self.worker.is_alive():
            return
        self.invalidate()
        self.messages.clear()
        self.groups.clear()
        self.tree.delete(*self.tree.get_children())
        self.busy(True)
        # Plain words only (fix 7): the status always says what the app
        # is doing — never a vague 'Reading locally…'.
        self.status.set(working_text)
        def task():
            try:
                result = loader()
            except Exception as exc:
                result = str(exc)
            self.results.put(result)
        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()

    def _stage(self, stage):
        # Worker-thread progress (e.g. the phone answered and the read
        # has begun) — drained by poll() on the UI thread.
        self.stages.put(stage)

    def read_phone(self):
        self._import_source = 'phone'
        self.phone_status.set('Waiting for the phone… unlock it, and tap Allow on the phone if it asks.')
        self.load_async(lambda: AdbReader(cancelled=self.cancelled, on_stage=self._stage).read(),
                        working_text='Waiting for the phone…')

    def import_xml(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title='SMS Backup & Restore backup file', filetypes=[('Backup file', '*.xml')])
        if path:
            self._import_source = 'backup'
            self.xml_name.set(path)
            self.show_screen('xml')
            self.load_async(lambda: parse_xml(path))

    def poll(self):
        if self.closing:
            if ((self.worker and self.worker.is_alive())
                    or (self.update_worker and self.update_worker.is_alive())):
                self.root.after(100, self.poll)
                return
            self.finish_close()
            return
        try:
            while True:
                stage = self.stages.get_nowait()
                if stage == 'reading':
                    self.phone_status.set('Reading your messages… keep the phone plugged in and unlocked.')
        except queue.Empty:
            pass
        try:
            result = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy(False)
            if isinstance(result, str):
                if self._import_source == 'phone':
                    # Phone-read failures reach the screen only as plain
                    # sentences (fix 7) — never the raw tool wording.
                    result = plain_phone_error(result)
                    self.phone_status.set(result)
                self.status.set(result)
            else:
                self.messages = result.messages
                self.groups = conversations(self.messages)
                for index, group in enumerate(self.groups.values()):
                    name = next((m.contact_name for m in group if m.contact_name), '')
                    latest = max((m.timestamp for m in group if m.timestamp is not None), default=None)
                    recent = datetime.fromtimestamp(latest / 1000).strftime('%Y-%m-%d') if latest is not None else 'Unreadable'
                    self.tree.insert('', 'end', iid=str(index), text=f'{name + " — " if name else ""}{group[0].address}', values=(len(group), recent))
                warning = ' '.join(result.warnings)
                self.status.set(f'{len(self.messages)} messages loaded. {warning}' if self.messages else 'No messages in this backup.')
                if self._import_source == 'phone':
                    self.phone_status.set('Done — here are your conversations.' if self.messages
                                          else 'Done — no messages were found on the phone.')
                if self.messages:
                    self._enable_workspace()
                    self.show_screen('transcript')
                    # Land straight on the messages (fix 6): open the
                    # first conversation so its bubbles are on screen —
                    # no separate 'Message Transcript' tap needed.
                    self.tree.selection_set('0')
                    self.select()
        try:
            kind, payload = self.update_results.get_nowait()
        except queue.Empty:
            pass
        else:
            self._handle_update_result(kind, payload)
        self.root.after(100, self.poll)

    def start_update(self):
        if self.closing or self.update_busy:
            return
        reason = updater_guard_reason(
            bool(self.worker and self.worker.is_alive()), bool(self.messages))
        if reason:
            self.status.set(reason)
            return
        self.update_busy = True
        self.update_button.configure(state='disabled')
        self.status.set('Checking the update feed…')
        self.update_worker = threading.Thread(
            target=self._check_update, daemon=True)
        self.update_worker.start()

    def _check_update(self):
        info = check_for_update()
        self.update_results.put(('checked', info))

    def _quiet_update_check(self):
        if self.closing:
            return
        worker = threading.Thread(target=self._check_update_quietly, daemon=True)
        worker.start()

    def _check_update_quietly(self):
        info = check_for_update()
        if info:
            self.update_results.put(('startup_available', info))

    def _handle_update_result(self, kind, payload):
        if kind == 'startup_available':
            if payload:
                self.update_info = payload
                self.update_button.configure(
                    text='⬆ UPDATE: v%s' % payload['version'])
        elif kind == 'checked':
            from tkinter import messagebox
            self.update_busy = False
            self.update_button.configure(state='normal')
            if not payload:
                self.status.set('No newer update found, or the update feed could not be reached.')
                return
            self.update_info = payload
            if not messagebox.askyesno(
                    'PrintMyTexts update',
                    'PrintMyTexts v%s is available (you have v%s).\\n\\n%s\\n\\n'
                    'Download and install it now? PrintMyTexts will restart.'
                    % (payload['version'], VERSION, payload.get('notes') or '')):
                self.status.set('Update cancelled. You are still using v%s.' % VERSION)
                return
            self.update_busy = True
            self.update_button.configure(state='disabled')
            self.status.set('Downloading and verifying PrintMyTexts v%s…'
                            % payload['version'])
            self.update_worker = threading.Thread(
                target=self._download_update, args=(payload,), daemon=True)
            self.update_worker.start()
        elif kind == 'downloaded':
            info, path, error = payload
            if error:
                self.update_busy = False
                self.update_button.configure(state='normal')
                self.status.set('Update not installed: %s. Still using v%s.'
                                % (error, VERSION))
                return
            reason = updater_guard_reason(
                bool(self.worker and self.worker.is_alive()),
                bool(self.messages))
            if reason:
                Path(path).unlink(missing_ok=True)
                self.update_busy = False
                self.update_button.configure(state='normal')
                self.status.set(reason)
                return
            self.status.set('Installing v%s and restarting…' % info['version'])
            try:
                begin_update(self.update_path, path, info['version'], VERSION)
            except Exception as exc:
                Path(path).unlink(missing_ok=True)
                self.update_busy = False
                self.update_button.configure(state='normal')
                self.status.set('Update could not start (%s). Still using v%s.'
                                % (exc, VERSION))
                return
            self.update_installing = True
            self.root.after(400, self.close)

    def _download_update(self, info):
        path, error = download_update(info, self.update_path.parent)
        self.update_results.put(('downloaded', (info, path, error)))

    def _report_update_result(self):
        if self.update_result_reported or self.closing:
            return
        result_path = self.update_path.parent / 'update_result.json'
        try:
            if not result_path.is_file():
                self.root.after(1000, self._report_update_result)
                return
            result = json.loads(result_path.read_text(encoding='utf-8'))
            result_path.unlink(missing_ok=True)
            self.update_result_reported = True
            if result.get('outcome') == 'rolled_back':
                self.status.set('Update did not start; restored PrintMyTexts v%s.'
                                % result.get('from_version', VERSION))
            elif result.get('outcome') == 'updated':
                self.status.set('Updated to PrintMyTexts v%s.'
                                % result.get('to_version', VERSION))
        except Exception:
            self.status.set('The last update result could not be read.')

    def selected(self):
        selection = self.tree.selection()
        if not selection:
            raise ValueError('Pick a conversation first.')
        return list(self.groups.values())[int(selection[0])]

    def select(self, _event=None):
        try:
            group = self.selected()
            self.name.set(next((m.contact_name for m in group if m.contact_name), ''))
            self.preview()
        except ValueError:
            pass

    def preview(self):
        from tkinter import messagebox
        self.invalidate()
        try:
            group = self.selected()
            messages = filter_dates(group, self.start.get().strip(), self.end.get().strip())
            if not messages:
                raise ValueError('No messages in that date range.')
            if self.engine is None:
                self.engine = WindowsPages()
            self.pages = layout_pages(messages, self.name.get(), group[0].address, self.engine.measure, private=self.private.get())
            self.page_index = 0
            self.show_page()
            self.render_chat(messages, self.name.get())
            self.print_button.configure(state='normal')
            self.pdf_button.configure(state='normal')
        except Exception as exc:
            messagebox.showerror('PrintMyTexts', str(exc))

    def show_page(self, delta=0):
        if not self.pages:
            return
        self.page_index = max(0, min(len(self.pages)-1, self.page_index + delta))
        # Pixel-identical page at 100% with scrolling; no browser caches.
        self.photo = self.tk.PhotoImage(data=png_bytes(self.engine.raster(self.pages[self.page_index])))
        self.canvas.delete('all')
        self.canvas.create_image(0, 0, anchor='nw', image=self.photo)
        self.canvas.configure(scrollregion=(0, 0, PAGE_W, PAGE_H))
        self.canvas.yview_moveto(0)
        if self.view == 'paper':
            self.page_label.configure(text=f'Page {self.page_index + 1} of {len(self.pages)}')

    def print_transcript(self):
        from tkinter import messagebox
        try:
            if self.pages and self.engine.print_pages(self.pages):
                self.status.set('Submitted to the Windows print spooler.')
        except Exception as exc:
            messagebox.showerror('Print failed', str(exc))

    def save_pdf(self):
        from tkinter import filedialog, messagebox
        if not self.pages:
            return
        path = filedialog.asksaveasfilename(title='Save customer PDF copy', defaultextension='.pdf', filetypes=[('PDF', '*.pdf')])
        if not path:
            return
        staged = self.work.path / 'export.pdf'
        try:
            write_pdf(staged, self.pages, self.engine.raster)
            shutil.copyfile(staged, path)
            self.status.set('PDF saved to the location you selected. This requested copy is retained.')
        except Exception as exc:
            messagebox.showerror('PDF export failed', str(exc))
        finally:
            staged.unlink(missing_ok=True)

    def close(self):
        self._save_geometry()
        self.closing = True
        self.cancelled.set()
        self.busy(True)
        self.invalidate()
        self.messages.clear()
        self.groups.clear()
        self.status.set('Closing and clearing working data…')
        if not self.worker or not self.worker.is_alive():
            self.finish_close()
        # poll waits for bounded ADB subprocesses before destroying the process.

    def finish_close(self):
        while not self.results.empty():
            self.results.get_nowait()
        while not self.update_results.empty():
            self.update_results.get_nowait()
        if not self.update_installing:
            for download in self.update_path.parent.glob('PrintMyTexts-PC-v*.download'):
                download.unlink(missing_ok=True)
        if self.engine:
            self.engine.close()
        self.work.close()
        self.root.destroy()


def main():
    import tkinter as tk
    ensure_stable_alias()
    root = tk.Tk()
    PrintMyTextsApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
