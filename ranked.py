#!/usr/bin/env python3
"""
ranked.py - configure a Ranked Master 65% (VID 0x3532 / PID 0xB0A1) from macOS.

Protocol from static analysis of Ranked Utility (OemDrv.exe), see protocol.md:
  every message = 64 bytes: 04 <cmd> <args...> zero-padded; keyboard echoes <cmd>.

Commands:
  python ranked.py info                       handshake, show model + firmware
  python ranked.py modes                      list lighting modes and what each supports
  python ranked.py led --mode 19 --color red --brightness 9
  python ranked.py led --mode 3 --speed 3 --brightness 6 --color random
  python ranked.py led ... --dry-run          print the bytes, send nothing

Safety: this tool can ONLY send the handshake (A0 02 00 01) and the lighting
command (AE 01). Bootloader (A5), resets (A0 02 03, AE 06) and macro wipe (AA)
are hard-blocked in send().

Requirements: brew install hidapi ; Input Monitoring enabled for your terminal.
"""
import argparse
import ctypes
import ctypes.util
import os
import sys

VID, PID = 0x3532, 0xB0A1
VENDOR_USAGE_PAGE = 0xFF00
REPORT_ID = 0x04
EXPECTED_PSD = bytes([0x0C, 0x01, 0x01])

CMD_GET_PSD = bytes([0xA0, 0x02, 0x00, 0x01])

# ---------------------------------------------------------------- lighting data
# From Dev/kb/M68/US/Dev.ini, LedOpt1..20. Columns: hw, effect, speed, light, direct, random, color
# "speed"/"light"(brightness)/"random"/"color" = 1 means the app shows that control for the mode.
LED_OPTS = [
    (0, 0, 0, 0, 0, 0, 0),
    (1, 0, 1, 1, 0, 0, 0),
    (2, 0, 1, 1, 0, 0, 0),
    (3, 0, 1, 1, 0, 1, 1),
    (4, 0, 1, 1, 0, 1, 1),
    (5, 0, 1, 1, 0, 1, 1),
    (6, 0, 0, 1, 0, 0, 1),
    (7, 0, 1, 1, 0, 1, 1),
    (8, 0, 1, 1, 0, 0, 0),
    (9, 0, 1, 1, 0, 0, 0),
    (10, 0, 1, 1, 0, 0, 0),
    (11, 0, 1, 1, 0, 0, 0),
    (12, 0, 1, 1, 0, 0, 0),
    (13, 0, 1, 1, 0, 0, 0),
    (14, 0, 1, 1, 0, 0, 0),
    (15, 0, 1, 1, 0, 1, 1),
    (16, 0, 1, 1, 0, 0, 0),
    (17, 0, 1, 1, 0, 0, 0),
    (18, 0, 1, 1, 0, 0, 0),
    (19, 0, 0, 1, 0, 0, 1),
]

# Color byte -> meaning (OemDrv.exe 0x46cba8..0x46cc17; COLORREF values converted to RGB)
COLORS = {
    "random": 0, "multi": 0,
    "red": 1,
    "green": 2,
    "blue": 3,
    "yellow": 4,
    "magenta": 5, "purple": 5,
    "cyan": 6,
    "white": 7,
}

# Default from Dev.ini LEDParam=...,59: high nibble speed=5, low nibble brightness=9
DEFAULT_SPEED, DEFAULT_BRIGHTNESS = 5, 9
MAX_LEVEL = 9  # Dev.ini "Light=0..9" suggests 10 levels; values above are refused to be safe

# ---------------------------------------------------------------- hidapi binding
_lib = None


class DevInfo(ctypes.Structure):
    pass


DevInfo._fields_ = [
    ("path", ctypes.c_char_p),
    ("vendor_id", ctypes.c_ushort),
    ("product_id", ctypes.c_ushort),
    ("serial_number", ctypes.c_wchar_p),
    ("release_number", ctypes.c_ushort),
    ("manufacturer_string", ctypes.c_wchar_p),
    ("product_string", ctypes.c_wchar_p),
    ("usage_page", ctypes.c_ushort),
    ("usage", ctypes.c_ushort),
    ("interface_number", ctypes.c_int),
    ("next", ctypes.POINTER(DevInfo)),
]


def lib():
    global _lib
    if _lib:
        return _lib
    for c in ("/opt/homebrew/lib/libhidapi.dylib", "/usr/local/lib/libhidapi.dylib",
              ctypes.util.find_library("hidapi")):
        if c and (os.path.exists(c) or not c.startswith("/")):
            try:
                L = ctypes.CDLL(c)
                break
            except OSError:
                pass
    else:
        sys.exit("libhidapi not found. Run:  brew install hidapi")
    L.hid_init.restype = ctypes.c_int
    L.hid_enumerate.argtypes = [ctypes.c_ushort, ctypes.c_ushort]
    L.hid_enumerate.restype = ctypes.POINTER(DevInfo)
    L.hid_free_enumeration.argtypes = [ctypes.POINTER(DevInfo)]
    L.hid_open_path.argtypes = [ctypes.c_char_p]
    L.hid_open_path.restype = ctypes.c_void_p
    L.hid_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    L.hid_write.restype = ctypes.c_int
    L.hid_read_timeout.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    L.hid_read_timeout.restype = ctypes.c_int
    L.hid_close.argtypes = [ctypes.c_void_p]
    L.hid_error.argtypes = [ctypes.c_void_p]
    L.hid_error.restype = ctypes.c_wchar_p
    if L.hid_init() != 0:
        sys.exit("hid_init failed")
    # hid_init() enables exclusive (seize) mode on macOS, which fails for keyboards in use.
    if hasattr(L, "hid_darwin_set_open_exclusive"):
        L.hid_darwin_set_open_exclusive(0)
    _lib = L
    return L


def hexs(b):
    return " ".join(f"{x:02x}" for x in b)


class Keyboard:
    def __init__(self):
        L = lib()
        head = L.hid_enumerate(VID, PID)
        path, self.release, self.product = None, 0, None
        node = head
        while node:
            d = node.contents
            if d.usage_page == VENDOR_USAGE_PAGE:
                path, self.release, self.product = d.path, d.release_number, d.product_string
                break
            node = d.next
        if head:
            L.hid_free_enumeration(head)
        if not path:
            sys.exit("Keyboard not found (VID 3532 PID B0A1, usage page FF00). Plugged in by cable?")
        self.dev = L.hid_open_path(path)
        if not self.dev:
            sys.exit(f"Open failed ({L.hid_error(None)}). Check Input Monitoring for your terminal.")

    def close(self):
        lib().hid_close(self.dev)

    def _read(self, timeout_ms):
        buf = ctypes.create_string_buffer(64)
        n = lib().hid_read_timeout(self.dev, buf, 64, timeout_ms)
        return buf.raw[:n] if n > 0 else b""

    def send(self, payload, verbose=False, timeout_s=1.5):
        """Send one command and wait for the echo. Only whitelisted commands pass."""
        p = bytes(payload)
        allowed = (p[:4] == CMD_GET_PSD or p[:2] == bytes([0xAE, 0x01])
                   or p[:2] == bytes([0xB6, 0x03])   # AskTrigger (read-only)
                   or (p[0] == 0xB6 and p[1] in (0x01, 0x04, 0x05))  # trigger tables
                   or (p[0] == 0xB5 and len(p) == 9 and p[7:9] == b"\x00\x01")  # options
                   or (p[:3] == bytes([0xA0, 0x02, 0x04]) and len(p) == 61
                       and p[4] == 0x0E and p[5] in (1, 2, 3, 5) and p[60] == 0xA5))  # keymap
        if not allowed:
            raise RuntimeError(f"Blocked: command {hexs(p[:4])} is not whitelisted in this tool")
        wire = bytes([REPORT_ID]) + p + bytes(63 - len(p))
        assert len(wire) == 64
        while self._read(0):  # drain
            pass
        if verbose:
            print("SEND:", hexs(wire))
        if lib().hid_write(self.dev, wire, 64) < 0:
            sys.exit(f"write failed: {lib().hid_error(self.dev)}")
        for _ in range(int(timeout_s / 0.05)):
            r = self._read(50)
            if not r:
                continue
            if r[0] != REPORT_ID and r[0] == p[0]:
                r = bytes([REPORT_ID]) + r  # report ID stripped
            if r[0] == REPORT_ID and len(r) > 1 and r[1] == p[0]:
                if verbose:
                    print("RECV:", hexs(r))
                return r
            # else: normal key/media/mouse report, ignore
        return None

    def handshake(self, verbose=False):
        r = self.send(CMD_GET_PSD, verbose)
        if not r:
            sys.exit("No reply to handshake.")
        if r[5:8] != EXPECTED_PSD:
            sys.exit(f"Unexpected model code {hexs(r[5:8])} (expected {hexs(EXPECTED_PSD)}). Stopping.")
        return r


# ---------------------------------------------------------------- commands
def build_led(mode, speed, brightness, color):
    return bytes([0xAE, 0x01, 0x00, 0x00, mode, speed, brightness, color])


def cmd_info(a):
    kb = Keyboard()
    try:
        r = kb.handshake(verbose=a.verbose)
        v = kb.release
        print(f"{kb.product}: model code {hexs(r[5:8])} OK, firmware V{(v>>8)&0xF:X}.{(v>>4)&0xF:X}.{v&0xF:X}")
        print("extra reply bytes:", hexs(r[8:18]))
    finally:
        kb.close()


# Matrix position -> key name (last field of each K line in Dev/kb/M68/US/Dev.ini)
KEY_AT = {
    21: "Esc", 22: "1", 23: "2", 24: "3", 25: "4", 26: "5", 27: "6", 28: "7", 29: "8", 30: "9",
    31: "0", 32: "-", 33: "=", 34: "Bksp", 35: "Del",
    42: "Tab", 43: "Q", 44: "W", 45: "E", 46: "R", 47: "T", 48: "Y", 49: "U", 50: "I", 51: "O",
    52: "P", 53: "[", 54: "]", 55: "\\", 56: "End",  # Dev.ini says 75 for \ ; device reports 55
    63: "Caps", 64: "A", 65: "S", 66: "D", 67: "F", 68: "G", 69: "H", 70: "J", 71: "K", 72: "L",
    73: ";", 74: "'", 76: "Enter", 77: "PgUp",
    84: "LShift", 86: "Z", 87: "X", 88: "C", 89: "V", 90: "B", 91: "N", 92: "M", 93: ",", 94: ".",
    95: "/", 96: "RShift", 97: "Up", 98: "PgDn",
    105: "LCtrl", 106: "LWin", 107: "LAlt", 111: "Space", 114: "RAlt", 115: "Fn", 116: "Fn2",
    117: "Left", 118: "Down", 119: "Right",
}


def _collect_b7(kb, seconds):
    """Collect 04 B7 input reports for `seconds`; returns list of raw 64-byte reports."""
    import time
    out, end = [], time.time() + seconds
    while time.time() < end:
        r = kb._read(50)
        if not r:
            continue
        if r[0] == 0xB7:
            r = bytes([REPORT_ID]) + r
        if r[0] == REPORT_ID and len(r) > 1 and r[1] == 0xB7:
            out.append(r)
    return out


def _frames(reports):
    """Group B7 reports into 126-byte tables: 59 + 59 + 8 bytes starting at wire offset 5."""
    frames, cur = [], b""
    for r in reports:
        cur += r[5:64]
        if len(cur) >= 126:
            frames.append(cur[:126])
            cur = b""
    return frames


def _show_table(t, only=None):
    cells = []
    for pos in sorted(KEY_AT):
        if only is not None and pos not in only:
            continue
        cells.append(f"{KEY_AT[pos]:>6}={t[pos]:3d}")
    for i in range(0, len(cells), 8):
        print("  " + " ".join(cells[i:i + 8]))
    extra = [i for i in range(126) if i not in KEY_AT and t[i]]
    if extra and only is None:
        print("  non-zero at unmapped positions:", ", ".join(f"{i}={t[i]}" for i in extra))


def cmd_trigger_dump(a):
    """Read-only: send AskTrigger (B6 03 01), print the 126-byte table(s), then B6 03 00."""
    kb = Keyboard()
    try:
        kb.handshake(verbose=a.verbose)
        wire = bytes([REPORT_ID, 0xB6, 0x03, 0x01]) + bytes(60)
        while kb._read(0):
            pass
        if a.verbose:
            print("SEND:", hexs(wire))
        lib().hid_write(kb.dev, wire, 64)
        print(f"Listening {a.watch}s" + (" - press and hold a few keys slowly..." if a.watch > 1 else "..."))
        reps = _collect_b7(kb, a.watch)
        # turn it back off (enable = 0), ignore reply
        lib().hid_write(kb.dev, bytes([REPORT_ID, 0xB6, 0x03, 0x00]) + bytes(60), 64)
        _collect_b7(kb, 0.3)
    finally:
        kb.close()

    print(f"\nreceived {len(reps)} B7 report(s)")
    if a.verbose:
        for r in reps[:9]:
            print("  ", hexs(r[:16]), "...")
    fr = _frames(reps)
    if not fr:
        print("No complete 126-byte table received. Paste this output with -v.")
        return
    print(f"assembled {len(fr)} table(s). First table (value at each key's matrix position):")
    _show_table(fr[0])
    if len(fr) > 1:
        changed = {i for f in fr[1:] for i in range(126) if f[i] != fr[0][i]}
        if changed:
            print("\nValues CHANGED during listening (looks like live key travel):")
            for i in sorted(changed):
                vals = [f[i] for f in fr]
                print(f"  {KEY_AT.get(i, f'pos{i}'):>6}: min {min(vals)}  max {max(vals)}")
        else:
            print("\nNo changes across tables (looks like stored settings, not live data).")


def _poll_table(kb, timeout_s=0.15):
    """Request one snapshot (B6 03 01) and return the 126-byte table, or None."""
    import time
    lib().hid_write(kb.dev, bytes([REPORT_ID, 0xB6, 0x03, 0x01]) + bytes(60), 64)
    got, end = b"", time.time() + timeout_s
    while time.time() < end and len(got) < 126:
        r = kb._read(20)
        if not r:
            continue
        if r[0] == 0xB7:
            r = bytes([REPORT_ID]) + r
        if r[0] == REPORT_ID and len(r) > 1 and r[1] == 0xB7:
            got += r[5:64]
    return got[:126] if len(got) >= 126 else None


def cmd_travel(a):
    """Read-only: poll live key travel; track per-key min/max; summarize (calibration check)."""
    import time
    kb = Keyboard()
    lo, hi, n = {}, {}, 0
    try:
        kb.handshake(verbose=a.verbose)
        while kb._read(0):
            pass
        print(f"Polling for {a.seconds:.0f}s. Press every key slowly ALL the way down, one at a time.")
        print("Values look like 0.1 mm (0 = at rest, ~40 = bottomed out). Ctrl+C to stop early.\n")
        end = time.time() + a.seconds
        try:
            while time.time() < end:
                t = _poll_table(kb)
                if t is None:
                    continue
                n += 1
                for pos in KEY_AT:
                    v = t[pos]
                    lo[pos] = min(lo.get(pos, 255), v)
                    hi[pos] = max(hi.get(pos, 0), v)
                live = "  ".join(f"{KEY_AT[p]}:{t[p]/10:.1f}" for p in sorted(KEY_AT) if t[p])
                sys.stdout.write("\r\033[K" + (live or "(no key pressed)")[:150])
                sys.stdout.flush()
                time.sleep(a.interval)
        except KeyboardInterrupt:
            pass
    finally:
        try:
            lib().hid_write(kb.dev, bytes([REPORT_ID, 0xB6, 0x03, 0x00]) + bytes(60), 64)
        except Exception:
            pass
        kb.close()

    print(f"\n\n{n} snapshots ({n / max(a.seconds, 0.1):.0f}/s).")
    if not n:
        print("No data. Paste output with -v.")
        return
    tested = sorted(p for p in KEY_AT if hi.get(p, 0) > 0)
    untested = [KEY_AT[p] for p in sorted(KEY_AT) if hi.get(p, 0) == 0]
    full = max(hi.values())
    print(f"Deepest reading on any key: {full} ({full/10:.1f} mm if units are 0.1 mm)\n")
    print("key      rest  max")
    for p in tested:
        flag = ""
        if hi[p] < full - 3:
            flag = "  <- didn't reach full depth (not pressed fully, or weak sensor/magnet)"
        if lo[p] > 0:
            flag += "  <- never read 0 at rest"
        print(f"{KEY_AT[p]:<7} {lo[p]:4d} {hi[p]:4d}{flag}")
    if untested:
        print(f"\nNot pressed: {', '.join(untested)}")


# HID keyboard usage IDs for the keys we can watch in rt-test
HID_USAGE = {**{chr(ord("A") + i): 0x04 + i for i in range(26)},
             **{str(i): 0x1E + i - 1 for i in range(1, 10)}, "0": 0x27,
             "Enter": 0x28, "Esc": 0x29, "Bksp": 0x2A, "Tab": 0x2B, "Space": 0x2C, "-": 0x2D,
             "=": 0x2E, "[": 0x2F, "]": 0x30, "\\": 0x31, ";": 0x33, "'": 0x34, ",": 0x36,
             ".": 0x37, "/": 0x38, "Caps": 0x39, "Del": 0x4C, "End": 0x4D, "PgUp": 0x4B,
             "PgDn": 0x4E, "Right": 0x4F, "Left": 0x50, "Down": 0x51, "Up": 0x52}


def _key_state(r):
    """Return set of pressed usages from a keyboard report, or None if not a key report."""
    if len(r) >= 64 and r[0] in (1, 2):        # NKRO reports on interface 1 (ID 1/2)
        return {b for b in r[2:64] if b}
    if len(r) == 8 and r[1] == 0:               # boot report on interface 0
        return {b for b in r[2:8] if b}
    return None


def cmd_rt_test(a):
    """Read-only: watch one key's travel and the key presses/releases the keyboard reports."""
    import time
    pos = _parse_keys(a.key)
    if not pos or len(pos) != 1:
        sys.exit("--key takes exactly one key name")
    pos = pos[0]
    name = KEY_AT[pos]
    usage = HID_USAGE.get(name)
    if usage is None:
        sys.exit(f"rt-test can't watch {name}; pick a letter, digit, Space, arrows, etc.")
    L = lib()
    kb = Keyboard()
    # also open the other interface(s) so we see key events whichever report they use
    extra = []
    head = L.hid_enumerate(VID, PID)
    node, paths = head, set()
    while node:
        d = node.contents
        if d.usage_page != VENDOR_USAGE_PAGE:
            paths.add(d.path)
        node = d.next
    if head:
        L.hid_free_enumeration(head)
    for p in paths:
        h = L.hid_open_path(p)
        if h:
            extra.append(h)
    state, _ = _load_state()
    print(f"Watching {name}. Last written by this tool: actuation {state['actuation'][pos]/10:.1f}, "
          f"RT press {state['press'][pos]/10:.1f}, RT release {state['release'][pos]/10:.1f} mm "
          "(0.0 = off)")
    print("Press slowly, bounce partway up and down without fully releasing. Ctrl+C to stop.\n")

    def drain_keys():
        nonlocal down
        for h in [kb.dev] + extra:
            while True:
                buf = ctypes.create_string_buffer(64)
                n = L.hid_read_timeout(h, buf, 64, 0)
                if n <= 0:
                    break
                handle(buf.raw[:n])

    depth, down, events = 0, False, 0
    got = []

    def handle(r):
        nonlocal down, events
        if r and (r[0] == 0xB7 or (r[0] == REPORT_ID and len(r) > 1 and r[1] == 0xB7)):
            if r[0] == 0xB7:
                r = bytes([REPORT_ID]) + r
            got.append(r[5:64])
            return
        ks = _key_state(r)
        if ks is None:
            return
        now = usage in ks
        if now != down:
            down = now
            events += 1
            sys.stdout.write(f"\r\033[K  {'PRESS  ' if now else 'RELEASE'} at {depth/10:.1f} mm\n")

    try:
        kb.handshake()
        end = time.time() + a.seconds
        last = None
        while time.time() < end:
            got.clear()
            L.hid_write(kb.dev, bytes([REPORT_ID, 0xB6, 0x03, 0x01]) + bytes(60), 64)
            t_end = time.time() + 0.15
            while time.time() < t_end and sum(len(g) for g in got) < 126:
                drain_keys()
                time.sleep(0.003)
            data = b"".join(got)
            if len(data) >= 126:
                depth = data[pos]
                if depth != last:
                    bar = "#" * (depth // 2)
                    sys.stdout.write(f"\r\033[K{name} {depth/10:.1f} mm |{bar:<20}| "
                                     f"{'DOWN' if down else 'up'}")
                    sys.stdout.flush()
                    last = depth
            drain_keys()
    except KeyboardInterrupt:
        pass
    finally:
        L.hid_write(kb.dev, bytes([REPORT_ID, 0xB6, 0x03, 0x00]) + bytes(60), 64)
        for h in extra:
            L.hid_close(h)
        kb.close()
    print(f"\n\n{events} press/release events seen.")
    if events == 0:
        print("No key events were visible to the script (macOS may hide them). "
              "Paste this output - I'll switch to reading typed characters instead.")


# ---------------------------------------------------------------- key remapping (A0 02 04)
# protocol.md 8.2: per layer 126 records x 6 bytes = [keyIdx][c0 c1 c2 c3][00] at keyIdx*6,
# all-zero record = not set (transparent in Fn/tap layers). 14 packets of 9 records:
#   A0 02 04 <pkt 1..14> 0E <layerID> <54 bytes> A5   (layer IDs: base 1, fn1 2, fn2 3, tap 5)
LAYER_IDS = {"base": 1, "fn1": 2, "fn2": 3, "tap": 5}

VK_HID = {**{0x41 + i: 0x04 + i for i in range(26)},                      # A-Z
          **{0x31 + i: 0x1E + i for i in range(9)}, 0x30: 0x27,            # 1-9, 0
          **{0x70 + i: 0x3A + i for i in range(12)},                      # F1-F12
          0x0D: 0x28, 0x1B: 0x29, 0x08: 0x2A, 0x09: 0x2B, 0x20: 0x2C, 0xBD: 0x2D, 0xBB: 0x2E,
          0xDB: 0x2F, 0xDD: 0x30, 0xDC: 0x31, 0xBA: 0x33, 0xDE: 0x34, 0xC0: 0x35, 0xBC: 0x36,
          0xBE: 0x37, 0xBF: 0x38, 0x14: 0x39, 0x2C: 0x46, 0x91: 0x47, 0x13: 0x48, 0x2D: 0x49,
          0x24: 0x4A, 0x21: 0x4B, 0x2E: 0x4C, 0x23: 0x4D, 0x22: 0x4E, 0x27: 0x4F, 0x25: 0x50,
          0x28: 0x51, 0x26: 0x52, 0x90: 0x53, 0x5D: 0x65}
HID_NAME = {}
MOD_BITS = {"lctrl": 0x01, "lshift": 0x02, "lalt": 0x04, "lwin": 0x08,
            "rctrl": 0x10, "rshift": 0x20, "ralt": 0x40, "rwin": 0x80}
VK_MOD = {0xA2: 0x01, 0x11: 0x01, 0xA0: 0x02, 0x10: 0x02, 0xA4: 0x04, 0x12: 0x04, 0x5B: 0x08,
          0xA3: 0x10, 0xA1: 0x20, 0xA5: 0x40, 0x5C: 0x80}

# names usable in --to (case-insensitive)
TARGET_HID = {**{chr(ord("a") + i): 0x04 + i for i in range(26)},
              **{str(i): 0x1E + i - 1 for i in range(1, 10)}, "0": 0x27,
              **{f"f{i}": 0x39 + i for i in range(1, 13)},
              "enter": 0x28, "esc": 0x29, "bksp": 0x2A, "backspace": 0x2A, "tab": 0x2B,
              "space": 0x2C, "-": 0x2D, "minus": 0x2D, "=": 0x2E, "equal": 0x2E, "[": 0x2F,
              "]": 0x30, "\\": 0x31, "backslash": 0x31, ";": 0x33, "'": 0x34, "`": 0x35,
              "grave": 0x35, ",": 0x36, ".": 0x37, "/": 0x38, "caps": 0x39, "capslock": 0x39,
              "printscreen": 0x46, "prtsc": 0x46, "scrolllock": 0x47, "pause": 0x48,
              "insert": 0x49, "ins": 0x49, "home": 0x4A, "pgup": 0x4B, "del": 0x4C,
              "delete": 0x4C, "end": 0x4D, "pgdn": 0x4E, "right": 0x4F, "left": 0x50,
              "down": 0x51, "up": 0x52, "numlock": 0x53, "menu": 0x65, "app": 0x65,
              # numpad (the official app offers these too)
              "kp/": 0x54, "kp*": 0x55, "kp-": 0x56, "kp+": 0x57, "kpenter": 0x58,
              "kpplus": 0x57, "kpminus": 0x56, "kpslash": 0x54, "kpstar": 0x55, "kpdot": 0x63,
              **{f"kp{i}": 0x58 + i for i in range(1, 10)}, "kp0": 0x62, "kp.": 0x63,
              # F13-F24: not offered by the official app (untested), handy as macOS shortcut keys
              **{f"f{i}": 0x68 + i - 13 for i in range(13, 25)}}
MOD_ALIASES = {"ctrl": "lctrl", "shift": "lshift", "alt": "lalt", "opt": "lalt", "option": "lalt",
               "win": "lwin", "cmd": "lwin", "gui": "lwin", "rcmd": "rwin", "ropt": "ralt"}
MEDIA = {"player": 0xA0, "play": 0x93, "playpause": 0x93, "stop": 0x94, "prev": 0x95,
         "next": 0x96, "volup": 0x90, "voldown": 0x91, "mute": 0x92, "calc": 0xA4}
MOUSE = {"mouse-left": 0xB0, "mouse-right": 0xB1, "mouse-middle": 0xB2, "mouse-forward": 0xB3,
         "mouse-back": 0xB4, "wheel-up": 0xB5, "wheel-down": 0xB6, "wheel-left": 0xB7,
         "wheel-right": 0xB8}
SPECIAL = {"led-mode-cycle": 0x00, "led-bright+": 0x04, "led-bright-": 0x05, "led-speed+": 0x07,
           "led-speed-": 0x08, "led-color-cycle": 0x09, "led-pause": 0x0D, "led-switch": 0x0E,
           "winlock": 0x10}
for _n, _u in TARGET_HID.items():
    HID_NAME.setdefault(_u, _n)


def _rec_key(vk, mods=0):
    """Encode a Dev.ini type-2 entry (Windows VK) the way OemDrv's 0x46bc20 does."""
    if vk == 0xFA:
        return (0xFF, 0, 0, 0)
    if vk == 0xFB:
        return (0xFE, 0, 0, 0)
    if vk in VK_MOD:
        bit = VK_MOD[vk] | mods
        return (0xFC, bit, 0xE3 if vk == 0x5B else 0x00, 0x00)
    return (0xFC, mods, VK_HID[vk], 0x00)


# Dev/kb/M68/US/Dev.ini defaults, keyed by device position (\ at 55, not the ini's 75)
BASE_VK = {21: 0x1B, 22: 0x31, 23: 0x32, 24: 0x33, 25: 0x34, 26: 0x35, 27: 0x36, 28: 0x37,
           29: 0x38, 30: 0x39, 31: 0x30, 32: 0xBD, 33: 0xBB, 34: 0x08, 35: 0x2E, 42: 0x09,
           43: 0x51, 44: 0x57, 45: 0x45, 46: 0x52, 47: 0x54, 48: 0x59, 49: 0x55, 50: 0x49,
           51: 0x4F, 52: 0x50, 53: 0xDB, 54: 0xDD, 55: 0xDC, 56: 0x23, 63: 0x14, 64: 0x41,
           65: 0x53, 66: 0x44, 67: 0x46, 68: 0x47, 69: 0x48, 70: 0x4A, 71: 0x4B, 72: 0x4C,
           73: 0xBA, 74: 0xDE, 76: 0x0D, 77: 0x21, 84: 0xA0, 86: 0x5A, 87: 0x58, 88: 0x43,
           89: 0x56, 90: 0x42, 91: 0x4E, 92: 0x4D, 93: 0xBC, 94: 0xBE, 95: 0xBF, 96: 0xA1,
           97: 0x26, 98: 0x22, 105: 0xA2, 106: 0x5B, 107: 0xA4, 111: 0x20, 114: 0xA5, 115: 0xFA,
           116: 0xFB, 117: 0x25, 118: 0x28, 119: 0x27}


def _default_layers():
    base = [None] * 126
    for p, vk in BASE_VK.items():
        base[p] = _rec_key(vk)
    fn1 = [None] * 126
    for p, vk in {21: 0xC0, 35: 0x2D, 56: 0x24, 77: 0x2C, 98: 0x13, 115: 0xFA, 42: 0x09,
                  63: 0x14, 76: 0x0D, 84: 0xA0, 96: 0xA5, 105: 0xA2, 107: 0xA4,
                  114: 0xA3}.items():
        fn1[p] = _rec_key(vk)
    for i in range(12):
        fn1[22 + i] = _rec_key(0x70 + i)
    fn1[106] = (0xFB, 0x10, 0, 0)                       # Fn1+LWin = Win lock
    fn2 = [None] * 126
    for p, m in {86: 0x93, 87: 0x94, 88: 0x95, 89: 0x96, 90: 0x92, 91: 0x91, 92: 0x90}.items():
        fn2[p] = (m, 0, 0, 0)
    fn2[53] = (0xFB, 0x00, 0, 0)                        # Fn2+[ = LED mode cycle
    fn2[54] = (0xFB, 0x0E, 0, 0)                        # Fn2+] = LED switch
    for p, vk in {116: 0xFB, 117: 0x25, 119: 0x27, 97: 0x26, 118: 0x28}.items():
        fn2[p] = _rec_key(vk)
    return {"base": base, "fn1": fn1, "fn2": fn2, "tap": [None] * 126}


def _parse_target(spec):
    s = spec.strip().lower()
    if s in ("none", "clear", "transparent"):
        return None
    if s in ("disable", "off"):
        return (0xBF, 0, 0, 0)
    if s == "fn":
        return (0xFF, 0, 0, 0)
    if s == "fn2":
        return (0xFE, 0, 0, 0)
    if s in MEDIA:
        return (MEDIA[s], 0, 0, 0)
    if s in MOUSE:
        return (MOUSE[s], 0, 0, 0)
    if s in SPECIAL:
        return (0xFB, SPECIAL[s], 0, 0)
    if s in TARGET_HID:                     # whole name first, so "kp+" isn't split
        return (0xFC, 0, TARGET_HID[s], 0x00)
    # split combos on "+", re-attaching a "+" that belongs to a key name (kp+, ctrl+kp+)
    parts = []
    for tok in s.split("+"):
        if tok == "" and parts:
            parts[-1] += "+"
        else:
            parts.append(tok)
    mods, keys = 0, []
    for part in parts:
        part = MOD_ALIASES.get(part, part)
        if part in MOD_BITS:
            mods |= MOD_BITS[part]
        elif part in TARGET_HID:
            keys.append(TARGET_HID[part])
        else:
            sys.exit(f"Unknown target '{part}'. Use key names (a, f5, esc, left...), modifiers "
                     f"(ctrl, shift, alt, cmd, rctrl...), combos like ctrl+c, media "
                     f"({', '.join(MEDIA)}), mouse ({', '.join(MOUSE)}), "
                     f"lighting/special ({', '.join(SPECIAL)}), fn, fn2, disable, none")
    if len(keys) > 2:
        sys.exit("At most two non-modifier keys in one combo")
    if not keys:
        if not mods:
            sys.exit("Empty target")
        # modifier-only key, same shape as OemDrv's own encoding
        return (0xFC, mods, 0xE3 if mods == 0x08 else 0x00, 0x00)
    keys += [0] * (2 - len(keys))
    return (0xFC, mods, keys[0], keys[1])


def _describe(rec):
    if rec is None:
        return "-"
    c0, c1, c2, c3 = rec
    if c0 == 0xFF:
        return "Fn"
    if c0 == 0xFE:
        return "Fn2"
    if c0 == 0xBF:
        return "disabled"
    if c0 == 0xFB:
        return next((k for k, v in SPECIAL.items() if v == c1), f"special {c1:#x}")
    if c0 == 0xFC:
        names = [k for k, b in MOD_BITS.items() if c1 & b]
        names += [HID_NAME.get(u, f"0x{u:02x}") for u in (c2, c3) if u and u != 0xE3]
        return "+".join(names) or "none"
    for d in (MEDIA, MOUSE):
        n = next((k for k, v in d.items() if v == c0), None)
        if n:
            return n
    return " ".join(f"{x:02x}" for x in rec)


def _load_layers():
    s = _read_state_file()
    if "layers" in s:
        return {k: [tuple(r) if r else None for r in v] for k, v in s["layers"].items()}, True
    return _default_layers(), False


def _layer_packets(layer, recs):
    block = bytearray(756)
    for idx, r in enumerate(recs):
        if r:
            block[idx * 6:idx * 6 + 6] = bytes([idx, *r, 0])
    for pkt in range(1, 15):
        chunk = bytes(block[(pkt - 1) * 54:pkt * 54])
        yield bytes([0xA0, 0x02, 0x04, pkt, 0x0E, LAYER_IDS[layer]]) + chunk + bytes([0xA5])


def _send_layer(layer, recs, dry_run=False, verbose=False):
    pk = list(_layer_packets(layer, recs))
    if dry_run:
        nz = [i for i, r in enumerate(recs) if r]
        print(f"would send layer {layer} (ID {LAYER_IDS[layer]}): 14 packets, "
              f"{len(nz)} keys set")
        for p in pk[:2]:
            print("  ", hexs(bytes([REPORT_ID]) + p)[:110], "...")
        return True
    import time
    kb = Keyboard()
    try:
        kb.handshake(verbose=verbose)
        time.sleep(0.03)
        for p in pk:
            if not kb.send(p, verbose=verbose):
                print(f"No acknowledgement for packet {p[3]} - stopping. Fn2+Esc restores defaults.")
                return False
    finally:
        kb.close()
    return True


def cmd_map_show(a):
    layers, known = _load_layers()
    if not known:
        print("(nothing written by this tool yet - showing the factory keymap from Dev.ini)")
    names = [a.layer] if a.layer else list(LAYER_IDS)
    for L in names:
        recs = layers[L]
        print(f"\n[{L}]" + ("  (unset keys fall through to base)" if L != "base" else ""))
        rows = [(KEY_AT.get(p, f"pos{p}"), _describe(r)) for p, r in enumerate(recs)
                if r and (L != "base" or a.all or r != _default_layers()["base"][p])]
        if L == "base" and not a.all:
            print("  (only keys that differ from factory; --all to list every key)")
        for k, d in rows:
            print(f"  {k:<7} -> {d}")
        if not rows:
            print("  (none)")


def cmd_map_set(a):
    layers, known = _load_layers()
    keys = _parse_keys(a.key)
    if not keys:
        sys.exit("--key needs one or more key names")
    if a.layer == "base" and not a.yes:
        sys.exit("Changing the base layer can make keys stop working until Fn2+Esc. "
                 "Try it on fn2 first; add --yes to proceed.")
    specs = _split_list(a.to)
    if len(specs) == 1:
        specs *= len(keys)                         # one target for every listed key
    elif len(specs) != len(keys):
        sys.exit(f"{len(keys)} keys but {len(specs)} targets: give one target for all, "
                 "or exactly one per key (paired in order)")
    factory = _default_layers()[a.layer]
    # "default" = this key's factory setting on this layer (for fn/tap: usually unset)
    targets = [factory[p] if s.strip().lower() in ("default", "factory") else _parse_target(s)
               for p, s in zip(keys, specs)]
    for p, rec in zip(keys, targets):
        if a.layer == "base" and p in (115, 116):
            sys.exit("Refusing to remap Fn/Fn2 on the base layer (you'd lose the Fn2+Esc reset).")
    for p, rec in zip(keys, targets):
        layers[a.layer][p] = rec
        print(f"{a.layer}: {KEY_AT[p]} -> {_describe(rec)}")
    if _send_layer(a.layer, layers[a.layer], a.dry_run, a.verbose) and not a.dry_run:
        _save_state({"layers": {k: [list(r) if r else None for r in v] for k, v in layers.items()}})
        print("OK - written and saved.")


def cmd_map_reset(a):
    layers, _ = _load_layers()
    d = _default_layers()
    names = list(LAYER_IDS) if a.layer == "all" else [a.layer]
    for L in names:
        layers[L] = d[L]
        print(f"restoring factory {L} layer")
        if not _send_layer(L, layers[L], a.dry_run, a.verbose):
            return
    if not a.dry_run:
        _save_state({"layers": {k: [list(r) if r else None for r in v] for k, v in layers.items()}})
        print("OK")


def cmd_modes(a):
    print("mode  speed  brightness  color")
    for o in LED_OPTS:
        hw, _, spd, light, _, rnd, col = o
        note = " (likely off)" if hw == 0 else ""
        print(f"{hw:>4}  {'yes' if spd else ' - ':>5}  {'yes' if light else ' - ':>10}  "
              f"{'yes' if col else ' - '}{note}")
    print("\ncolors:", ", ".join(k for k in COLORS if k not in ("multi", "purple")))
    print("Mode names aren't in the profile; try them and note what each looks like.")


def cmd_led(a):
    if a.mode not in range(len(LED_OPTS)):
        sys.exit(f"--mode must be 0..{len(LED_OPTS)-1}")
    for name, v in (("speed", a.speed), ("brightness", a.brightness)):
        if not 0 <= v <= MAX_LEVEL:
            sys.exit(f"--{name} must be 0..{MAX_LEVEL}")
    color = COLORS.get(a.color.lower())
    if color is None:
        sys.exit(f"--color must be one of: {', '.join(COLORS)}")
    _, _, has_spd, _, _, _, has_col = LED_OPTS[a.mode]
    if a.color.lower() not in ("random", "multi") and not has_col:
        print(f"note: mode {a.mode} doesn't use a color in the Windows app; sending anyway")
    if a.speed != DEFAULT_SPEED and not has_spd:
        print(f"note: mode {a.mode} has no speed setting in the Windows app")

    payload = build_led(a.mode, a.speed, a.brightness, color)
    if a.dry_run:
        print("would send:", hexs(bytes([REPORT_ID]) + payload), "+ zero padding to 64 bytes")
        return
    kb = Keyboard()
    try:
        kb.handshake(verbose=a.verbose)
        r = kb.send(payload, verbose=a.verbose)
        print("OK - keyboard acknowledged." if r else "No acknowledgement (setting may not have applied).")
    finally:
        kb.close()


# ---------------------------------------------------------------- trigger settings
# protocol.md section 7: three 126-byte per-key tables, 1 byte per matrix position, 0.1 mm units.
#   B6 01 actuation point   2..38 (0.2-3.8 mm), factory 20 (2.0 mm)
#   B6 04 rapid-trigger press sensitivity    0..36, 0 = RT off
#   B6 05 rapid-trigger release sensitivity  0..36, 0 = RT off
# Sent as 3 packets: 04 B6 <sub> 00 <pkt> + 59/59/8 data bytes. The keyboard cannot report these
# settings back, so the last values written are kept in ranked_state.json next to this script.
TABLES = {"actuation": 0x01, "press": 0x04, "release": 0x05}
FACTORY = {"actuation": 20, "press": 0, "release": 0}
LIMITS = {"actuation": (2, 38), "press": (0, 36), "release": (0, 36)}
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ranked_state.json")

ALIASES = {"backslash": "\\", "minus": "-", "equal": "=", "equals": "=", "lbracket": "[",
           "rbracket": "]", "semicolon": ";", "quote": "'", "comma": ",", "period": ".",
           "dot": ".", "slash": "/", "backspace": "Bksp", "delete": "Del", "capslock": "Caps",
           "pageup": "PgUp", "pagedown": "PgDn", "win": "LWin", "cmd": "LWin"}


def _load_state():
    import json
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
        return {k: list(s[k]) for k in TABLES}, True
    except (OSError, ValueError, KeyError):
        return {k: [FACTORY[k]] * 126 for k in TABLES}, False


def _read_state_file():
    import json
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    """Merge `state` (any top-level keys) into the state file, keeping other sections."""
    import json
    s = _read_state_file()
    s.update(state)
    with open(STATE_FILE, "w") as f:
        json.dump(s, f, indent=1)


# ---------------------------------------------------------------- keyboard options (B5)
# protocol.md 8.1: B5 <tapOn> <tapTime/10ms> <debounceCnt> <debounceTime> <magicFN> <capsLED> 00 01
# All six are sent every time. Defaults below are exactly what the official app sends for this
# model (tap/debounce/MagicFN pages are hidden for the Master 65%, so it always sends these).
OPT_DEFAULTS = {"tap": 1, "tap_time": 30, "debounce": 2, "debounce_time": 2, "magic_fn": 0,
                "caps_led": 0}


def _options_payload(o):
    return bytes([0xB5, o["tap"], o["tap_time"], o["debounce"], o["debounce_time"],
                  o["magic_fn"], o["caps_led"], 0x00, 0x01])


def cmd_options(a):
    s = _read_state_file()
    o = dict(OPT_DEFAULTS, **s.get("options", {}))
    known = "options" in s
    onoff = {"on": 1, "off": 0}
    changed = False
    if a.caps_led is not None:
        o["caps_led"] = onoff[a.caps_led]; changed = True
    if a.tap is not None:
        o["tap"] = onoff[a.tap]; changed = True
    if a.tap_time is not None:
        if not 0 <= a.tap_time <= 1000 or a.tap_time % 10:
            sys.exit("--tap-time must be 0..1000 ms in steps of 10")
        o["tap_time"] = a.tap_time // 10; changed = True
    if a.debounce is not None:
        if not 0 <= a.debounce <= 5:
            sys.exit("--debounce must be 0..5")
        o["debounce"] = a.debounce; changed = True
    if a.magic_fn is not None:
        o["magic_fn"] = a.magic_fn; changed = True
    if a.app_defaults:
        o = dict(OPT_DEFAULTS); changed = True

    def show():
        print(f"  Caps Lock LED : {'on' if o['caps_led'] else 'off'}")
        print(f"  tap           : {'on' if o['tap'] else 'off'}, {o['tap_time']*10} ms  (hidden for this model)")
        print(f"  debounce      : {o['debounce']}  (hidden for this model; likely mechanical boards only)")
        print(f"  Magic Fn mode : {o['magic_fn']}  (hidden for this model)")
    if not changed:
        print("Options last written by this tool:" if known else
              "(nothing written by this tool yet - showing the official app's defaults)")
        show()
        return
    for k, label in (("tap", "tap"), ("tap_time", "tap time"), ("debounce", "debounce"),
                     ("magic_fn", "Magic Fn")):
        if o[k] != OPT_DEFAULTS[k]:
            print(f"note: {label} differs from what the official app sends for this model; "
                  "its effect on this keyboard is unknown (Fn2+Esc undoes it)")
    payload = _options_payload(o)
    print("Sending:")
    show()
    if a.dry_run:
        print("would send:", hexs(bytes([REPORT_ID]) + payload), "+ zero padding")
        return
    kb = Keyboard()
    try:
        kb.handshake(verbose=a.verbose)
        r = kb.send(payload, verbose=a.verbose)
    finally:
        kb.close()
    if r:
        _save_state({"options": o})
        print("OK - keyboard acknowledged.")
    else:
        print("No acknowledgement; nothing saved.")


def _split_list(spec):
    """Split on "," but keep the comma key itself: "," / "a,,,b" / ",,a" / "a,," """
    toks, names, i = spec.split(","), [], 0
    while i < len(toks):
        if toks[i] == "":
            names.append(",")
            i += 2 if i + 1 < len(toks) and toks[i + 1] == "" else 1
        else:
            names.append(toks[i])
            i += 1
    return names


def _parse_keys(spec):
    if not spec or spec.lower() == "all":
        return None  # all positions
    by_name = {v.lower(): p for p, v in KEY_AT.items()}
    out = []
    for raw in _split_list(spec):
        n = raw.strip()
        n = ALIASES.get(n.lower(), n).lower()
        if n not in by_name:
            sys.exit(f"Unknown key '{raw}'. Names: {', '.join(KEY_AT.values())} "
                     f"(aliases: {', '.join(ALIASES)})")
        out.append(by_name[n])
    return out


def _mm(name, v):
    b = int(round(v * 10))
    lo, hi = LIMITS[name]
    if not lo <= b <= hi:
        sys.exit(f"--{name} {v} mm is outside {lo/10:.1f}..{hi/10:.1f} mm")
    if name == "actuation" and b > 36:
        print(f"warning: actuation {v} mm is near the bottom; travel readings saturate around there")
    if name in ("press", "release") and b == 1:
        print(f"warning: {name} sensitivity 0.1 mm equals the sensor noise; expect phantom retriggers")
    return b


def _packets(sub, table):
    data = bytes(table)
    assert len(data) == 126 and all(0 <= x <= 38 for x in data)
    for pkt, off in enumerate((0, 59, 118)):
        chunk = data[off:off + 59]
        yield bytes([0xB6, sub, 0x00, pkt]) + chunk


def _write_tables(state, names, dry_run=False, verbose=False):
    if dry_run:
        for name in names:
            for p in _packets(TABLES[name], state[name]):
                print(f"would send ({name}):", hexs(bytes([REPORT_ID]) + p)[:120], "...")
        return True
    import time
    kb = Keyboard()
    try:
        kb.handshake(verbose=verbose)
        for name in names:
            time.sleep(0.035)
            for p in _packets(TABLES[name], state[name]):
                time.sleep(0.02)
                if not kb.send(p, verbose=verbose):
                    print(f"No acknowledgement for {name} packet {p[3]} - stopping. "
                          "Previous settings may be partly applied; re-run or use Fn2+Esc.")
                    return False
            print(f"  {name}: written")
    finally:
        kb.close()
    return True


def _summary(state):
    def fmt(name, b):
        if name != "actuation" and b == 0:
            return "off"
        return f"{b/10:.1f}"
    print("key      actuation  RT press  RT release   (mm)")
    for p in sorted(KEY_AT):
        print(f"{KEY_AT[p]:<8} {fmt('actuation', state['actuation'][p]):>9} "
              f"{fmt('press', state['press'][p]):>9} {fmt('release', state['release'][p]):>11}")


def cmd_trigger_show(a):
    state, known = _load_state()
    if not known:
        print("(nothing written by this tool yet - showing factory defaults; "
              "the keyboard's real settings may differ)")
    _summary(state)


def cmd_trigger_set(a):
    if a.actuation is None and a.press is None and a.release is None and a.rt is None:
        sys.exit("Give at least one of --actuation, --press, --release, --rt (all in mm)")
    state, known = _load_state()
    keys = _parse_keys(a.keys)
    if keys is not None and not known:
        print("note: first write - the other keys will be sent as factory defaults "
              "(actuation 2.0 mm, rapid trigger off)")
    if a.rt is not None:
        a.press = a.press if a.press is not None else a.rt
        a.release = a.release if a.release is not None else a.rt
    changed = []
    for name in TABLES:
        v = getattr(a, name)
        if v is None:
            continue
        b = _mm(name, v)
        for p in (keys if keys is not None else range(126)):
            state[name][p] = b
        changed.append(name)
    # tables never written before still have to be consistent; send them all on first write
    names = list(TABLES) if not known else changed
    if _write_tables(state, names, a.dry_run, a.verbose) and not a.dry_run:
        _save_state(state)
        print("Saved. Check with:  python ranked.py travel   /   python ranked.py trigger show")


def cmd_trigger_reset(a):
    state = {k: [FACTORY[k]] * 126 for k in TABLES}
    print("Writing factory values: actuation 2.0 mm, rapid trigger off, all keys")
    if _write_tables(state, list(TABLES), a.dry_run, a.verbose) and not a.dry_run:
        _save_state(state)


def cmd_trigger_auto(a):
    """Measure per-key rest noise, then set RT sensitivity >= noise + margin on each key."""
    import time
    base_press, base_release = _mm("press", a.rt), _mm("release", a.rt)
    act = _mm("actuation", a.actuation) if a.actuation is not None else None
    kb = Keyboard()
    noise = {p: 0 for p in KEY_AT}
    n = 0
    try:
        kb.handshake(verbose=a.verbose)
        while kb._read(0):
            pass
        print("Let go of all keys...", end="", flush=True)
        # wait until every key has been back at rest (<= 0.2 mm) for 1 s, e.g. the Enter
        # used to launch this command; give up after 15 s
        quiet_since, give_up = None, time.time() + 15
        while True:
            t = _poll_table(kb)
            if t is not None:
                if max(t[p] for p in KEY_AT) <= 2:
                    quiet_since = quiet_since or time.time()
                    if time.time() - quiet_since >= 1.0:
                        break
                else:
                    quiet_since = None
            if time.time() > give_up:
                sys.exit("\nA key never came back to rest within 15 s. Nothing was written.")
            time.sleep(0.02)
        print(f" ok.\nMeasuring sensor noise for {a.seconds:.0f}s - DON'T touch the keyboard...")
        end = time.time() + a.seconds
        while time.time() < end:
            t = _poll_table(kb)
            if t is None:
                continue
            n += 1
            for p in KEY_AT:
                noise[p] = max(noise[p], t[p])
            time.sleep(0.02)
        lib().hid_write(kb.dev, bytes([REPORT_ID, 0xB6, 0x03, 0x00]) + bytes(60), 64)
    finally:
        kb.close()
    if n < 10:
        sys.exit("Too few readings; aborting without changes.")
    touched = [KEY_AT[p] for p in KEY_AT if noise[p] > 5]
    if touched:
        sys.exit(f"Keys looked pressed during the measurement ({', '.join(touched)}); "
                 "re-run without touching the keyboard. Nothing was written.")

    state, known = _load_state()
    print(f"\n{n} snapshots. key: noise -> RT press/release (mm)")
    for p in sorted(KEY_AT):
        floor = noise[p] + a.margin if noise[p] else 0
        prs = max(base_press, floor) if base_press else 0
        rel = max(base_release, floor) if base_release else 0
        state["press"][p], state["release"][p] = min(prs, 36), min(rel, 36)
        if act is not None:
            state["actuation"][p] = max(act, noise[p] + 2)
        if noise[p] or a.verbose:
            print(f"  {KEY_AT[p]:<7} noise {noise[p]/10:.1f} -> {state['press'][p]/10:.1f}/"
                  f"{state['release'][p]/10:.1f}")
    if not any(noise.values()):
        print("  no noise on any key")
    if a.dry_run:
        _write_tables(state, list(TABLES), dry_run=True)
        return
    if _write_tables(state, list(TABLES), False, a.verbose):
        _save_state(state)
        print("Saved.")


def main():
    ap = argparse.ArgumentParser(description="Ranked Master 65% configurator (macOS)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print raw bytes")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    sub.add_parser("modes").set_defaults(fn=cmd_modes)
    t = sub.add_parser("trigger-dump", help="read-only: dump the per-key trigger table (B6 03)")
    t.add_argument("--watch", type=float, default=1.0, help="seconds to listen (try 10 and press keys)")
    t.set_defaults(fn=cmd_trigger_dump)
    tr = sub.add_parser("travel", help="read-only: live key travel + per-key range check")
    tr.add_argument("--seconds", type=float, default=60)
    tr.add_argument("--interval", type=float, default=0.02, help="pause between polls")
    tr.set_defaults(fn=cmd_travel)
    rt = sub.add_parser("rt-test", help="read-only: show where one key presses/releases")
    rt.add_argument("--key", required=True)
    rt.add_argument("--seconds", type=float, default=60)
    rt.set_defaults(fn=cmd_rt_test)

    mp = sub.add_parser("map", help="key remapping per layer (base, fn1, fn2, tap)")
    ms = mp.add_subparsers(dest="mcmd", required=True)
    m1 = ms.add_parser("show")
    m1.add_argument("--layer", choices=list(LAYER_IDS))
    m1.add_argument("--all", action="store_true", help="list every base-layer key")
    m1.set_defaults(fn=cmd_map_show)
    m2 = ms.add_parser("set", help="e.g. --layer tap --key RShift --to up")
    m2.add_argument("--layer", required=True, choices=list(LAYER_IDS))
    m2.add_argument("--key", required=True, help="key(s) to change, comma list")
    m2.add_argument("--to", required=True, help="key, combo (ctrl+c), media, mouse, special, "
                                                "fn, fn2, disable, none (unset), default (factory)")
    m2.add_argument("--yes", action="store_true", help="required for the base layer")
    m2.add_argument("--dry-run", action="store_true")
    m2.set_defaults(fn=cmd_map_set)
    m3 = ms.add_parser("reset", help="send the factory keymap for a layer")
    m3.add_argument("--layer", required=True, choices=list(LAYER_IDS) + ["all"])
    m3.add_argument("--dry-run", action="store_true")
    m3.set_defaults(fn=cmd_map_reset)

    op = sub.add_parser("options", help="Caps Lock LED, tap, debounce, Magic Fn (no args = show)")
    op.add_argument("--caps-led", choices=["on", "off"])
    op.add_argument("--tap", choices=["on", "off"], help="advanced; hidden for this model")
    op.add_argument("--tap-time", type=int, help="ms, 0-1000 step 10; advanced")
    op.add_argument("--debounce", type=int, help="0-5; advanced, likely mechanical only")
    op.add_argument("--magic-fn", type=int, choices=[0, 1, 2], help="advanced")
    op.add_argument("--app-defaults", action="store_true", help="send the official app's values")
    op.add_argument("--dry-run", action="store_true")
    op.set_defaults(fn=cmd_options)

    tg = sub.add_parser("trigger", help="actuation / rapid-trigger settings")
    ts = tg.add_subparsers(dest="tcmd", required=True)
    ts.add_parser("show").set_defaults(fn=cmd_trigger_show)
    s = ts.add_parser("set", help="values in mm; --keys W,A,S,D (default all)")
    s.add_argument("--actuation", type=float, help="0.2-3.8 mm (factory 2.0)")
    s.add_argument("--press", type=float, help="RT press sensitivity 0-3.6 mm, 0=off")
    s.add_argument("--release", type=float, help="RT release sensitivity 0-3.6 mm, 0=off")
    s.add_argument("--rt", type=float, help="shortcut: same press+release sensitivity")
    s.add_argument("--keys", help="comma list, e.g. W,A,S,D,Space (default: all)")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_trigger_set)
    r = ts.add_parser("reset", help="write factory values (2.0 mm, RT off)")
    r.add_argument("--dry-run", action="store_true")
    r.set_defaults(fn=cmd_trigger_reset)
    au = ts.add_parser("auto", help="measure noise, set RT sensitivity safely per key")
    au.add_argument("--rt", type=float, required=True, help="desired RT sensitivity, mm")
    au.add_argument("--actuation", type=float, help="optional actuation for all keys, mm")
    au.add_argument("--seconds", type=float, default=30)
    au.add_argument("--margin", type=int, default=2, help="tenths of mm above noise (default 2)")
    au.add_argument("--dry-run", action="store_true")
    au.set_defaults(fn=cmd_trigger_auto)
    p = sub.add_parser("led", help="set lighting mode")
    p.add_argument("--mode", type=int, required=True)
    p.add_argument("--speed", type=int, default=DEFAULT_SPEED)
    p.add_argument("--brightness", type=int, default=DEFAULT_BRIGHTNESS)
    p.add_argument("--color", default="random")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_led)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
