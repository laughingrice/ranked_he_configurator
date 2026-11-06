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
                   or (p[0] == 0xB6 and p[1] in (0x01, 0x04, 0x05)))  # trigger tables
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


def _save_state(state):
    import json
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def _parse_keys(spec):
    if not spec or spec.lower() == "all":
        return None  # all positions
    by_name = {v.lower(): p for p, v in KEY_AT.items()}
    out = []
    for raw in spec.split(","):
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
        print(f"Measuring sensor noise for {a.seconds:.0f}s - DON'T touch the keyboard...")
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
