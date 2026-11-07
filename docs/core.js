/* ranked_he_configurator - protocol core (port of ranked.py). No DOM, no I/O.
 * Every function returns payloads (63-byte max, without the 0x04 report ID).
 * Works in the browser (window.RankedCore) and in node (module.exports) for tests. */
(function (root) {
  "use strict";
  const err = (m) => { throw new Error(m); };

  // ------------------------------------------------------------- device
  const VID = 0x3532, PID = 0xB0A1, USAGE_PAGE = 0xFF00, REPORT_ID = 0x04;
  const EXPECTED_PSD = [0x0C, 0x01, 0x01];
  const GET_PSD = [0xA0, 0x02, 0x00, 0x01];

  // ------------------------------------------------------------- keys
  // [name, position, x1, y1, x2, y2] - positions are what the keyboard uses (\ = 55);
  // rectangles from the official profile's on-screen layout (627 x 215 units)
  const KEYS = [
    ["Esc",21,9,9,45,46],["1",22,48,9,84,46],["2",23,86,9,122,46],["3",24,124,9,160,46],
    ["4",25,162,9,198,46],["5",26,200,9,236,46],["6",27,238,9,274,46],["7",28,277,9,313,46],
    ["8",29,315,9,351,46],["9",30,353,9,389,46],["0",31,391,9,427,46],["-",32,429,9,465,46],
    ["=",33,468,9,504,46],["Bksp",34,506,9,580,46],["Del",35,582,9,618,46],
    ["Tab",42,9,49,64,86],["Q",43,67,49,103,86],["W",44,105,49,141,86],["E",45,143,49,179,86],
    ["R",46,181,49,217,86],["T",47,220,49,256,86],["Y",48,258,49,294,86],["U",49,296,49,332,86],
    ["I",50,334,49,370,86],["O",51,372,49,408,86],["P",52,410,49,446,86],["[",53,449,49,485,86],
    ["]",54,487,49,523,86],["\\",55,525,49,580,86],["End",56,582,49,618,86],
    ["Caps",63,9,89,73,126],["A",64,76,89,112,126],["S",65,114,89,150,126],["D",66,152,89,188,126],
    ["F",67,190,89,226,126],["G",68,229,89,265,126],["H",69,267,89,303,126],["J",70,305,89,341,126],
    ["K",71,343,89,379,126],["L",72,381,89,417,126],[";",73,420,89,456,126],["'",74,458,89,494,126],
    ["Enter",76,496,89,580,126],["PgUp",77,582,89,618,126],
    ["LShift",84,9,129,92,166],["Z",86,95,129,131,166],["X",87,133,129,169,166],["C",88,171,129,207,166],
    ["V",89,210,129,246,166],["B",90,248,129,284,166],["N",91,286,129,322,166],["M",92,324,129,360,166],
    [",",93,362,129,398,166],[".",94,401,129,437,166],["/",95,439,129,475,166],
    ["RShift",96,477,129,541,166],["Up",97,543,129,579,166],["PgDn",98,582,129,618,166],
    ["LCtrl",105,9,169,54,206],["LWin",106,57,169,102,206],["LAlt",107,104,169,149,206],
    ["Space",111,152,169,389,206],["RAlt",114,391,169,427,206],["Fn",115,429,169,465,206],
    ["Fn2",116,467,169,503,206],["Left",117,506,169,542,206],["Down",118,544,169,580,206],
    ["Right",119,582,168,618,205],
  ].map(([name, pos, x1, y1, x2, y2]) => ({ name, pos, x1, y1, x2, y2 }));
  const KEY_AT = Object.fromEntries(KEYS.map((k) => [k.pos, k.name]));
  const POSITIONS = KEYS.map((k) => k.pos).sort((a, b) => a - b);
  const KEY_ALIASES = { backslash: "\\", minus: "-", equal: "=", equals: "=", lbracket: "[",
    rbracket: "]", semicolon: ";", quote: "'", comma: ",", period: ".", dot: ".", slash: "/",
    backspace: "Bksp", delete: "Del", capslock: "Caps", pageup: "PgUp", pagedown: "PgDn",
    win: "LWin", cmd: "LWin" };

  function splitList(spec) {          // "," list that keeps the comma key: "a,,,b" -> a , b
    const toks = spec.split(","), out = [];
    for (let i = 0; i < toks.length;) {
      if (toks[i] === "") { out.push(","); i += (i + 1 < toks.length && toks[i + 1] === "") ? 2 : 1; }
      else { out.push(toks[i]); i += 1; }
    }
    return out;
  }
  function parseKeys(spec) {
    const byName = Object.fromEntries(KEYS.map((k) => [k.name.toLowerCase(), k.pos]));
    return splitList(spec).map((raw) => {
      let n = raw.trim(); n = (KEY_ALIASES[n.toLowerCase()] || n).toLowerCase();
      if (!(n in byName)) err(`Unknown key '${raw}'`);
      return byName[n];
    });
  }

  // ------------------------------------------------------------- lighting
  // [hw, effect, speed, light, direct, random, color] from the profile's LedOpt1..20
  const LED_OPTS = [[0,0,0,0,0,0,0],[1,0,1,1,0,0,0],[2,0,1,1,0,0,0],[3,0,1,1,0,1,1],
    [4,0,1,1,0,1,1],[5,0,1,1,0,1,1],[6,0,0,1,0,0,1],[7,0,1,1,0,1,1],[8,0,1,1,0,0,0],
    [9,0,1,1,0,0,0],[10,0,1,1,0,0,0],[11,0,1,1,0,0,0],[12,0,1,1,0,0,0],[13,0,1,1,0,0,0],
    [14,0,1,1,0,0,0],[15,0,1,1,0,1,1],[16,0,1,1,0,0,0],[17,0,1,1,0,0,0],[18,0,1,1,0,0,0],
    [19,0,0,1,0,0,1]];
  const EFFECT_COLORS = { random: 0, red: 1, green: 2, blue: 3, yellow: 4, magenta: 5, cyan: 6, white: 7 };
  const MAX_LEVEL = 9;
  const ledPayload = (mode, speed, bright, color) => [0xAE, 0x01, 0x00, 0x00, mode, speed, bright, color];

  // per-key RGB ("game mode" = mode 19, colour byte FF, 13 x [pos|0x80,R,G,B] per packet, FF ends)
  const RGB_MODE = 19;
  const RGB_NAMES = { off: "000000", black: "000000", white: "ffffff", red: "ff0000", green: "00ff00",
    blue: "0000ff", yellow: "ffff00", cyan: "00ffff", magenta: "ff00ff", purple: "8000ff",
    orange: "ff6000", pink: "ff3080", teal: "00a0a0", lime: "80ff00", gold: "ffb000" };
  function rgbPackets(keys, bright) {     // keys: {"pos": "rrggbb"}
    const entries = Object.keys(keys).map(Number).sort((a, b) => a - b).map((p) => {
      const h = keys[String(p)];
      return [p | 0x80, parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
    });
    const header = [0xAE, 0x01, 0x00, 0x00, RGB_MODE, 0x00, bright, 0xFF];
    const chunks = [];
    for (let i = 0; i < entries.length; i += 13) chunks.push(entries.slice(i, i + 13));
    if (!chunks.length) chunks.push([]);
    return chunks.map((ch, i) => header.concat(ch.flat(), i === chunks.length - 1 ? [0xFF] : []));
  }
  const vkToPos = (vk) => { vk = ({ 0x10: 0xA0, 0x11: 0xA2, 0x12: 0xA4 })[vk] || vk;
    const e = Object.entries(BASE_VK).find(([, v]) => v === vk); return e ? Number(e[0]) : null; };
  const GAOSHOU = ["1b,57,41,53,44,26,28,25,27",
    "70,71,72,31,32,33,34,35,9,51,57,45,52,41,53,44,47,10,42,11,12,20,2c,21,22,24,23",
    "31,32,33,34,35,36,37,51,57,45,52,54,41,53,44,46,47,10,43,56,11",
    "31,32,33,34,35,36,37,51,57,45,52,41,53,44,46", "57,52,41,53,44,10,11,12,26,28,25,27"];

  // ------------------------------------------------------------- triggers
  const TABLES = { actuation: 0x01, press: 0x04, release: 0x05 };
  const FACTORY = { actuation: 20, press: 0, release: 0 };
  const LIMITS = { actuation: [2, 38], press: [0, 36], release: [0, 36] };
  function triggerPackets(sub, table) {
    if (table.length !== 126) err("trigger table must have 126 bytes");
    return [0, 59, 118].map((off, pkt) => [0xB6, sub, 0x00, pkt].concat(table.slice(off, off + 59)));
  }

  // ------------------------------------------------------------- options
  const OPT_DEFAULTS = { tap: 1, tap_time: 30, debounce: 2, debounce_time: 2, magic_fn: 0, caps_led: 0 };
  // keyboard's own factory values (read back from a freshly reset Master 65%)
  const OPT_FACTORY = { tap: 0, tap_time: 13, debounce: 0, debounce_time: 1, magic_fn: 0, caps_led: 1 };
  const OPT_FIELDS = ["tap", "tap_time", "debounce", "debounce_time", "magic_fn", "caps_led"];
  // the GetPSD reply (report ID stripped) carries the current options at bytes 9..14, then 00 01
  function optionsFromReply(d) {
    if (!d || d.length < 17 || d[15] !== 0 || d[16] !== 1) return null;
    return Object.fromEntries(OPT_FIELDS.map((k, i) => [k, d[9 + i]]));
  }
  const optionsPayload = (o) => [0xB5, o.tap, o.tap_time, o.debounce, o.debounce_time, o.magic_fn, o.caps_led, 0x00, 0x01];

  // ------------------------------------------------------------- keymap
  const LAYER_IDS = { base: 1, fn1: 2, fn2: 3, tap: 5 };
  const VK_HID = {};
  for (let i = 0; i < 26; i++) VK_HID[0x41 + i] = 0x04 + i;
  for (let i = 0; i < 9; i++) VK_HID[0x31 + i] = 0x1E + i;
  for (let i = 0; i < 12; i++) VK_HID[0x70 + i] = 0x3A + i;
  Object.assign(VK_HID, { 0x30: 0x27, 0x0D: 0x28, 0x1B: 0x29, 0x08: 0x2A, 0x09: 0x2B, 0x20: 0x2C,
    0xBD: 0x2D, 0xBB: 0x2E, 0xDB: 0x2F, 0xDD: 0x30, 0xDC: 0x31, 0xBA: 0x33, 0xDE: 0x34, 0xC0: 0x35,
    0xBC: 0x36, 0xBE: 0x37, 0xBF: 0x38, 0x14: 0x39, 0x2C: 0x46, 0x91: 0x47, 0x13: 0x48, 0x2D: 0x49,
    0x24: 0x4A, 0x21: 0x4B, 0x2E: 0x4C, 0x23: 0x4D, 0x22: 0x4E, 0x27: 0x4F, 0x25: 0x50, 0x28: 0x51,
    0x26: 0x52, 0x90: 0x53, 0x5D: 0x65 });
  const MOD_BITS = { lctrl: 0x01, lshift: 0x02, lalt: 0x04, lwin: 0x08, rctrl: 0x10, rshift: 0x20, ralt: 0x40, rwin: 0x80 };
  const VK_MOD = { 0xA2: 0x01, 0x11: 0x01, 0xA0: 0x02, 0x10: 0x02, 0xA4: 0x04, 0x12: 0x04, 0x5B: 0x08,
    0xA3: 0x10, 0xA1: 0x20, 0xA5: 0x40, 0x5C: 0x80 };
  const TARGET_HID = { enter: 0x28, esc: 0x29, bksp: 0x2A, backspace: 0x2A, tab: 0x2B, space: 0x2C,
    "-": 0x2D, minus: 0x2D, "=": 0x2E, equal: 0x2E, "[": 0x2F, "]": 0x30, "\\": 0x31, backslash: 0x31,
    ";": 0x33, "'": 0x34, "`": 0x35, grave: 0x35, ",": 0x36, ".": 0x37, "/": 0x38, caps: 0x39,
    capslock: 0x39, printscreen: 0x46, prtsc: 0x46, scrolllock: 0x47, pause: 0x48, insert: 0x49,
    ins: 0x49, home: 0x4A, pgup: 0x4B, del: 0x4C, delete: 0x4C, end: 0x4D, pgdn: 0x4E, right: 0x4F,
    left: 0x50, down: 0x51, up: 0x52, numlock: 0x53, menu: 0x65, app: 0x65,
    "kp/": 0x54, "kp*": 0x55, "kp-": 0x56, "kp+": 0x57, kpenter: 0x58, kpplus: 0x57, kpminus: 0x56,
    kpslash: 0x54, kpstar: 0x55, kpdot: 0x63, kp0: 0x62, "kp.": 0x63 };
  for (let i = 0; i < 26; i++) TARGET_HID[String.fromCharCode(97 + i)] = 0x04 + i;
  for (let i = 1; i <= 9; i++) { TARGET_HID[String(i)] = 0x1E + i - 1; TARGET_HID["kp" + i] = 0x58 + i; }
  TARGET_HID["0"] = 0x27;
  for (let i = 1; i <= 12; i++) TARGET_HID["f" + i] = 0x39 + i;
  for (let i = 13; i <= 24; i++) TARGET_HID["f" + i] = 0x68 + i - 13;
  const HID_NAME = {};
  for (const [n, u] of Object.entries(TARGET_HID)) if (!(u in HID_NAME)) HID_NAME[u] = n;
  const MOD_ALIASES = { ctrl: "lctrl", shift: "lshift", alt: "lalt", opt: "lalt", option: "lalt",
    win: "lwin", cmd: "lwin", gui: "lwin", rcmd: "rwin", ropt: "ralt" };
  const MEDIA = { player: 0xA0, play: 0x93, playpause: 0x93, stop: 0x94, prev: 0x95, next: 0x96,
    volup: 0x90, voldown: 0x91, mute: 0x92, calc: 0xA4 };
  const MOUSE = { "mouse-left": 0xB0, "mouse-right": 0xB1, "mouse-middle": 0xB2, "mouse-forward": 0xB3,
    "mouse-back": 0xB4, "wheel-up": 0xB5, "wheel-down": 0xB6, "wheel-left": 0xB7, "wheel-right": 0xB8 };
  const SPECIAL = { "led-mode-cycle": 0x00, "led-bright+": 0x04, "led-bright-": 0x05, "led-speed+": 0x07,
    "led-speed-": 0x08, "led-color-cycle": 0x09, "led-pause": 0x0D, "led-switch": 0x0E, winlock: 0x10 };

  function recKey(vk, mods = 0) {
    if (vk === 0xFA) return [0xFF, 0, 0, 0];
    if (vk === 0xFB) return [0xFE, 0, 0, 0];
    if (vk in VK_MOD) return [0xFC, VK_MOD[vk] | mods, vk === 0x5B ? 0xE3 : 0, 0];
    return [0xFC, mods, VK_HID[vk], 0];
  }
  const BASE_VK = { 21: 0x1B, 22: 0x31, 23: 0x32, 24: 0x33, 25: 0x34, 26: 0x35, 27: 0x36, 28: 0x37,
    29: 0x38, 30: 0x39, 31: 0x30, 32: 0xBD, 33: 0xBB, 34: 0x08, 35: 0x2E, 42: 0x09, 43: 0x51, 44: 0x57,
    45: 0x45, 46: 0x52, 47: 0x54, 48: 0x59, 49: 0x55, 50: 0x49, 51: 0x4F, 52: 0x50, 53: 0xDB, 54: 0xDD,
    55: 0xDC, 56: 0x23, 63: 0x14, 64: 0x41, 65: 0x53, 66: 0x44, 67: 0x46, 68: 0x47, 69: 0x48, 70: 0x4A,
    71: 0x4B, 72: 0x4C, 73: 0xBA, 74: 0xDE, 76: 0x0D, 77: 0x21, 84: 0xA0, 86: 0x5A, 87: 0x58, 88: 0x43,
    89: 0x56, 90: 0x42, 91: 0x4E, 92: 0x4D, 93: 0xBC, 94: 0xBE, 95: 0xBF, 96: 0xA1, 97: 0x26, 98: 0x22,
    105: 0xA2, 106: 0x5B, 107: 0xA4, 111: 0x20, 114: 0xA5, 115: 0xFA, 116: 0xFB, 117: 0x25, 118: 0x28,
    119: 0x27 };
  function defaultLayers() {
    const empty = () => new Array(126).fill(null);
    const base = empty(), fn1 = empty(), fn2 = empty();
    for (const [p, vk] of Object.entries(BASE_VK)) base[p] = recKey(vk);
    const f1 = { 21: 0xC0, 35: 0x2D, 56: 0x24, 77: 0x2C, 98: 0x13, 115: 0xFA, 42: 0x09, 63: 0x14,
      76: 0x0D, 84: 0xA0, 96: 0xA5, 105: 0xA2, 107: 0xA4, 114: 0xA3 };
    for (const [p, vk] of Object.entries(f1)) fn1[p] = recKey(vk);
    for (let i = 0; i < 12; i++) fn1[22 + i] = recKey(0x70 + i);
    fn1[106] = [0xFB, 0x10, 0, 0];
    const media = { 86: 0x93, 87: 0x94, 88: 0x95, 89: 0x96, 90: 0x92, 91: 0x91, 92: 0x90 };
    for (const [p, m] of Object.entries(media)) fn2[p] = [m, 0, 0, 0];
    fn2[53] = [0xFB, 0x00, 0, 0]; fn2[54] = [0xFB, 0x0E, 0, 0]; fn2[116] = recKey(0xFB);
    fn2[117] = [0xFB, SPECIAL["led-speed-"], 0, 0]; fn2[118] = [0xFB, SPECIAL["led-bright-"], 0, 0];
    fn2[119] = [0xFB, SPECIAL["led-speed+"], 0, 0]; fn2[97] = [0xFB, SPECIAL["led-bright+"], 0, 0];
    return { base, fn1, fn2, tap: empty() };
  }

  function parseTarget(spec, macros = {}) {
    const s = spec.trim().toLowerCase();
    if (s.startsWith("macro:")) {
      const m = s.match(/^macro:([a-z0-9_.-]+)(?:\*(\d+)|@(hold|toggle))?$/);
      if (!m) err("Macro target: macro:NAME, macro:NAME*3, macro:NAME@hold, macro:NAME@toggle");
      if (!(m[1] in macros)) err(`No macro '${m[1]}'`);
      if (m[3] === "hold") return ["M", m[1], 0xF1, 0];
      if (m[3] === "toggle") return ["M", m[1], 0xF0, 0];
      const n = parseInt(m[2] || "1", 10);
      if (n < 1 || n > 65535) err("Repeat count must be 1..65535");
      return ["M", m[1], 0xF3, n];
    }
    if (["none", "clear", "transparent"].includes(s)) return null;
    if (s === "disable" || s === "off") return [0xBF, 0, 0, 0];
    if (s === "fn") return [0xFF, 0, 0, 0];
    if (s === "fn2") return [0xFE, 0, 0, 0];
    if (s in MEDIA) return [MEDIA[s], 0, 0, 0];
    if (s in MOUSE) return [MOUSE[s], 0, 0, 0];
    if (s in SPECIAL) return [0xFB, SPECIAL[s], 0, 0];
    if (s in TARGET_HID) return [0xFC, 0, TARGET_HID[s], 0];
    const parts = [];
    for (const tok of s.split("+")) { if (tok === "" && parts.length) parts[parts.length - 1] += "+"; else parts.push(tok); }
    let mods = 0; const keys = [];
    for (let part of parts) {
      part = MOD_ALIASES[part] || part;
      if (part in MOD_BITS) mods |= MOD_BITS[part];
      else if (part in TARGET_HID) keys.push(TARGET_HID[part]);
      else err(`Unknown target '${part}'`);
    }
    if (keys.length > 2) err("At most two non-modifier keys in one combo");
    if (!keys.length) { if (!mods) err("Empty target"); return [0xFC, mods, mods === 0x08 ? 0xE3 : 0, 0]; }
    while (keys.length < 2) keys.push(0);
    return [0xFC, mods, keys[0], keys[1]];
  }

  function describe(rec) {
    if (!rec) return "-";
    if (rec[0] === "M") return `macro:${rec[1]}` + ({ 0xF1: "@hold", 0xF0: "@toggle" }[rec[2]] || (rec[3] === 1 ? "" : `*${rec[3]}`));
    const [c0, c1, c2, c3] = rec;
    if (c0 === 0xFF) return "Fn";
    if (c0 === 0xFE) return "Fn2";
    if (c0 === 0xBF) return "disabled";
    if (c0 === 0xFB) { const n = Object.keys(SPECIAL).find((k) => SPECIAL[k] === c1); return n || `special 0x${c1.toString(16)}`; }
    if (c0 === 0xFC) {
      const names = Object.keys(MOD_BITS).filter((k) => c1 & MOD_BITS[k]);
      for (const u of [c2, c3]) if (u && u !== 0xE3) names.push(HID_NAME[u] || `0x${u.toString(16)}`);
      return names.join("+") || "none";
    }
    for (const d of [MEDIA, MOUSE]) { const n = Object.keys(d).find((k) => d[k] === c0); if (n) return n; }
    return rec.map((x) => x.toString(16).padStart(2, "0")).join(" ");
  }
  const sameRec = (a, b) => JSON.stringify(a || null) === JSON.stringify(b || null);

  function layerPackets(layer, recs, ids = {}) {
    const block = new Array(756).fill(0);
    recs.forEach((r, idx) => {
      if (!r) return;
      if (r[0] === "M") r = [r[2], ids[r[1]], r[3] >> 8, r[3] & 0xFF];
      [idx, ...r, 0].forEach((b, i) => { block[idx * 6 + i] = b; });
    });
    const out = [];
    for (let pkt = 1; pkt <= 14; pkt++)
      out.push([0xA0, 0x02, 0x04, pkt, 0x0E, LAYER_IDS[layer], ...block.slice((pkt - 1) * 54, pkt * 54), 0xA5]);
    return out;
  }
  const macroRefs = (layers) => [...new Set(Object.values(layers).flatMap((recs) =>
    recs.filter((r) => r && r[0] === "M").map((r) => r[1])))].sort();

  // ------------------------------------------------------------- macros
  const MACRO_MAX = 0x200, MACRO_MEMORY = 0x1000;
  const MOD_USAGE = { lctrl: 0xE0, lshift: 0xE1, lalt: 0xE2, lwin: 0xE3, rctrl: 0xE4, rshift: 0xE5, ralt: 0xE6, rwin: 0xE7 };
  const MOUSE_BTN = { left: 1, right: 2, middle: 3 };
  const SHIFTED = { "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8",
    "(": "9", ")": "0", "_": "-", "+": "=", "{": "[", "}": "]", "|": "\\", ":": ";", '"': "'",
    "~": "`", "<": ",", ">": ".", "?": "/" };
  const usage = (name) => { const n = MOD_ALIASES[name] || name;
    if (n in MOD_USAGE) return MOD_USAGE[n]; if (n in TARGET_HID) return TARGET_HID[n];
    err(`Unknown key '${name}' in macro`); };
  function charUsages(ch) {
    if (ch === " ") return [0x2C]; if (ch === "\n") return [0x28]; if (ch === "\t") return [0x2B];
    if (/^[A-Za-z]$/.test(ch)) return ch === ch.toUpperCase() ? [0xE1, TARGET_HID[ch.toLowerCase()]] : [TARGET_HID[ch]];
    if (ch in SHIFTED) return [0xE1, TARGET_HID[SHIFTED[ch]]];
    if (ch in TARGET_HID) return [TARGET_HID[ch]];
    err(`Can't type character '${ch}' in text:`);
  }
  function tokenize(spec) {            // shell-like: spaces separate, quotes group
    const out = []; let cur = "", q = null, has = false;
    for (let i = 0; i < spec.length; i++) {
      const c = spec[i];
      if (q) {
        if (c === q) q = null;
        else if (c === "\\" && q === '"' && i + 1 < spec.length) cur += spec[++i];
        else cur += c;
      } else if (c === '"' || c === "'") { q = c; has = true; }
      else if (/\s/.test(c)) { if (cur || has) out.push(cur); cur = ""; has = false; }
      else if (c === "\\" && i + 1 < spec.length) { cur += spec[++i]; }
      else cur += c;
    }
    if (q) err("Unclosed quote in macro steps");
    if (cur || has) out.push(cur);
    return out;
  }
  function compileMacro(spec, gap = 10) {
    const ev = [];
    const add = (b, d = 0) => ev.push([b, d]);
    const tap = (us) => { us.forEach((u) => add([0x02, u])); [...us].reverse().forEach((u) => add([0x03, u])); ev[ev.length - 1][1] = gap; };
    for (const t of tokenize(spec)) {
      const tl = t.toLowerCase(); let m;
      if ((m = tl.match(/^(\d+)ms$/))) { if (!ev.length) err("A macro can't start with a delay"); ev[ev.length - 1][1] = Math.min(+m[1], 65535); }
      else if (tl.startsWith("text:")) { for (const ch of t.slice(5)) tap(charUsages(ch)); }
      else if (tl.startsWith("down:") || tl.startsWith("up:")) { const [k, n] = tl.split(/:(.*)/s); add([k === "down" ? 0x02 : 0x03, usage(n)]); }
      else if (/^(click|mdown|mup):/.test(tl)) {
        const [k, b] = tl.split(/:(.*)/s);
        if (!(b in MOUSE_BTN)) err(`Mouse button must be left/right/middle, not '${b}'`);
        if (k !== "mup") add([0x04, MOUSE_BTN[b]]);
        if (k !== "mdown") add([0x05, MOUSE_BTN[b]]);
        ev[ev.length - 1][1] = gap;
      } else if ((m = tl.match(/^wheel:(up|down)(?:\*(\d+))?$/))) {
        for (let i = 0; i < +(m[2] || 1); i++) add([m[1] === "up" ? 0x08 : 0x09]);   // 1 byte per notch
        ev[ev.length - 1][1] = gap;
      } else if (tl.startsWith("raw:")) {
        const h = tl.slice(4); if (!/^([0-9a-f]{2})+$/.test(h) || h.startsWith("00")) err(`raw: needs hex bytes, e.g. raw:08`);
        add(h.match(/../g).map((x) => parseInt(x, 16)));
      } else if (tl in TARGET_HID) tap([TARGET_HID[tl]]);
      else {
        const parts = [];
        for (const tok of tl.split("+")) { if (tok === "" && parts.length) parts[parts.length - 1] += "+"; else parts.push(tok); }
        const us = parts.map(usage);
        tap([...us.filter((u) => u >= 0xE0), ...us.filter((u) => u < 0xE0)]);
      }
    }
    if (!ev.length) err("Empty macro");
    const blob = [0x01, ...new Array(30).fill(0)];
    for (const [b, d] of ev) { blob.push(...b); if (d) blob.push(0x01, d >> 8, d & 0xFF); }
    if (blob.length > MACRO_MAX) err(`Macro is ${blob.length} bytes; the limit is ${MACRO_MAX}`);
    return { events: ev, blob };
  }
  const macroAlloc = (id, size) => [0xA7, id, (size + 5) >> 8, (size + 5) & 0xFF];
  function macroDataPackets(id, blob) {
    const chunks = []; for (let i = 0; i < blob.length; i += 57) chunks.push(blob.slice(i, i + 57));
    return chunks.map((c, k) => [0xA8, id, 0x00, k + 1, chunks.length, c.length, ...c]);
  }

  // ------------------------------------------------------------- live per-key stream ("music mode")
  // protocol.md 10.2: frame = 126 keys x [R,G,B] (378 bytes), sent as 7 packets
  //   B1 00 00 <pkt 0..6> <57 bytes>, no reply. Stop = stop sending.
  function streamPackets(frame) {
    if (frame.length !== 378) err("stream frame must be 378 bytes");
    const out = [];
    for (let pkt = 0; pkt < 7; pkt++) out.push([0xB1, 0x00, 0x00, pkt, ...frame.slice(pkt * 57, pkt * 57 + 57)]);
    return out;
  }

  // ------------------------------------------------------------- safety
  // the only payloads that may ever be sent (bootloader A5, resets A0 02 03 / AE 06 never pass)
  function allowed(p) {
    const eq = (a, b) => a.length >= b.length && b.every((x, i) => a[i] === x);
    if (p.length > 63) return false;
    if (eq(p, GET_PSD) && p.length === 4) return true;
    if (p[0] === 0xB1 && p[1] === 0 && p[2] === 0 && p[3] <= 6 && p.length <= 61) return true;
    if (p[0] === 0xAE && p[1] === 0x01) return true;
    if (p[0] === 0xB6 && [0x01, 0x03, 0x04, 0x05].includes(p[1])) return true;
    if (p[0] === 0xB5 && p.length === 9 && p[7] === 0 && p[8] === 1) return true;
    if (p.length === 2 && p[0] === 0xAA && p[1] === 0) return true;
    if (p[0] === 0xA7 && p.length === 4) return true;
    if (p[0] === 0xA8) return true;
    if (eq(p, [0xA0, 0x02, 0x04]) && p.length === 61 && p[4] === 0x0E && [1, 2, 3, 5].includes(p[5]) && p[60] === 0xA5) return true;
    return false;
  }

  const api = { VID, PID, USAGE_PAGE, REPORT_ID, EXPECTED_PSD, GET_PSD, KEYS, KEY_AT, POSITIONS,
    splitList, parseKeys, LED_OPTS, EFFECT_COLORS, MAX_LEVEL, ledPayload, RGB_MODE, RGB_NAMES,
    rgbPackets, GAOSHOU, vkToPos, TABLES, FACTORY, LIMITS, triggerPackets, OPT_DEFAULTS,
    optionsPayload, OPT_FACTORY, OPT_FIELDS, optionsFromReply, LAYER_IDS, TARGET_HID, MOD_BITS, MEDIA, MOUSE, SPECIAL, defaultLayers, parseTarget,
    describe, sameRec, layerPackets, macroRefs, MACRO_MAX, MACRO_MEMORY, MOD_USAGE, compileMacro,
    macroAlloc, macroDataPackets, streamPackets, allowed, tokenize };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.RankedCore = api;
})(typeof window !== "undefined" ? window : globalThis);
