/* ranked_he_configurator - web UI (WebHID). Protocol/encoding lives in core.js. */
"use strict";
const C = window.RankedCore;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (a) => Array.from(a, (b) => b.toString(16).padStart(2, "0")).join(" ");
const clone = (x) => JSON.parse(JSON.stringify(x));
const mm = (v) => (v / 10).toFixed(1);

// ------------------------------------------------------------------ toast + log
function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = "toast " + kind; el.textContent = msg;
  const box = $("#toast");
  box.appendChild(el);
  while (box.children.length > 2) box.firstChild.remove();     // keep the newest two
  setTimeout(() => el.remove(), kind === "err" ? 7000 : 2500);
}
const LOG = [];
function log(cls, text) {
  const t = new Date().toTimeString().slice(0, 8);
  LOG.push([cls, `${t} ${text}`]);
  if (LOG.length > 500) LOG.shift();
  if (!$('[data-panel="log"]').hidden) renderLog();
}
function renderLog() {
  const el = $("#log");
  el.innerHTML = "";
  for (const [c, t] of LOG) { const d = document.createElement("div"); d.className = c; d.textContent = t; el.appendChild(d); }
  el.scrollTop = el.scrollHeight;
}

// ------------------------------------------------------------------ device
class Device {
  constructor() { this.hid = null; this.demo = false; this.ready = false; this.chain = Promise.resolve();
    this.wait = null; this.collect = null; this.demoT = 0; }

  async connectReal(hid) {
    if (!hid.opened) await hid.open();
    this.hid = hid; this.demo = false;
    hid.oninputreport = (e) => {
      if (e.reportId !== C.REPORT_ID) return;
      this.onInput(new Uint8Array(e.data.buffer, e.data.byteOffset, e.data.byteLength));
    };
    const r = await this.req(C.GET_PSD, { quiet: false });
    if (!r) throw new Error("The keyboard didn't answer the handshake.");
    const psd = Array.from(r.slice(4, 7));
    if (psd.join() !== C.EXPECTED_PSD.join())
      throw new Error(`Unexpected model code ${hex(psd)} (expected ${hex(C.EXPECTED_PSD)}). Not a Master 65%?`);
    this.ready = true;
  }
  connectDemo() { this.hid = null; this.demo = true; this.ready = true; }
  async disconnect() {
    this.ready = false;
    if (this.hid) { try { await this.hid.close(); } catch (e) { /* already gone */ } }
    this.hid = null; this.demo = false;
  }

  onInput(d) {   // d = report without the report ID
    if (d[0] === 0xB7 && this.collect) { this.collect.push(d.slice(4, 63)); log("rx", "RX " + hex(d.slice(0, 12)) + " …"); return; }
    if (this.wait && d[0] === this.wait.cmd) { log("rx", "RX " + hex(d.slice(0, 16)) + " …"); const w = this.wait; this.wait = null; w.resolve(d); }
  }

  // run fn with exclusive access to the device (one transaction at a time)
  exclusive(fn) {
    const run = this.chain.then(fn);
    this.chain = run.catch(() => {});
    return run;
  }

  // send one payload; wait for the echo of its first byte (unless echo=false)
  async req(p, { echo = true, timeout = 1500, quiet = false } = {}) {
    p = Array.from(p);
    if (!C.allowed(p)) throw new Error(`Blocked: ${hex(p.slice(0, 4))} isn't a whitelisted command`);
    const buf = new Uint8Array(63); buf.set(p);
    if (!quiet) log("tx", "TX 04 " + hex(p.slice(0, 20)) + (p.length > 20 ? " …" : ""));
    if (this.demo) {
      await sleep(2);
      if (!echo) return null;
      const r = new Uint8Array(63); r[0] = p[0]; r[1] = 1;
      if (p[0] === 0xA0 && p[3] === 0x01) r.set([0xA0, 0x02, 0x00, 0x01, ...C.EXPECTED_PSD], 0);
      if (!quiet) log("rx", "RX (demo) " + hex(r.slice(0, 8)) + " …");
      return r;
    }
    if (!this.hid) throw new Error("Not connected");
    let resolve; const got = new Promise((r) => { resolve = r; });
    if (echo) this.wait = { cmd: p[0], resolve };
    await this.hid.sendReport(C.REPORT_ID, buf);
    if (!echo) return null;
    const timer = sleep(timeout).then(() => null);
    const r = await Promise.race([got, timer]);
    if (!r) { this.wait = null; log("er", `no reply to ${hex(p.slice(0, 4))}`); }
    return r;
  }

  // one live-travel snapshot (126 bytes, 0.1 mm units)
  async poll() {
    if (this.demo) {
      this.demoT += 0.12; const t = new Array(126).fill(0);
      [44, 64, 65, 66].forEach((p, i) => { t[p] = Math.max(0, Math.min(40, Math.round(Math.sin(this.demoT + i * 1.6) * 48))); });
      if (Math.random() < 0.05) t[67] = 1;
      return t;
    }
    this.collect = [];
    await this.req([0xB6, 0x03, 0x01], { echo: false, quiet: true });
    const end = performance.now() + 150;
    while (performance.now() < end && this.collect.reduce((n, c) => n + c.length, 0) < 126) await sleep(3);
    const chunks = this.collect; this.collect = null;
    const flat = []; chunks.forEach((c) => flat.push(...c));
    return flat.length >= 126 ? flat.slice(0, 126) : null;
  }
  async stopPoll() { if (!this.demo) await this.req([0xB6, 0x03, 0x00], { echo: false }); }
}
const dev = new Device();

function need() { if (!dev.ready) throw new Error("Connect the keyboard first (or try Demo)."); }
async function sendAll(packets, gap, what) {
  for (const p of packets) {
    await sleep(gap);
    if (!(await dev.req(p))) throw new Error(`No acknowledgement writing ${what}. Fn2+Esc resets the keyboard if needed.`);
  }
}

// ------------------------------------------------------------------ state (same shape as ranked_state.json)
const STATE_KEY = "ranked_state", PROF_KEY = "ranked_profiles";
let S = {};
try { S = JSON.parse(localStorage.getItem(STATE_KEY) || "{}"); } catch (e) { S = {}; }
const saveS = () => { try { localStorage.setItem(STATE_KEY, JSON.stringify(S)); } catch (e) { toast("Couldn't save to browser storage", "err"); } };
const known = (k) => k in S;
const sTriggers = () => ({ actuation: S.actuation ? [...S.actuation] : new Array(126).fill(20),
  press: S.press ? [...S.press] : new Array(126).fill(0), release: S.release ? [...S.release] : new Array(126).fill(0) });
const sLayers = () => (S.layers ? clone(S.layers) : C.defaultLayers());
const sOptions = () => Object.assign({}, C.OPT_DEFAULTS, S.options || {});
const sMacros = () => S.macros || {};
function sRgb() { const L = S.lighting || {}; return L.color === 255 ? { keys: { ...(L.keys || {}) }, bright: L.brightness } : { keys: {}, bright: L.brightness ?? 9 }; }

function loadProfiles() { try { return JSON.parse(localStorage.getItem(PROF_KEY) || "{}"); } catch (e) { return {}; } }
function saveProfiles(p) { localStorage.setItem(PROF_KEY, JSON.stringify(p)); }

// ------------------------------------------------------------------ keyboard ops
async function opLed(mode, speed, bright, color) {
  need();
  await dev.exclusive(async () => { await sendAll([C.ledPayload(mode, speed, bright, color)], 0, "lighting"); });
  S.lighting = { mode, speed, brightness: bright, color }; saveS();
}
async function opRgb(keys, bright) {
  need();
  await dev.exclusive(() => sendAll(C.rgbPackets(keys, bright), 10, "per-key colours"));
  S.lighting = { mode: C.RGB_MODE, speed: 0, brightness: bright, color: 255, keys: { ...keys } }; saveS();
}
async function opTriggers(t, names = Object.keys(C.TABLES)) {
  need();
  await dev.exclusive(async () => {
    for (const n of names) { await sleep(35); await sendAll(C.triggerPackets(C.TABLES[n], t[n]), 20, n); }
  });
  Object.assign(S, clone(t)); saveS();
}
async function opOptions(o) {
  need();
  await dev.exclusive(() => sendAll([C.optionsPayload(o)], 0, "options"));
  S.options = { ...o }; saveS();
}
// write layers; if any layer uses macros, re-upload all bound macros and every layer that uses one
async function opKeymap(layers, send) {
  need();
  const macros = sMacros();
  const refs = C.macroRefs(layers);
  const ids = Object.fromEntries(refs.map((n, i) => [n, i + 1]));
  const blobs = {};
  for (const n of refs) {
    if (!macros[n]) throw new Error(`Keymap uses macro '${n}' but it isn't defined`);
    blobs[n] = C.compileMacro(macros[n].steps, macros[n].gap ?? 10).blob;
  }
  const total = refs.reduce((s, n) => s + blobs[n].length + 5, 0);
  if (total > C.MACRO_MEMORY) throw new Error(`Bound macros need ${total} bytes; the keyboard has about ${C.MACRO_MEMORY}.`);
  const todo = [...new Set([...send, ...Object.keys(C.LAYER_IDS).filter((L) => layers[L].some((r) => r && r[0] === "M"))])];
  await dev.exclusive(async () => {
    for (const L of todo) { await sleep(30); await sendAll(C.layerPackets(L, layers[L], ids), 0, `layer ${L}`); }
    if (refs.length) {
      if (!(await dev.req([0xAA, 0x00]))) throw new Error("No acknowledgement freeing macro memory");
      await sleep(120);
      for (const n of refs) {
        await sleep(30);
        const r = await dev.req(C.macroAlloc(ids[n], blobs[n].length));
        if (!r || r[1] !== 0x01) throw new Error(`The keyboard has no room for macro '${n}'`);
        await sleep(100);
        await sendAll(C.macroDataPackets(ids[n], blobs[n]), 20, `macro ${n}`);
      }
    }
  });
  S.layers = clone(layers); saveS();
}
async function opFreeMacros() { need(); await dev.exclusive(() => sendAll([[0xAA, 0x00]], 0, "macro memory")); }

async function busy(btn, fn, okMsg) {
  const b = typeof btn === "string" ? $(btn) : btn;
  const old = b ? b.textContent : "";
  if (b) { b.disabled = true; b.textContent = "Writing…"; }
  try { await fn(); if (okMsg) toast(okMsg, "ok"); return true; }
  catch (e) { toast(e.message, "err"); log("er", e.message); return false; }
  finally { if (b) { b.disabled = false; b.textContent = old; } }
}

// ------------------------------------------------------------------ connection UI
function setStatus() {
  const s = $("#status");
  s.className = "pill" + (dev.ready ? (dev.demo ? " demo" : " on") : "");
  s.textContent = dev.ready ? (dev.demo ? "Demo (nothing is sent)" : "Master 65% connected") : "Not connected";
  $("#btnConnect").textContent = dev.ready && !dev.demo ? "Disconnect" : "Connect keyboard";
  $("#btnDemo").textContent = dev.demo ? "Exit demo" : "Demo";
}
const FILTERS = [{ vendorId: C.VID, productId: C.PID, usagePage: C.USAGE_PAGE }];
const isVendor = (d) => d.vendorId === C.VID && d.productId === C.PID && d.collections.some((c) => c.usagePage === C.USAGE_PAGE);
async function connect(hid) {
  try { await dev.connectReal(hid); toast("Connected to the Master 65%", "ok"); }
  catch (e) { await dev.disconnect(); toast(e.message, "err"); }
  setStatus();
}
$("#btnConnect").onclick = async () => {
  if (dev.ready && !dev.demo) { stopLive(); await dev.disconnect(); setStatus(); return; }
  if (!("hid" in navigator)) { toast("This browser has no WebHID - use Chrome or Edge.", "err"); return; }
  if (dev.demo) await dev.disconnect();
  try {
    const list = await navigator.hid.requestDevice({ filters: FILTERS });
    const d = list.find(isVendor);
    if (d) await connect(d); else if (list.length) toast("That device doesn't have the settings interface.", "err");
  } catch (e) { toast(e.message, "err"); }
};
$("#btnDemo").onclick = async () => {
  stopLive();
  if (dev.demo) await dev.disconnect(); else { await dev.disconnect(); dev.connectDemo(); toast("Demo mode: commands are only logged, nothing is sent.", "ok"); }
  setStatus();
};
if ("hid" in navigator) {
  navigator.hid.addEventListener("disconnect", (e) => { if (dev.hid === e.device) { stopLive(); dev.disconnect(); setStatus(); toast("Keyboard disconnected"); } });
  navigator.hid.addEventListener("connect", (e) => { if (!dev.ready && isVendor(e.device)) connect(e.device); });
  navigator.hid.getDevices().then((ds) => { const d = ds.find(isVendor); if (d && !dev.ready) connect(d); });
} else $("#noHid").hidden = false;

// ------------------------------------------------------------------ tabs
let TAB = "lighting";
$$("#tabs button").forEach((b) => (b.onclick = () => showTab(b.dataset.tab)));
function showTab(t) {
  if (TAB === "trigger" && t !== "trigger") stopLive();
  TAB = t;
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === t)));
  $$(".panel").forEach((p) => (p.hidden = p.dataset.panel !== t));
  $("#kbCard").hidden = !["rgb", "trigger", "keymap"].includes(t);
  ({ lighting: initLighting, rgb: renderRgb, trigger: renderTrig, keymap: renderMap,
     macros: renderMacros, options: initOptions, profiles: renderProfiles, log: renderLog })[t]?.();
  renderKb();
}

// ------------------------------------------------------------------ shared keyboard
const sel = new Set();
let dragMode = null;
const kb = $("#kb");
const keyEls = {};
for (const k of C.KEYS) {
  const el = document.createElement("div");
  el.className = "key"; el.dataset.pos = k.pos;
  Object.assign(el.style, { left: (k.x1 / 627 * 100) + "%", top: (k.y1 / 215 * 100) + "%",
    width: ((k.x2 - k.x1) / 627 * 100) + "%", height: ((k.y2 - k.y1) / 215 * 100) + "%" });
  el.innerHTML = '<div class="bar" style="height:0"></div><span class="n"></span><span class="v"></span>';
  el.querySelector(".n").textContent = k.name;
  kb.appendChild(el); keyEls[k.pos] = el;
}
kb.addEventListener("pointerdown", (e) => {
  const el = e.target.closest(".key"); if (!el) return;
  const p = +el.dataset.pos;
  if (TAB === "rgb" && $("#rgbClickPaint").checked) { paintKeys([p]); dragMode = "paint"; return; }
  dragMode = sel.has(p) ? "del" : "add"; applyDrag(p);
});
kb.addEventListener("pointerover", (e) => {
  if (!dragMode || !(e.buttons & 1)) return;
  const el = e.target.closest(".key"); if (!el) return;
  if (dragMode === "paint") paintKeys([+el.dataset.pos]); else applyDrag(+el.dataset.pos);
});
window.addEventListener("pointerup", () => { dragMode = null; });
function applyDrag(p) { dragMode === "add" ? sel.add(p) : sel.delete(p); renderKb(); }
$("#selAll").onclick = () => { C.KEYS.forEach((k) => sel.add(k.pos)); renderKb(); };
$("#selNone").onclick = () => { sel.clear(); renderKb(); };
const GROUPS = {
  WASD: [44, 64, 65, 66], Arrows: [97, 117, 118, 119], Numbers: [22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
  Letters: C.KEYS.filter((k) => /^[A-Z]$/.test(k.name)).map((k) => k.pos),
  Modifiers: [84, 96, 105, 106, 107, 114, 115, 116, 63, 42, 76, 34],
};
C.GAOSHOU.forEach((g, i) => { GROUPS[`Ranked game preset ${i + 1}`] = [...new Set(g.split(",").map((x) => C.vkToPos(parseInt(x, 16))).filter((p) => p !== null))]; });
for (const g of Object.keys(GROUPS)) $("#selGroup").add(new Option(g, g));
$("#selGroup").onchange = (e) => { if (e.target.value) { GROUPS[e.target.value].forEach((p) => sel.add(p)); e.target.value = ""; renderKb(); } };

// overlays per tab: returns {v, dim, bg, fg, bar, noisy}
let overlay = () => ({});
function renderKb() {
  for (const k of C.KEYS) {
    const el = keyEls[k.pos], o = overlay(k.pos) || {};
    el.classList.toggle("sel", sel.has(k.pos));
    el.classList.toggle("noisy", !!o.noisy);
    const v = el.querySelector(".v"); v.textContent = o.v ?? ""; v.classList.toggle("dim", !!o.dim);
    el.style.background = o.bg || ""; el.style.color = o.fg || "";
    el.querySelector(".bar").style.height = (o.bar ? Math.min(100, o.bar * 100) : 0) + "%";
    el.title = o.title || k.name;
  }
}
const contrast = (h) => { const r = parseInt(h.slice(0, 2), 16), g = parseInt(h.slice(2, 4), 16), b = parseInt(h.slice(4, 6), 16);
  return (r * 299 + g * 587 + b * 114) / 1000 > 140 ? "#111" : "#fff"; };

// ------------------------------------------------------------------ lighting tab
const MODE_NAMES = { 0: "off (likely)" };
function initLighting() {
  if (!$("#ledMode").options.length) {
    C.LED_OPTS.forEach((o) => { const caps = [o[2] && "speed", o[5] && "random", o[6] && "colour"].filter(Boolean);
      $("#ledMode").add(new Option(`Effect ${o[0]}${MODE_NAMES[o[0]] ? " – " + MODE_NAMES[o[0]] : ""}${caps.length ? " (" + caps.join(", ") + ")" : ""}`, o[0])); });
    for (const [n, v] of Object.entries(C.EFFECT_COLORS)) $("#ledColor").add(new Option(n, v));
    const L = S.lighting && S.lighting.color !== 255 ? S.lighting : { mode: 1, speed: 5, brightness: 9, color: 0 };
    $("#ledMode").value = L.mode; $("#ledSpeed").value = L.speed; $("#ledBright").value = L.brightness; $("#ledColor").value = L.color;
    ["#ledMode", "#ledSpeed", "#ledBright", "#ledColor"].forEach((s) => ($(s).oninput = ledHints));
  }
  ledHints();
}
function ledHints() {
  const o = C.LED_OPTS[+$("#ledMode").value];
  $("#ledSpeedV").textContent = $("#ledSpeed").value; $("#ledBrightV").textContent = $("#ledBright").value;
  $("#ledSpeed").disabled = !o[2]; $("#ledColor").disabled = !o[6];
  $("#ledHint").textContent = o[0] === 0 ? "Effect 0 probably turns the lights off." : (!o[6] ? "This effect has its own colours." : "");
}
$("#ledApply").onclick = () => busy("#ledApply", () => opLed(+$("#ledMode").value, +$("#ledSpeed").value, +$("#ledBright").value, +$("#ledColor").value), "Lighting applied");

// ------------------------------------------------------------------ per-key RGB tab
let W_rgb = sRgb();
Object.entries(C.RGB_NAMES).forEach(([n, h]) => { if (n === "black") return;
  const s = document.createElement("button"); s.className = "sw"; s.title = n; s.style.background = "#" + h;
  s.onclick = () => { $("#rgbColor").value = "#" + h; }; $("#rgbSwatches").appendChild(s); });
const curColor = () => $("#rgbColor").value.slice(1).toLowerCase();
function paintKeys(ps, c = curColor()) { ps.forEach((p) => { if (c === "000000") delete W_rgb.keys[p]; else W_rgb.keys[p] = c; }); renderRgb(); }
$("#rgbPaint").onclick = () => { if (!sel.size) return toast("Select keys first"); paintKeys([...sel]); };
$("#rgbOthers").onclick = () => paintKeys(C.KEYS.map((k) => k.pos).filter((p) => !sel.has(p)));
$("#rgbOffSel").onclick = () => paintKeys([...sel], "000000");
$("#rgbAllOff").onclick = () => { W_rgb.keys = {}; renderRgb(); };
$("#rgbBright").oninput = () => { W_rgb.bright = +$("#rgbBright").value; renderRgb(); };
$("#rgbRevert").onclick = () => { W_rgb = sRgb(); renderRgb(); };
$("#rgbWrite").onclick = () => busy("#rgbWrite", () => opRgb(W_rgb.keys, W_rgb.bright).then(renderRgb), "Colours written");
function renderRgb() {
  $("#rgbBright").value = W_rgb.bright; $("#rgbBrightV").textContent = W_rgb.bright;
  const cur = sRgb(); const dirty = JSON.stringify(cur) !== JSON.stringify(W_rgb);
  $("#rgbWrite").classList.toggle("dirty", dirty);
  $("#rgbInfo").textContent = (dirty ? "Unsaved changes. " : "") + `${Object.keys(W_rgb.keys).length} keys lit.` +
    (S.lighting && S.lighting.color !== 255 ? " (Keyboard is currently in an effect mode.)" : "");
  overlay = (p) => { const c = W_rgb.keys[p]; return c ? { bg: "#" + c, fg: contrast(c), title: `#${c}` } : { v: "off", dim: true }; };
  if (TAB === "rgb") { $("#kbHint").textContent = "Select keys, pick a colour, then Paint (or tick “click paints directly”)."; renderKb(); }
}

// ------------------------------------------------------------------ trigger tab
let W_t = sTriggers();
const tSync = () => { $("#tActV").textContent = mm($("#tAct").value) + " mm";
  $("#tPressV").textContent = +$("#tPress").value ? mm($("#tPress").value) + " mm" : "off";
  $("#tRelV").textContent = +$("#tRel").value ? mm($("#tRel").value) + " mm" : "off"; };
["#tAct", "#tPress", "#tRel"].forEach((s) => ($(s).oninput = tSync));
$("#tAct").value = 20; $("#tPress").value = 0; $("#tRel").value = 0; tSync();
$("#tApplySel").onclick = () => { if (!sel.size) return toast("Select keys first");
  for (const p of sel) { W_t.actuation[p] = +$("#tAct").value; W_t.press[p] = +$("#tPress").value; W_t.release[p] = +$("#tRel").value; }
  renderTrig(); };
$("#tPick").onclick = () => { const p = [...sel][0]; if (p === undefined) return toast("Select a key first");
  $("#tAct").value = W_t.actuation[p]; $("#tPress").value = W_t.press[p]; $("#tRel").value = W_t.release[p]; tSync(); };
$("#tFactory").onclick = () => { W_t = { actuation: new Array(126).fill(20), press: new Array(126).fill(0), release: new Array(126).fill(0) }; renderTrig(); };
$("#tRevert").onclick = () => { W_t = sTriggers(); renderTrig(); };
$("#tWrite").onclick = () => busy("#tWrite", () => opTriggers(clone(W_t)).then(renderTrig), "Actuation settings written");
let live = null, noise = null, liveRun = false;
function renderTrig() {
  const dirty = JSON.stringify(W_t) !== JSON.stringify(sTriggers()) || !known("actuation");
  $("#tWrite").classList.toggle("dirty", dirty);
  $("#tInfo").textContent = !known("actuation") ? "Not written by this page yet; shown as factory." : (dirty ? "Unsaved changes." : "");
  overlay = (p) => {
    const a = W_t.actuation[p], pr = W_t.press[p], re = W_t.release[p];
    const o = { v: `${mm(a)}${pr || re ? ` · ${pr ? mm(pr) : "–"}/${re ? mm(re) : "–"}` : ""}`,
      title: `actuation ${mm(a)} mm, RT press ${pr ? mm(pr) : "off"}, release ${re ? mm(re) : "off"}` };
    if (live) { o.bar = live[p] / 40; if (live[p]) o.v = mm(live[p]) + " mm"; }
    if (noise && noise[p]) o.noisy = true;
    return o;
  };
  if (TAB === "trigger") { $("#kbHint").textContent = "Labels: actuation · RT press/release (mm). Select keys, set sliders, Apply."; renderKb(); }
}
function stopLive() {
  if (!liveRun) return;
  liveRun = false; live = null; $("#tLive").textContent = "Show live key travel"; $("#tLiveInfo").textContent = "";
  if (dev.ready) dev.exclusive(() => dev.stopPoll()).catch(() => {});
  if (TAB === "trigger") renderTrig();
}
$("#tLive").onclick = async () => {
  if (liveRun) return stopLive();
  try { need(); } catch (e) { return toast(e.message, "err"); }
  liveRun = true; $("#tLive").textContent = "Stop live view";
  $("#tLiveInfo").textContent = "Press keys to see their depth.";
  while (liveRun && dev.ready) {
    try { const t = await dev.exclusive(() => dev.poll()); if (t && liveRun) { live = t; renderTrig(); } }
    catch (e) { toast(e.message, "err"); break; }
    await sleep(25);
  }
  stopLive();
};
$("#tNoise").onclick = () => busy("#tNoise", async () => {
  need(); stopLive();
  const n = new Array(126).fill(0); let count = 0;
  $("#tLiveInfo").textContent = "Measuring - don't touch the keyboard…";
  await sleep(800);
  const end = performance.now() + 10000;
  while (performance.now() < end) {
    const t = await dev.exclusive(() => dev.poll());
    if (t) { count++; t.forEach((v, i) => { n[i] = Math.max(n[i], v); }); }
    await sleep(20);
  }
  await dev.exclusive(() => dev.stopPoll());
  if (count < 10) throw new Error("Too few readings.");
  const touched = C.KEYS.filter((k) => n[k.pos] > 5).map((k) => k.name);
  if (touched.length) throw new Error(`Keys looked pressed (${touched.join(", ")}); try again without touching.`);
  noise = n;
  const noisy = C.KEYS.filter((k) => n[k.pos]).map((k) => `${k.name} ${mm(n[k.pos])}`);
  $("#tLiveInfo").textContent = noisy.length ? `${count} readings. Noisy keys (outlined): ${noisy.join(", ")}` : `${count} readings. No noise on any key.`;
  $("#tNoiseFix").hidden = !noisy.length;
  renderTrig();
});
$("#tNoiseFix").onclick = () => { if (!noise) return;
  let changed = 0;
  for (const k of C.KEYS) { const p = k.pos, floor = noise[p] ? noise[p] + 2 : 0;
    for (const t of ["press", "release"]) if (W_t[t][p] && W_t[t][p] < floor) { W_t[t][p] = Math.min(36, floor); changed++; } }
  toast(changed ? `Raised ${changed} RT values to noise + 0.2 mm. Write to apply.` : "RT is off or already above the noise on those keys.");
  renderTrig(); };

// ------------------------------------------------------------------ keymap tab
let W_l = sLayers(), LAYER = "fn1";
const LAYER_LABEL = { base: "Base", fn1: "Fn1", fn2: "Fn2", tap: "Tap (unsupported?)" };
for (const L of Object.keys(C.LAYER_IDS)) {
  const b = document.createElement("button"); b.className = "btn small"; b.textContent = LAYER_LABEL[L]; b.dataset.layer = L;
  b.onclick = () => { LAYER = L; renderMap(); }; $("#layerBtns").appendChild(b);
}
const SHORT = { lctrl: "Ctrl", lshift: "Shift", lalt: "Alt", lwin: "Win", rctrl: "RCtrl", rshift: "RShift", ralt: "RAlt", rwin: "RWin" };
const shortDesc = (r) => (r && r[0] === "M") ? C.describe(r)
  : C.describe(r).split("+").map((x) => SHORT[x] || (x === "" ? "+" : x[0].toUpperCase() + x.slice(1))).join("+");
const CATS = {
  Keys: [...Object.keys(C.TARGET_HID).filter((k) => !/^(backspace|minus|equal|backslash|grave|capslock|prtsc|ins|delete|app|kpplus|kpminus|kpslash|kpstar|kpdot)$/.test(k))],
  Modifiers: ["ctrl", "shift", "alt", "cmd", "rctrl", "rshift", "ralt", "rcmd"],
  Media: Object.keys(C.MEDIA), Mouse: Object.keys(C.MOUSE), Lighting: Object.keys(C.SPECIAL),
  Special: ["fn", "fn2", "disable"], Macros: [],
};
function fillPick() { const c = $("#mapCat").value; $("#mapPick").innerHTML = "";
  const list = c === "Macros" ? Object.keys(sMacros()).map((n) => "macro:" + n) : CATS[c];
  $("#mapPick").add(new Option("…", ""));
  list.forEach((v) => $("#mapPick").add(new Option(v, v))); }
Object.keys(CATS).forEach((c) => $("#mapCat").add(new Option(c, c)));
$("#mapCat").onchange = fillPick; fillPick();
$("#mapPick").onchange = () => { if ($("#mapPick").value) $("#mapTarget").value = $("#mapPick").value; };
[...Object.keys(C.TARGET_HID), ...CATS.Modifiers, ...CATS.Media, ...CATS.Mouse, ...CATS.Lighting, ...CATS.Special]
  .forEach((v) => { const o = document.createElement("option"); o.value = v; $("#targetList").appendChild(o); });
function mapGuard() {
  if (!sel.size) throw new Error("Select keys first");
  if (LAYER === "base" && !$("#baseOk").checked) throw new Error("Tick “allow base-layer edits” first (mistakes there can make keys stop working until Fn2+Esc).");
  if (LAYER === "base" && (sel.has(115) || sel.has(116))) throw new Error("Fn and Fn2 can't be remapped on the base layer (you'd lose the Fn2+Esc reset).");
}
function assign(fn) { try { mapGuard(); for (const p of sel) W_l[LAYER][p] = fn(p); renderMap(); } catch (e) { toast(e.message, "err"); } }
$("#mapAssign").onclick = () => { const t = $("#mapTarget").value.trim(); if (!t) return toast("Type or pick a target");
  try { const specs = C.splitList(t); const ps = [...sel].sort((a, b) => a - b);
    if (specs.length > 1) { mapGuard(); if (specs.length !== ps.length) throw new Error(`${ps.length} keys selected but ${specs.length} targets`);
      ps.forEach((p, i) => { W_l[LAYER][p] = C.parseTarget(specs[i], sMacros()); }); renderMap(); return; }
    const r = C.parseTarget(t, sMacros()); assign(() => clone(r));
  } catch (e) { toast(e.message, "err"); } };
$("#mapDefault").onclick = () => { const d = C.defaultLayers()[LAYER]; assign((p) => d[p]); };
$("#mapClear").onclick = () => assign(() => (LAYER === "base" ? [0xBF, 0, 0, 0] : null));
$("#mapRevert").onclick = () => { W_l = sLayers(); renderMap(); };
const dirtyLayers = () => Object.keys(C.LAYER_IDS).filter((L) => !known("layers") ? JSON.stringify(W_l[L]) !== JSON.stringify(C.defaultLayers()[L])
  : JSON.stringify(W_l[L]) !== JSON.stringify(sLayers()[L]));
$("#mapWrite").onclick = () => { const d = dirtyLayers(); if (!d.length) return toast("No changes to write");
  busy("#mapWrite", () => opKeymap(clone(W_l), d).then(renderMap), `Keymap written (${d.join(", ")})`); };
function renderMap() {
  $$("#layerBtns button").forEach((b) => b.classList.toggle("primary", b.dataset.layer === LAYER));
  $("#baseOkWrap").hidden = LAYER !== "base";
  const d = dirtyLayers(); $("#mapWrite").classList.toggle("dirty", d.length > 0);
  $("#mapInfo").textContent = d.length ? `Unsaved: ${d.join(", ")}` : (known("layers") ? "" : "Showing the factory keymap.");
  const def = C.defaultLayers()[LAYER];
  overlay = (p) => { const r = W_l[LAYER][p];
    if (!r) return { v: LAYER === "base" ? "dead" : "–", dim: true, title: "falls through to base" };
    const changed = !C.sameRec(r, def[p]);
    return { v: shortDesc(r), title: C.describe(r) + (changed ? " (changed)" : ""), bg: changed ? "color-mix(in srgb, var(--accent) 18%, var(--key))" : "" }; };
  if (TAB === "keymap") { $("#kbHint").textContent = `${LAYER_LABEL[LAYER]} layer. Highlighted keys differ from factory.`; renderKb(); }
}

// ------------------------------------------------------------------ macros tab
function boundWhere(name) { const out = []; const L = sLayers();
  for (const [ln, recs] of Object.entries(L)) recs.forEach((r, p) => { if (r && r[0] === "M" && r[1] === name) out.push(`${LAYER_LABEL[ln]}+${C.KEY_AT[p]}`); });
  return out; }
function renderMacros() {
  const t = $("#macroTable"); t.innerHTML = "<tr><th>Name</th><th>Steps</th><th>Size</th><th>Bound to</th><th></th></tr>";
  const ms = sMacros();
  if (!Object.keys(ms).length) { t.insertRow().insertCell().textContent = "No macros yet."; }
  for (const [n, m] of Object.entries(ms).sort()) {
    const tr = t.insertRow(); let size = "?";
    try { size = C.compileMacro(m.steps, m.gap ?? 10).blob.length + " B"; } catch (e) { size = "error"; }
    [n, m.steps, size, boundWhere(n).join(", ") || "–"].forEach((v, i) => { const c = tr.insertCell(); c.textContent = v; if (i === 1) c.className = "mono"; });
    const b = document.createElement("button"); b.className = "btn small"; b.textContent = "Edit";
    b.onclick = () => { $("#mName").value = n; $("#mSteps").value = m.steps; $("#mGap").value = m.gap ?? 10; preview(); };
    tr.insertCell().appendChild(b);
  }
  fillPick();
}
function preview() {
  const s = $("#mSteps").value.trim(); if (!s) { $("#mPreview").textContent = ""; return; }
  try { const { events, blob } = C.compileMacro(s, +$("#mGap").value || 0);
    const rev = {}; for (const [k, v] of Object.entries(C.TARGET_HID)) if (!(v in rev)) rev[v] = k;
    for (const [k, v] of Object.entries(C.MOD_USAGE)) rev[v] = k;
    const txt = events.slice(0, 40).map(([b, d]) => {
      const kind = { 2: "↓", 3: "↑", 4: "mouse↓", 5: "mouse↑", 8: "wheel↑", 9: "wheel↓" }[b[0]] || "raw";
      const what = b[0] <= 3 ? (rev[b[1]] || b[1]) : b[0] <= 5 ? ({ 1: "left", 2: "right", 3: "middle" }[b[1]]) : "";
      return `${kind}${what}${d ? ` (${d}ms)` : ""}`; }).join("  ");
    $("#mPreview").textContent = `${blob.length} of ${C.MACRO_MAX} bytes · ${txt}${events.length > 40 ? " …" : ""}`;
  } catch (e) { $("#mPreview").textContent = "⚠ " + e.message; }
}
$("#mSteps").oninput = preview; $("#mGap").oninput = preview;
$("#mSave").onclick = () => busy("#mSave", async () => {
  const name = $("#mName").value.trim().toLowerCase();
  if (!/^[a-z0-9_.-]+$/.test(name)) throw new Error("Macro names: letters, digits, _ . - only");
  const steps = $("#mSteps").value.trim(), gap = +$("#mGap").value || 0;
  C.compileMacro(steps, gap);
  S.macros = { ...sMacros(), [name]: { steps, gap } }; saveS();
  if (boundWhere(name).length) { await opKeymap(sLayers(), []); toast(`Macro '${name}' saved and uploaded`, "ok"); }
  else toast(`Macro '${name}' saved. Bind it on the Keymap tab: macro:${name}`, "ok");
  renderMacros();
});
$("#mDelete").onclick = () => busy("#mDelete", async () => {
  const name = $("#mName").value.trim().toLowerCase(); const ms = sMacros();
  if (!ms[name]) throw new Error(`No macro '${name}'`);
  if (boundWhere(name).length) {
    if (!$("#mForce").checked) throw new Error(`'${name}' is bound to ${boundWhere(name).join(", ")}. Tick “also unbind from keys”.`);
    const L = sLayers(), def = C.defaultLayers(), changed = [];
    for (const [ln, recs] of Object.entries(L)) recs.forEach((r, p) => { if (r && r[0] === "M" && r[1] === name) { recs[p] = def[ln][p]; if (!changed.includes(ln)) changed.push(ln); } });
    await opKeymap(L, changed);
    if (!C.macroRefs(L).length) await opFreeMacros();
    W_l = sLayers();
  }
  delete ms[name]; S.macros = ms; saveS(); renderMacros(); toast(`Deleted '${name}'`, "ok");
});

// ------------------------------------------------------------------ options tab
function initOptions() { const o = sOptions();
  $("#oCaps").checked = !!o.caps_led; $("#oTap").checked = !!o.tap; $("#oTapTime").value = o.tap_time;
  $("#oDeb").value = o.debounce; $("#oMagic").value = o.magic_fn; optLabels(); }
const optLabels = () => { $("#oTapTimeV").textContent = $("#oTapTime").value * 10 + " ms"; $("#oDebV").textContent = $("#oDeb").value; };
$("#oTapTime").oninput = optLabels; $("#oDeb").oninput = optLabels;
$("#oApply").onclick = () => busy("#oApply", () => opOptions({ ...sOptions(), caps_led: +$("#oCaps").checked, tap: +$("#oTap").checked,
  tap_time: +$("#oTapTime").value, debounce: +$("#oDeb").value, magic_fn: +$("#oMagic").value }), "Options applied");
$("#oDefaults").onclick = () => { const o = C.OPT_DEFAULTS; $("#oCaps").checked = !!o.caps_led; $("#oTap").checked = !!o.tap;
  $("#oTapTime").value = o.tap_time; $("#oDeb").value = o.debounce; $("#oMagic").value = o.magic_fn; optLabels(); };

// ------------------------------------------------------------------ profiles + settings file
function snapshot() {   // same as ranked.py _snapshot()
  const s = {};
  if (S.actuation && S.press && S.release) s.triggers = { actuation: S.actuation, press: S.press, release: S.release };
  if (S.layers) { s.keymap = S.layers; const used = C.macroRefs(S.layers);
    if (used.length) s.macros = Object.fromEntries(Object.entries(sMacros()).filter(([n]) => used.includes(n))); }
  if (S.options) s.options = S.options;
  if (S.lighting) s.lighting = S.lighting;
  return clone(s);
}
function download(name, obj) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 1)], { type: "application/json" }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function renderProfiles() {
  const P = loadProfiles(), t = $("#profTable"), cur = JSON.stringify(snapshot());
  t.innerHTML = "<tr><th>Name</th><th>Contains</th><th></th></tr>";
  if (!Object.keys(P).length) t.insertRow().insertCell().textContent = "No profiles yet.";
  for (const [n, p] of Object.entries(P).sort()) {
    const tr = t.insertRow(); tr.insertCell().textContent = n;
    const same = Object.entries(p).every(([k, v]) => JSON.stringify(snapshot()[k]) === JSON.stringify(v));
    tr.insertCell().textContent = Object.keys(p).join(", ") + (same && cur !== "{}" ? "  · matches keyboard" : "");
    const c = tr.insertCell(); c.className = "row";
    const mk = (txt, fn, cls = "") => { const b = document.createElement("button"); b.className = "btn small " + cls; b.textContent = txt; b.onclick = fn; c.appendChild(b); };
    mk("Load", (e) => busy(e.target, () => loadProfile(p), `Loaded '${n}'`), "primary");
    mk("Export", () => download(n + ".json", p));
    mk("Delete", () => { const Q = loadProfiles(); delete Q[n]; saveProfiles(Q); renderProfiles(); }, "danger");
  }
}
async function loadProfile(p) {
  need();
  if (p.options) await opOptions({ ...C.OPT_DEFAULTS, ...p.options });
  if (p.lighting) { const L = p.lighting;
    if (L.color === 255) await opRgb(L.keys || {}, L.brightness); else await opLed(L.mode, L.speed, L.brightness, L.color); }
  if (p.triggers) await opTriggers(clone(p.triggers));
  if (p.keymap) {
    if (p.macros) { S.macros = { ...sMacros(), ...p.macros }; saveS(); }
    const layers = { ...sLayers(), ...clone(p.keymap) };
    await opKeymap(layers, Object.keys(p.keymap));
  }
  W_rgb = sRgb(); W_t = sTriggers(); W_l = sLayers(); renderProfiles();
}
$("#pSave").onclick = () => {
  const name = $("#pName").value.trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) return toast("Profile names: letters, digits, _ . - only", "err");
  const secs = $$(".pSec").filter((c) => c.checked).map((c) => c.value);
  const snap = Object.fromEntries(Object.entries(snapshot()).filter(([k]) => secs.includes(k) || (k === "macros" && secs.includes("keymap"))));
  if (!Object.keys(snap).length) return toast("Nothing to save yet - write some settings first.", "err");
  const P = loadProfiles();
  if (P[name] && !confirmOverwrite(name)) return;
  P[name] = snap; saveProfiles(P); renderProfiles();
  const missing = secs.filter((s) => !(s in snap));
  toast(`Saved '${name}'` + (missing.length ? ` (not included, never set here: ${missing.join(", ")})` : ""), "ok");
};
let overwriteArmed = null;
function confirmOverwrite(name) {   // second click within 4 s overwrites (no blocking dialogs)
  if (overwriteArmed === name) { overwriteArmed = null; return true; }
  overwriteArmed = name; setTimeout(() => { overwriteArmed = null; }, 4000);
  toast(`'${name}' exists - click Save again to overwrite.`); return false;
}
async function readJsonFile(input) { const f = input.files[0]; input.value = ""; if (!f) return null;
  try { return { name: f.name.replace(/\.json$/i, ""), data: JSON.parse(await f.text()) }; }
  catch (e) { toast("That isn't a valid JSON file", "err"); return null; } }
$("#pImport").onchange = async (e) => { const r = await readJsonFile(e.target); if (!r) return;
  if (!["triggers", "keymap", "options", "lighting"].some((k) => k in r.data)) return toast("That doesn't look like a profile", "err");
  const P = loadProfiles(); P[r.name] = r.data; saveProfiles(P); renderProfiles(); toast(`Imported '${r.name}'`, "ok"); };
$("#sExport").onclick = () => download("ranked_state.json", S);
$("#sImport").onchange = async (e) => { const r = await readJsonFile(e.target); if (!r) return;
  S = r.data; saveS(); W_rgb = sRgb(); W_t = sTriggers(); W_l = sLayers();
  toast("Settings file imported. Nothing was sent - load a profile or press Write to push it to the keyboard.", "ok"); renderProfiles(); };
$("#sForget").onclick = () => { S = {}; saveS(); W_rgb = sRgb(); W_t = sTriggers(); W_l = sLayers(); toast("Forgot all written settings (assuming factory).", "ok"); renderProfiles(); };
$("#logClear").onclick = () => { LOG.length = 0; renderLog(); };

// ------------------------------------------------------------------ start
const repo = location.hostname.endsWith("github.io")
  ? `https://github.com/${location.hostname.split(".")[0]}/${location.pathname.split("/")[1] || ""}` : null;
if (repo) $("#repoLink").href = repo; else $("#repoLink").hidden = true;
setStatus();
showTab("lighting");
