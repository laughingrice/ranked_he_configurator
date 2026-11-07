# ranked_he_configurator

Free, open-source configurator for **Ranked magnetic (Hall-effect) keyboards**. It covers what the
official Windows-only *Ranked Utility* does (actuation, rapid trigger, key remapping, macros,
lighting), and runs on macOS from the command line.

Developed and tested on the **Ranked Master 65%** (USB `3532:B0A1`). Other models that use the same
utility (Nova 60%, Guardian 65%, …) probably speak the same protocol but are untested. The tool
checks the model code and refuses to talk to anything else.

> **Unofficial.** This project isn't affiliated with or endorsed by Ranked. It was built by
> studying how the official utility talks to the keyboard, for compatibility. Use at your own
> risk. See [Safety](#safety-and-recovery).

## Features

| | |
|---|---|
| **Actuation and rapid trigger** | Per-key actuation point (0.2–3.8 mm), RT press and release sensitivity, automatic noise-based setup |
| **Live key travel** | Watch key depth in real time; see exactly where a key presses and releases |
| **Key remapping** | Base, Fn1, Fn2 layers: keys, combos, media, mouse, lighting controls, numpad, F13–F24, disable |
| **Macros** | Keys, combos, typed text, delays, mouse clicks, scrolling; play once / N times / while held / toggle |
| **Lighting** | 20 built-in effects with speed, brightness and color, plus per-key RGB |
| **Options** | Caps Lock LED (plus hidden tap/debounce/Magic Fn settings) |
| **Profiles** | Save and load complete setups (e.g. `mac` / `win`) in one command |

## Requirements

- macOS (Apple Silicon or Intel), Python 3.9+
- hidapi: `brew install hidapi`
- The keyboard connected **by USB cable**
- **Input Monitoring** permission for your terminal app (System Settings → Privacy & Security →
  Input Monitoring), then fully quit and reopen the terminal

No Python packages are needed; the script calls the hidapi library directly.

## Quick start

```sh
python ranked.py info                 # handshake: model code + firmware version
python ranked.py led --mode 19 --color red
python ranked.py trigger set --actuation 1.2 --rt 0.3
python ranked.py rt-test --key F      # see where F presses/releases
python ranked.py profile save default
```

Every command has `--help`. Commands that write to the keyboard accept `--dry-run` to print the
exact bytes without sending anything. `-v` (before the command) shows raw traffic.

## Commands

### Lighting

```sh
python ranked.py modes                                   # list effects and what each supports
python ranked.py led --mode 3 --speed 3 --brightness 6 --color random
python ranked.py rgb set --keys wasd --color red --others "#202020"
python ranked.py rgb set --keys W,A,S,D --color red,green,blue,#ff8800
python ranked.py rgb set --keys arrows --color cyan      # adds to the current layout
python ranked.py rgb off [--keys ...]
python ranked.py rgb show
```

`--keys` accepts key names, `all`, or groups: `wasd`, `arrows`, `numbers`, `letters`, `mods`,
`game1`–`game5` (Ranked's own gaming presets). Colors are names (`red`, `teal`, `gold`, …) or
`#rrggbb`. Speed and brightness are 0–9.

### Actuation and rapid trigger

```sh
python ranked.py trigger set --actuation 1.0 --press 0.5 --release 0.5 [--keys W,A,S,D]
python ranked.py trigger set --rt 0.3                    # same press + release sensitivity
python ranked.py trigger auto --rt 0.3 --actuation 1.0   # measures sensor noise first
python ranked.py trigger show
python ranked.py trigger reset                           # factory: 2.0 mm, RT off
```

All values are in mm, in 0.1 mm steps. RT sensitivity `0` turns rapid trigger off.
`trigger auto` asks you not to touch the keyboard, measures each key's resting noise, and raises
RT sensitivity on noisy keys so they don't phantom-trigger.

### Key travel tools (read-only)

```sh
python ranked.py travel --seconds 60      # live depth; per-key range/noise report
python ranked.py rt-test --key F          # PRESS / RELEASE events with the depth they happened at
```

### Key remapping

```sh
python ranked.py map show [--layer fn1]
python ranked.py map set --layer fn1 --key m,comma,.,k --to left,down,right,up
python ranked.py map set --layer fn2 --key 1 --to f13
python ranked.py map set --layer fn2 --key a --to cmd+shift+4
python ranked.py map set --layer fn2 --key p --to default     # this key's factory setting
python ranked.py map set --layer fn2 --key p --to none        # unset (falls through to base)
python ranked.py map reset --layer fn2|all
```

- **Layers:** `base`, `fn1`, `fn2` (and `tap`, which appears unsupported on this model).
- **Lists:** one target applies to all listed keys; a list of targets pairs up with the keys in
  order. Write a comma inside a list as `,,` or use the name `comma`.
- **Targets:**
  - keys: `a`, `f5`, `esc`, `left`, `kp4`, `kp+`, `f13`–`f24`
  - modifiers: `ctrl`, `shift`, `alt`/`opt`, `win`/`cmd`, and `r…` versions
  - combos: `cmd+c`
  - media: `play`, `next`, `volup`, `mute`, …
  - mouse: `mouse-left`, `wheel-up`, …
  - lighting: `led-mode-cycle`, `led-bright+`, …
  - other: `winlock`, `fn`, `fn2`, `disable`, `macro:NAME`
- **Base layer:** changes require `--yes`. Fn and Fn2 can't be remapped there, so the Fn2+Esc
  reset always keeps working.

### Macros

```sh
python ranked.py macro add sig 'text:"Hello world" 200ms enter'
python ranked.py macro add zoom 'cmd+= 100ms cmd+=' --gap 20
python ranked.py macro add scroll 'wheel:down*5 100ms click:right'
python ranked.py map set --layer fn2 --key 1 --to macro:sig          # play once
python ranked.py map set --layer fn2 --key 2 --to macro:zoom*3       # play 3 times
python ranked.py map set --layer fn2 --key 3 --to macro:scroll@hold  # repeat while held
python ranked.py map set --layer fn2 --key 4 --to macro:sig@toggle   # repeat until any key
python ranked.py macro list | show NAME | delete NAME [--force] | sync
```

| Step | Does |
|---|---|
| `a`, `cmd+c`, `f13` | tap a key or combo |
| `text:"..."` | type text (US layout) |
| `250ms` | wait |
| `down:shift` / `up:shift` | hold / release |
| `click:left`, `mdown:right` / `mup:right` | mouse buttons (left / right / middle) |
| `wheel:up`, `wheel:down*3` | scroll |

- **Size limits:** up to 512 bytes per macro (about 70 typed characters at the default 10 ms
  gap), about 4 KB in total.
- **Updates:** changing a bound macro re-uploads it automatically.
- **Deleting:** `delete --force` also unbinds the macro from every key.

### Options

```sh
python ranked.py options                       # show
python ranked.py options --caps-led on|off
python ranked.py options --app-defaults        # what the official app sends
```

Tap, debounce and Magic Fn are hidden for this model in the official app. They're available as
`--tap`, `--tap-time`, `--debounce` and `--magic-fn`, but had no visible effect on the Master 65%.

### Profiles

```sh
python ranked.py profile save mac [--only keymap,triggers] [--force]
python ranked.py profile load win [--only lighting] [--full] [--dry-run]
python ranked.py profile list | show NAME | delete NAME
```

- **Sections:** `triggers`, `keymap` (including the macros it uses), `options`, `lighting`
  (effects or per-key RGB).
- **Loading:** skips keymap layers that are already on the keyboard. Use `--full` to resend
  everything, e.g. after a Fn2+Esc reset or after using the official app.

## How settings are stored

The keyboard stores every setting as soon as it's written, and settings survive unplugging. It
**cannot report its settings back**: the only thing it reports is live key travel. So the tool
keeps a record of everything it writes:

- **`ranked_state.json`:** what the keyboard currently holds, as far as this tool knows.
  Commit it, since it's your only record.
- **`profiles/*.json`:** saved profiles.

If you change settings with the official app or reset the keyboard, this record goes stale.
After **Fn2+Esc**, run `python ranked.py trigger reset` and `python ranked.py map reset
--layer all`, or `profile load NAME --full`, so the record matches the keyboard again.

## Safety and recovery

- **Factory reset:** hold **Fn2 + Esc for 5 seconds**. This resets keymaps, macros, lighting,
  and actuation/rapid trigger.
- **Whitelist:** the tool can only send commands on a whitelist. The **bootloader / firmware
  update command is hard-blocked**, as are the keymap and lighting wipe commands.
- **Limits:** values are range-checked against the official app's limits, and the model code is
  verified before every write.
- **Firmware updates:** don't update firmware through the official app unless you need to. It
  isn't needed for anything here.

## Quirks worth knowing

- **First press with rapid trigger on:** happens at *actuation + press sensitivity*. That's
  firmware behaviour; set actuation lower to compensate.
- **Full-depth readings:** key travel reads 4.0 mm slightly before the physical bottom, so
  actuation above about 3.6 mm is unreliable.
- **Cmd and Option:** on a Mac, Win = Cmd and Alt = Option. If you swap them in macOS
  (Keyboard → Modifier Keys), remapped combos and macros get swapped too: write `opt+c` to
  get Cmd+C.
- **Fn1 + Win toggles Win lock,** which disables Cmd on a Mac.
- **Numpad keys** don't act as arrows on macOS: there's no Num Lock behaviour there.
- **The official app writes `\` settings to the wrong key position** (75 instead of 55). This
  tool uses the correct one.
- **Tap mode / layers:** the official app sends tap keys to layer slot 5, which this firmware
  ignores. The real tap layer is slot 4 (`map set --layer slot4`, experimental), active only
  while `options --tap on`. On the Master 65% it's buggy: the slot-4 key replaces the base key,
  fires on release and stays pressed until the next key, and holding never produces the base key.
- **Second actuation point** (`trigger second`, experimental): accepted, but has no effect.
- **Options read-back:** the handshake reply reports the current options (Caps LED, tap,
  debounce, Magic Fn), so `options` and the web app read them from the keyboard. Factory values:
  tap off (130 ms), debounce 0, Magic Fn 0, Caps LED on.
- **Music mode** (web app): the keyboard accepts a live per-key colour stream (`B1`, 126 × RGB,
  7 packets/frame, ~25 fps). Nothing is stored on the keyboard; stopping the stream ends it.
- **Firmware updates** are encrypted on the PC and decrypted by the keyboard's bootloader, so
  firmware can't be read or modified from the computer.

## Protocol

[`protocol.md`](protocol.md) documents the USB HID protocol: framing, every command, the keymap,
macro and lighting formats, and which commands are dangerous. In short, it's a vendor HID
interface (usage page `0xFF00`, report ID 4) carrying 64-byte messages
`04 <cmd> <args…>`, and the keyboard replies by echoing the command byte.

## Repository contents

This repository contains only original work: the script, documentation and protocol notes. It
does **not** include Ranked's utility, DLLs, firmware images, device profiles or artwork. Those
remain Ranked's property.

## License

MIT, see [LICENSE](LICENSE).
