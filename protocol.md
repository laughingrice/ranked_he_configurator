# OemDrv.exe — HID settings protocol (static analysis)

Target: `OemDrv.exe` (PE32 x86, MFC), SHA-256 `22f9f599f89e55b4b77fc10121c01259de2fa2c724100197f220258c7c7dcffd`
Profile: `Dev/kb/M68/US/Dev.ini` (VID 0x3532, PID 0xB0A1, `Psd=0c,01,01`, `LayerNum=4`, `ShowKeyTrigger=1`)
Method: Hopper via REA plus `objdump -d` (Apple LLVM 21) to get exact stack offsets. **No data was sent to any device.**

All addresses are virtual addresses in OemDrv.exe (image base 0x400000). Function names such as `SendData` and `GetPSD`
come from the app's own debug log strings (`OutputDebugString`-style logger at `[0x6189cc]`). Hopper shows them as `sub_XXXXXX`.

Notation:
* **payload** = the 63 bytes after the report ID.
* **wire** = the full 64-byte buffer passed to WriteFile, where `wire[0] = 0x04` and `wire[n+1] = payload[n]`.

Confidence tags:
* **[obs]** = read directly from instructions.
* **[inf]** = inferred from context.
* **[?]** = not resolved.

---

## 1. Device discovery and open

| Step | Address | Detail |
|---|---|---|
| Enumerate | `0x40f950` (SetupDiGetClassDevsW @ `0x40f97f`) | Uses the HID class GUID (`HidD_GetHidGuid`) and iterates interfaces [obs] |
| Probe each interface | `0x40fa20` ("OpenDeviceInterface") | `SetupDiGetDeviceInterfaceDetailW`, optional `StrStrIW` path filter, `CreateFileW(path, 0x12019f or 0, FILE_SHARE_READ\|WRITE, OPEN_EXISTING)` @ `0x40faed`/`0x40fafe`. Then `HidD_GetPreparsedData`, `HidD_GetAttributes`, `HidP_GetCaps`, `HidD_GetProductString`. Results go into a global table at `0x6189d8` (stride 0x22c; WCHAR path at +0, caps/attrs at +0x208..+0x224, in-use flag at +0x228) [obs] |
| Select + open | `0x46a730` | Walks the table (`0x618bfc`..`0x61f894`). A candidate must pass all of: **VID == profile VID**; **PID in the profile's 12-entry PID list**; not in use; **UsagePage (+0x218) == 0xFF00**; field +0x21c == 0 [? likely an unused caps field]; **report length fields +0x20c and +0x210 both == 0x40** (64-byte input and output reports). It then opens `CreateFileW(path, 0x12019f, 3, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0)` @ `0x46a7cc` [obs] |
| Psd handshake | `0x46a7d9`–`0x46a83d` | Runs if the profile Psd (cfg+0x1e) is non-zero or cfg+0x23 is set. Calls **GetPSD** (`0x46b130`) on the new handle and compares the 3 returned bytes with the profile's `Psd`. On mismatch it logs `"Psd unmatch: gVar.nPsd=%x,%x, nDevPsd=%x,%x"` (`0x5d9e90`) and tries the next candidate [obs] |
| FW version | `0x46a8xx` (after the match) | `HidD_GetAttributes(hDev).VersionNumber` is stored at dev+0x10 and logged `"FW Version=0x%x"` (`0x5d9ee8`) [obs] |
| Input thread | `0x46a400` ("ServiceThread") | Loops an overlapped `ReadFile(hDev, buf, 0x40)` @ `0x46a493`. Each 64-byte input report (report ID still at [0]) is pushed into a ring buffer (`0x462b60`) when the device is current (`ebx == [0x6036d4]`) [obs] |

`Psd` comes from Dev.ini `[OPT] Psd=` via `GetPrivateProfileStringW` @ `0x40d5b3` (key string `0x5cba34`), parsed as hex bytes by `0x44e000` [obs].

## 2. Transport layer (all device I/O)

| Function | Address | What it does |
|---|---|---|
| `HidWrite` | `0x469f20` | Requires `len <= 0x3f`. Builds a 0x200-byte local zero buffer with **`buf[0] = 0x04`** (`0x469f86`), `memcpy(buf+1, payload, len)`, then **`WriteFile(hDev, buf, 0x40, ...)`** (overlapped) @ **`0x469fad`**. Waits 1000 ms (`0x469fc8`); on timeout it calls `CancelIo`. Returns 63 on success [obs] |
| `HidSend` | `0x46a1a0` | Copies 63 bytes from the caller and calls `HidWrite` once (its loop ends after 63 bytes) [obs] |
| `HidReadSync` | `0x46a070` | **`ReadFile(hDev, buf, 0x40)`** @ **`0x46a0e0`** with a timeout. Returns `buf+1`, so the report ID is stripped [obs] |
| `HidReadSync` wrapper | `0x46a240` | Calls `0x46a070`, then `Sleep(20)` [obs] |
| `PopReport` | `0x46a9f0` | Pops 64 bytes from the ServiceThread ring buffer (report ID **included**). Polls 3× with `Sleep(30)` [obs] |
| **`SendData`** | **`0x46aa50`** | Args: `(dev, payload*, timeout, async)`. Copies 63 payload bytes, optionally hex-dumps `"SendData:"`, and sends with `HidSend`. Reply handling: **async=1** uses `PopReport` and requires `reply[1] == payload[0]`; **async=0** uses `HidReadSync` and requires `reply[0] == payload[0]` (`0x46aaed`…`0x46ac63`). Up to 3 attempts. The reply is copied back into the caller's buffer [obs] |
| `SendNoReply` | `0x46b0b0` | Sends 63 bytes with `HidSend` and reads no reply [obs] |

**Framing (applies to every command):** `wire = 04 | cmd | args… | zero pad to 64 bytes`.
* No checksum, length prefix, or sequence byte is added by the transport [obs].
* Multi-packet commands carry their own packet index/count bytes, described per command below.
* Success means the reply echoes the command byte. In async mode the echo is at wire offset 1; in sync mode it is at offset 0 of the stripped buffer, which is the same wire position.

### WriteFile / ReadFile call-site inventory

| Site | Function | Target |
|---|---|---|
| WriteFile `0x469fad` | `HidWrite` 0x469f20 | **Keyboard (only device write)** |
| ReadFile `0x46a0e0` | `HidReadSync` 0x46a070 | **Keyboard (sync replies)** |
| ReadFile `0x46a493` | ServiceThread 0x46a400 | **Keyboard (async input reports)** |
| WriteFile `0x45894b`,`0x458976`,`0x458995` | 0x458930 | `mac.dct` macro file [obs string] |
| WriteFile `0x459053`,`0x45907a`; ReadFile `0x458ed0`… | 0x458fc0 etc. | profile `.pro` files ("Save pro/Load pro") |
| WriteFile `0x45930f`; ReadFile `0x459214`,`0x459412` | 0x459270 | `gSetting.dct` |
| WriteFile `0x459522` | 0x459460 | `Register.dct` |
| WriteFile `0x46d274` | 0x46d230 | debug dump `D:\recvbuf2.txt` |
| ReadFile `0x4194a7`…`0x41960a` | — | `.rak` profile import |
| ReadFile `0x43fdfc` | — | skin `.skn` file |
| ReadFile `0x457ebe`,`0x457f17` | — | game file |
| `0x479d21/0x479d5f`, `0x57ca9e`…`0x57d5d8` | library code | MFC/CRT file I/O, not device I/O [inf: no HID handle reaches it; no protocol strings nearby] |
| `0x5a0270`,`0x5a0284` | IAT slots | import thunks |

## 3. First command after detection; firmware version

1. **First HID command = GetPSD.** It is sent from the open routine `0x46a730` at `0x46a7fb`, synchronously, with a 1000 ms timeout:
   ```
   wire: 04 A0 02 00 01 00 00 … 00
   ```
   Built at `0x46b152`–`0x46b161`: payload `A0 02 00 01`, then `memset(payload+4, 0, 0x3b)` [obs].
   Reply (sync, report ID stripped): `reply[0]` must be `A0`. **`reply[4..6]` = device PSD** (`0x46b19a`–`0x46b1a6`), which is **wire bytes 5, 6, 7** of the input report [obs].
2. **The `Psd=0c,01,01` bytes are never sent.** They are only the *expected reply*: `0x46a804`–`0x46a81f` compares `reply[4],[5],[6]` with `0C,01,01` [obs]. A matching keyboard should answer roughly `04 A0 ?? ?? ?? 0C 01 01 …` [inf on bytes 1–3].
3. **Firmware version shown in the UI does not come from any protocol command.** It is the USB `bcdDevice`, read with `HidD_GetAttributes().VersionNumber` right after the Psd check (logged at `0x5d9ee8`) and stored at dev+0x10.
   * The UI formats it at `0x44a2c0`–`0x44a2e1` as `"V%X.%X.%X"` (`0x5d5bb8`) using `(v>>8)&0xF, (v>>4)&0xF, v&0xF`. For example, bcdDevice 0x0123 is shown as `V1.2.3` [obs].
   * `[0x6117a8]` is formatted with the same pattern, but it is the app/driver version (title bar at `0x405d35`), not the firmware version.

## 4. Command table

Bytes are **payload** bytes (prepend `04` for the wire). `async` is the SendData mode. Unless stated otherwise, the reply only has to echo the command byte.

| Cmd payload | Builder (log name) | Called from / UI feature | Reply |
|---|---|---|---|
| `A0 02 00 01` + 0×59 | `0x46b130` GetPSD | Device open `0x46a7fb`: handshake / model check | sync; `reply[4..6]` = PSD (see §3) |
| `A0 02 03 00…` | inline @ `0x46cecb` "ResetMatrix" | ApplySetting flag `0x20` (**Reset to default**): restores the default keymap | echo A0 |
| `A0 02 04 <pkt> 0E <layer> <54 data bytes>` … `payload[0x3c]=A5` | `0x46b2b0` SetMatrix | ApplySetting flag `0x01` (**key remap per layer**) `0x46c97e`. `pkt` runs 1..14 and `0x0E` is the total, so 14×54 = 756 (0x2f4) bytes per layer. `layer` = index+1 (index 3 → 5 when cfg+0x47a0 is set; `0x46c94e`–`0x46c95f`). The constant `0xA5` at payload[0x3c] (wire byte 61) is written at `0x46b341` [obs; purpose unknown, likely a trailer marker] | echo A0, async |
| `AA 00…` | inline @ `0x46c9d4` (log "FreeMacroID(0)") | Flag `0x01`, before macros are uploaded: frees all macro slots | echo AA, async |
| `A7 <id> <sz_hi> <sz_lo>` (sz = nSize+5) | `0x46b530` MallocMacroID | First step of SetMacro | async; **`reply[2]==0x01` = OK**, otherwise logs "has no memory" (`0x46b588`) [obs]. Reply[2] is wire byte 2 |
| `A8 <id> 00 <pkt 1..N> <N> <len≤0x39> <data>` | `0x46b3a0` SetMacro | Flag `0x01` (**macros**) `0x46cb4c`. Packets are sent with `Sleep(20)` between them | echo A8, async |
| `AE 01 00 00 <mode> <speed> <bright> <color>` | `0x46b5d0` SetLED | Flag `0x12` (**lighting mode / brightness / speed / color**) `0x46cd70`. Color codes: 0=multi/random, 1=0x0000FF, 2=0x00FF00, 3=0xFF0000, 4=0x00FFFF, 5=0xFF00FF, 6=0xFFFF00, 7=white (COLORREF compare at `0x46cba8`–`0x46cc17`). Brightness and speed come from the profile LED params (Dev.ini `LEDParam`: low nibble = brightness, high nibble = speed) | echo AE, async |
| `AE 01 00 00 <mode> <speed> <bright> FF` + `payload[8..]` = 13 × `[key\|0x80, R, G, B]`, list ends with `FF` | `0x46b5d0` per-key path ("SetLED(Game mode)") | Flag `0x10` (**per-key color / game mode**). Entries are built at `0x46ccf0`–`0x46cd40`. Packets reuse the same 8-byte header, with 52 data bytes each and `Sleep(10)`. No packet index is present [obs]. White 0xFFFFFF becomes 0xFFFFB4 when cfg+0x488b is set | echo AE, async |
| `AE 06 00…` | `0x46b1c0` ResetLED | Flag `0x20` (**Reset**), right after ResetMatrix @ `0x46cf1f` | echo AE, async |
| `B1 00 00 <pkt> <≤57 data>` | `0x46b800` SendMusicData | Music/audio-reactive lighting stream (caller is indirect [?]). `Sleep(3)` per packet | **none** (`SendNoReply`) |
| `B5 <tapOn> <tapTime> <debCnt> <debTime> <magicFN> <capsLED> 00 01` | `0x46b770` (log "SetKBParam") | Flag `0x60` @ `0x46c793` (**tap / debounce / MagicFN / CapsLock LED options**). `tapOn = (nTapOFF==0)`. Source fields are cfg+0x2d90..0x2d95. Timeout 500 ms | echo B5, async |
| `B6 <1\|2> 00 <pkt 0..> <≤59 data>` | `0x46ac70` SetKeyTrigger | Flag `0x80` "APPLY_SET_TRIGGER" (**per-key actuation / rapid-trigger**). Indirect call @ `0x46cdcd`, data at cfg+0x2ea4 | echo B6, async |
| `B6 <4\|5> 00 <pkt 0..> <≤59 data>` | `0x46af80` SetKeySensitiv | Flag `0x80`, indirect @ `0x46ce37`/`0x46ce82` ("Sensitivity(down)", "Sensitivity( up )"). Sub-command = 4 if arg2 != 0, otherwise 5 [obs]. Which value means up and which means down is [?] | echo B6, async |
| `B6 03 <enable> 00…` | `0x46ada0` AskTrigger | Reads the trigger table back (caller indirect [?]). Sent with `HidSend` directly | 3 input reports, each `04 B7 …`. **Data starts at wire offset 5**: 59 + 59 + 8 = 126 bytes (`0x46aea9`–`0x46aedc`) |
| **`A5 01 00…`** | **`0x46b230` ToBootloader** | **Firmware update** (see §5) | **none read** |

ApplySetting dispatcher: `0x46c630` ("CDevLWKB::ApplySetting", `0x5da578`). The `nFlag` bit tests are at `0x46c6ed` (0x80), `0x46c713` (0x60), `0x46c7aa` (0x01), `0x46cb69` (0x12), `0x46cc49` (0x10), `0x46cd92` (0x80) and `0x46cea1` (0x20).

## 5. ⚠️ Dangerous commands (bootloader, reset, flash)

| Command | Risk | Evidence |
|---|---|---|
| **`04 A5 01 00…` ToBootloader** | **Switches the keyboard into bootloader / firmware-update mode.** No reply is read, and the app immediately closes the handle | Builder `0x46b230` (bytes at `0x46b254`/`0x46b259`). Only caller is `OnStartUpdate` @ `0x44ba97` |
| Firmware flash (after A5) | **Firmware writes go through `UsbHid_v1.0.6.dll`, not OemDrv's protocol.** A thread (`0x44bb80`) waits 3 s, re-enumerates looking for **`vid_352d&pid_1101`** (bootloader device; `0x44bbed`–`0x44bc05`), then calls `userSetCfgFilePath` @ `0x44be47` and **`appUpdateFirmware(callback 0x44baf0)` @ `0x44bea2`** | DLL exports: `appUpdateFirmware` 0x10005be0, **`chipGoToBootFirmware`** 0x10005b50 (imported but never called from OemDrv), `userSetCfgFilePath` 0x10005d80. The DLL itself was not analyzed |
| Update gate | Update is offered when `nKbVer <= FwVerNeedToUpdate` (`0x442a6d`, `0x44ba28`) and `FwVerNeedToUpdate != 0` (`0x442a55`) | In this Dev.ini `FwVerNeedToUpdate` is commented out, so the automatic prompt is disabled |
| `A0 02 03` ResetMatrix | Erases user key mapping (writes defaults to keyboard storage [inf]) | `0x46cecb` |
| `AE 06` ResetLED | Resets lighting to defaults | `0x46b1c0` |
| `AA 00` FreeMacroID(0) | Deletes all on-device macros | `0x46c9d4` |
| `A0 02 04`, `A8`, `A7`, `AE 01`, `B5`, `B6 01/02/04/05` | Persistent configuration writes (likely stored in on-board flash/EEPROM [inf]) | see §4 |

Read-only and safe to probe in principle: `A0 02 00 01` (GetPSD) and `B6 03` (AskTrigger). Async input reports also arrive unsolicited.

## 6. Open items

* What the field at table entry +0x21c means (it must be 0 to select the device).
* The meaning of reply bytes 1–3 for GetPSD, and the full layout of reply data.
* Direct callers of SetKeyTrigger, SetKeySensitiv, AskTrigger and SendMusicData. They are called through the vtable, so the UI handler for each is not mapped.
* Mapping of B6 sub-commands 4/5 to "down"/"up" sensitivity.
* The meaning of the `A5` byte at payload[0x3c] in SetMatrix packets.
* The SetMatrix key-entry encoding (4 bytes per key [inf], matching Dev.ini `[KEY]` entries like `0x02,0x1B,0x00`). Converted by `0x46c0d0`/`0x46c540`/`0x46c580`; not decoded.
* `UsbHid_v1.0.6.dll` internals (the bootloader flashing protocol) were not analyzed.

---

## 7. Key trigger / rapid-trigger UI (`CKeyTriggerDlg`) and the B6/B7 commands

Static analysis only. No data was sent to any device. Sources: `objdump -d` of OemDrv.exe, the UI strings in `Text/*/text.xml`, and constants read from `.rdata`.
Dialog class name: `"CKeyTriggerDlg"` (`0x5cd6f8`). Below, `dlg` is the dialog `this` and `cfg` is the per-device settings block. All code accesses `cfg` through `[mainwnd+0x121c]` in the UI and through `ebp` in ApplySetting.

### 7.1 Per-key tables in `cfg` (all 0x84 = 132 bytes, indexed by key index)

| Offset | Meaning | Default (`0x458bbf`–`0x458bf3`) | Written by | Sent to device |
|---|---|---|---|---|
| `cfg+0x2e20` | "Enable secondary sensitivity" checkbox state (0/1) | 0 | checkbox `dlg+0x550` @ `0x41ded8` | **never** |
| **`cfg+0x2ea4`** | **Actuation point 1** (tenths of mm, 2..38) | **0x14 = 2.0 mm** | trigger slider thumb 1 @ `0x41dbcc`/`0x41dbff`; edit box @ `0x41e63f`/`0x41e6ac` | **B6 01**, 126 bytes |
| `cfg+0x2f28` | Actuation point 2 (thumb 2 of the same slider; = `0x2ea4 + 1*0x84`) | 0x14 | slider thumb 2 (same handler, `HIWORD(lParam)-1 == 1`); set to 8 when the checkbox is enabled (`0x41df0b`) | **never** (see 7.3) |
| **`cfg+0x2fac`** | **Rapid-trigger press ("Key down") sensitivity**, tenths of mm, 0..36; 0 = RT OFF | 0 | slider `dlg+0x1938` @ `0x41dcbe`/`0x41dce3` | **B6 04**, 126 bytes |
| **`cfg+0x3030`** | **Rapid-trigger release ("Key up") sensitivity**, tenths of mm, 0..36; 0 = RT OFF | 0 | slider `dlg+0x2d50` @ `0x41dd9e`/`0x41ddc0` | **B6 05**, 126 bytes |

**Key index.** The index is the byte at key-table entry +8 (entries are 0x14 bytes, table at `[[mainwnd+0x1238]+0x34]+0x18`). For example, the UI reads it as `movzx eax, byte [base + 4*(5*i) + 8]` @ `0x41d66a`. In `Dev/kb/M68/US/Dev.ini` the last field of every `K<n>=` line ranges from 21 to 119, all below 126, so this field is very likely that index [inf]. With 126-byte frames, byte *n* of every B6/B7 data block belongs to the key whose `[KEY]` index is *n*.

When several keys are selected (`[dlg+0x4194]+0x16a8[i] != 0`, used in the loops at `0x41dba0`, `0x41dca0`, `0x41dd80` and `0x41e620`), a change is written to every selected key.

### 7.2 UI value → byte conversion (Q1)

All three settings store the raw slider value as one byte, in units of **0.1 mm**. No scaling or offset is applied before sending.

* **Display.** Every label uses `fild value; fmul qword [0x5dadb0]` (0x5dadb0 = double 0.1, raw `000000a09999b93f`), then `swprintf(buf, L"%0.1fmm")`. The format string is at `0x5cd8c8`. Sites: `0x41d6f2`/`0x41d711` (paint), `0x41d969`–`0x41da59` (live drag), `0x41db20`, `0x41dc1a` and `0x41dcfe` (on change).
* **Actuation slider** (custom dual-thumb slider at `dlg+0x6e8`, class ctor `0x436d50`). The tick table is built at **`0x41cef0`–`0x41cefe`**: `for i in 0..36: tick[i] = i+2`. It is copied (0x94 bytes) into `dlg+0xc04` (= slider+0x51c) at `0x41cf1a`, with tick count 0x25 = 37 (`0x41cf2a`). Tick pixel positions are 8, 16, …, 0x128 (`0x41cf4a`–`0x41cf63`).
  → **Byte range 2..38 = 0.2 mm … 3.8 mm in 0.1 mm steps. Default 20 (2.0 mm).**
  The slider notifies the parent with message `0x801`: `wParam = tick value`, `lParam = (thumb# << 16) | ctrlID` (`0x436f94`–`0x436fcc`). The parent stores `wParam` directly (`0x41dbc9`).
* **Manual entry** (edit control; Enter key handler at `0x41e490`).
  1. `_wtof(text)` (`0x41e52a`), logged as `"fData=%f"` (`0x5cd8d8`).
  2. Range check **0.2 ≤ f ≤ 3.8**. The bounds are the doubles at **`0x5dada8` = 0.2** and **`0x5dada0` = 3.8** (`0x41e542`–`0x41e56b`).
  3. Out of range: posts `0x870` (`0x41e6c7`). That handler (`0x41e1a1`) shows the string at `0x626004`, which is consistent with `tc_comment8` *"The effective value range is 0.2 ~ 3.8"*.
  4. In range: **`byte = (int)(f * 10.0)`**. `0x5dad38` = 10.0; the conversion is `_ftol` (`0x573670`, `cvttsd2si`), so it **truncates** (`0x41e5ab`–`0x41e5b7`). Because of this, an input like `2.3` can become 22 instead of 23 through FP rounding [inf].
  5. Only actuation point 1 (`cfg+0x2ea4`) can be typed in.
* **Sensitivity sliders** (generic slider created by `0x450060`; down slider at `dlg+0x1938` with message 0x802, up slider at `dlg+0x2d50` with message 0x803).
  * Range **min = 0** and **max = 0x24 = 36**: the max is `push 0x24` @ `0x41d1a2`/`0x41d3ac`, stored at `0x450393`/`0x4503a4` (`slider+0x139c` = min, `+0x13a0` = max). The code asserts `max - min + 1 == 37` at `0x41d1e0`/`0x41d3ea`.
  * → **Byte 0..36 = 0.0 … 3.6 mm. Default 0.**
  * Label is `"%s %s"` (`0x5cd81c`) = name + `"(RT ON)"` (`tc_kb36`) if the position is non-zero, otherwise `"(RT OFF)"` (`tc_kb37`) (`0x41c2e4`–`0x41c3b9`). **0 disables rapid trigger** for that direction.
* **UI text pointers.** The `tc_kbN` text table starts at `0x625f48` (loader at `0x43f210`, format `tc_kb%d`). Relevant entries: `tc_kb31` "Enable secondary sensitivity" = `[0x625fc0]`, `tc_kb32` "Start tracking key stroke" = `[0x625fc4]`, `tc_kb33` = `[0x625fc8]`, `tc_kb34` "Key down sensitivity" = `[0x625fcc]`, `tc_kb35` "Key up sensitivity" = `[0x625fd0]`, `tc_kb36/37` RT ON/OFF = `[0x625fd4]`/`[0x625fd8]`.
* **No SetRange/SetPos (TBM_*) messages are used.** Both slider types are owner-drawn classes with their own tick tables, so there are no `msctls_trackbar` ranges to find.

### 7.3 Which sub-command is which (Q2)

ApplySetting flag `0x80` (`0x46cd92`) runs only if **`[gVar+0x47a0]` (Dev.ini `[OPT] ShowKeyTrigger`, read at `0x40e2f6`, stored at `0x40e315`) is non-zero**. It then runs these steps:

| Step | Code | Packet |
|---|---|---|
| `Sleep(25)` | `0x46cdb1` | |
| `vtbl+0x2c` = SetKeyTrigger(**sub=1**, `cfg+0x2ea4`, **0x7e**) | `0x46cdc2`–`0x46cdcd` | **B6 01** = actuation point 1 |
| PostMessage(hwnd, msg, 0x50, 0) (progress) | `0x46ce01` | |
| `Sleep(35)`; hexdump "Sensitivity(down):" of `cfg+0x2fac` | `0x46ce07`–`0x46ce1f` | |
| `vtbl+0x34` = SetKeySensitiv(`cfg+0x2fac`, 0x7e, **flag=1**) | `0x46ce30`–`0x46ce37` | **B6 04** = press (down) sensitivity |
| `Sleep(35)`; hexdump "Sensitivity( up ):" of `cfg+0x3030` | `0x46ce56`–`0x46ce6e` | |
| `vtbl+0x34` = SetKeySensitiv(`cfg+0x3030`, 0x7e, **flag=0**) | `0x46ce7b`–`0x46ce82` | **B6 05** = release (up) sensitivity |

The device vtable is at `0x5da908`: +0x20 = ApplySetting `0x46c630`, +0x24 = SendMusicData, +0x2c = SetKeyTrigger `0x46ac70`, +0x30 = AskTrigger `0x46ada0`, +0x34 = SetKeySensitiv `0x46af80`.

* **SetKeySensitiv sub-command** (corrects §4). The sub-command comes from **arg3**: `sub = (arg3 == 0) + 4` (`0x46afd1`–`0x46afd8`). So flag=1 gives **4 (down/press)** and flag=0 gives **5 (up/release)**. The down slider and the "Sensitivity(down)" log both use `cfg+0x2fac`, which confirms the mapping [obs].
* **B6 02 is never sent by this build.**
  * SetKeyTrigger accepts sub ∈ {1, 2} (`0x46ac95`–`0x46ac9d`).
  * The only call site found passes `push 0x1` (`0x46cdcb`).
  * The second actuation point (`cfg+0x2f28`) and the "secondary sensitivity" flag (`cfg+0x2e20`) are edited in the UI and saved, but are not transmitted.
  * It follows that B6 02 is the firmware slot for **actuation point 2** (second-stage trigger), carrying a 126-byte block in the same format [inf]. It is **not** a release or reset command. Release behaviour lives in B6 05.
* **UI quirks around point 2** [obs]:
  * The checkbox only enables thumb 2 when thumb 1's tick value is below 9. Otherwise it shows `tc_kb33` (`0x41de1a`–`0x41de2a`).
  * Enabling sets thumb 2 to tick value 9 but stores 8 (`0x41def0`–`0x41df0b`).
  * Repaint sets thumb 2 from `cfg[0x2f28]+1` (`0x41d675`–`0x41d689`), but dragging thumb 2 stores the raw tick value. The resulting off-by-one is harmless only because the value is never sent.
  * The slider forces thumb 2 deeper than thumb 1 (`0x436f16`–`0x436f20`).

### 7.4 Exact packet layout of B6 01/02/04/05 (Q5)

Both builders use the same loop (`0x46acc1`–`0x46ad31` and `0x46afe0`–`0x46b050`). Each iteration:

1. `Sleep(20)`.
2. `memset(buf, 0, 63)`.
3. `buf[0]=0xB6`, `buf[1]=sub`, `buf[2]=0`, `buf[3]=pkt` (pkt starts at 0).
4. `memcpy(buf+4, data+off, min(59, len-off))`.
5. `SendData(dev, buf, 1000 ms, async=1)`.
6. Abort if no `B6` echo, logging `"SetKeyTrigger: package %d failed."` / `"SetKeySensitiv: package %d failed."`.

There is no total-count byte and no checksum. With len = 0x7e = 126 the result is exactly **3 packets, 59 + 59 + 8**:

```
wire: 04 B6 <sub> 00 00 | data[  0.. 58]                 (59 bytes)
wire: 04 B6 <sub> 00 01 | data[ 59..117]                 (59 bytes)
wire: 04 B6 <sub> 00 02 | data[118..125] | 51 × 00       (8 bytes + zero pad)
        sub: 01 = actuation pt 1 (cfg+0x2ea4)   04 = press sens (cfg+0x2fac)
             02 = actuation pt 2 [unused]        05 = release sens (cfg+0x3030)
data[n] = setting for key index n, 1 byte, units 0.1 mm
        (pt: 2..38 ; sens: 0..36, 0 = RT off)
```

Only the first 126 of the 132 table bytes are sent. Bytes 126–131 stay local.

### 7.5 B6 03 / B7: live key-travel polling, not a settings read-back (Q3)

**AskTrigger** `0x46ada0`, arguments `(bEnable, outBuf, len)`:

* If `dev+0x14 != 0` it returns 1 immediately and sends nothing (`0x46adb6`).
* Otherwise it builds `B6 03 <bEnable!=0> 00…` (`0x46ae04`–`0x46ae22`), logs `"AskTrigger: bEnable=%x"`, and sends with `HidSend`, without going through SendData.
* **bEnable = 0**: no reply is read (`0x46ae8a`).
* **bEnable ≠ 0**: up to 3 reports are popped from the async ring (`PopReport`). Each must be 64 bytes with **`wire[1] == 0xB7`** (`0x46aead`). Otherwise it logs `"AskTrigger: Err bCmd[1]=%x, i=%d"`.
* Copy length per report is `i==2 ? 8 : 59` (`0x46aeb5`–`0x46aec1`). Data is taken **from wire offset 5** (`[esp+0x21]` = buf+5). It stops once `len` bytes are collected.
* B7 frame: `04 B7 ?? ?? ?? | 59 data bytes`. Bytes 2–4 are not checked [?]. They are probably sub/packet index, mirroring B6.

**Caller** = the key-trigger dialog. Checkbox `dlg+0x220` ("Start tracking key stroke", `tc_kb32`; handler `0x41df67` → `0x41e050`) controls it:

* **Start**: optional `0x436a80(0)` + `Sleep(100)`, then **`SetTimer(hwnd, 0x411, 30 ms)`** (`0x41e090`–`0x41e09d`).
* **Every tick** (OnTimer `0x41e120`): `memset(buf, 0x0A, 0x84)`, then **`AskTrigger(1, buf, 0x84)`** (`0x41e166`–`0x41e18e`). On success it calls `0x41d890`.
* **Stop** (unchecking, or page change via `0x454811`): `KillTimer(0x411)`, then **`AskTrigger(0, NULL, 0)`**, i.e. **`B6 03 00`** (`0x41e0b6`–`0x41e0ef`).

So **`B6 03 01` is a one-shot poll** that returns a 126-byte snapshot of **live key travel** for all keys. The app sends it every 30 ms while tracking. `B6 03 00` presumably tells the firmware to leave tracking mode [inf]. The command does **not** return stored actuation or sensitivity settings: nothing writes the reply into `cfg+0x2ea4`/`0x2fac`/`0x3030`.

**Display** (`0x41d890`):
* The 132-byte buffer is copied to `dlg+0x41bc`. Only the **currently selected key** (`dlg+0x41b8`, index from key-entry +8) is visualised.
* If `v = travel[idx] <= 1`, the marker is hidden (`slider+0xe88 = 0`).
* Otherwise the actuation slider draws a live position marker at the tick whose value equals **`v - 2`** (`0x41d904` → `0x438020`, which sets `slider+0xe84/0xe88`).
* So the live travel byte appears to be in 0.1 mm units with an offset of +2 (marker at (v−2)×0.1 mm), and it is shown only when `v-2` is in 2..38 [inf on the exact physical meaning of the offset].

### 7.6 Calibration (Q4)

There is nothing calibration-related in this build:

* **Strings.** No match in OemDrv.exe (ASCII or UTF-16), `UsbHid_v1.0.6.dll`, or any `Text/*/text.xml` for `calib`, `Calibr`, `zero`, `travel`, `actuat`, `rapid`, `校准`, `校正`, `归零` (searched as UTF-16, GBK and UTF-8). The only "range" string is the macro-sharing URL `querysharemacro.php?start=%d&range=%d`.
* **Commands.** B6 is used only with sub-commands 1, 2, 3, 4 and 5, and B7 is only parsed in AskTrigger. The other `0xB6`/`0xB7` immediates (`0x4ce9c4`, `0x4d2286`, …) are MFC exception-state bytes at `[ebp-4]`, not protocol code.
* **Skins.** No skin asset refers to calibration.

If the firmware supports calibration, it is triggered on the keyboard itself (for example by a key combination such as the `Fn2+4` reset in `tc_comment6`) and not through this app.

### 7.7 Updates to earlier sections

* §4 row `B6 <4|5>`: the sub-command comes from **arg3**: flag=1 → **4 = press/down**, flag=0 → **5 = release/up**.
* §4 row `B6 <1|2>`: only sub=1 (actuation point 1) is ever sent, with len 126 → 3 packets.
* §4 row `B6 03`: the caller is CKeyTriggerDlg's 30 ms timer 0x411 (live travel). It is not a settings read.
* §6 open items resolved: the callers of SetKeyTrigger / SetKeySensitiv / AskTrigger, and the 4/5 → down/up mapping.
* Still open:
  * B7 bytes 2–4.
  * The exact physical meaning of the "+2" offset in live travel values.
  * Whether firmware accepts B6 02.
  * Whether anything other than `0x46cdcd` calls vtable slot +0x2c. Only direct `push`-argument call sites were searched.
