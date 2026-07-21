# amnezia-client — unauthenticated local privilege escalation via IPC to root service

## Iteration 1 — 2026-07-20 — Falsifier + Exploit-analyst

Target: AmneziaVPN desktop (`~/c/amnezia-client` @ d656031f). Split-privilege architecture:
unprivileged Qt GUI ↔ **root/SYSTEM** background service (`service/server/`). Trust boundary here is
the *local privilege boundary* — the IPC socket between an ordinary local user and root. Attacker =
any local unprivileged process/user. No user interaction, no config import.

### Map / what feeds this surface (all [V])
- The root service `LocalServer` opens a `QLocalServer` at `getIpcServiceUrl()` (=`/tmp/{IPC_SERVICE_URL}`
  on *nix; a named pipe on Windows) with **`QLocalServer::WorldAccessOption`**
  `[V service/server/localserver.cpp:28-31]` — socket reachable by **any local user**.
- On **every** new connection it unconditionally `addHostSideConnection(...)` +
  `enableRemoting(&m_ipcServer)` — **no auth, no peer-credential check, no token**
  `[V service/server/localserver.cpp:36-44]`.
- `IpcServer::createPrivilegedProcess()` has no caller check either `[V ipc/ipcserver.cpp:31-65]`;
  it spawns a per-process `QRemoteObjectHost` node also set `WorldAccessOption` `[V ipcserver.cpp:41]`.
- A client sets the program by enum id → `permittedProcessPath` (whitelist: OpenVPN / Wireguard /
  Tun2Socks / CertUtil) `[V ipc/ipc.h:13-35, ipc/ipcserverprocess.cpp:78-82]`.
- Arguments go through `sanitizeArguments(program, args)` `[V ipcserverprocess.cpp:56-59]`, **but** the
  validator switch only covers `Tun2Socks`; the `default:` case (**OpenVPN, Wireguard, CertUtil**) is
  `//FIXME return args;` — **arguments returned UNSANITIZED** `[V ipc/ipc.h:59-67]`.
- `m_process->start()` then runs the whitelisted binary as root `[V ipcserverprocess.cpp:37]`.

### Candidates examined
- **Unauth local → root code exec via unsanitized OpenVPN args.** SURVIVES every kill attempt:
  socket is WorldAccess `[V]`, no auth on connect `[V]`, no auth in createPrivilegedProcess `[V]`,
  OpenVPN args unsanitized `[V ipc.h:64-66]`.
- Tun2Socks arg injection — KILLED: `-device` must be `tun://`, `-proxy` must be `socks5://`
  `[V ipc.h:60-63]` (only Tun2Socks is actually validated).

### Confirmed findings
- **AMNEZIA-2: Unauthenticated local privilege escalation to root via world-accessible IPC +
  unsanitized privileged-process arguments.**
  - Class / Reach / Rating: **DIV (broken local authz) → command exec as root** · **R2** (full path
    hand-traced `[V]`, not executed) · **Critical** (unauth local→root; no user interaction).
  - Path: any local user → connect `/tmp/{IPC_SERVICE_URL}` (WorldAccess, no auth)
    `[V localserver.cpp:29-44]` → `createPrivilegedProcess()` `[V ipcserver.cpp:31-65]` → connect the
    returned world-access node → `setProgram(OpenVPN)` `[V ipcserverprocess.cpp:78-82]` →
    `setArguments(["--config","/tmp/attacker.ovpn"])` → `sanitizeArguments` default returns them
    unmodified `[V ipc.h:64-66]` → `start()` runs `openvpn --config /tmp/attacker.ovpn` as root
    `[V ipcserverprocess.cpp:37]` → attacker `.ovpn` with `script-security 2` + `up "/bin/sh -c …"`
    ⇒ **arbitrary command execution as root/SYSTEM**.
  - Attacker/control/precond/impact/confidence: attacker = any local unprivileged user; controls the
    program id (from whitelist) and, for OpenVPN/Wireguard/CertUtil, the **full argument vector**;
    precondition = the Amnezia service is installed and running (its normal state); impact = root/SYSTEM
    code execution = complete local compromise; confidence HIGH on mechanism (deterministic), R2 not
    executed.
  - Directly-exposed root primitives also abusable by any local user without the arg trick (network
    DoS / manipulation): `routeAddList`, `routeDeleteList`, `createTun`/`deleteTun`, `updateResolvers`,
    `restoreResolvers`, `enableKillSwitch`/`disableAllTraffic`, `xrayStart(cfg)` `[V ipcserver.cpp:67-323]`.
  - Fix (proposed): (1) drop `WorldAccessOption` — restrict the socket to the installing user / verify
    peer credentials (SO_PEERCRED / GetNamedPipeClientProcessId) on connect; (2) implement
    `sanitizeArguments` for **all** permitted processes (remove the `default: return args` FIXME),
    whitelisting only the exact flags each backend needs and validating `--config` path provenance;
    (3) do not allow client-chosen `--up`/`--script-security`/config for the privileged openvpn.

### Relationship to AMNEZIA-1
Distinct attacker model. AMNEZIA-1 (`dev/openvpn-config-injection/`) = remote-ish: victim imports a
shared malicious config, then connect → root exec. AMNEZIA-2 = purely local: any unprivileged user →
root, no user interaction, no import. AMNEZIA-2 is the more severe (Critical vs High). Both share the
root sink (privileged `openvpn` with attacker-influenced config/args) and the same missing-filter root cause.

### Open / next
- R2→R0: build the service, connect a raw QtRO client (or `nc`/socket script) to `/tmp/{IPC_SERVICE_URL}`
  as an unprivileged user, drive createPrivilegedProcess→OpenVPN→args, confirm root `up` exec. Not done.
- Windows named-pipe DACL under WorldAccessOption: confirm it grants Everyone (same LPE vs SYSTEM).

## Iteration 2 — 2026-07-21 — fix applied (item 2 of 3)

Applied proposed fix item (2) — `ipc/ipc.h`'s `sanitizeArguments` no longer has a
`default: //FIXME return args;` passthrough. Every `PermittedProcess` case is now an
explicit whitelist:
- **OpenVPN:** `--config <path>` (must exist, no shell metacharacters in the path string),
  `--management <host> <port>` (both tokens restricted to `[A-Za-z0-9.:_-]+`),
  `--management-client` (flag). Matches exactly what `openvpnprotocol.cpp` passes.
  Anything else — `--up`, `--down`, `--plugin`, `--script-security`, arbitrary extra
  flags — is now silently dropped instead of reaching `argv`.
- **CertUtil:** `-f`, `-importpfx` (flags), `-p <password>` (opaque, not shell-parsed),
  `<filename>` (must exist) + `NoExport` (positional, in that order). Matches
  `ikev2_vpn_protocol_windows.cpp` exactly.
- **Wireguard:** no caller in this checkout drives it through `createPrivilegedProcess()`
  (grep-confirmed) — now denies by default (`return {}`) instead of the previous
  unconditional passthrough.

Verified by compiling the new logic against real Qt6 headers (`pkg-config Qt6Core`) with
four cases: legit OpenVPN args pass through unchanged; an injected
`--up "/bin/sh -c evil" --script-security 2` is fully stripped, leaving only `--config`;
legit CertUtil args pass through unchanged; Wireguard args now come back empty.

**What this does and doesn't close:** this closes arbitrary-CLI-flag injection via the
IPC layer — an attacker who reaches `createPrivilegedProcess()` can no longer add
`--up`/`--plugin`/etc regardless of what they pass. It does **not** close the
config-*content* variant of this attack chain: OpenVPN's `--config` path is a
`QTemporaryFile` under the OS temp directory (`m_configFile` in
`openvpnprotocol.cpp`), which is not distinguishable from an attacker-planted file by
path alone (both live in `/tmp`), so restricting `--config` to a "trusted directory"
isn't meaningful with the current architecture. Closing that fully needs proposed fix
item (1) — peer-credential verification on the IPC socket, so only the legitimate GUI
process can reach `createPrivilegedProcess()` at all — which was not attempted this
iteration; item (1) remains open, as does the R2→R0 promotion above.

**Status: PARTIALLY FIXED** (item 2 of 3 proposed fixes applied and verified against real
Qt6; items 1 and 3 — socket peer-auth, and the deeper config-content vector — remain
open). Pushed to `origin` (gearonixx/amnezia-client) on branch
`fix/ipc-sanitize-arguments`.
