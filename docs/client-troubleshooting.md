# When a client cannot connect

A client that will not connect looks the same from the outside whatever is
wrong: the node is in the list, the app says it is set up, and no traffic
moves. The three causes below have nothing to do with each other, and each one
has its own check. This page is the order to work through them in.

- [§1 The device key belongs to the device](#1-the-device-key-belongs-to-the-device)
  — the handshake is refused, because the credential on file is not the one the
  client presents.
- [§2 The 2FA switch says off while an enrollment is pending](#2-the-2fa-switch-says-off-while-an-enrollment-is-pending)
  — the node holds a token, not a credential.
- [§3 The service is a different binary from the app](#3-the-service-is-a-different-binary-from-the-app)
  — the traffic goes through a build that is not the one on screen.
- [§4 The logs](#4-the-logs) — where each side writes, and which lines matter.

## 1. The device key belongs to the device

The server files a credential per **device** — not per client, and not per
endpoint:

```toml
[auth.clients.client-001]
secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"        # the credential of the device that names none

[auth.clients.client-001.devices.laptop-7f3a9c21]
public_key = "…"                   # a device that proves itself with a key
created_at = "1723756800"
```

A device answers a handshake with either the TOTP secret filed under its name,
or an Ed25519 signature over the challenge, which the server verifies against
the public half it holds. The private half never leaves the device — not even
at enrollment.

**The name is the device's own, and it does not move.** The desktop derives it
from the machine's hostname plus a random code (`laptop-7f3a9c21`); the Android
app derives one from the device model plus a code. Both keep it rather than
making a new one per launch, because a name that changed every time would leave
the server holding an entry for every device the machine had ever claimed to
be.

**The endpoint is not part of that identity.** The credential belongs to a
client, and a client lives in one server's configuration. Point the same
machine at another server and it is a different client *there*: the new server
has no row for it, so the handshake is refused — and refusing it is right,
because the row the old server holds is the one that says what this device may
do.

So, when the server changes:

| What changed | What the server sees | What to do |
| --- | --- | --- |
| The endpoint — another server, or the same one rebuilt | another client id; no row for this device | enroll again against the new server, **with the same key** |
| The device name — a renamed host, or a reinstall that lost it | another device | the old row is dead weight: `nexapipe client revoke <client> --device <old name>` |
| The client id | another client | `nexapipe client list` shows what exists |

**The key follows the device, not the node.** The private half is a property of
the machine: the desktop keeps one machine-wide key and each node's own copy of
it, the Android app keeps the same shape. Three rules follow, and they are what
the client does when it enrolls:

- A node that already enrolled with a key keeps **that** key. Offering another
  one would make the node a different device to the server, and the server
  refuses an enrollment that tries to take over a device that is already there.
- A node with no key of its own uses the **machine's** key, so a second server
  this machine enrolls with is answered with the same key rather than a new one.
- A machine with no key at all mints one — for the machine, not for a node.

That is why the device name does not follow the server: the name is the
machine's, the key is the machine's, and the endpoint id the server answers to
changes when the server is rebuilt or replaced. A node that answers a rebuilt
server with a different key is a different device to it, and is refused as a
takeover.

**How to check.** `nexapipe client list` prints the clients and the devices
under each, with no secret in the output:

```bash
nexapipe client list --config config.toml
```

The server's access log says the same thing per request, in the last two
fields — `client=acme device=laptop-7f3a9c21` — which is the quickest way to
see which device the server thinks the caller is.

**How to recover.** Free the name, then enroll again:

```bash
nexapipe client revoke client-001 --device laptop-7f3a9c21 --config config.toml
```

The client's own error says the same thing when the server refuses the
enrollment: *"… (client 'client-001', device 'laptop-7f3a9c21'; if that device
is already enrolled on the server, an operator can free it with `nexapipe client
revoke client-001 --device laptop-7f3a9c21`)"*.

Enrolling again needs a fresh invite: the token in an invite is one-time, and
the server burns it in the same write that issues the credential.

## 2. The 2FA switch says off while an enrollment is pending

A node's 2FA has three states, not two:

| State | What it means |
| --- | --- |
| off | the node holds no credential, and is not waiting for one |
| pending | the node holds a one-time enrollment token that the server has not answered yet |
| on | the node holds a credential — a secret, or a key together with the device name it was issued to |

**Pending is not off.** A token is not a credential: it is a claim on one. The
server answers it with a freshly issued secret — or files the public half of
the key the client offered — and burns the token in the same write. Until that
answer arrives the node cannot answer a handshake, so a switch that reads "off"
says "nothing is missing here" when something is.

Since v1.0 both apps draw that state as *pending* rather than as *off*, and the
desktop's node card says which of the three it is showing.

**What to do.** Let the node connect once: the enrollment is retried on the
next attempt, and the credential arrives with the answer. If the token was
already spent — the server says so, and the client logs *"Enrollment succeeded
for client 'client-001'; the token is spent"* only when it worked — a new
invite is needed, because a token cannot be spent twice.

## 3. The service is a different binary from the app

This one is Windows-only, and it is the one that hides longest, because the app
on screen is the new build while the traffic goes through the old one.

**The shape of it.** The desktop app installs per user, into
`%LOCALAPPDATA%\nexa`, and ships a second binary beside it:
`nexa-service.exe`. The service itself runs as LocalSystem, so the binary it
runs must not be writable by the user who installed the app — a replaced
service binary is a program of the user's choosing running as SYSTEM. The app
therefore copies that binary to

```text
C:\Program Files\Nexa\Service\nexa-service.exe
```

and points the control manager at the copy (`sc config nexa-service binPath= …`).

**Why an upgrade leaves the two out of step.** An upgrade replaces the app's
own files. The system-wide copy is the app's to replace, and it is replaced
when the service is registered again — which is what the Settings page does.
So the file on screen and the file the control manager starts can be two
different builds.

**The symptom.** The handshake fails in a way the new code cannot produce. The
old client opened a *second* stream for the handshake after its enrollment, and
the server — which had already read the connection's first stream and decided
what it carried — read that stream's bytes as an HTTP request. The client's own
log says it like this:

```text
Enrollment succeeded for client 'win11'; the token is spent
Authenticating connection with 2FA as client 'win11'
2FA authentication failed: auth message length 1347703880 is out of range
```

The middle line is the give-away on its own: a client that has just enrolled
does not authenticate a second time. The last line is what the client saw when
the server closed that stream — the server's own log says `the connection ended
in error: invalid HTTP method parsed`, because the bytes it was sent were not
an HTTP request, and the answer the client got back was not an auth message.

**How to check.** Compare the two files:

```powershell
Get-FileHash "$env:LOCALAPPDATA\nexa\nexa-service.exe"
Get-FileHash "C:\Program Files\Nexa\Service\nexa-service.exe"
```

Two different hashes mean the service is running the other build.

**How to fix.** Register the service again from the Settings page: it copies
the current service binary over the system-wide copy, re-points the entry at
it, and starts it. If the page is not available, do it by hand, elevated:

```powershell
Copy-Item "$env:LOCALAPPDATA\nexa\nexa-service.exe" "C:\Program Files\Nexa\Service\nexa-service.exe" -Force
sc.exe stop nexa-service
sc.exe start nexa-service
```

and keep the permissions the app gives that file — SYSTEM and the
administrators may write it, ordinary users may only read and execute:

```powershell
icacls "C:\Program Files\Nexa\Service\nexa-service.exe" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "*S-1-5-32-545:RX"
```

A service binary the ordinary user can write is a program of the user's
choosing running as SYSTEM, so the copy under Program Files is the point of
the whole arrangement rather than a detail.

## 4. The logs

| Side | Where |
| --- | --- |
| Desktop app | `%APPDATA%\nexa\logs\nexa.log.YYYY-MM-DD` on Windows, `$XDG_STATE_HOME/nexa/logs/nexa.log.YYYY-MM-DD` on Unix |
| Windows service | `%PROGRAMDATA%\nexa\logs\nexa-service.log.YYYY-MM-DD` |
| Unix service | `/var/log/nexa-service/` |
| Android | `adb logcat`, filtered on the app's tags — or `nexa_vpn_log.txt` when `run_android.ps1` drove the build |
| Server | the `[log] dir` of `config.toml`; `NEXAPIPE_LOG_DIR` overrides it |

Files rotate daily, and `RUST_LOG` sets the level.

The lines that matter:

| Line | Where | What it means |
| --- | --- | --- |
| `Enrollment succeeded for client 'client-001'; the token is spent` | client | the enrollment worked and the token cannot be used again |
| `Authenticating connection with 2FA as client 'client-001'` | client | a handshake on a fresh stream — right after an enrollment this means the client is an older build (§3) |
| `auth message length 1347703880 is out of range` | client or server | the peer sent something that is not a handshake message |
| `2FA authentication failed: …` | client | the handshake was refused; the detail says why |
| `Authentication failed for <peer id>: …` | server | the same refusal, from the other side |
| `the connection ended in error: invalid HTTP method parsed` | server | the connection carried something that was not an HTTP request |
| `No reachable backend out of 1 probed node(s)` | desktop | the proxy found no endpoint it could use |
| `client=acme device=laptop-7f3a9c21` | server access log | which client and which device the server thinks the caller is |

The server's clock and the client's clock are compared when a code is
refused, and a device whose clock has drifted far enough answers with a code
the server rejects as expired rather than as wrong — so a refusal right after a
scan is worth a look at the clock before anything else.

## See also

- [Device keys](../README.md#device-keys) — what a key device is, and how one
  is registered.
- [Endpoint invites](../README.md#endpoint-invites) — how an invite is made,
  and what `--registration` changes.
- [`nexapipe client`](../README.md#nexapipe-client) — the commands that list,
  add and revoke credentials.
