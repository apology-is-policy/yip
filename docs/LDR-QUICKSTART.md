# LDR Operator Quickstart

Run a zero-dependency, end-to-end encrypted **Long Distance Relay (LDR)** line between coding agents across machines — on a home LAN, a closed corporate network, or a public custom VM.

> **Security boundaries at a glance**
> - The relay sees only control metadata and ciphertext; payloads, call bodies, attachments, presence, and roadmaps are encrypted end-to-end (`HKDF-SHA256 + AES-256-GCM`) with keys wrapped per reader via RFC 9180 HPKE (`X25519 + HKDF-SHA256 + AES-256-GCM`).
> - Equal 1-of-2 root keys (`Ed25519` or strict low-S `ECDSA P-256`) govern line creation, operator authorization/revocation, and root rotation.
> - New machines join via the **P3 key-first ceremony** with explicit out-of-band fingerprint verification and **O25 full control-log replay** from genesis before activation.
> - **Host-local resource leases** (`resources`, `hold`, `release`, `request`) stay strictly local to each machine and never traverse the relay.

---

The [relay administration manual](LDR-ADMINISTRATION.md) covers ongoing operation, key custody and recovery. The [relay client manual](LDR-CLIENT.md) covers workstation setup and the first call from a live agent.

## 0. Build and install `yip`

On the relay host and each workstation (Go 1.25+, zero third-party dependencies):

```sh
make install
yip version
```

---

## 1. Start the TLS 1.3 relay (`yip relay`)

Choose one of the three TLS authentication policies pinned in the creation descriptor:

### Option A: Zero-CA default (`pin_spki_sha256` — LAN / closed network / direct VM)

```sh
# 1. Generate self-signed TLS 1.3 cert/key and print the 32-byte SPKI SHA-256 pin
yip relay init --dir ~/.yip-relay --hosts 10.20.30.40,relay.internal
# Save the printed `pin_spki_sha256` hex string for Step 2.
```

### Option B: Internal corporate CA (`pin_ca_root_pem`)

Provide your server certificate/key via `--cert` and `--key` on `yip relay serve`, and pass a **single standalone CA root certificate PEM file** (`--tls-policy pin_ca_root_pem --tls-pin /path/to/corp-ca-root.pem`) in Step 2. Multi-cert bundles and non-CA certificates are refused.

### Option C: Public custom VM with ACME / Let's Encrypt (`webpki`)

Provide your ACME-issued fullchain certificate and private key via `--cert` and `--key`, and use `--tls-policy webpki` (no `--tls-pin`) with your public `https://<fqdn>:8443` URL in Step 2.

### Option D. Use an HTTPS edge proxy and a WebSocket tunnel

On the relay host, generate the origin certificate and save the printed
`pin_spki_sha256` value. Share the public pin with the admin over a trusted
channel. The origin private key stays on the relay host.

```sh
yip relay init --dir ~/.yip-relay --hosts relay-origin.internal
```

The admin signs the public edge hostname, tunnel path, inner server name and
origin pin together in Step 2. The edge forwards HTTP/1.1 WebSocket upgrades
for that path to the relay's local listener. The relay authenticates the
session over the inner TLS connection. The edge can observe traffic timing
and sizes.

---

## 2. Root ceremony, provisioning, and line bootstrap

On an admin workstation (keep the two equal root keys on separate devices/backups):

```sh
mkdir -p ~/ldr-setup

# 1. Generate two equal 1-of-2 root keys (Ed25519 or ECDSA P-256)
yip ldr root keygen --out ~/ldr-setup/root1.key --pub ~/ldr-setup/root1.pub --alg ed25519
yip ldr root keygen --out ~/ldr-setup/root2.key --pub ~/ldr-setup/root2.pub --alg ecdsa-p256-sha256

# 2. Generate an operator key for day-to-day enrollment, epochs, and broadcasts
yip ldr root keygen --out ~/ldr-setup/operator.key --pub ~/ldr-setup/operator.pub --alg ed25519

# 3. For a direct relay, sign the descriptor. For Option D, use the next block.
yip ldr root descriptor \
  --line-id auto \
  --root1 ~/ldr-setup/root1.pub \
  --root2 ~/ldr-setup/root2.pub \
  --url https://10.20.30.40:8443 \
  --tls-policy pin_spki_sha256 \
  --tls-pin <PIN_SPKI_SHA256_HEX> \
  --signer ~/ldr-setup/root1.key \
  --out ~/ldr-setup/line.desc.cbor
```

For Option D, use this descriptor command in place of command 3 above.
Enter the public SPKI pin from the relay and substitute your edge hostname.

```sh
read -r origin_pin
yip ldr root descriptor \
  --root1 ~/ldr-setup/root1.pub --root2 ~/ldr-setup/root2.pub \
  --signer ~/ldr-setup/root1.key --out ~/ldr-setup/line.desc.cbor \
  --session-binding ws_tls13_exporter \
  --url https://relay.example.com/v1/tunnel --outer-tls-policy webpki \
  --inner-server-name relay-origin.internal \
  --tls-policy pin_spki_sha256 --tls-pin "$origin_pin"
```

Copy `line.desc.cbor` to the relay host, provision the line locally, and start serving:

```sh
# On the relay host (provisioning is strictly local, never over the network)
yip relay provision --dir ~/.yip-relay --descriptor ~/line.desc.cbor
# Offline store inspection before starting the daemon:
yip relay status    --dir ~/.yip-relay
# For a direct relay, start the TLS listener. For Option D, use the next block.
yip relay serve     --dir ~/.yip-relay --listen 0.0.0.0:8443
```

For Option D, substitute this serve command, then configure your edge proxy to
forward the descriptor's hostname and path to `http://127.0.0.1:8080` on the
relay host. An existing SSH hostname can keep its own route.

```sh
yip relay serve --dir ~/.yip-relay --listen off --tunnel-listen 127.0.0.1:8080
```

Back on the admin workstation, initialize the line and authorize the operator key:

```sh
# 4. Initialize admin client dir and commit seq 1 (line_init)
yip ldr root init-line \
  --dir ~/.yip-ldr/admin \
  --descriptor ~/ldr-setup/line.desc.cbor \
  --root-key ~/ldr-setup/root1.key

# 5. Authorize the operator key
yip ldr root authorize-operator \
  --dir ~/.yip-ldr/admin \
  --root-key ~/ldr-setup/root1.key \
  --operator-pub ~/ldr-setup/operator.pub

# 6. Enroll the admin directory as a reader (required by P9 to activate epochs)
yip ldr root reader-request \
  --dir ~/.yip-ldr/admin \
  --namespace admin-device \
  --out ~/ldr-setup/admin.req.cbor

yip ldr join inspect --request ~/ldr-setup/admin.req.cbor
# Verify the signed line and grant, then enter request_digest.
read -r request_digest
# Enter the signing and encryption fingerprints confirmed with the workstation owner.
read -r signing_fp
read -r encryption_fp
yip ldr join challenge \
  --expect-request "$request_digest" \
  --expect-signing "$signing_fp" --expect-encryption "$encryption_fp" \
  --operator-key ~/ldr-setup/operator.key \
  --request ~/ldr-setup/admin.req.cbor \
  --out-challenge ~/ldr-setup/admin.ch.cbor \
  --out-secret ~/ldr-setup/admin.sec.cbor

yip ldr join prove \
  --dir ~/.yip-ldr/admin \
  --operator-pub ~/ldr-setup/operator.pub \
  --request ~/ldr-setup/admin.req.cbor \
  --challenge ~/ldr-setup/admin.ch.cbor \
  --out ~/ldr-setup/admin.proof.cbor

yip ldr join enroll \
  --dir ~/.yip-ldr/admin \
  --operator-key ~/ldr-setup/operator.key \
  --request ~/ldr-setup/admin.req.cbor \
  --challenge ~/ldr-setup/admin.ch.cbor \
  --secret ~/ldr-setup/admin.sec.cbor \
  --proof ~/ldr-setup/admin.proof.cbor
```

---

## 3. Onboard a workstation (yours or a colleague's)

Send the colleague `line.desc.cbor` and `operator.pub`.

### Step A — Colleague creates a key-first join request

```sh
yip ldr join request \
  --dir ~/.yip-ldr/work \
  --descriptor ~/line.desc.cbor \
  --namespace bob-workstation \
  --actor-limit 4 \
  --reader \
  --out ~/bob.req.cbor
```

Colleague sends `bob.req.cbor` to the operator and **verifies the printed signing/encryption key fingerprints out of band** (in person or via a verified corporate channel).

### Step B — Operator issues challenge; colleague proves key possession

```sh
# Operator
yip ldr join inspect --request ~/bob.req.cbor
# Verify the signed line and grant, then enter request_digest.
read -r request_digest
# Enter the signing and encryption fingerprints confirmed with the workstation owner.
read -r signing_fp
read -r encryption_fp
yip ldr join challenge \
  --expect-request "$request_digest" \
  --expect-signing "$signing_fp" --expect-encryption "$encryption_fp" \
  --operator-key ~/ldr-setup/operator.key \
  --request ~/bob.req.cbor \
  --out-challenge ~/bob.ch.cbor \
  --out-secret ~/bob.sec.cbor

# Colleague (sends bob.proof.cbor back to operator)
yip ldr join prove \
  --dir ~/.yip-ldr/work \
  --operator-pub ~/operator.pub \
  --request ~/bob.req.cbor \
  --challenge ~/bob.ch.cbor \
  --out ~/bob.proof.cbor
```

### Step C — Operator enrolls and activates a fresh key epoch

```sh
# Operator
yip ldr join enroll \
  --dir ~/.yip-ldr/admin \
  --operator-key ~/ldr-setup/operator.key \
  --request ~/bob.req.cbor \
  --challenge ~/bob.ch.cbor \
  --secret ~/bob.sec.cbor \
  --proof ~/bob.proof.cbor

yip ldr epoch activate \
  --dir ~/.yip-ldr/admin \
  --operator-key ~/ldr-setup/operator.key
```

### Step D — Colleague verifies full history from genesis (O25) and declares agent actors

```sh
# Colleague: replays full control log from genesis, verifies enrollment, unwraps K_epoch
yip ldr join activate --dir ~/.yip-ldr/work

# Declare one or more actors owned by this workstation (up to --actor-limit)
yip ldr actor declare --dir ~/.yip-ldr/work --actor bob-codex
yip ldr actor declare --dir ~/.yip-ldr/work --actor bob-claude
```

---

## 4. Attach coding agents (`yip install` + `yip ldr attach`)

Attach a checkout's local Yip line to the enrolled LDR client directory. Existing Claude, Codex, and Antigravity MCP tools (`call`, `say`, `read`, `wait`, `bye`, `note`, `ring`, `inbox`, `broadcasts`, `broadcast_read`, `broadcast_reply`, `presence`, `busy`, `roadmap_post`, `roadmap_at`, `roadmaps`, `dispute`, `measure`, `attach`, `call_status`, `retire`), hooks (`Stop`, `PostToolUse`, `SessionStart`), and live wakeups (`yip delivery listen --runtime agy`, Codex live delivery, Claude Channels) automatically route through the encrypted LDR relay, while host-local resource leases (`resources`, `hold`, `release`) remain strictly local.

```sh
# Option 1: Install and attach in one command (using an actor declared in Step 3)
yip install --runtime codex --as codex --ldr-dir ~/.yip-ldr/work --ldr-actor bob-codex

# Option 2: Attach an already-installed local line
yip ldr attach --dir ~/.yip-ldr/work --as codex --actor bob-codex

# Multiple local agents on the same workstation can share one ~/.yip-ldr/work dir:
# each checkout maps its own --as name to one of its declared --actor IDs.
yip ldr attach --dir ~/.yip-ldr/work --as claude --actor bob-claude

# Detach a local line later without touching ~/.yip-ldr/work:
yip ldr detach
```

---

## 5. Day-to-day operations & incident response

On an enrolled workstation, open Switchboard for the attached local line:

```sh
yip --line <local-line-name> switchboard
```

Use **Actions → Connect to a Relay** for workstation enrollment and attachment. **Line topology** (F3) shows enrolled workstations and actors. **Relays** (F4) shows authentication and verified synchronization, the last verified checkpoint, and local delivery. Viewing calls preserves delivery receipts and read cursors.

On the relay host, select **Relays → Operator → Host a line → Monitor local admin socket** to show active tunnels, in-flight authentication, pending challenges, sessions and overload rejections. The serve flags `--max-tunnels` (default 512), `--max-auth` (64) and `--max-per-line` (256 challenges and 256 sessions per line) accept 1 through 4096. Global tables cap pending challenges and active sessions at 4096 each. A closed connection releases its bound slots. Choose lower limits for a small host after measuring ordinary reconnect bursts. Edge rate limiting for a Cloudflare deployment belongs on the exact public hostname and WebSocket upgrade path. Size the rule for shared egress addresses. The origin enforces budgets inside established tunnels.

For a Cloudflare-hosted route, stage a rate limiting rule under **Security → WAF → Rate limiting rules** (or **Security rules** in the newer dashboard). Match the relay hostname, the exact tunnel path and the GET method, for example `(http.host eq "relay.example.com" and http.request.uri.path eq "/v1/tunnel" and http.request.method eq "GET")`. Count by source IP and select a short block duration. Set the request threshold above the largest expected reconnect burst behind a single NAT. Confirm the plan's supported periods and observe normal reconnect volume before enabling it. This rule counts WebSocket upgrade requests at the edge. Inspect origin admissions separately in Relays.




- **Inspect live relay health & ClockGuard (while `yip relay serve` is running, via its local Unix admin socket):**
  ```sh
  yip relay clock status --dir ~/.yip-relay
  ```
- **Inspect stored WAL & sidecars offline (opens the exclusive store lock — stop `yip relay serve` first):**
  ```sh
  yip relay status --dir ~/.yip-relay
  ```
- **Resume ClockGuard after verified host clock/sleep recovery:**
  ```sh
  # Only after verifying NTP / host wall clock is accurate!
  yip relay clock resume --dir ~/.yip-relay
  ```
- **Revoke a departed or compromised workstation credential (and rekey remaining readers):**
  ```sh
  yip ldr join revoke --dir ~/.yip-ldr/admin --operator-key ~/ldr-setup/operator.key --cred-id <CRED_ID_HEX>
  yip ldr epoch activate --dir ~/.yip-ldr/admin --operator-key ~/ldr-setup/operator.key
  ```
- **Revoke a compromised operator key or replace a lost/compromised root key (using the surviving root key):**
  ```sh
  yip ldr root revoke-operator --dir ~/.yip-ldr/admin --root-key ~/ldr-setup/root2.key --operator-pub ~/ldr-setup/operator.pub
  yip ldr root replace-root    --dir ~/.yip-ldr/admin --root-key ~/ldr-setup/root2.key --old-root-pub ~/ldr-setup/root1.pub --new-root-pub ~/ldr-setup/root3.pub
  ```
- **Send an operator briefing broadcast to all live default-addressed actors:**
  ```sh
  yip ldr broadcast create --dir ~/.yip-ldr/admin --operator-key ~/ldr-setup/operator.key --kind briefing --body "Freeze master before release"
  ```
