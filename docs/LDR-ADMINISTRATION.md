# Yip relay administration manual

Use this manual to put a project line into service, admit colleagues, keep the relay running, and handle loss of a host or key. It describes the commands shipped with this release. A successful installation ends with two independently enrolled workstations exchanging an encrypted call and receiving a reply after reconnect. Opening a port is only the first of those checks.

| If you are here to… | Start here |
|---|---|
| Plan a deployment or decide who holds the keys | [Roles and records](#roles-and-records) |
| Install the service and choose its network path | [Prepare the host](#prepare-the-host) and [Choose the transport](#choose-the-transport) |
| Bring up the first line | [Sign the descriptor](#sign-the-descriptor), [Run the service](#run-the-service), then [Bootstrap authority](#bootstrap-authority) |
| Add a colleague or set up their agent | [Enroll a workstation](#enroll-a-workstation) and the [client manual](LDR-CLIENT.md) |
| Inspect the relay, change membership, or respond to loss | [Operate the relay](#operate-the-relay), [Keys and departures](#keys-and-departures), [Backup and recovery](#backup-and-recovery) |
| Diagnose a failed step | [Fault isolation](#fault-isolation) |

## Guided setup in Switchboard

Open **Actions → Set up a relay**. Use the same version of Yip on the host, the operator workstation and each joining workstation. For each private folder, enter a new path on persistent local storage. Yip creates it with mode `0700`. The relay service account owns the host folder. Your personal operator account owns the setup folder. Only files explicitly named for transfer belong in the exchange channel.

| Where | Step | What you do |
|---|---|---|
| Relay host | **Create host identity** | Enter the public HTTPS URL. For direct TLS use an origin such as `https://relay.internal:8443`. For an HTTPS edge proxy select **Use a WebSocket tunnel** and include its routed path, for example `https://relay.example.org/v1/tunnel`. Deliver `share/host.yip` to the operator over a channel that authenticates the sender. |
| Operator workstation | **Prepare keys and sign line** | Select the host file. Choose three paths for file-backed signing keys or leave them blank for Yip to create them in the setup folder under `custody/`. An existing private Yip signing key at an explicitly chosen path can be used. Give the relay host the resulting `share/line.desc.cbor` through the trusted channel. |
| Relay host | **Provision on relay host** | Select the signed line descriptor. The wizard verifies the signature and checks its origin against the host identity. It prints the service command. |
| Relay host | **Start relay here** | Run in this terminal for a trial, or put the printed command under the service manager for persistent operation. Direct TLS uses the public URL port and listens on all interfaces for a non-loopback hostname. You can override the listener, for example with the office interface address. Tunnel mode uses HTTP on `127.0.0.1:8080` carrying pinned inner TLS. Configure DNS, the proxy route, firewall and service account on the host. |
| Operator workstation | **Initialize line** | Reopen the operator setup folder once the relay is reachable. Yip initializes the line, authorizes the operator, enrolls its reader credential and establishes the first encryption epoch. Keep each root in separate custody. Keep the daily signing key and the `admin/` client available to the operator. |

Either root can authorize a new operator. The default custody folder contains ordinary private key files, so choose your backup or offline storage before moving them. Hardware signing requires its own supported integration. **Show setup progress** recalls the last completed step. Repeating a completed enrollment with the same workspace and files preserves its keys and verifies its recorded membership.

### Invite a colleague

1. Choose **Actions → Invite a workstation → Create invitation**. Choose a fresh private folder for this invitation, the workstation name, its actor limit and whether it may read line content. Select the **Operator setup folder** from the previous table. On an existing line, use the existing operator client directory and signing key fields instead.
2. Send `share/invitation.yip` to the owner over an authenticated channel. It contains the signed descriptor, public operator identity and signed offer for this workstation. Keep the private invitation folder until enrollment finishes. The operator still decides which workstation receives the grant.
3. Open **Review workstation request** on the returned `request.cbor`. Read the grant. Compare the displayed code with the code the workstation owner gives you through an authenticated channel. Choose **Approve workstation** and enter that code. Send `share/challenge.cbor` to the owner.
4. Open **Complete enrollment** with the returned `proof.cbor`. Yip verifies it, admits that credential and advances the encryption epoch for the line's entitled readers. Tell the owner to activate. The admin client must have an enrolled reader for this step. Each workstation needs its own invitation and private folder.

**Automatic file exchange.** If you and the owner already share an authenticated, access-controlled sync channel, give this invitation its own empty exchange folder there. Each person uses the local path to their copy. Keep every key and private workspace outside that folder. After creating the invitation, select **Pair using an exchange folder**. The owner selects **Join using an exchange folder**. Yip transfers the public artifacts through the folder. Review the request, confirm the code with the owner, then apply the exchange step with that code. Both sides can select **Wait** to check for replies for up to two minutes. Reopen the same step to continue after a timeout. Keep the exchange folder available until the workstation reports its verified checkpoint. The relay needs no additional public port for this workflow.

For a scripted setup, run `yip ldr wizard help` for the matching commands. The remaining sections cover individual operations, service hardening, backup and recovery.

## Roles and records

A **relay host** stores and sequences signed operations for one or more lines. Each **line** has its own 16-byte ID, signed creation descriptor, membership, log and encryption epochs. One organization can host several lines on one listener. A Git repository, a DNS name and a local Yip line name each identify something different. Two teams that need different readership should use different signed lines, even if they share a repository.

| Who | What they hold | What they can do |
|---|---|---|
| Host administrator | OS/service access, persistent relay directory, TLS certificate and private key, any edge routing configuration | Install, provision a signed descriptor locally, supervise the listener, monitor its clock, back it up and fence a failed instance |
| Root custodians | Two distinct line root keypairs held separately | Either current root can initialize the line, authorize or revoke operators, and replace the other root. Loss of either private key is a security incident |
| Line operator | An authorized operator signing key, an admin client directory and an enrolled reader credential for epoch activation | Admit and revoke workstations, distribute fresh epoch keys, issue operator broadcasts and administer the line over its authenticated connection |
| Workstation owner | Private client directory with signing and encryption credentials, verified log, epoch keys and local state | Enroll the device, declare actors within its grant, attach local agents, and use the line |
| Agent | A runtime connected through a local identity mapped to a declared actor | Call and reply under that identity, receive addressed notices, and use the operations available to that session |

One person can perform several roles. Use separate storage and accounts according to the authority each role needs. The host needs the signed descriptor and its own TLS key. Keep root keys, operator keys and admin reader state outside the service account. A user who can read a private client directory can obtain its credentials and any locally accessible plaintext. Multiple sessions with access to the same account do not form an isolation boundary.

**Reader access is line-wide.** Recipients, floors and broadcasts govern interaction and delivery. A reader with a given epoch key can decrypt line content from that epoch, including calls addressed to other actors. The relay handles ciphertext, public control records and routing metadata. An edge proxy can observe connection timing and volume. Enrollment verifies control history from genesis. A newly enrolled reader gets keys from its admission epoch forward. Revocation cannot recall already delivered keys, local transcripts or copies.

Keep a restricted deployment record. Record the release and architecture, service owner, data directory, listener, edge route if used, TLS names/policies and pin or CA source, signed descriptor and digest, line ID, root and operator **public** keys with named custodians, enrollment grants and credential IDs, and separately witnessed current checkpoints. Record key custody locations by reference. Do not put private keys, proof secrets or client directories into the shared repo or a ticket.

## Prepare the host

Choose a persistent local filesystem, a stable DNS name or VPN address, a service account, and a reliable UTC time source. A laptop that sleeps may trip clock protection. Allow room for the log, sidecars, backups and growth. Measure disk space, free inodes and write latency on your host under representative load. Keep client working directories off network shares and out of Git. Arrange administrative shell access separately so you can recover a failed listener.

Choose the archive for the machine running each binary. Linux and macOS builds are available for amd64 and arm64 in the release build configuration. On Unix, `uname -s` and `uname -m` identify the OS and architecture. `x86_64` corresponds to amd64, and `aarch64` or `arm64` to arm64. Obtain the archive and checksum list from your trusted release source. In the download directory, use `sha256sum -c SHA256SUMS` on Linux or `shasum -a 256 -c SHA256SUMS` on macOS if you have all the listed files. With a single archive, calculate its SHA-256 and compare its entry before extracting it. Checksums from the same untrusted download do not establish publisher identity.

From the extracted archive, install the core and its matching Switchboard companion together. For a shared system installation run the installer with authority to write the destination. The account running the service needs execute access.

~~~sh
sudo sh scripts/install-binary.sh ./yip /usr/local/bin/yip
/usr/local/bin/yip version
/usr/local/bin/yip switchboard --check
~~~

For a per-account installation use `"$HOME/.local/bin/yip"` as the destination, ensure that directory is on `PATH`, and use its absolute path in your supervisor. From source use `make build` or `make install` on a supported native build host. The release guide covers toolchains, verification and rollback of the paired binaries. [Release instructions](RELEASE.md)

**Linux example.** Substitute your site’s account-creation tooling if accounts are centrally managed. Create the account and directory once as a host administrator. The rest of the relay commands must use this account and this same directory.

~~~sh
sudo useradd --system --user-group --home-dir /var/lib/yip-relay \
  --shell /usr/sbin/nologin yip-relay
sudo install -d -m 0700 -o yip-relay -g yip-relay /var/lib/yip-relay
~~~

In the host examples below, `relay_yip` runs Yip as the service account. Define it in the administrator's shell. On a single-account pilot use a private directory such as `"$HOME/.yip-relay"`, define `relay_yip() { yip "$@"; }`, and skip the Linux account and system-service steps.

~~~sh
DATA=/var/lib/yip-relay
relay_yip() { sudo -u yip-relay /usr/local/bin/yip "$@"; }
~~~

## Choose the transport

Decide before signing. The descriptor binds the endpoint and trust policy. Give the root custodian the exact public URL and the origin's authentic trust material through a verified channel. Neither a downloaded descriptor alone nor a successful WebSocket upgrade establishes that a workstation found the intended line.

| Route | What clients reach | Where TLS terminates | What to configure |
|---|---|---|---|
| Direct LAN, VPN or routed server | `https://relay.internal:8443`, with client DNS and TCP reachability | TLS 1.3 at Yip, bound to the application session by a TLS exporter | Direct listener and firewall allowlist. A reverse proxy used here must pass the TLS stream through intact |
| HTTPS edge with WebSocket forwarding | `https://relay.example.com/v1/tunnel` | Outer TLS at the edge, inner TLS 1.3 at Yip inside the WebSocket | Signed outer policy, inner server name and policy, HTTP/1.1 upgrade route, local tunnel listener |

**Direct pinned example.** Issue the cert for the name clients will use. Substitute a real hostname for `relay.internal`. Include actual client-facing IP addresses explicitly in `--hosts` if clients use an IP literal. Open the TCP port only on the intended interface and network.

~~~sh
relay_yip relay init --dir "$DATA" --hosts relay.internal
~~~

**Edge example.** Use this in place of the direct init on a new host. The inner name is the name the relay certificate must cover. Clients do not need to resolve the inner name through public DNS. For an existing relay, inspect its certificate before changing the plan.

~~~sh
relay_yip relay init --dir "$DATA" --hosts relay-origin.internal
~~~

`relay init` generates the host's TLS certificate and key at `tls/server.crt` and `tls/server.key` under the data directory. It prints `pin_spki_sha256`. It needs **zero line root keys**. Save the printed pin and the certificate names. Re-running init on a valid existing pair preserves the key and checks coverage. Inspect a partial or mismatched pair before changing anything. Losing the pinned private key can strand clients whose descriptor trusts it.

For a private CA, use a valid server certificate and matching key at serve time with `--cert /absolute/fullchain.pem --key /absolute/server.key`. Sign the descriptor with `--tls-policy pin_ca_root_pem --tls-pin /absolute/root-ca.pem`. The CA input must contain **one standalone CA certificate**. For a direct listener using system Web PKI, choose `--tls-policy webpki` and omit `--tls-pin`. Install the full server chain and ensure the chosen name is covered. For SPKI pins the input is the 64-hex SHA-256 of the public key’s SPKI encoding. Certificate hostname and validity still matter. Renew before expiry, preserve the pinned key where policy permits, and test from an independent client after restart.

For a WebSocket descriptor the inner policy must pin the origin SPKI or a single CA. The outer policy may use system Web PKI or its own independent CA/SPKI pin. Set `--outer-tls-policy` and, for a pinned outer policy, `--outer-tls-pin`. The public URL must have a clean path, such as `/v1/tunnel`, without a query string, fragment or embedded credentials.

For an HTTPS edge, publish its DNS name and map the exact hostname and tunnel path to the origin. For example, in Cloudflare Tunnel add a published application on `relay.example.com` with service type **HTTP** and URL `127.0.0.1:8080` when the connector shares the host's network namespace. Forward `/v1/tunnel` without rewriting it and allow HTTP/1.1 WebSocket upgrades. Leave unrelated hostnames, such as an existing SSH route, on their own ingress rules. If the connector runs in a container, its loopback points into that container. Arrange a shared network namespace or a shared private Unix socket supported by both ends. Verify reachability from the connector's actual execution environment. A browser login/interstitial on the WebSocket route can block a headless client. [Cloudflare published applications](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/) · [WebSocket behavior](https://developers.cloudflare.com/network/websockets/)

## Sign the descriptor

On the root custodian’s and operator’s own machines, choose private locations and `umask 077`. The example paths below live under each role's own home. Exchange only the public files called for at each step. On the signing workstation `KIT` will hold public inputs, the signed descriptor and enrollment exchange files. `ADMIN` will be the private **admin client** directory. The `relay provision` command uses an entirely separate host directory.

~~~sh
umask 077
KIT="$HOME/yip-project-ceremony"
ADMIN="$HOME/.yip-ldr/project-admin"
mkdir -p "$KIT" "$HOME/.yip-ldr"
~~~

1. Custodian A runs the first command in their private directory. Custodian B runs the second on a separate custody device. The operator runs the third in their own private directory. Define `KIT` and create it on each device first.
2. Give both public root files to the signing custodian. Verify their identity with the custodians. Give `operator.pub` to the root owner and authenticate its provenance before authorization. Keep each private file with its owner.
3. If policy requires non-exportable hardware root keys, resolve that before creating a production line. This CLI accepts signing **key files**. Plugging in a USB key, unlocking a passkey or supplying a PKCS#11 URI does not fulfill `--signer` or `--root-key`. One supported root signs a descriptor containing **both** public roots. Both devices never have to be plugged into the relay.

~~~sh
# Custodian A
yip ldr root keygen --alg ed25519 --out "$KIT/root-a.key" --pub "$KIT/root-a.pub"
# Custodian B
yip ldr root keygen --alg ecdsa-p256-sha256 --out "$KIT/root-b.key" --pub "$KIT/root-b.pub"
# Operator
yip ldr root keygen --alg ed25519 --out "$KIT/operator.key" --pub "$KIT/operator.pub"
~~~

On the signing workstation set `PIN` to the origin pin verified with the host administrator. Use **one** descriptor command. The fingerprint you distribute to members is the `descriptor_digest` printed by Yip, which a client can reproduce with `ldr inspect`. Keep the exact signed file and the printed line ID and genesis anchor.

~~~sh
# Direct
read -r PIN
yip ldr root descriptor --line-id auto \
  --root1 "$KIT/root-a.pub" --root2 "$KIT/root-b.pub" --signer "$KIT/root-a.key" \
  --url https://relay.internal:8443 --tls-policy pin_spki_sha256 --tls-pin "$PIN" \
  --out "$KIT/line.desc.cbor"
~~~

~~~sh
# Edge with a public Web PKI certificate and a pinned inner relay
read -r PIN
yip ldr root descriptor --line-id auto \
  --root1 "$KIT/root-a.pub" --root2 "$KIT/root-b.pub" --signer "$KIT/root-a.key" \
  --session-binding ws_tls13_exporter --url https://relay.example.com/v1/tunnel \
  --outer-tls-policy webpki --inner-server-name relay-origin.internal \
  --tls-policy pin_spki_sha256 --tls-pin "$PIN" --out "$KIT/line.desc.cbor"
~~~

~~~sh
yip ldr inspect --descriptor "$KIT/line.desc.cbor"
~~~

Read the line ID, descriptor digest, relay URL, carrier and TLS policy back to the host administrator. Give them the signed file. Give the digest to future members through a separate authenticated channel. Pinning a digest that arrived only alongside the file lets whoever replaced both choose the line.

## Run the service

**Host administrator.** Receive the descriptor, verify its digest, then stage it somewhere the service account can read. Use a different staging filename per line. The example assumes your received copy is in your own home. Paste the trusted descriptor digest at the `read` prompt. The data directory is exclusively locked. For a second line, schedule a maintenance window for *all* lines in that directory, stop the daemon and repeat provisioning with the second descriptor.

~~~sh
read -r DIGEST
yip ldr inspect --descriptor "$HOME/line.desc.cbor" --expect "$DIGEST"
sudo install -o yip-relay -g yip-relay -m 0600 "$HOME/line.desc.cbor" "$DATA/project.desc.cbor"
relay_yip relay provision --dir "$DATA" --descriptor "$DATA/project.desc.cbor"
relay_yip relay status --dir "$DATA"
~~~

For a per-user pilot, copy the verified descriptor into your private data directory in place of the `sudo install` line. Check that the returned line ID matches the custody record. A newly provisioned line can have sequence zero until the root initializes it. `relay status` opens the store for replay and recovery and may repair a torn final write. Use it offline. While the service is up, query its private administration socket.

First run the chosen listener in the foreground so startup errors are visible. The direct address below is an **example**. Use the interface address assigned to your host, or use `127.0.0.1:8443` for a same-machine rehearsal with a certificate covering the loopback address. Another terminal can run health checks. Stop the foreground process before starting a supervised one.

~~~sh
# Direct
relay_yip relay serve --dir "$DATA" --listen 10.20.30.40:8443
~~~

~~~sh
# Edge
relay_yip relay serve --dir "$DATA" --listen off \
  --tunnel-listen 127.0.0.1:8080 --tunnel-path /v1/tunnel
~~~

The direct listener defaults to `127.0.0.1:8443`. `--listen off` disables it and needs a tunnel listener. The WebSocket origin listener accepts loopback or `unix:/absolute/path`. Keep the Unix socket and its parent accessible to the intended connector under its actual service identity. Do not expose the relay's administration socket as a tunnel origin.

**Example Linux service.** Place the following in `/etc/systemd/system/yip-relay.service` as root after provisioning. Use the same absolute binary, data directory, bind address and certificate flags as the successful foreground run. For an edge service replace the whole `ExecStart` line with the edge command above, expanded to absolute paths and with the `relay_yip` wrapper replaced by `/usr/local/bin/yip`. If using external certificates, make only the required paths readable by this service and keep the key out of group/world-readable directories. [systemd execution environment](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

~~~ini
[Unit]
Description=Yip long distance relay
After=network-online.target
Wants=network-online.target

[Service]
User=yip-relay
Group=yip-relay
UMask=0077
StateDirectory=yip-relay
StateDirectoryMode=0700
ExecStart=/usr/local/bin/yip relay serve --dir /var/lib/yip-relay --listen 10.20.30.40:8443
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
~~~

~~~sh
sudo systemd-analyze verify /etc/systemd/system/yip-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now yip-relay
sudo systemctl status yip-relay --no-pager
sudo journalctl -u yip-relay -n 50 --no-pager
relay_yip relay clock status --dir "$DATA"
~~~

**Example macOS system service.** For a Mac that must serve before anyone logs in, use a LaunchDaemon. Have the host administrator create or select a dedicated non-admin service account using the site's normal account tooling. In this example its short name is `yip-relay`. Create `/Library/Application Support/YipRelay`, make that account its owner and set mode `0700`. Set `DATA` to this directory for init, provision and status. Install the executable and companion under `/usr/local/bin`. Check the chosen foreground listener under the same account before scheduling it. [Apple’s launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)

Save this as `/Library/LaunchDaemons/org.example.yip-relay.plist`, owned by `root:wheel` and mode `0644`. Replace the example bind address. Each argument is a separate plist string, including paths containing spaces. An edge deployment replaces the direct listener arguments with its working tunnel arguments.

~~~xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.example.yip-relay</string>
  <key>UserName</key><string>yip-relay</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/yip</string><string>relay</string><string>serve</string>
    <string>--dir</string><string>/Library/Application Support/YipRelay</string>
    <string>--listen</string><string>10.20.30.40:8443</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>/Library/Application Support/YipRelay/service.log</string>
  <key>StandardErrorPath</key><string>/Library/Application Support/YipRelay/service.error.log</string>
</dict>
</plist>
~~~

Run `plutil -lint /Library/LaunchDaemons/org.example.yip-relay.plist`, then `sudo launchctl bootstrap system /Library/LaunchDaemons/org.example.yip-relay.plist`. Inspect `sudo launchctl print system/org.example.yip-relay`, the log files, and live socket status. For maintenance use `sudo launchctl bootout system/org.example.yip-relay`, wait for exit, then bootstrap the same plist to restart. Arrange log rotation and test the machine's sleep and reboot behavior before relying on it.


On a different supervisor, use the same foreground executable and arguments, a private persistent working area and one unprivileged owner. Run one writer per data directory. Arrange a graceful SIGTERM on stop and inspect startup failures before retrying. Verify a host reboot during a maintenance window, including connector supervision on an edge deployment.

**From the admin workstation, before using a root:** verify the signed descriptor using the independently recorded digest and probe the actual signed endpoint. `Origin verified over TLS 1.3` demonstrates reachability and trust under the signed transport policy. The next steps separately establish line membership and write access.

~~~sh
read -r DIGEST
yip ldr inspect --descriptor "$KIT/line.desc.cbor" --expect "$DIGEST" --probe
~~~

## Bootstrap authority

Use a dedicated admin workstation/account. The example uses one controlled admin workspace. During the bootstrap ceremony the custodian makes root A available to the signing commands there, checks their results, then returns it to custody. The operator subsequently uses the same admin client directory with their separately held operator key. If responsibilities are split, arrange supervised access to this workstation and a separately mounted signing-key location while each signer is present. Substitute that key’s actual file path. Do not hand root A to the operator along with the workspace or copy a live admin directory between machines.

~~~sh
yip ldr root init-line --dir "$ADMIN" --descriptor "$KIT/line.desc.cbor" \
  --root-key "$KIT/root-a.key"
yip ldr root authorize-operator --dir "$ADMIN" --root-key "$KIT/root-a.key" \
  --operator-pub "$KIT/operator.pub"
~~~

Use a fresh `ADMIN` on a new line. The first command creates local admin state and commits `line_init` at sequence 1. Check the returned sequence and head. The second commits operator authorization using the operator **public** key. Check its commit and retain its sequence. Disconnect the root's key storage after these operations. The operator needs no root key for ordinary enrollment. If initialization times out after creating the directory, preserve both ends and reconcile the stored and authenticated heads before retrying. A second fresh descriptor would identify an entirely different line.

**Enroll the admin workstation as a reader.** Epoch activation must wrap fresh content keys for the eligible readers. The operator signature authorizes the action and an enrolled reader credential in this directory participates in the key operation. An operator signing key by itself cannot satisfy both requirements. Use fresh exchange paths for each ceremony.

~~~sh
OP="$KIT/operator.key"
yip ldr root reader-request --dir "$ADMIN" --namespace project-admin \
  --out "$KIT/admin.req.cbor"
~~~

Inspect the request and verify the admin reader grant. Enter its `request_digest` first, then the signing and encryption fingerprints from the request you created. Record the `cred_id` as the admin reader. Use `operator.pub` authenticated at bootstrap. The challenge and the private challenge secret must have **different** output paths.

~~~sh
yip ldr join inspect --request "$KIT/admin.req.cbor"
read -r REQUEST_DIGEST
read -r SIG_FP
read -r ENC_FP
yip ldr join challenge --operator-key "$OP" --request "$KIT/admin.req.cbor" --expect-request "$REQUEST_DIGEST" \
  --expect-signing "$SIG_FP" --expect-encryption "$ENC_FP" \
  --out-challenge "$KIT/admin.ch.cbor" --out-secret "$KIT/admin.sec.cbor"
yip ldr join prove --dir "$ADMIN" --operator-pub "$KIT/operator.pub" \
  --request "$KIT/admin.req.cbor" --challenge "$KIT/admin.ch.cbor" \
  --out "$KIT/admin.proof.cbor"
yip ldr join enroll --dir "$ADMIN" --operator-key "$OP" \
  --request "$KIT/admin.req.cbor" --challenge "$KIT/admin.ch.cbor" \
  --secret "$KIT/admin.sec.cbor" --proof "$KIT/admin.proof.cbor"
yip ldr epoch activate --dir "$ADMIN" --operator-key "$OP"
yip ldr sync --dir "$ADMIN" --project
~~~

Verify that the enrollment committed the expected credential ID, the epoch activation returned a new `key_epoch`, and the synced admin status includes it in `has_epoch_keys`. Admin directories start activated. `join activate` later applies to each new **member** directory. Preserve the admin directory and its reader keys under an appropriate backup policy.

## Enroll a workstation

Opening a transport connection or inspecting a descriptor requires no pre-approved source IP in Yip. A useful member session requires an operator-enrolled credential bound to the signed line. Network allowlists, VPNs or an edge firewall can impose separate reachability requirements. The authorization decision is on the project line. There is no public registration endpoint where knowing a line name earns admission.

1. Agree with the colleague on the device/account, namespace, number of agent identities and reader entitlement. Use a distinct namespace such as `alice-laptop` and start with the actor count they need. Give them the signed descriptor and authenticated operator public key. Confirm the descriptor digest and the authenticity of the operator public key through a previously established channel. For example, compare `shasum -a 256 operator.pub` or `sha256sum operator.pub` on both hosts.
2. Have them create their request following the client manual. Ask for the signed request file and the output identifying the device, grant, credential ID and both fingerprints. Confirm the grant with the person and verify both fingerprints independently of the exchange used to send the file. For a remote ceremony also compare the SHA-256 of the actual request file independently. Inspect the actual signed grant in the received file and keep its `request_digest`. A fingerprint match alone leaves the grant unchecked. The enrollment uses the grant inside the request. [Inspect the grant in a received request](#inspect-the-grant-in-a-received-request). Have them make a corrected request if its grant is unsuitable.
3. On the operator's workstation, create a private exchange directory for **this one request**, save the incoming file as `request.cbor`, and enter the independently checked fingerprints. Use the challenge it produces. Keep `secret.cbor` on the operator's machine.

~~~sh
X="$KIT/alice-laptop-01"
mkdir -m 0700 "$X"
# Receive the colleague's request into "$X/request.cbor" before continuing.
yip ldr join inspect --request "$X/request.cbor"
# Compare the line and grant, then enter the reviewed request digest and the verified fingerprints.
read -r REQUEST_DIGEST
read -r SIG_FP
read -r ENC_FP
yip ldr join challenge --operator-key "$OP" --request "$X/request.cbor" --expect-request "$REQUEST_DIGEST" \
  --expect-signing "$SIG_FP" --expect-encryption "$ENC_FP" \
  --out-challenge "$X/challenge.cbor" --out-secret "$X/secret.cbor"
~~~

4. Send only `challenge.cbor` to the member. They use the original request, verified operator public key and **the same private client directory** to prove possession. Receive their `proof.cbor` into this exchange directory. A proof from a different challenge, operator or keypair fails verification.
5. Commit the enrollment. Compare its `cred_id` with the device record. Once all intended additions in the batch have committed, activate a fresh reader epoch. Record its sequence and number, then tell the colleagues to activate and declare their actors.

~~~sh
yip ldr join enroll --dir "$ADMIN" --operator-key "$OP" \
  --request "$X/request.cbor" --challenge "$X/challenge.cbor" \
  --secret "$X/secret.cbor" --proof "$X/proof.cbor"
yip ldr epoch activate --dir "$ADMIN" --operator-key "$OP"
~~~

Use the same workflow for each new machine or OS account. Prospectively granting a second actor to one credential is different from enrolling a second independent device. Maintain a register of which actors and readers each credential represents so that the scope of a later revocation is clear.

**Switchboard equivalents.** In `yip switchboard` use **F4 → Relay operator → Host a line** for host-local operations, **Line administration** for roots and the admin reader request, and **Enroll workstation** for challenge, enrollment, epoch and revocation. Forms call the same underlying commands and take local filesystem paths. A file picker on an administrator's laptop cannot read a file on the relay host. Open Switchboard under the service identity on the host (for example, over SSH with a terminal) for the host-local operations. For a member, **Actions → Connect to a Relay** walks through inspection, proof, activation and attachment. Use the window's help button for field guidance.

**Commissioning test.** Enroll two independent member directories, preferably on the networks and machines your team will use. Have both verify the same line ID and descriptor digest, activate, and declare distinct actors. Have A open a call, B read the exact phrase and reply, A read the reply, and both close it. With both runtimes attached, repeat in reverse while the recipient session is idle. Stop and resume one runtime, send a fresh phrase, and check delivery in that exact session. Record the endpoint, actors, release, checkpoint and observed results. A receipt visible in a local queue and a reply coming back from the intended session establish different things. [Client acceptance test](LDR-CLIENT.md#verify-a-two-workstation-call)


## Operate the relay

**Live monitoring.** As the service identity run `relay_yip relay clock status --dir "$DATA"`. With a custom socket, specify `--admin-sock /absolute/private/admin.sock` instead. The default is `$DATA/admin.sock`, mode `0600`. Keep this socket private. It also accepts clock-resume operations. For a graphical view use **Host a line → Monitor local admin socket**. On a client, **Relays (F4)** shows that client's authenticated connection and checkpoint. Comparing these views distinguishes an origin problem from a client sync or runtime delivery problem.

| Observe | Interpretation and action |
|---|---|
| `lines[].line_id`, `generation`, `head_seq` and `head` | Record these together. A quiet line need not advance. Compare a client's freshly synchronized `checkpoint_seq` and `checkpoint_head` while writes are quiescent. Equal sequence numbers with different heads warrant investigation |
| `clock.trusted`, `uncertain_reason`, `floor_ms`, `last_wall_ms`, `last_drift_ms` | Milliseconds. A persisted floor constrains time-based decisions. Investigate a backward step, a large wall/monotonic discrepancy, a freeze or a long outage before resuming |
| `recovered_torn_tail` | Startup recovered an incomplete final write. Preserve logs, verify disk health and compare committed checkpoints. Acknowledged history matters even when the service can start |
| `quarantined` and `quarantine_reason` | Stop using the affected line for writes. Preserve evidence and investigate store consistency. Clock resume does not repair a missing WAL, mismatched sidecar or divergent history |
| `admission.active_tunnels`, `in_flight_auth`, `pending_challenges`, `active_sessions` | These are current occupancy counts. Short-lived CLI requests can legitimately leave them at zero. Compare peak values and reconnect behavior to expected use |
| `admission.overload_rejections` | Track changes over time and record service restarts when interpreting the counter. Look for a reconnect burst, an undersized host, or abusive traffic before raising limits |
| Disk, service and connector health | Monitor free space/inodes, I/O errors, certificate expiry, service exits, clock synchronization and tunnel connectivity outside Yip. Send diagnostic output to a restricted destination |

**Admission and denial of service.** The server can bound active WebSocket tunnels (`--max-tunnels`, default 512), concurrent authentication (`--max-auth`, default 64) and per-line challenges and sessions (`--max-per-line`, default 256 for each). Each flag accepts 1–4096. The global pending-challenge and active-session tables cap at 4096 each. These are admission limits, not throughput estimates. A small host should be sized using its measured memory, CPU, open-file budget, write latency and synchronized-client reconnect bursts. Apply changed flags in the supervisor and restart in a maintenance window. Check occupancy and perform an authenticated call afterward.

A private deployment can limit network sources to the office/VPN. For a public edge, restrict the origin to the connector, allow upgrades on the intended host and path, and consider rate limiting upgrade requests there. A match such as `(http.host eq "relay.example.com" and http.request.uri.path eq "/v1/tunnel" and http.request.method eq "GET")` targets handshakes. Size thresholds for colleagues sharing a NAT and test reconnects. An established WebSocket carries many frames after that one GET. Origin admission still matters, and volumetric attacks on the uplink need upstream handling. Monitor the tunnel and origin separately. [Cloudflare WebSocket behavior](https://developers.cloudflare.com/network/websockets/)

**Clock incident.** Record the affected line ID and status first. Check the host's UTC time and time-service state against a trusted reference (`date -u` and, on systemd Linux, `timedatectl status` or your site's chrony tooling). Investigate suspend/resume, VM snapshots and changes to the time source. Current defaults allow 5 seconds of backward skew and of wall/monotonic step drift, detect a frozen wall clock at 30 seconds, and check restart forward jumps against a 30-day threshold. Once time is sound and the recorded floor makes sense, resume only the affected line. Enter its 32-hex ID from the status output.

~~~sh
read -r LINE_ID
relay_yip relay clock resume --dir "$DATA" --line-id "$LINE_ID"
relay_yip relay clock status --dir "$DATA"
~~~

Inspect the per-line result and `clock.trusted`. Omitting the line selector requests resume for all hosted lines. If the floor is unexpectedly in the future or trust fails again, keep writes stopped while investigating. Backdating a host clock or editing stored floors undermines the expiry checks.

**Certificate maintenance.** As an account that can read the certificate, inspect its validity and subject with `openssl x509 -in "$DATA/tls/server.crt" -noout -subject -dates`. Use `openssl x509 -in "$DATA/tls/server.crt" -noout -checkend 2592000` as a 30-day expiry check. For an external certificate use its configured path. Treat the signed origin pin as part of your renewal plan. For a CA-issued renewal, verify the chain, SAN and applicable pin before restarting with the new pair, then run the signed-descriptor probe from a client. Re-running init on an intact existing certificate does not renew it.

**Routine changes and upgrades.** Announce the outage, record the running release/configuration, take a verified checkpoint and a consistent backup, and stage the new core with its matching Switchboard. Stop the service, install the pair and restart with the same data directory and flags. Inspect the live status for every line, verify the TLS origin on a client, sync and exchange a fresh call. Restart long-lived MCP/dispatcher processes after updating client binaries. Retain the old executable pair and determine data-format compatibility before attempting a binary rollback. An older backup may omit acknowledged operations. To add a line, sign a separate descriptor with its intended roots and origin, stop the service briefly, provision it in the existing directory, restart, then bootstrap and enroll on the new line.

**Routine reader rekey.** Record the last activation and schedule periodic review. In addition to membership changes, the signed v1 profile specifies an epoch budget of 1,048,576 messages and 90 days. The operator can initiate a fresh epoch with `yip ldr epoch activate --dir "$ADMIN" --operator-key "$OP"`. Record the new sequence and epoch, then sync a remaining reader and verify it can read a fresh message. Plan rotations explicitly. There is no rotation scheduler in the serve CLI.

**Operator communications.** To send a maintenance notice from the enrolled admin reader, use `yip ldr broadcast create --dir "$ADMIN" --operator-key "$OP" --kind briefing --body "The project relay will restart at 17:00 UTC"`. The default addresses eligible default-addressed actors. Use `--to alice-codex,bob-claude` for named recipients. Retain the returned broadcast ID to track its responses. For a call requiring an explicit operator decision, `yip ldr call ratify --dir "$ADMIN" --operator-key "$OP" --call CALL_ID --body "Decision text"` records the signed statement. Specify the decision and its scope.

**Endpoint changes.** When the signed public URL, policy and pinned identity remain valid, DNS or a connector backend may be moved during a controlled migration. Probe from clients after the change. If a change would invalidate the signed origin, plan a transition with new trust information. This release exposes no command to edit a live line’s signed origin. Establish a new signed line and enroll workstations there when continuity of the old policy cannot be preserved. Do not distribute a replacement file as though it had the old descriptor digest.

## Keys and departures

| Event | Action |
|---|---|
| An agent session ends, device remains trusted | Stop or detach its local runtime. Remove its actor if it should cease participating. Other actors of that credential can remain |
| A colleague leaves, a laptop is lost, or client credentials were copied | Identify the exact credential ID in the enrollment record. Revoke it, activate a fresh epoch for remaining readers, and confirm an unaffected reader can sync and decrypt a new message |
| An operator signing key is lost or exposed | Use a current root to revoke that operator and authorize a fresh public key. Inspect recent enrollments, revocations and key epochs. Revoke suspect credentials separately and rekey remaining readers |
| One root is compromised or lost | Use the surviving current root to replace the affected public root. Verify the commit and review recent root and operator actions for unauthorized changes |
| Both roots are unavailable | Existing authorized operator actions may continue while their keys remain usable. Root-only actions need a surviving authorized signer. Plan a newly rooted line if custody cannot be restored |
| Host or TLS key is compromised | Isolate the instance, revoke connector access where applicable, retain evidence, assess exposure of stores and TLS credentials, and establish trusted endpoint continuity or issue a new line. Handle any admin/client keys present on that host as separately exposed |

**Workstation revocation.** Enter the 64-hex credential ID from the admission record. Verify the person, device and line before submitting. This affects all actors of the credential. Take especial care with the only enrolled admin reader. Maintain an authorized operator with a usable enrolled reader for rekeying.

~~~sh
read -r CRED_ID
yip ldr join revoke --dir "$ADMIN" --operator-key "$OP" --cred-id "$CRED_ID"
yip ldr epoch activate --dir "$ADMIN" --operator-key "$OP"
yip ldr sync --dir "$ADMIN" --project
~~~

**Operator rotation.** Generate the replacement on its owner’s machine and authenticate its public file. During planned rotation authorize the replacement first, verify it can perform operator-role sync from the correct directory, then revoke the old key. For a compromise prioritize revocation using a trusted root and device. Revoking the operator signing key and revoking the same device's reader credential are separate actions.

~~~sh
yip ldr root authorize-operator --dir "$ADMIN" --root-key "$KIT/root-b.key" \
  --operator-pub "$KIT/new-operator.pub"
yip ldr sync --dir "$ADMIN" --role operator --key "$KIT/new-operator.key"
yip ldr root revoke-operator --dir "$ADMIN" --root-key "$KIT/root-b.key" \
  --operator-pub "$KIT/operator.pub"
~~~

**Root replacement.** Generate a fresh pair in the new custodian's custody, deliver only its verified public key, and sign the replacement with the other surviving root. Keep the original creation descriptor for full replay. The signed transition changes the current root set. Record its sequence/head, the new public key, and custody.

~~~sh
yip ldr root replace-root --dir "$ADMIN" --root-key "$KIT/root-b.key" \
  --old-root-pub "$KIT/root-a.pub" --new-root-pub "$KIT/new-root-a.pub"
~~~

## Backup and recovery

**What belongs in a backup.** Preserve the entire relay data directory as a unit. It includes TLS material by default and `lines/<line-id>/provision.cbor`, `wal.log` and content-addressed `sidecars/`. The live Unix socket is recreated on startup. Also preserve the service definition, external certificate chain/key if applicable, connector configuration and independently trusted checkpoint records. Back up admin and member state under their respective owners, separately from the relay, with encryption, restricted access and a tested restore procedure. Track secret recovery and retention policy for each backup set. Keep independent root custody even for backups.

**Consistent cold copy and drill.**

1. Quiesce writers. Sync a trusted independent client, record its verified line ID, generation, sequence and head for each hosted line, and compare with live host status. Make sure no later writes are admitted between the checkpoint and shutdown.
2. Stop the daemon gracefully (`sudo systemctl stop yip-relay` in the example), confirm it is down and prevent automatic start on another host. Copy the entire stopped store with modes and ownership, plus dependent external configuration. An archive on Linux can be made with `sudo tar -C /var/lib -cpf /secure-backup/yip-relay.tar yip-relay`, using a private, encrypted destination accessible only to its custodians. Verify the archive digest against a separately kept record. Restart the original if this was only a backup.
3. Restore a **copy** on an isolated machine, with the correct service ownership. Keep it unreachable from real clients and the original off its routing path. Run offline `yip relay status --dir …`, inspect every line, then start a private listener and probe from an isolated test client using the signed trust and hostname. Compare the head, generation, clock and sidecars through sync and projection. Never connect two active copies to the same production line or let a drill generate writes on a production route.
4. For a real host replacement, establish that the copy includes the latest acknowledged prefix for every hosted line, including revocations. Fence the old host, preserve the same signed origin and TLS identity, then cut over. Verify service health, client checkpoint and an addressed call. Record which copy is now authoritative and prevent the old host from restarting.

**A stale snapshot is a different problem from a host move.** A valid checksum proves that a copy was retained intact. It cannot establish that no later commits exist. A stale snapshot can revive revoked credentials, reverse key epochs or contradict a client's checkpoint. Preserve both sides and stop writes if the current prefix cannot be established. The repository describes a recovery protocol and model traces. This release has no operator CLI to perform a production recovery-generation ceremony. If a sound current copy cannot be established, provision a fresh signed line, communicate its new digest independently, enroll again with new client directories and update local mappings. Retain the old state for investigation according to policy. The source checkout includes the model and its assumptions in `docs/LDR-RECOVERY.md`.

**Decommissioning.** Agree on the last operating date and record the final authenticated checkpoints. End active calls, stop dispatchers, detach workstations or move them to the replacement line, then stop and disable the service. Remove its external DNS/tunnel/firewall route and rotate or retire connector credentials as appropriate. For a shared relay retain the other lines' routes and service. Archive or destroy sensitive host/client/key material according to the team's retention obligations. There is no supported live line-deletion command in this CLI. Removing an actor, detaching a checkout and deleting history have different effects.

## Fault isolation

| Symptom | First checks and next action |
|---|---|
| Direct connection refused or times out | Confirm service state, selected interface/port, DNS from the client, ACL/VPN and supervised argv. Loopback on a remote workstation points to that workstation |
| Edge returns an HTTP error or never upgrades | Inspect hostname/path, DNS, connector state and connector-to-origin reachability. A 502 can mean the connector cannot reach its local origin. Use the descriptor probe for the two TLS layers |
| Trust, hostname or expiry error | Verify client UTC, cert names, each CA chain or pin and the independent descriptor digest. For a tunnel check outer and inner identities separately. Keep certificate validation enabled |
| Store locked or admin socket unavailable | Confirm execution account, data directory, service state and socket path. Use live clock status while serving and offline status only after stopping. Leave lock files in place |
| Origin probe succeeds, member fails to authenticate | Verify that exact line is provisioned and initialized, operator authorized, credential enrolled and active, and participant is using the original client directory |
| Enrollment proof fails or output already exists | Match request/challenge/proof/secret by ceremony and signer, check both fingerprints, and preserve the original keys and files. Use distinct export paths and investigate partial creation before retrying |
| Successful enrollment but messages unreadable | Check the reader grant, a fresh epoch after enrollment, `join activate` on the member, `has_epoch_keys` and `ldr sync --project`. Earlier epochs remain outside a new reader's access |
| Valid session but no agent wake | Check the client’s mapping, runtime opt-in, profile, live dispatcher, and exact recipient seat. A relay cannot start an arbitrary local chat. Use the client manual's layer-by-layer checks |
| Disk or durability error, missing history, inconsistent head | Quiesce writes, capture error, heads, supervisor logs and storage health. Retain a cold copy before offline replay. Never patch a WAL, drop a sidecar, or recreate a missing store file to force startup |

For an escalation collect versions, OS/architecture, redacted endpoint/policy, line ID, time in UTC, operation, exit status, generation, sequence/head, and the relevant error. Share any identifying metadata only with the intended support recipient. Exclude key files, enrollment secrets, entire client directories and plaintext transcripts. For a shorter operator/member walk-through use the [team deployment guide](LDR-TEAM-DEPLOYMENT.md).

## Inspect the grant in a received request

On the operator's workstation use **Enroll workstation → Inspect signed request**, or run the following command from the installed release. It verifies the workstation signature and displays the signed request offline. It requires only the received file.

~~~sh
yip ldr join inspect --request "$X/request.cbor"
~~~

Compare `line_id` and `descriptor_digest` with the project record, and `cred_id`, `sig_fingerprint` and `enc_fingerprint` with the intended workstation. Read the signed `namespace`, `actor_limit` and `reader` values before approving. For the Alice example expect `alice-laptop`, one actor and reader access. The output also shows the request's capabilities list. The current enrollment operation grants the namespace, actor limit and reader setting.

After reviewing the values, record `request_digest` and supply it in **Issue challenge → Reviewed request digest** or the CLI's `--expect-request` flag. This digest covers the signed request. It differs from a file checksum and from the line's descriptor digest. If the file changes before the challenge, the comparison fails. Keep the checked device fingerprints from your independent channel. If the grant differs from what you agreed, ask the workstation owner for a corrected request.
