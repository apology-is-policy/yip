# Yip relay client manual

Use this guide to connect a human’s workstation and its coding agents to an existing Long Distance Relay (LDR) line. You need an invitation from the line operator and an agent runtime on the machine where the session will run. Your Git checkout can be shared with colleagues through normal Git hosting. Each workstation keeps its own Yip identity and keys.

| Your starting point | What to do |
|---|---|
| The operator has invited you and nothing is installed | Start at [Before enrollment](#before-enrollment) and work down through the call test |
| You are a human preparing a session for someone else | Complete setup in the intended OS account, run [the call test](#verify-a-two-workstation-call) and give the session the [agent handoff](#handoff-to-a-configured-agent) |
| You are an agent whose human already configured Yip | Start at [Handoff to a configured agent](#handoff-to-a-configured-agent). An existing enrollment and profile should be reused |
| You need to add another agent to an enrolled machine | [Declare and attach an actor](#declare-and-attach-an-actor), within the original actor limit |
| A call is missing, unreadable or waking the wrong session | [Check each layer](#check-each-layer) |
| You are changing machines, leaving the team or reinstalling | [Move or remove a client](#move-or-remove-a-client) |
| You are standing up or operating the server itself | [Relay administration manual](LDR-ADMINISTRATION.md) |

## Before enrollment

Ask the line operator for the following. You can forward this list as your invitation request.

- The signed line descriptor file, usually `line.desc.cbor`, and its canonical **descriptor digest**, confirmed through a trusted channel independent of file delivery.
- The authorized operator's **public** key file, `operator.pub`, and a way to authenticate it. Comparing its file SHA-256 with the operator over an established channel works. This is a different value from the descriptor digest.
- The agreed workstation namespace, actor limit, whether this workstation should read encrypted content, which actor name to use per session, and a colleague's declared actor for a test call.
- Any office DNS, VPN or tunnel-network requirements, the Yip release to install, and the person who will issue your challenge. An HTTPS edge deployment carries the public hostname and the inner relay identity in the descriptor.

Five identifiers are easy to mix up during setup. For a colleague named Alice they might look like this.

| Identifier | Example | Where it applies |
|---|---|---|
| Signed line ID | 32 hex characters printed by `ldr inspect` | Shared by every workstation on this particular relay line |
| Workstation namespace | `alice-laptop` | Part of the operator-approved device grant |
| Credential ID | 64 hex characters printed by `join request` | Identifies the enrolled keypair bundle for revocation and audit |
| Local line and local identity | `project-relay` and `alice-codex` | Select Yip routing on this workstation and the session/seat receiving notices |
| Relay actor | `alice-codex` | Declared by the enrolled credential and addressed by peers on the signed line. It may differ from the local identity when explicitly mapped |

**Choose the account first.** If a human will set up an agent, perform the workstation steps as the OS user that runs it, in that user’s home. Do not initialize that user's credentials as root or put them in a shared checkout. If colleagues share one server, use separate OS accounts/private directories for independent membership. Several agents under one account can share a single enrolled directory and use separate actors up to its grant. They also share its privileges and reader keys. For independent revocation, enroll independent credentials.

Install the archive matching the client OS/architecture from your trusted release source. Compare its SHA-256 with the trusted checksum entry before extraction. From the extracted directory, keep the release binary and Switchboard companion together and run the installer. Confirm that the invoked path is the newly installed one.

~~~sh
mkdir -p "$HOME/.local/bin"
sh scripts/install-binary.sh ./yip "$HOME/.local/bin/yip"
export PATH="$HOME/.local/bin:$PATH"
command -v yip
yip version
yip switchboard --check
~~~

A persistent shell `PATH` or a suitable absolute executable path also needs to be available when you launch the agent. If building from the project source, follow the native build instructions for the core and companion. [Release instructions](RELEASE.md)

**Choose local paths.** The examples use Alice’s workstation. Substitute your own namespace, actor, recipient and paths. Use a fresh private client directory per enrollment. The exchange directory is a different directory for the few files you exchange with the operator. Create the parents, and let `join request` initialize the client directory. Define these variables again if you open a new terminal.

~~~sh
umask 077
CLIENT="$HOME/.yip-ldr/project"
EXCHANGE="$HOME/yip-join-project"
LOCAL_LINE=project-relay
ACTOR=alice-codex
mkdir -p "$HOME/.yip-ldr" "$EXCHANGE"
~~~

Put the received `line.desc.cbor` and `operator.pub` in `$EXCHANGE`. Paste the independently confirmed descriptor digest at the `read` prompt below. Check the displayed line ID, relay URL, carrier and origin TLS policy. The probe contacts the endpoint and verifies the descriptor's TLS policy. It creates no credential and needs no operator action.

~~~sh
read -r DIGEST
yip ldr inspect --descriptor "$EXCHANGE/line.desc.cbor" --expect "$DIGEST" --probe
~~~

The expected final line is `Origin verified over TLS 1.3`. Compare the operator public file fingerprint before using it. On macOS run `shasum -a 256 "$EXCHANGE/operator.pub"` and on Linux use `sha256sum "$EXCHANGE/operator.pub"`. Authenticate that full output digest with the operator. If either comparison fails, preserve the received files and resolve the discrepancy before proceeding.

## Enroll and activate

**1. Create your device keys and request.** The example requests one actor and reader access. Choose `--reader` for conversations whose content you need to read. A nonreader does not receive content epoch keys. The operator approves the grant embedded in your request. Confirm its terms together before proceeding.

~~~sh
yip ldr join request --dir "$CLIENT" --descriptor "$EXCHANGE/line.desc.cbor" \
  --expect "$DIGEST" --namespace alice-laptop --actor-limit 1 --reader \
  --out "$EXCHANGE/request.cbor"
~~~

The command makes local credentials and returns `cred_id`, `sig_fingerprint`, `enc_fingerprint`, `namespace`, `actor_limit` and `reader`. Check the values and save the credential ID. Send `request.cbor` to the operator. Verify the two fingerprints through your previously established channel. Compare the request file's SHA-256 with the operator too, alongside your intended grant. The signing key proves control of the device identity. The encryption key allows your device to decrypt the challenge and receive wrapped epoch keys.

**2. Prove ownership.** Wait for the operator's challenge file. Save it as `$EXCHANGE/challenge.cbor`. Keep your original request and original client directory. Your workstation needs the verified operator public key. The operator keeps the *separate secret file* on their machine. Run this as the workstation owner and return just `proof.cbor`.

~~~sh
yip ldr join prove --dir "$CLIENT" --operator-pub "$EXCHANGE/operator.pub" \
  --request "$EXCHANGE/request.cbor" --challenge "$EXCHANGE/challenge.cbor" \
  --out "$EXCHANGE/proof.cbor"
~~~

**3. Wait for enrollment and key distribution.** The operator verifies your proof, commits your credential with `join enroll`, then commits a new reader epoch with `epoch activate`. Ask them to confirm your credential ID and the epoch number. Producing a proof on your machine completes only your half of enrollment. The order matters if several workstations join together.

**4. Activate locally.** Run this in the same OS account with the same client directory. Activation fetches and verifies control history from genesis and checks that the enrollment matches the original requested keys and grant. For a reader, sync and confirm that the expected new epoch is available before testing encrypted calls.

~~~sh
yip ldr join activate --dir "$CLIENT"
yip ldr sync --dir "$CLIENT" --project --scan
yip ldr status --dir "$CLIENT"
~~~

Compare `status.line_id` and `cred_id` with your record. Look for `activated: true` and the operator's epoch in `has_epoch_keys` for a reader. A newly admitted reader can verify earlier membership and log ordering but has no keys for earlier conversations. Readers can decrypt content for epochs for which they have keys, including conversations between other actors on the line. Choose a separate line for a smaller confidentiality group.

| File or value | Who receives it |
|---|---|
| Signed descriptor and operator public file | Every intended member. Authenticate their identities independently |
| Request and proof | From this workstation to the operator |
| Challenge | From the operator back to the workstation that made the request |
| Workstation signing/encryption fingerprints and agreed grant | Compare with the operator independently of the transfer channel |
| Operator challenge secret, root and operator private signing keys | Retained by their custodians. A member or agent needs none of these files |
| Client directory including `cred.key` and `epochs.cbor` | This OS account and its protected backup. Keep it out of Git, chat and shared sync folders |

**Using Switchboard instead of typing the enrollment commands.** In `yip switchboard` open **Actions → Connect to a Relay**. Select **Inspect signed descriptor**, then **Verify relay connection** with the verified digest. **Create workstation request** takes the namespace, actor limit, private directory and reader toggle. After receiving the challenge, choose **Prove workstation keys** with the same directory. After the operator confirms enrollment and epoch, choose **Activate workstation**. The resulting credential is the same one used by the CLI. Use **Relays → Client tools → Client status** to inspect it. You may switch between the TUI and CLI without repeating enrollment.

## Declare and attach an actor

Declaring an actor creates its remote identity. Attaching maps the local Yip identity used by your agent to that remote actor. A runtime installation makes Yip tools and delivery available in the particular agent process. Complete all three, in the intended account and checkout.

~~~sh
yip ldr actor declare --dir "$CLIENT" --actor "$ACTOR"
yip ldr sync --dir "$CLIENT"
yip ldr actor list --dir "$CLIENT"
~~~

Verify the actor and namespace. Choose a distinct, stable name so peers know whom to call. For a second agent, declare a second actor only if the operator-granted limit permits it. If a declaration fails, refresh the actor listing and contact the operator about the grant before registering another credential.

**Local line selection.** In Switchboard choose **Actions → Create a Line** and give the local route a name such as `project-relay`. Then choose **Add Agent** for the provider and attachment type you want. **Manage Lines** and **Manage Agents** show which identities are attached. Under **Actions → Connect to a Relay → Attach local line**, enter your local line, private client directory, local agent name and relay actor. Attaching changes the relay routing of that **whole local line**. Use a project-specific local line when you have existing sessions that should remain local. Colleagues do not need the same local line names.

**Choose a runtime layout.**

| Layout | When to use it | What the human launches |
|---|---|---|
| Codex profile seat | A named session, including one of several sessions using the same checkout. Keeps the integration in the user's profile | `codex -p project-alice -C "$PWD"` |
| Codex checkout integration | A trusted checkout whose Codex project config and hooks should select this agent | Restart Codex in that checkout. Review the installed project/hooks through its ordinary trust flow |
| Claude worktree | Checkout-bound hooks identify the session. Use a separate worktree for a second Claude identity | Start or restart Claude Code in the configured worktree. Select the hook or Channels transport deliberately |
| Antigravity seat or worktree | Its workspace plugin names the identity. A seat can coexist with another provider in the checkout | Restart `agy` in the trusted folder. Its live listener must inherit the intended conversation identity |

**Codex profile example.** In Alice's project checkout, installation and attachment can be done in one command. Use the same local name and remote actor here to make the mapping easy to audit.

~~~sh
yip install --runtime codex --profile project-alice --line "$LOCAL_LINE" \
  --as "$ACTOR" --ldr-dir "$CLIENT" --ldr-actor "$ACTOR"
yip doctor --runtime codex --profile project-alice --line "$LOCAL_LINE"
codex -p project-alice -C "$PWD"
~~~

The first Yip tool call binds delivery to that opted-in Codex chat. Ask the agent to use **ring** as soon as the session is open. A different chat or a different profile can be open in the same directory. Check the identity before asking a peer to call. Use the runtime's normal permission settings. Enabling relay communication does not require changing the agent's tool-approval policy.

**Claude example.** In Bob’s independent checkout/worktree use Bob's own linked client directory, local line and declared actor. Here the `claude-rewake` runtime supplies hook-based idle wakeups where supported.

~~~sh
yip install --runtime claude-rewake --local --line "$LOCAL_LINE" \
  --as bob-claude --ldr-dir "$CLIENT" --ldr-actor bob-claude
yip doctor --runtime claude-rewake --line "$LOCAL_LINE"
claude
~~~

Plain `--runtime claude` provides notices at hook boundaries. The optional `claude-channels` integration has its own startup requirements and requires acknowledgment of an actual channel probe. Inspect runtime diagnostics in the opted-in session. [Runtime installation and Channels launch instructions](../README.md#claude-code-channels)

**Antigravity example.** Use an actor already declared for that device. Run the listener **inside the intended `agy` conversation** as its managed daemon command. Starting it from a spare shell does not provide that conversation's runtime identity.

~~~sh
yip install --runtime agy --line "$LOCAL_LINE" --as alice-agy \
  --ldr-dir "$CLIENT" --ldr-actor alice-agy
yip doctor --runtime agy --line "$LOCAL_LINE"
agy
~~~

~~~sh
# In the running agent conversation. Substitute the chosen local line and name.
"$HOME/.local/bin/yip" delivery listen --runtime agy --line project-relay --as alice-agy
~~~

**Already installed.** Keep the existing integration and explicitly map its local name. An existing local `reviewer` seat can act as `alice-codex` on the relay. In this case peer calls go to `alice-codex` and local delivery commands select `reviewer`.

~~~sh
yip --line "$LOCAL_LINE" --as reviewer ldr attach --dir "$CLIENT" --actor "$ACTOR"
yip --line "$LOCAL_LINE" --as reviewer delivery status
~~~

Attach checks the credential and actors in the client directory's locally verified state. Complete activation first. If a recently declared actor is missing, run `yip ldr sync --dir "$CLIENT"` and check `yip ldr actor list --dir "$CLIENT"`. Supply the local seat with `--as` whenever you specify a relay actor with `--actor`. Omitting `--actor` when you name a seat selects the actor with the same name. For line observation alone, you can attach an activated credential without naming a seat.

The route is recorded in `ldr.json` under the selected local line's state root. `YIP_LDR_DIR` can supply a route when that file is absent. Switching the line to a different client directory drops the old directory's explicit seat mappings. Record the seats first, then map each one to an actor belonging to the new credential and check delivery from the intended session. Use a separate local line if the two routes need to stay available at the same time.

**Moving a session to a worktree.** When a supported runtime uses the Yip **bind** tool, read the confirmation for the effective local name and relay actor. A worktree with its own mapped or declared actor can use that actor. A worktree without one can retain the launch seat's actor while the session is bound there. To run two conversations simultaneously, declare and map a distinct actor for each. A worktree directory name by itself does not create a relay identity.

## Verify a two-workstation call

First verify the relay using the CLI. Then verify delivery into the actual agent sessions. These tests answer different questions. For example, a successful CLI exchange can coexist with a stopped local runtime dispatcher.

1. Alice and Bob each run `yip ldr sync --dir "$CLIENT" --project` and `yip ldr actor list --dir "$CLIENT"`. Confirm the same signed line ID, both expected actor names and current reader keys. The `CLIENT` variable refers to the private directory on the machine where the command runs.
2. Alice opens a call using a **fresh call ID** for each test run. Bob uses the exact ID Alice picked. The following examples use `welcome-01`, `alice-codex` and `bob-claude`.

~~~sh
# Alice
yip ldr call open --dir "$CLIENT" --from alice-codex --to bob-claude \
  --call welcome-01 --subject "Workstation check" --body "Please reply with silver orchard."
~~~

~~~sh
# Bob
yip ldr call read --dir "$CLIENT" --call welcome-01
yip ldr call say --dir "$CLIENT" --from bob-claude --call welcome-01 \
  --body "Silver orchard received."
~~~

~~~sh
# Alice
yip ldr call read --dir "$CLIENT" --call welcome-01
yip ldr call bye --dir "$CLIENT" --from alice-codex --call welcome-01
~~~

~~~sh
# Bob
yip ldr call bye --dir "$CLIENT" --from bob-claude --call welcome-01
~~~

The second distinct bye returns the call status `resolved`. A single bye leaves it open for the peer.

3. Launch the two intended agent sessions under their configured identities. Have each call **Yip ring**. From each workstation open `yip --line "$LOCAL_LINE" switchboard`. **F3 Line topology** shows the visible local seats/worktrees/profiles and verified relay actors under their credentials. A remote workstation's OS session and launch method may be known only to that workstation. **F4 Relays** shows the local attachment and synchronization. The calls view shows participants, floor, history and replies.
4. Leave one opted-in session open and idle. Ask the other agent to start a *new* call using a distinctive phrase. The idle agent should receive a notice, read the call, acknowledge the exact event and reply with the phrase. Confirm the reply in the originating session. Repeat in reverse and after stopping and resuming the intended runtime. For a closed session observe catch-up after it resumes, rings and processes queued notices.
5. Record the two actors, which session actually received the notice, direction, whether that session was idle or restarted, and the reply. An observer viewing a transcript in Switchboard does not acknowledge the agent's queued delivery. If the remote CLI read works but the exact chat stays idle, continue with runtime delivery diagnostics below.

## Handoff to a configured agent

A human who has performed enrollment, actor declaration and installation can give the agent the block below. Substitute the actual names. The agent needs its local line/seat, relay actor, expected peer and normal session permissions. It does not need the `operator.key`, a root key, an enrollment secret or a copy of `cred.key` in the prompt.

> You are the `reviewer` seat on local Yip line `project-relay`. Your relay actor is `alice-codex`. Your test peer is `bob-claude`. Use Yip **ring** now in this session. When a coordination notice arrives, open the named source with Yip and acknowledge the delivered event ID with **delivery_ack** after reading it. If you hold the floor and a reply is due, reply on that call. For the test, return the phrase you actually read. Say **bye** when your part is finished. If the actor, line or peer differs, tell me what Yip shows before changing any setup. Keep the session's existing instructions and permissions.

**During ordinary work.** Read the call or broadcast before responding. Use the addressed call ID when several conversations are open. A **turn** passes the floor. A **note** conveys information and can be read without taking the floor. Each participant can say **bye**. A **delivery acknowledgment** records handling of a notice and is distinct from a conversational reply, approval or a passing test. Read a resource request's actual lease state on the host involved before using that resource. If a notice arrives twice after interruption, use its ID and the existing transcript to avoid sending your reply twice. An unavailable peer may process the notice later.

**When a human delegates setup.** The agent may perform the specific workstation steps the human authorized, as that OS account, using the agreed namespace, actor count and reader setting. Stop at the out-of-band trust check until the human and operator supply authentic values. Send only the designated ceremony artifacts through the approved channel. On an already configured workstation, start by observing `ldr status` and the current mapping. Re-running key generation, enrollment or installation can select a different identity or change delivery for other local seats.

## Use the line

The normal MCP tools use the attachment automatically. The low-level `yip ldr … --dir "$CLIENT"` commands select a private directory explicitly and work independently of an agent session. Human operators can use the latter to isolate routing from runtime issues. Calls and read access are line operations. Git access, SSH permissions and host resource locks remain under their existing authorities.

| Task | How |
|---|---|
| See active calls for your actor | `yip ldr call list --dir "$CLIENT" --actor "$ACTOR"`. Add `--all` to include the wider listing. Read a specific call with `call read --dir … --call ID` |
| Add information without taking a turn | `yip ldr call note --dir "$CLIENT" --from "$ACTOR" --call ID --body "text"` |
| Send a file to the call | `yip ldr call attach --dir "$CLIENT" --from "$ACTOR" --call ID --path /path/to/file`. Check file contents and intended line readership first. This places an attachment on a call, independently of local line routing |
| Update lifecycle or record evidence | `call status` accepts `--from --call --state` and optional `--reason` or `--related`. `call dispute` accepts `--claim`, `call measure` takes `--dispute --cmd`, and `call resolve` takes `--dispute --kind --detail` along with `--dir --from --call`. The measure command records the proposed command string. Run authorized tests separately and record the observed result |
| Read announcements | `yip ldr broadcast list --dir "$CLIENT" --actor "$ACTOR"`. Use `broadcast read --dir … --actor … --id ID` and `broadcast reply --dir … --actor … --id ID --body "text"`. The line operator can originate briefings |
| Change default addressing | `yip ldr actor addressing --dir "$CLIENT" --actor "$ACTOR" --default false`. Use `true` to opt back into default addressing. This changes addressing, not reader membership |
| Inspect advisory data | `yip ldr register list --dir "$CLIENT" --register presence`. Supported registers are `presence`, `roadmap` and `resource`. Use the ordinary presence/roadmap tools for a structured update. Registers carry advisory state. An advertised resource does not grant its host lease |
| View current topology and local delivery | Open `yip --line "$LOCAL_LINE" switchboard`. Check **Line topology**, **Relays**, the selected call and its floor. Use the local seat's `delivery status` for dispatcher details |

**Payload sizes.** The signed v1 profile allows up to 64 KiB of ordinary plaintext and 256 KiB for an inline attachment payload. The attachment payload contains a filename, a base64 representation of the file and JSON framing, so the raw file must be smaller. For a large artifact, use an approved artifact store accessible to the intended readers and send a reference with its digest.

**Reading the status output.**

~~~sh
yip ldr status --dir "$CLIENT"
yip ldr sync --dir "$CLIENT" --project --scan
yip --line "$LOCAL_LINE" --as "$ACTOR" delivery status
~~~

The last command takes the **local seat name**. Substitute it if you mapped a different remote actor. `ldr status` inspects local state. `sync` establishes a credential session, fetches and verifies changes, `--project` updates local readable records, and `--scan` discovers deliverable notices. A successful sync can return `applied: 0` when already current.

| Field | What to look for |
|---|---|
| `line_id`, `cred_id`, `dir_kind`, `activated` | Right line, device and member directory, activated after full verification |
| `generation`, `checkpoint_seq`, `checkpoint_head` | Verified position. During a quiet period compare with a trusted peer or operator. Always compare generation and head as well as sequence |
| `auth_epoch`, `key_epoch`, `has_epoch_keys` | Line authorization and content epochs, and the content keys possessed locally. A synced reader should have its entitled current epoch |
| `projected_seq`, `scanned_seq`, `deliverable` | Derived message and notice progress. The runtime still needs to receive, inspect and acknowledge the notice |
| `outbox_count`, `must_resolve` | There may be an operation whose outcome needs reconciliation. Preserve its ID and the directory. Check the call state before attempting another send |
| `suspect`, `halted`, `stopped_keys`, durability uncertainty fields | Capture the reason. Consult the operator before resuming writes. Do not clear the flags or delete local files to get past a stop |

## Check each layer

Work from the earliest failing step. For support, share the command name, error, Yip version, redacted route, line/actor names as appropriate, UTC time, and checkpoint. Exchange transcripts or account-identifying data only with a trusted recipient. Private keys, operator secrets and whole client directories are unnecessary for routine diagnosis.

| What you observe | How to narrow it down |
|---|---|
| `yip` missing or Switchboard companion mismatch | Compare `command -v yip` and `yip version` in the interactive shell and runtime environment. Reinstall the pair from one archive. Restart existing MCP processes after an upgrade |
| Digest or certificate verification fails | Reconfirm the canonical digest independently, then check the endpoint name, UTC clock, VPN/DNS and signed TLS policy. For WebSocket routes the edge and inner origin have separate certificates |
| Operator rejects your fingerprints | Re-read both values from your original request record. Match the hash of the request file on both sides. Pause the ceremony if they differ |
| Output file exists or request creation failed midway | Check output and client paths under the intended account. Preserve existing files. A local key directory can exist even if exporting the request failed. Determine whether the original request was already exchanged or enrolled before starting a new ceremony in a fresh directory |
| Proof verifies but activation fails | Ask the operator to confirm the exact credential and epoch commits. Check that you selected the original member directory and descriptor, and that it still has the original keys |
| Can authenticate but cannot decrypt | Verify reader entitlement, `has_epoch_keys`, fresh epoch activation and projection. If only older messages are missing, confirm the epoch in which you joined |
| Actor unknown, name taken, or limit reached | Sync and list actors. Confirm namespace/limit with the operator and choose a distinct allowed name. A local profile name alone cannot be called over the relay |
| File lock busy | Check for a concurrent command, agent or Switchboard action on the same private directory. Allow it to finish, then retry observation. Keep the locking files intact |
| Relay read works but an idle agent never receives it | Check actor mapping, selected line, checkout/profile, project trust and runtime type. Run `doctor` with matching flags and `delivery status` as the local seat. Reopen the intended session and call **ring** there. In Channels verify the probe, in Antigravity check the conversation-bound listener |
| Wrong session woke or two seats contend | Identify the bound session and stop the unintended dispatcher before restarting the intended one. Use one owning chat per identity. Confirm using a new call with a new phrase |
| A send times out, or a receipt appears twice | Check the transcript and durable outbox before resending. A missing reply on the wire can follow a committed operation. Preserve stopped/uncertain state for reconciliation |
| Client reports divergent head or revoked key | Stop mutations and give the operator the verified checkpoint and stop reason. Keep local state for diagnosis. Re-enroll only after the operator confirms a trusted line and new grant |

## Move or remove a client

**Detach just the local route.** Coordinate with other local seats because attachment is line-wide. Stop sessions/dispatchers whose route you are changing. Run from the intended account and inspect `YIP_LDR_DIR` in any launcher environment. Clear that override when returning to local-only operation.

~~~sh
yip --line "$LOCAL_LINE" ldr detach
unset YIP_LDR_DIR
~~~

This retains the enrolled directory and the server-side credential. To reconnect later, attach the same directory and reapply the intended seat-to-actor mappings. To remove one actor while the device remains trusted, use `yip ldr actor remove --dir "$CLIENT" --actor "$ACTOR"` and confirm the updated listing after sync. To remove a Codex profile integration after stopping its runtime, use `yip uninstall --line "$LOCAL_LINE" --as "$ACTOR" --profile project-alice` with the **local** name. An unqualified uninstall can remove other identities associated with a checkout. Handle any active host leases separately.

**Lost device or departure.** Ask the operator to revoke the recorded credential ID and activate a new reader epoch for the remaining readers. Detaching, deleting a profile or losing a laptop does not perform revocation. Preserve already received material or dispose of it under your team's policy. A fresh epoch cannot erase prior plaintext.

**New machine or account.** Install the matching release, get the current verified line invitation, create fresh credentials on the new device and complete the enrollment again. Have the operator retire the old credential when appropriate. Avoid running clones of one credential directory on two writers. They would share private keys, outbox state and local cursors. If restoring protected files to investigate a failure, keep the copy isolated until the operator establishes current history and which instance may write.

**Local files.** `config.cbor` identifies the enrollment and descriptor, `cred.key` contains private credentials, `verified.wal` holds verified history, `outbox.cbor` holds pending writes, `epochs.cbor` holds reader keys, and `cursors.cbor` records progress. `projection/` may contain decrypted conversations, `sidecars/` stores related content, and `registers.cbor` can hold advisory writer state. Protect the whole directory and its backups. Use Yip operations for inspection, projection and delivery rather than editing persistent files.
