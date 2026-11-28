# Put a project team on a shared Yip relay

Use this guide to connect colleagues’ agent sessions across machines while they work on the same Git repository. It assumes the workstations can reach an internal relay over the office network or VPN. Install the same Yip release on the relay host and each workstation. For a packaged release, extract the archive for each machine’s platform and follow the [binary installation instructions](RELEASE.md).

Use one signed project line, a private client directory per colleague’s workstation account, and a distinct actor name for each participating agent. **Reader access applies to the whole line.** Call recipients determine who gets addressed. Every enrolled reader can decrypt line content for the key epochs it receives. A new reader verifies the earlier control history but receives no earlier message keys. Choose line membership separately from Git repository access.

For host operation, backup and key incidents use the [relay administration manual](LDR-ADMINISTRATION.md). For workstation enrollment, runtime configuration and agent handoff use the [relay client manual](LDR-CLIENT.md).

For guided setup, start with **Switchboard → Actions → Set up a relay**. Existing operators can go directly to **Invite a workstation**. Colleagues use **Join a line**. [Guided administration](LDR-ADMINISTRATION.md#guided-setup-in-switchboard) · [Join from an invitation](LDR-CLIENT.md#join-from-an-invitation)

## 1. Relay administrator — prepare the shared host

Run the relay under a dedicated, unprivileged service account with a private, persistent data directory. In that account, substitute your internal DNS name for `relay.internal` and generate the server certificate.

```sh
umask 077
yip relay init --dir "$HOME/.yip-relay" --hosts relay.internal
```

Keep the TLS private key on the server. Give the root owner the printed `pin_spki_sha256` through a trusted channel. The root and operator private keys belong under separate custody from the relay service account.

## 2. Root owner — create the project line once

1. On the admin workstation, open **Switchboard → Relays (F4) → Relay operator → Line administration**. Generate two distinct root keys. Either root can authorize an operator or replace the other, so keep them separately. Generate a third signing key for day-to-day operator work.
2. Choose **Sign line descriptor**. Supply both root public keys, one root signing key, the URL `https://relay.internal:8443`, TLS policy `pin_spki_sha256`, and the pin verified with the relay administrator. Save `line.desc.cbor`.
3. Give the relay administrator the signed descriptor. On the server, provision the line and start the listener. Replace the example IP below with the server’s internal interface address.

   ```sh
   yip relay provision --dir "$HOME/.yip-relay" --descriptor "$HOME/line.desc.cbor"
   yip relay serve --dir "$HOME/.yip-relay" --listen 10.20.30.40:8443
   ```

   Run the serve command under the host’s service manager, using the same account and data directory. Allow the listener port from the office or VPN network and keep the server clock synchronized. The relay can suspend writes if its clock becomes uncertain.
4. On the admin workstation, choose **Initialize provisioned line** and then **Authorize operator**. Use a private admin client directory such as `~/.yip-ldr/admin`, a root signing key, and the operator public key. Return the roots to storage.

The companion guide includes the CLI equivalents and alternative configurations for a corporate CA or HTTPS edge proxy. [LDR operator quickstart](LDR-QUICKSTART.md)

## 3. Operator — enroll the admin reader once

**The operator key authorizes enrollment. Activating a fresh encryption epoch also requires an enrolled reader credential in the admin client directory.** Complete this step before enrolling your team.

Choose **Line administration → Create operator reader request**, using the same admin directory. Choose **Inspect signed request**, check the admin reader grant, then issue a challenge using its reviewed request digest and both device fingerprints. Prove possession in the admin directory, then enroll the verified workstation with the operator key. These are the same **Issue challenge**, **Prove workstation keys**, and **Enroll verified workstation** actions described below. The challenge secret stays in the admin account.

If you also want your own coding session on the line, enroll it as an ordinary member. Keep administrative keys and the admin client directory outside the agent’s accessible workspace.

## 4. Operator and colleague — enroll each workstation

Give each colleague `line.desc.cbor` and `operator.pub`. Confirm the descriptor fingerprint and the operator public key through a known channel independent of the file transfer. The operator can display the descriptor fingerprint with this command.

```sh
yip ldr inspect --descriptor line.desc.cbor
```

| Who | Switchboard action | Handoff |
| --- | --- | --- |
| Colleague | Under **Actions → Connect to a Relay**, choose **Verify relay connection** and enter the trusted descriptor fingerprint. Then choose **Create workstation request**. Use a private client directory such as `~/.yip-ldr/project`, a unique namespace such as `alice-laptop`, an actor limit of `1` for one agent, and **Receive encrypted content**. | Send the request file to the operator. Confirm both printed workstation fingerprints, signing and encryption, through the independent channel. |
| Operator | Under **Relays → Relay operator → Enroll workstation**, choose **Inspect signed request**. Check line, namespace, actor limit and reader access. Choose **Issue challenge** using the reviewed request digest and both independently confirmed fingerprints. | Send the challenge file to the colleague. Keep the separate secret file in the operator account. |
| Colleague | Choose **Prove workstation keys** with the original client directory, request, challenge, and verified operator public key. | Return the proof file. The private workstation keys stay in the colleague’s account. |
| Operator | Choose **Enroll verified workstation** with the request, challenge, secret, and proof. After enrolling the intended readers, choose **Activate reader epoch** from the enrolled admin directory. | Tell the colleagues they can activate their workstations. Several readers can be enrolled before this epoch change. |
| Colleague | Choose **Activate workstation**, then **Declare actor**. Use distinct names, for example `alice-codex` and `bob-claude`. | The workstation can now reconnect using its enrolled credential. |

Put each private client directory on the machine where the corresponding agent runs. If several colleagues run on the same physical server, use separate OS accounts and private client directories.

## 5. Colleague — attach the intended agent session

In your checkout, choose **Actions → Create a Line** to create a dedicated local routing name such as `project-relay`. Choose **Add Agent**, then the provider and attachment type. Under **Actions → Connect to a Relay → Attach local line**, select that line, your enrolled client directory, the local agent name, and its declared relay actor.

**Attaching changes routing for the entire local line.** Giving the pilot its own local line keeps unrelated sessions on their existing routes. Each workstation can choose its own local line name. The signed descriptor identifies the common relay line.

For one Codex session among several, choose **Codex profile**. Here is the CLI equivalent of installing and attaching Alice’s profile after enrollment and actor declaration. Run it from her checkout.

```sh
yip install --runtime codex --profile project-alice \
  --line project-relay --as alice-codex \
  --ldr-dir "$HOME/.yip-ldr/project" --ldr-actor alice-codex

codex -p project-alice -C "$PWD"
```

For Claude Code, choose **Worktree**, install in Bob’s own checkout, and attach his local identity to `bob-claude`. Restart Claude there so it loads the Yip integration.

## 6. Both colleagues — verify a real call

Have both agents run **Yip ring** and leave Bob’s session idle. Ask Alice’s agent to call `bob-claude` with a short phrase and ask Bob to reply. Check **Line topology (F3)** for both actors under their respective workstations, **Relays (F4)** for a verified checkpoint, and the call transcript for Bob’s reply. This exercises enrollment, routing, and delivery into the intended session.

When a colleague leaves, the operator revokes the workstation credential and activates a fresh reader epoch. **Detach** changes local routing only. The [operator quickstart](LDR-QUICKSTART.md) includes the revocation commands.
