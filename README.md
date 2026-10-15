# envs

## GitHub Issue Actions: one Org Secret slot

`jev-api.github-actions` binds the existing encrypted SOPS source to the single
`roccho-org/JEV_API_KEY` Actions Org Secret, selected by the stable IDs of
`roccho-org/ops` and `roccho-org/envs`. No Ops Repository or Environment Secret
copy is produced. The existing Cloudflare/local bindings and authoring inputs
are unchanged.

The provided `envs-effect` entry has an owner-only setup command:

```sh
envs-effect --root <exact-source-checkout> project-org-secret \
  --envs-sha <provided-source-sha> \
  --auth-config /work/repos/.auth/roccho-dev/gh \
  --identity /work/repos/.auth/roccho-dev/age/oci-dev.key
```

Without `--apply`, this performs authentication/Org identity/public-key reads
only: no SOPS decryption, encryption, secret write or handoff. The output is a
plan, never a projection receipt. Actual `--apply` needs an explicit effect
grant. The controller must be the existing `roccho-dev` principal; private
inputs must be owned regular files with mode0600 under mode0700 directories.
The controller credential remains in the owner's native process, never CI.

An applied operation uses SOPS plaintext only in the bounded process and gh
encryption stdin, writes only the Org slot using selected repository IDs, and
requires exact name/visibility/repository readback. Only then is
`handoffs/dev-jev-api.github-actions.json` created. It binds the provided source,
target and controller but explicitly records `provider_use: NOT_RUN`. A plan,
CI PASS or that receipt is not evidence of a real Jev evaluation. Existing Org
slot, handoff or unknown write/readback is reconciled, not replayed or overwritten.
Setup needs an exclusive authorized writer; a metadata GET is not an atomic
lock against another administrator.
Rotation/revoke remains separately authorized: replacement real use must precede
provider revocation; this command does not issue or revoke a Jev key.

Normal evaluation runs on GitHub-hosted Actions and does not call, clone or wait
for envs CI. OCI is used only for development and authorized setup, not as an
application ingress or runtime dependency. Consumer admission, finite budget,
same-Issue append/readback and first/next real evaluation are separate app gates.

`envs` holds public environment contracts, performs bounded provider projection, and returns a non-secret exact-SHA handoff.

- canonical branch: `proposals`
- retained compatibility branch: `main`
- accepted handoff identity: exact commit SHA

`main` remains available, but it has no independent meaning, direct changes, pull-request base, Environment effect, or handoff identity. When `main` is refreshed, its push-time check requires that revision to equal the then-current `proposals` revision. There is no continuous synchronization claim; `main` may be stale between explicit compatibility refreshes.

## Ownership

```text
contracts  = public meaning, IDs, relationships, required input names/types/lifecycles, and forbidden dependencies; never values
ciphertexts = versioned dev ciphertext only
adapters   = bounded envs-owned authoring/projection/readback
handoffs   = non-secret provider-effect receipts
checks     = executable repository and adapter specifications
```

`envs` does not own application runtime acceptance, independent consumer execution, generic deployment, UI meaning, live target observation, secret issuance, or target runtime state.

## Durable tree

```text
.github/workflows/
flake.nix, flake.lock
contracts/
ciphertexts/       # absent while dev (Jev, rent tunnel) is NOT_CONFIGURED
adapters/jev_api.py
adapters/place.ps1, adapters/rent-receive.sh   # target-run placement entrance and rent receiver
providers/         # disposable probe and state-proof declarations only; never state or lock files
handoffs/          # absent until real projection/readback PASS
checks/
LICENSES/
LICENSE_POLICY.md
THIRD_PARTY_NOTICES.md
```

## Contracts

- `contracts/environments.jsonl` — stage and secret-plane ownership
- `contracts/bindings.jsonl` — application and capability bindings
- `contracts/targets.jsonl` — desired target meaning only
- `contracts/provider-consumer.jsonl` — envs/apps/ops responsibility and normal-path exclusions
- `handoffs/dev-jev-api.json` — real projection/readback PASS after exact-SHA non-secret handoff

## Environment inputs

`contracts/environments.jsonl` declares each GitHub Environment's `required_secrets` and `required_variables` by name, type, and lifecycle. The actual values live only in the GitHub Environment; the owner sets them there without a commit. Git never stores a value body: before any provider effect the adapter turns a missing or invalid required input RED, and turns RED when a live Variable value appears anywhere in the repository. The only exception is the recipient metadata that sops writes into `ciphertexts/dev-jev-api.sops.yaml`, `ciphertexts/dev-rent-tunnel.sops.yaml`, `ciphertexts/dev-rent-client.sops.yaml` and `ciphertexts/dev-jev-api.oci-dev.sops.yaml`. A binding may declare its own input on an existing Environment (`jev-api.oci-dev` declares `OCI_DEV_AGE_RECIPIENT` on `dev-authoring`); only that binding's authoring reads it.

| Environment input | Kind | Type | Lifecycle |
|---|---|---|---|
| `dev-authoring/JEV_API_KEY` | secret | opaque | one_shot_ingress |
| `dev-authoring/OPENCODE_API_KEY` | secret | opaque | one_shot_ingress |
| `dev-authoring/SOPS_AGE_RECIPIENTS` | variable | age_recipient_list | persistent |
| `dev-authoring/OCI_DEV_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `dev-authoring/VERSAPRO_OWN_OCI_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `dev-projection/SOPS_AGE_KEY` | secret | age_identity | persistent |
| `dev-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-projection/RENT_CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `dev-projection/RENT_CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `dev-projection/RENT_TUNNEL_ID` | variable | cloudflare_tunnel_id | persistent |
| `dev-projection/RENT_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `dev-projection/AWS_ACCESS_KEY_ID` | secret | opaque | persistent |
| `dev-projection/AWS_SECRET_ACCESS_KEY` | secret | opaque | persistent |
| `dev-projection/RENT_STATE_PASSPHRASE` | secret | opaque | persistent |
| `dev-projection/RENT_CLOUDFLARE_ZONE_ID` | variable | cloudflare_zone_id | persistent |
| `dev-projection/RENT_HOSTNAME` | variable | opaque | persistent |
| `dev-projection/RENT_ORIGIN_SERVICE` | variable | opaque | persistent |
| `dev-projection/RENT_SERVICE_TOKEN_DURATION` | variable | opaque | persistent |
| `dev-projection/RENT_STATE_BUCKET` | variable | opaque | persistent |
| `dev-projection/RENT_STATE_KEY` | variable | opaque | persistent |
| `dev-projection/RENT_CLIENT_AGE_RECIPIENT` | variable | age_recipient | persistent |
| `dev-projection/LINODE_API_TOKEN` | secret | opaque | persistent |
| `stg-projection/JEV_API_KEY` | secret | opaque | persistent |
| `stg-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `stg-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |
| `prd-projection/JEV_API_KEY` | secret | opaque | persistent |
| `prd-projection/CLOUDFLARE_API_TOKEN` | secret | opaque | persistent |
| `prd-projection/CLOUDFLARE_ACCOUNT_ID` | variable | cloudflare_account_id | persistent |

A host is not a GitHub Environment. The dev stage keeps two functional Environments, `dev-authoring` and `dev-projection`; rent's stage ingress lives in `dev-projection` beside Pages, Mail and Linode, and no host-specific `dev-rent-tunnel`, `dev-rent-client` or `dev-rent-access-probe` Environment is selected or declared. Rent never reads the Pages/Mail `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID` slots: its Cloudflare inputs are the distinct `RENT_CLOUDFLARE_API_TOKEN`, `RENT_CLOUDFLARE_ACCOUNT_ID` and `RENT_CLOUDFLARE_ZONE_ID` slots, which the adapter hands to its OpenTofu/API children only under the provider-native names. No equality of value or scope between the two token slots is assumed, and no combined token exists. Sharing one Environment is the chosen stage trust boundary: each job maps only its own inputs, which limits exposure but is not job-level secret isolation.

`dev-projection` carries the rent planes: the standalone tunnel token GET (`dev.rent-tunnel`, no workflow) and the persistent root (`dev.rent-root`), which the hard-inactive workflow would run and which reads every rent input above except `RENT_TUNNEL_ID`. `RENT_TUNNEL_ID` stays declared for that standalone entry only; nothing creates or invents its value. `opaque` inputs are checked only for presence and for not appearing in the repository; OpenTofu and the provider decide whether a hostname, origin service or duration is valid, so this document names inputs and never their values.

There are no stg or prd authoring Environments. The disposable Access probe and R2 state proof (`dev.rent-access-probe`, `dev.rent-state-proof`), their workflows, provider roots and parent token inputs are retired; their earlier runs remain history only, and any leftover provider cleanup is a separate owner decision.

A plane row's `github_environment` names where the contract declares that plane's inputs; it is not an instruction to provision a GitHub Environment. The claim runs one way: a plane row alone does not require a live Environment, and a workflow job that selects one with `environment:` requires it for that run. `ACTIVE` still records only a sealed envelope. `dev.rent-client` is an output plane with no Environment of its own: `ciphertexts/dev-rent-client.sops.yaml` is sealed by `rent-root`, which reads its one recipient, `dev-projection/RENT_CLIENT_AGE_RECIPIENT`, as the producer, and whose job is hard-inactive (`if: ${{ false && ... }}`); the standalone `rent-client` entry reads the same producer declaration. Likewise `stg.projection` and `prd.projection` are `NOT_CONFIGURED` declarations; they do not require live Environments to be provisioned. Conversely, the absence of a selecting job does not show that an existing Environment is unneeded or may be deleted: it may serve a future stage, hold retained state or credentials, or be selected by a workflow on another ref.

### Temporary one-time rent Secret relocation

Until it is retired, `relocate-dev-rent-secrets` is the only workflow that still selects the old `dev-rent-tunnel` Environment. It is manual, gated before the Environment to `roccho-org/envs`, the branch ref `refs/heads/proposals` (never a tag), `workflow_dispatch`, the dispatched `expected_source_sha` (its only input), run attempt 1 and the `roccho-dev` controller, with `contents: read` only. It builds the locked nixpkgs Python with PyNaCl and runs a synthetic self-test before its one seal step maps the four existing Secrets `CLOUDFLARE_API_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `RENT_STATE_PASSPHRASE`; that job is one trusted Environment boundary, and the step mapping is not job isolation. `adapters/relocate_rent_secrets.py` seals their exact environment bytes (no strip, normalization or format check; only non-empty and at most 48 KiB each) with a standard libsodium sealed box to the existing `dev-projection` public key fixed in source, and writes one encrypted receipt (destination names `RENT_CLOUDFLARE_API_TOKEN` and the three unchanged names, `key_id`, run and Environment identities) uploaded for three days. No value, length or hash is printed, and nothing here can decrypt it. The owner registers each ciphertext through the standard Environment Secret API and copies the nine Variables privately; the old `MAIL_CONFIG` is not moved and `RENT_TUNNEL_ID` is not created. This proves byte-preserving transport and API receipts only, not provider or runtime acceptance. The workflow, entry, its tests, the repository-check exception and its `check` steps are retired, and the receipt artifact deleted, before `dev-rent-tunnel` is deleted.

## Dev Jev flow

```text
dev-authoring/SOPS_AGE_RECIPIENTS
+ dev-authoring/JEV_API_KEY
→ author-dev-jev-api, target jev-api
→ ciphertext PR
→ merge to exact proposals SHA
→ dev-authoring/JEV_API_KEY may then be deleted by the owner (one-shot ingress);
  author stays RED until it is set again

ciphertext
+ dev-projection/SOPS_AGE_KEY, CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
→ project-dev-jev-api
→ provider effect + name-only readback
→ non-secret handoff PR (no account ID)
```

`envs` never deletes an Environment input; deleting the one-shot source is a separate owner effect.

`author-dev-jev-api` requires one declared target; there is no default. Each target has one literal step that receives only its own inputs, and `author --target jev-api` is the unchanged Cloudflare authoring above.

## Dev OCI Jev target (roccho-dev/adrs#460)

The trusted WSLC OCI dev target (owned by `roccho-dev/windows`) starts the apps dev server with `JEV_API_KEY` in one child process. envs owns only the target-bound ciphertext:

```text
dev-authoring/JEV_API_KEY + dev-authoring/OCI_DEV_AGE_RECIPIENT
→ author-dev-jev-api, `author --target jev-api.oci-dev` (manual dispatch on proposals only)
→ ciphertexts/dev-jev-api.oci-dev.sops.yaml, encrypted to exactly that one recipient
→ ciphertext handoff PR → merge to exact proposals SHA
```

- The binding `jev-api.oci-dev` keeps capability `jev-api` and declares `OCI_DEV_AGE_RECIPIENT`, a single age recipient; a list is RED. This target never reads `SOPS_AGE_RECIPIENTS`, and the Cloudflare target never reads `OCI_DEV_AGE_RECIPIENT`.
- OCI authoring writes only its ciphertext. It changes no plane state, no handoff, and no other target's ciphertext; its readiness is only that ciphertext validating at an exact commit (fields exactly `JEV_API_KEY` plus SOPS metadata, exactly one recipient).
- The key reaches SOPS on stdin only; a key or recipient value already in a tracked file is RED before SOPS runs.
- `checks/test_jev_api.py` proves the gates with fake sops, and in `check` it runs the real locked sops with check-only `age-keygen` identities: the target identity decrypts, and another identity or a tampered ciphertext is RED.

Not proven here, and not owned by envs: the target's identity, applying the ciphertext on the target, the launcher, application runtime acceptance, and any deployment. Source and CI PASS is not a real authoring PASS.

## Dev OpenCode Go OCI authoring (ADRS #530)

`opencode-go.oci-dev` is a separate source capability for the already accepted Windows Pi v1.0.4
`pi_auth_command` resolver. Its authoring selects only its own secret and the one OCI-dev age
recipient, under the existing `dev-authoring` GitHub Environment:

```text
dev-authoring/OPENCODE_API_KEY + dev-authoring/OCI_DEV_AGE_RECIPIENT
→ author-dev-jev-api, `author --target opencode-go.oci-dev` (manual dispatch on proposals only)
→ ciphertexts/dev-opencode-go.oci-dev.sops.yaml (exactly OPENCODE_API_KEY + SOPS metadata; one recipient)
→ ciphertext-only source PR → accepted canonical proposals revision
```

- `dev.opencode-go-authoring` declares the Go source separately from `dev.authoring` (Jev).
  The workflow's literal target steps never pass `OPENCODE_API_KEY` to a
  Jev step or `JEV_API_KEY` to the Go step. Cloudflare's `SOPS_AGE_RECIPIENTS` list
  is not an OCI-dev author input. Sharing the target age recipient does not share the source key.
- The Windows target is exactly `{"repository":"roccho-dev/windows","host":"oci-dev","kind":"pi_auth_command"}`;
  public contract projection validates this *source shape* even when unselected, but it cannot
  execute or project the selected Go secret as a `process_env` value.
- The selected Go source is encrypted to precisely one age recipient by the locked SOPS tool
  using stdin, not argv or process environment. Input leaks into tracked Git, wrong recipients,
  added fields, non-SOPS plaintext or missing inputs are RED before an accepted handoff.
- The existing `checks/test_jev_api.py` fixture tests Go/Jev input isolation, encrypted dummy
  source roundtrip with check-only target/wrong age identities, tampering and rejection cases.
  No real `OPENCODE_API_KEY` value, production ciphertext, provider call, target key or runtime
  adoption is part of this source stage. The committed Go plane is `NOT_CONFIGURED`; only
  later real canonical ciphertext/provisioning can move the live acceptance gate.

## Dev OpenCode Go VersaPro own OCI authoring (roccho-dev/resources#10)

`opencode-go.versapro-own-oci` is the same Go source capability for the VersaPro own OCI's
target-bound Pi resolver. It reads the same Go source plane but its own single recipient:

```text
dev-authoring/OPENCODE_API_KEY + dev-authoring/VERSAPRO_OWN_OCI_AGE_RECIPIENT
→ author-dev-jev-api, `author --target opencode-go.versapro-own-oci` (manual dispatch on proposals only)
→ ciphertexts/dev-opencode-go.versapro-own-oci.sops.yaml (exactly OPENCODE_API_KEY + SOPS metadata; one recipient)
→ ciphertext-only source PR → accepted canonical proposals revision
```

- The target is exactly `{"repository":"roccho-dev/resources","host":"versapro-own-oci","kind":"pi_auth_command"}`,
  the one the resolver built for that OCI compares as a whole value; host `versapro` or `oci-dev` is RED.
- Each target reads only its own declared recipient: `OCI_DEV_AGE_RECIPIENT` is never a fallback for
  this target, and `VERSAPRO_OWN_OCI_AGE_RECIPIENT` never reaches the `opencode-go.oci-dev` step.
- The recipient is the public key the target creates in place with its own bounded `jev-age-init`;
  no private identity leaves the target.
- Declared is not usable: this binding has no ciphertext until it is authored and accepted at an
  exact envs revision, and the target resolver then checks that ciphertext, its one recipient and
  this exact target before any key is released to Pi.

## Dev rent tunnel flow (windows #14)

The rent OCI host runs `cloudflared` from a token file. envs owns only the step from the provider-issued Named Tunnel token to a ciphertext that exactly one target can open:

```text
dev-projection/RENT_CLOUDFLARE_API_TOKEN, RENT_CLOUDFLARE_ACCOUNT_ID, RENT_TUNNEL_ID, RENT_AGE_RECIPIENT
→ envs-effect rent-tunnel (the standalone entry; the workflow now runs rent-root below)
→ one bounded GET of the tunnel token (30 s, 64 KiB, no redirect, entry-owned CA bundle)
→ token in memory → sops stdin, SOPS_AGE_RECIPIENTS = the one target recipient
→ ciphertexts/dev-rent-tunnel.sops.yaml + dev.rent-tunnel ACTIVE
→ ciphertext handoff PR → merge to exact proposals SHA
```

- Inputs are declared, not valued: until the owner configures these `dev-projection` slots, the plane is `NOT_CONFIGURED` and every missing or malformed input is RED before any provider call. `RENT_AGE_RECIPIENT` is a single age recipient; a list is RED, and the ciphertext must name exactly that recipient and carry only `RENT_TUNNEL_TOKEN`.
- The token and the API token never enter argv, a log line, an error message, or the result JSON, and the adapter writes neither to Git. If either is already in a tracked file, the run is RED: the API token before the provider call, the tunnel token before SOPS or any write. The ciphertext is public and permanent in history; recovering from a leaked target identity means rotating the tunnel token, not deleting the file.
- `checks/test_rent_tunnel.py` proves the gates and failure cases with a fake provider and fake sops, and in `check` it runs the real locked sops with check-only `age-keygen` identities: the target identity decrypts, another identity and a tampered ciphertext are RED. `age` is a separate `check-age` output, and `check` proves it is absent from the provided artifact.

## Retired dev rent Access SSH probe (windows #14)

The disposable Access SSH probe (`dev.rent-access-probe`, its manual workflow, provider root, adapter entries and fake/real-ssh checks) is retired from source. It never became a current operation; its earlier runs and their exact-ID cleanup facts remain only in their own run history. Retirement neither deletes nor proves the absence of any provider resource it may have created; any such cleanup is a separate owner decision. `check` still asserts the closure `cloudflared` version and its service-token flags.

Not proven here, and not owned by envs: a real provider retrieval or dispatch of this workflow, the Cloudflare API token scope it needs, whether Actions may open the handoff PR and whether `check` then runs for it, the target's age identity, applying the ciphertext on the target, the client credential, and unattended SSH.

## Dev rent persistent Cloudflare root (windows #14-E)

`providers/dev-rent-cloudflare/main.tf` declares the persistent SSH path the rent will use: one named Tunnel (`config_src = "cloudflare"`) with its ingress, the DNS CNAME, a self-hosted Access application and a Service Auth (`non_identity`) policy for exactly one service token. It reuses the resource shape the disposable probe ran against the real provider, without its `create` gate, and pins the same standard provider (5.21.1). Account, zone, hostname, origin service and `service_token_duration` are required inputs with no default; nothing adopts, imports or moves an existing resource.

It is applied only by `rent-root` under a separate effect grant: the manual `project-dev-rent-tunnel` workflow runs that one entry from the verified artifact, and nothing else plans or applies it. `check` initializes it without its backend and validates it with network access closed, and the repository check refuses the four things native validation accepts: a local (plaintext) backend instead of the locked native S3 backend, unenforced state or plan encryption, a credentials output that is not sensitive, and a service-token lifetime fixed in source. The output being sensitive does not keep the secrets out of state: the Tunnel token and the service-token secret are stored there, encrypted.

```text
dev-projection/RENT_CLOUDFLARE_API_TOKEN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, RENT_STATE_PASSPHRASE,
  RENT_CLOUDFLARE_ACCOUNT_ID, RENT_CLOUDFLARE_ZONE_ID, RENT_HOSTNAME, RENT_ORIGIN_SERVICE, RENT_SERVICE_TOKEN_DURATION,
  RENT_STATE_BUCKET, RENT_STATE_KEY, RENT_AGE_RECIPIENT, RENT_CLIENT_AGE_RECIPIENT
→ project-dev-rent-tunnel (manual dispatch on proposals only; hard-inactive) → envs-effect rent-root
→ the RENT_CLOUDFLARE_* slots reach OpenTofu only as CLOUDFLARE_API_TOKEN, TF_VAR_account_id and TF_VAR_zone_id
→ tofu init (-backend-config bucket and key; the R2 endpoint of RENT_CLOUDFLARE_ACCOUNT_ID) → tofu apply
   TF_ENCRYPTION is built from RENT_STATE_PASSPHRASE with the fixed key provider and method name k0
→ tofu output -json credentials, in memory → tunnel token sealed to RENT_AGE_RECIPIENT and the service token
   pair to RENT_CLIENT_AGE_RECIPIENT, both before any write
→ ciphertexts/dev-rent-tunnel.sops.yaml + ciphertexts/dev-rent-client.sops.yaml
   + dev.rent-tunnel, dev.rent-client and dev.rent-root ACTIVE → ciphertext handoff PR
```

- Secrets reach only the OpenTofu and SOPS children, by environment; the root output exists only in captured process memory. No value enters argv, the outer log, the result JSON, a plain file, a PR or an artifact; a failure prints `RENT_ROOT=RED: <kind> at <stage>`, nothing else.
- `RENT_STATE_PASSPHRASE` must be 64 lowercase hex characters, the format `secrets.token_hex(32)` produces. That is a format check, not proof of strength or of a recoverable copy: the owner keeps its recovery custody, the name `k0` is fixed for the state's life, and rotation is not part of this entry.
- Failures: before the first write (init, apply, output, parse, either seal), existing ciphertext and plane-state files are unchanged. At or after a write, a filesystem, plane-update or validation failure can leave an unpublished partial diff; the run fails, no handoff PR is opened and nothing is claimed. Nothing is cleaned up or rolled back, and a successful apply's provider resources and encrypted remote state stay as they are: no destroy, import, adoption or retry.
- `ACTIVE` records only that the envelopes were sealed (declared plane state); it does not prove that the Environment, the provider or the backend is configured.
- The handoff commit names the repository owner (roccho); the pushing actor is the workflow token and the commit is unsigned. GitHub documents that a pull request opened by the workflow token gets `check` runs that wait for approval. Before merge, the handoff's exact head must have successful `check` runs, from that approval or, only if no such run exists after reconciliation, from a separately authorized `check` dispatch on that branch, never both.
- `checks/test_rent_tunnel.py` proves the entry's routing, refusals, ordering, scoped environments, redaction and failure semantics with fakes; in `check` the closure `tofu` applies an encrypted schema-only fixture root whose synthetic credentials arrive only as `TF_VAR_credentials`, and the production sealer turns its real output into both envelopes with the real sops.

Not proven here: a real Cloudflare apply, the R2 backend's existence, ownership, locking and durability, the state key's recovery, real issued values, credential rotation, any dispatch or approval, and anything on a target. The existing owned bucket, a least-scoped principal, the backend credential, the state-key custody and each target's own age identity are owner prerequisites of the effect grant. The retired disposable R2 proof was design evidence only; a denied connection still needs provider Access evidence, and the exact Windows client, reboot and cutover are later windows #14/#8 gates.

## Dev rent placement (windows #14-E)

One G6I3 normal-user Access service credential serves every surface of the `windows-rent` alias; the rent gets only its Tunnel token. envs owns the projection, the envelopes and the target-run entrance; windows owns each slot's format, the client slot's writer and the consumer (windows PR #37).

```text
tofu output -json credentials (the persistent root's sensitive output) → stdin of `rent-client`
→ the service token pair, each one line of the windows slot rule → sops stdin, one recipient
   (dev-projection/RENT_CLIENT_AGE_RECIPIENT, the producer's declaration) → ciphertexts/dev-rent-client.sops.yaml
   + dev.rent-client ACTIVE

on the target, from the verified envs-placement-<sha> distribution (pinned official sops.exe 3.13.2, the locked
sops version, by its release digest; adapters/place.ps1; adapters/rent-receive.sh; this source's ciphertexts):
place.ps1 -Target client -Identity <the target's own age identity> -WindowsDist <verified windows-dist>
→ sops.exe stdout into memory → '<id>LF<secret>LF' on the stdin of win.ps1 -Mode RentAccess
place.ps1 -Target rent -Identity <identity> -RentImage ghcr.io/roccho-dev/windows-rent@sha256:<digest>
→ token on the stdin of a one-shot `wslc run --rm -i` of that exact image running rent-receive.sh
```

- The plaintext exists only in `place.ps1`'s memory and its private child pipes: never printed, logged, in argv, environment or a file. The writer's exit code is the only result; a refusal is one fixed line. `rent-receive.sh` uses only the image's own bash and coreutils, holds no quote or backslash so it travels as one argument, and replaces the slot rent-start checks (regular file, 0:0, mode 600, 1-4096 bytes, not blank) only while an existing one is exactly that owned shape; any other object is refused and kept, and the same value changes nothing. Both `/var/lib/rent` and `/var/lib/rent/cloudflared` must be real directories owned by uid 0 with no group or other write bit (rent-start lays the state root out 0:0 755; any such mode is accepted), so no other user can redirect or replace the slot. `place.ps1` reads each decrypted value into one fixed buffer of its bound (1024 per client line, 4096 for the token) plus a line break, stops sops beyond it, and discards every other child stream unread.
- `rent-client` projects only the service token pair from a root output given on stdin and never applies the root; `rent-root` above applies it and seals both envelopes. Until an envelope is sealed, its plane is `NOT_CONFIGURED`.
- `placement-gate` in `check` uses each platform's actual CI output from one run: `placement-artifact` builds the Windows distribution, `placement-author` seals synthetic values with the provided Linux artifact, `placement-windows` binds the exact published windows Release named in `contracts/provider-consumer.jsonl` (the tag names that commit; github-actions[bot] published it from a push run whose scope, build, Windows proof, rent image and publish jobs passed; every asset equals GitHub's digest; the ZIP equals its `.sha256`; `rent-image.json` names that source) and runs `place.ps1` in Windows PowerShell 5.1 into windows' own released `ReadRentAccessInput` and `Get-RentAccessProblem`, and `placement-rent` runs `rent-receive.sh` in the rent image that Release names, by digest, after the registry tag resolves to it. Until that Release exists the gate is RED, never assumed.
- Distribution to targets: after every `check` job of a canonical `proposals` push passes, `placement-publish`, the only job with `contents: write`, takes that run's exact `envs-placement-<sha>` directory, requires its closed member set (`SOURCE` naming the commit; `place.ps1`, `rent-receive.sh`, the license texts, the notice and every committed ciphertext byte-equal to the source, `ciphertexts/dev-rent-tunnel.sops.yaml` included; `sops.exe` by its pinned digest; `age-keygen.exe`), writes one ZIP with root members, checks every CRC and byte against the directory, and publishes exactly those bytes with their `.sha256` as Release `envs-placement-<sha>`, whose tag must resolve to that commit (not latest). Pull requests, `main` and manual dispatch never publish. A tag naming another commit, an existing Release with other bytes or uploader, or a failed read without a definite not-found stops the job with nothing created, replaced or retried. A target downloads `envs-placement.zip` without credentials, accepts it only when its size and SHA-256 equal that asset's GitHub digest (the trust anchor; the `.sha256` only has to agree) and its `SOURCE` names the expected commit, extracts it into an absent directory and runs `place.ps1` from there, as above.

Not proven here: the production `-Mode RentAccess` glue (G6I3 normal-user caller, ledger lock, owner-only write; the windows proof covers the writer functions), WSLC (Docker stands in for the receiver), the target identities and their bootstrap, real issuance or placement, Cloudflare acceptance and denial, no-browser behaviour, and packaged Windows Codex.

## Retired dev rent R2 state proof (windows #8/#14)

The disposable R2 state proof (`dev.rent-state-proof`, its manual workflow, bucket and backend roots, adapter entry, evidence parser and checks) is retired from source, and its parent token is no longer an input of any plane. Its earlier runs stay in their own run history only. Retirement deletes and proves nothing about provider buckets, objects or the parent and temporary credentials; old R2 credential and cleanup status remains a separate owner matter.

- History: the parent token ID was once registered as a variable, and as a variable its value was printed in the public step log (run 36797154456); that exposure remains part of the record. A 2026-10-15 audit observed it registered in `dev-rent-access-probe` as a Secret, not a Variable. That observation is not evidence of rotation, revocation or cleanup, and no rent or projection plane reads it.

## Effect toolchain

### Mail plan lifecycle

The Owner adopted [Mail M0 without persistent plans](https://github.com/roccho-dev/adrs/issues/578#issuecomment-6143250867).
The matching operating contract is [ops PR #535](https://github.com/roccho-org/ops/pull/535);
the helper pins its exact candidate commit/tree and unchanged native resources.
The manual Mail entry previews changes with native
`plan -input=false -lock=true -detailed-exitcode`, without `-out`.
An Owner-selected apply uses
`apply -input=false -lock=true -auto-approve -json`; OpenTofu re-plans the approved
fixed source and target at execution time. Approval concerns convergence to
that declaration, not byte equality with an earlier speculative plan.

There is no plan bucket/key, saved-plan show, R2 plan transfer or ETag gate.
The strict private `MAIL_CONFIG` now contains 13 explicit fields: account,
zone, literal alias, Gmail destination, priority, state bucket/key, verified
destination ID and four managed/preflight flags. `plan_bucket` and `plan_key`
are rejected. The existing four credential/passphrase slots remain separate.
The state backend, encryption, lock and recovery still require independent
qualification; this change does not migrate Mail state to a GitHub ref.

Native outputs remain private. A public result may expose only a non-secret
summary; an earlier CI diff never authorizes an apply or a retry. After an
approved apply, independently read the state/provider outcome and require
native no-op exit 0; exit 2, errors, timeout and unknown outcomes are unfinished.
Each fresh runner initializes the selected backend, then performs exactly
one preview or apply. Init failure prevents the operation; there is no
preview-to-apply chain or automatic retry. A preview delta is reported as
`DELTA`; its private native JSON capture yields only fixed resource labels,
action names and consistent add/change/remove counts. Native messages,
attributes, IDs and output values never enter that summary. Missing,
unrecognized or inconsistent inventory is `PREVIEW_UNPROVEN`, not permission
to apply. Its fixed rejection reason and finite native exit distinguish parser
rejection from native operation failure without exposing event payloads.
OpenTofu uses apply-style hooks for data-source reads during planning. Preview
accepts paired `action=read` hooks only for the two fixed verification data
sources, before the plan summary; resource mutation hooks remain rejected.
The supplied native toolchain checks this with a local synthetic data source.
No provider authentication, real state or mail setting is used by that fixture.
Apply success is only `APPLIED_UNVERIFIED`. A failed apply remains
`OPERATION_UNPROVEN`; its bounded private JSON capture may identify fixed resource
labels and numeric HTTP/API codes. Native diagnostic text, URLs and values are
discarded. Unsupported or malformed evidence yields `UNCLASSIFIED`, with the
failure/timeout exit retained. Init failures expose only the fixed init stage.
No failure summary authorizes a retry or recovers a discarded older capture.

`operate-dev-mail-routing` is manual and restricted to the exact canonical
SHA, `roccho-dev`, first attempt and serialized runs. Its closed operations
are `qualify`, `preview` and `apply`, defaulting to qualification.
Target data is never a dispatch input. It always selects the static
`dev-projection` Environment: `MAIL_CONFIG`, its Cloudflare token and
`MAIL_STATE_INPUTS`; it never reads the rent `RENT_*` or `AWS_*` slots.
The state-input Secret is one JSON object containing only `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY` and the unchanged `RENT_STATE_PASSPHRASE`. Its exact
field/type/ASCII/passphrase checks precede private native composition.
The real age identity stays on the Owner's computer; Mail maps no private
age-key Secret and does not use the unrelated existing `SOPS_AGE_KEY`.

Qualification is a separate GET-only step with only target config/token.
It does not receive state inputs or enter crypto. Preview/apply consume the
state-input Secret in memory, copy the pinned Ops files to owner-only scratch,
and use the same-SHA provided effect artifact. Preflight precedes backend init;
init precedes exactly one native operation, with no saved plan or automatic
retry. The packed Secret does not reach native child environments; only the
selected backend/provider inputs do. Native streams remain private and are
never uploaded. No arguments or unsupported operations still return
`INACTIVE / NOT_RUN`, exit78 before reading protected input.

The one-time recovery operation, which once selected the former rent
Environment solely to seal its three state slots to the existing owner public
recipient, has completed and is retired with its `recipient` input, dynamic
Environment selector and upload step. The fixed
`ciphertexts/dev-mail-state.sops.json` remains a recovery copy, not a CI
decryption dependency. Local restoration with the Owner's existing identity
provides only the three necessary values for the projection Secret. Credential
entry and submission in the browser belong to the Owner. Private keys and the
unrelated projection identity are not replaced.

The adopted carrier came from canonical recovery run38511433848,
artifact11869414743. Exact ZIP digest/member bytes were independently
verified, archived under an owner-only ACL, and authenticated decryption to
private memory passed the three-field contract. Source adopts identical
encrypted bytes. No plaintext file or decrypted value/key hash was produced.
Shared age-key holders can open this backup. Structural Source checks reject
duplicate members, plaintext fields/comments, extra documents and alternative
key mechanisms; they do not replace authenticated recovery verification.

Before dispatch, establish the exact target/preflight, operation permissions
and state/lock access. Initial destination/DNS apply keeps the rule unmanaged.
After human Gmail verification and fresh ready/verified readback, a separate
rule apply preserves flags of already-owned resources. A later preview must
return no-op0, and actual delivery needs an independent test message. Input
recovery does not prove existing-state restoration, backend/lock access or
Mail delivery. Source merge does not register inputs or dispatch an operation.

`flake.nix` and `flake.lock` define the only toolchain for authoring and projection: Python, SOPS, Wrangler, Git, GitHub CLI and curl from the locked nixpkgs input, plus the `envs-effect` entry running this source's adapter. `.#effect-artifact` is that entry's complete store closure as one tar with an `ENTRY` pointer.

```text
check (secret-free)   nix build .#effect-artifact → upload envs-effect-<source sha>  # provided artifact
clean-start / effect  obtain by source SHA → verify digest → extract to /nix/store     # no checkout build, no Nix
                      envs-effect --root <checkout> toolchain | author | project        # store paths only
```

`check` checks out, builds, and names the artifact after the exact source commit (the PR head, never a merge ref), and Nix records that commit (`self.rev`) as the artifact's `SOURCE` and manifest `source`; GitHub records its artifact id (locator) and `sha256` digest. The consumer step, identical in `check`'s effect-shape and clean-start jobs and both effect workflows, resolves the one unexpired `envs-effect-<sha>` artifact, requires its producing run to be this repository's `check.yml` for that SHA and branch and either a successful `push` run or the current run, verifies the downloaded bytes against GitHub's digest, requires `SOURCE` to equal the SHA, and only then extracts it without installing Nix. The effect-shape job runs the provided entry over a checkout of the same commit with `--root`, exactly as the effect workflows do before secrets. Effect workflows resolve by the dispatched `github.sha`, so each `proposals` commit consumes the artifact its own post-merge `check` push run provided; no SHA is copied by hand. They record `envs-effect toolchain` before the secret-bearing step and then run only provided store paths; the repository check rejects any rebuild, Nix, other executable, absolute path, command chaining, or substitution there. The runner image (recorded as `ImageOS`/`ImageVersion`), its shell/curl/jq/coreutils/tar/unzip/sudo, and SHA-pinned Actions are the platform boundary; Nix is installed only by the producer.

The entry carries a manifest of its exact tools and nixpkgs lock; before SOPS or Wrangler starts, the adapter turns RED when that manifest is absent, outside the Nix store, differs from the data root's `flake.lock` or adapter, lacks a tool, or is not running on its own Python. `check` also proves Nix regenerates the committed `flake.lock` byte-for-byte, executes each closure tool (including Wrangler's `pages secret put|list --help`), and proves missing, altered, and mismatched artifacts RED in the clean-start job.

This is source and CI evidence only. It does not claim a real authoring or projection effect.

Normal apps/ops execution uses only target-native auth. It does not start or wait for envs, use envctl as a parent, decrypt SOPS, or receive an age identity.

## Checks

```text
python3 checks/repository.py
python3 checks/test_repository.py
python3 checks/test_jev_api.py                                        # --sops/--age-keygen in check: real OCI roundtrip
python3 checks/test_rent_tunnel.py
nix build .#effect-toolchain .#effect-artifact --no-update-lock-file   # check workflow, toolchain job
nix build .#check-age --no-update-lock-file                             # check-only, real SOPS roundtrip
```

The repository oracle calculates accepted structure and state. Its tests deliberately create invalid states and require RED rather than repeating only happy-path execution.

### GitHub-ref transition: S2 SOURCE only (not activated)

The existing `dev.rent-root` effect workflow is **source-hard-inactive at its job
admission guard** (`false && roccho-org/envs && proposals`), before any
Environment secret, artifact/child, old S3/Cloudflare inspect, native apply,
ciphertext write or Git/PR handoff. All other five effect workflows and the
independent R2 state proof retain their prior source and ownership.

The `envs-effect rent-root-inspect` entry has a bounded, read-only
implementation for the **future** approved I/B/K/G process: old R2 S3
state/lock HEAD observations, native encrypted state pull and Cloudflare
GET-only finite page inventory, returning public counts but **NOT_PROVEN**
world/state equivalence. It currently refuses at `source_guard` before
looking at any secret or spawning any child. CI simulates the read path with
fixture tools; it never performs real inspection. No key/ref/backend migration,
activation, provider apply, transport or credential change is authorized by
this source.

The effect toolchain carries the same pinned upstream `terraform-backend-git`
v0.1.12 release binary as windows `infra/git-state` (manifest tool
`terraform_backend_git`). Building the toolchain runs only its `--help` and
requires the loopback `--address` flag.

`providers/dev-rent-cloudflare/main.tf` now declares only a partial standard
`backend "http" {}`; resources, providers and enforced encryption are
unchanged. Its state location is the `state_backend` of `dev.rent-root` in
`contracts/environments.jsonl`: repository `roccho-org/envs` (stable id
1391871347), ref `refs/heads/tofu-state`, state `state/dev-rent-cloudflare.json`
and the upstream lock ref `refs/heads/locks/state/dev-rent-cloudflare.json`.
For one operation a transient loopback `terraform-backend-git` child serves that
ref; only that child receives the workflow's ref principal (`GITHUB_TOKEN`),
with the fixed non-secret `GIT_USERNAME=x-access-token` that upstream v0.1.12
HTTPS authentication requires beside a token.
The rent-root flow above, with `-backend-config` bucket and key, is the
**former R2 S3 era**: that apply (`rent-root`) is now closed in source.

Two future entries are composed but closed in source, like inspect:
`envs-effect rent-root-migrate` (standard `tofu init -migrate-state` from the
former S3 backend, read through a source-declared legacy root, onto the empty
GitHub ref, holding both locks; it requires the same lineage and resources and
at most one serial step, and retains the former object) and
`envs-effect rent-root-plan` (the unchanged root planned against the existing
GitHub-ref state must be empty; any change refuses, nothing is applied or
saved). `rent-root`, `rent-root-inspect`, `rent-root-migrate` and
`rent-root-plan` each refuse at `source_guard` before any contract, tool, secret
or child. No workflow selects migrate or plan yet; activation, real transport,
custody and every live effect need their own later phase grants.

## Family calendar Cloudflare Pages (bounded exception)

The static product bytes are owned by `roccho-dev/apps/packages/calendar/src`. This repo owns only one explicitly authorized provider upload of an exact, CI-green apps source to the fixed `roccho-family-calendar-2026` Direct Upload Pages project. `dev-projection` supplies its existing `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` to a single bounded effect step. No secret is transferred to apps, no Pages secret is projected into the browser, and this is not a generic deployment platform.

On [envs Issue #69](https://github.com/roccho-org/envs/issues/69), the existing `roccho-dev` principal comments `/deploy-calendar <40-character apps SHA>`. The comment becomes data for a strict validator; envs only fetches that commit after its `calendar acceptance` and `nix-check` runs are both success. It uses the envs exact-commit Nix toolchain artifact, deploys only the two static files to Pages, and accepts completion only after public byte-for-byte readback of both. A failure never represents success. All data in `events.jsonl` is public. The provider secret scope must independently include `Pages Write` (a working zone read alone does not prove it).
