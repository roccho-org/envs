# One browser-authenticated SSH host

Unapplied standalone OpenTofu source. Cloudflare provider is pinned to **5.21.1**.
It creates one named Tunnel, a loopback SSH ingress plus 404 fallback, proxied DNS,
one exact-email Allow policy and a self-hosted Access application. No service token,
client credential slot, shared root migration, apply workflow or permission grant.
Existing `dev-rent-cloudflare`, its state and hard-inactive operation gates stay unchanged.

`g6i3.roccho.com` is already reachable through Cloudflare. Do not apply this
create-only root to recreate that endpoint. First identify its current owner,
state and adopted source; any import or migration needs its own reviewed plan.
Lati client acceptance does not adopt this Provider root or prove that relation.

The owner supplies every variable in `variables.tf`. The `.example` has deliberately
invalid nulls, is not auto-loaded, and adopts no hostname, account, email or host.
Select the real Access identity/IdP or OTP configuration and verify browser login;
an email Allow rule alone is not proof the account's login method is ready.

Before initialization, the Provider/state owner chooses a **separate** HTTP state and
lock location and provides enforced state/plan encryption through `TF_ENCRYPTION`.
Use the owner's existing authenticated backend and approved OpenTofu runtime.
Never point this root at rent's backend, import/move its resources, disable encryption,
or place API/backend/encryption credentials in source or command arguments.
This root intentionally supplies no backend address, backend credential or encryption key.

Owner verification sequence (no commands here have been run against Cloudflare):

1. Supply real inputs and the independent authenticated/encrypted backend; reject an
   existing hostname/Tunnel/state conflict. Inspect current Cloudflare ownership first.
2. With the pinned provider installed by the owner, run native formatting/validation,
   a locked saved plan, and `tofu show -json` into a **private** file. Review the native
   plan and run `python check_initial_plan.py <private-plan.json>` as a second boundary.
   That guard admits initial creation only. It does not validate provider semantics or
   authorize applying. Later updates/revocation require the owner's separately reviewed plan.
3. Apply only through the owner's authorized operation boundary. Preserve state/lock,
   encryption custody and rollback information. Verify actual DNS/Tunnel/App/policy.
4. Deliver `connector_token` only through the target's existing protected secret path.
   It is sensitive but still exists in encrypted state/plan. Never use `output -raw`
   into a public receipt, log, Git file or Lati client configuration.
5. Return `public_binding` with the accepted source revision and Provider readback
   provenance. Add the target's independently trusted SSH host pin/account/identity
   authorization and connector/sshd readiness before client adoption.

The target installs/runs the connector with its own token and local sshd. Lati uses
fixed cloudflared `access ssh --hostname <adopted hostname>` through typed SSH config;
browser approval is personal, not a new Service Auth secret. Prove the actual consumer,
strict pin, SSH principal, denial, reconnect and restart recovery. LAN SSH is not this proof.

## Validation limits

`checks/test_browser_ssh.py --tofu <provided-tofu>` validates the real pinned provider
schema and six mocked plans using the repository's existing toolchain in CI.
It initializes no backend and supplies no Cloudflare credential. Mock plans use
the mock provider with loopback proxy settings; this is not OS egress isolation
or live API proof. The tests cover exact identity/loopback/fallback
and refusal of wildcard/empty identity, non-loopback/overflow origin and long sessions.

`python -B -m unittest -v test_initial_plan.py` runs synthetic native-plan JSON
admission/negative fixtures offline. It never invokes OpenTofu, Cloudflare, SSH or a
backend. A fixture PASS is not native `tofu validate`, a real plan, Provider application,
G6 adoption or Lati connection. Native schema and mock plans were also verified on
Lati with OpenTofu 1.10.6 and Cloudflare 5.21.1; this is not a live plan or application.
