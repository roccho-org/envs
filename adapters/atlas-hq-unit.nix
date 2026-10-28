# A generic user unit that runs the flake named by its data directory's `app.ref`, with the data directory as its one
# argument (roccho-dev/adrs#701 I3). It names no repository: which code runs is the operator's data, one line
# `github:<owner>/<repo>/<40-hex commit>` (no branch, no short sha); the entry point it starts checks the rest.
# The token nix needs to fetch that flake is the host user's own gh login (adrs#701, the User's decision c6454860441),
# read when the unit starts and given to nix only through this process's NIX_CONFIG (nix.conf untouched); its value is
# never printed. Installing and enabling the unit (and the user's linger) are host effects outside this file.
{ pkgs, state ? "/work/repos/.hq" }:
let
  launcher = pkgs.writeShellScriptBin "atlas-hq-launch" ''
    set -euo pipefail
    state=${state}
    ref=$(${pkgs.coreutils}/bin/head -n 1 "$state/app.ref")
    case "$ref" in
      github:*/*/*) ;;
      *) echo "atlas-hq: app.ref is not github:<owner>/<repo>/<commit>" >&2; exit 64 ;;
    esac
    commit=''${ref##*/}
    if ! printf '%s' "$commit" | ${pkgs.gnugrep}/bin/grep -Eqx '[0-9a-f]{40}'; then
      echo "atlas-hq: app.ref must end with an exact 40-hex commit" >&2; exit 64
    fi
    token=$(${pkgs.gh}/bin/gh auth token 2>/dev/null) || { echo "atlas-hq: gh is not logged in for this user" >&2; exit 65; }
    [ -n "$token" ] || { echo "atlas-hq: gh auth token is empty" >&2; exit 65; }
    export NIX_CONFIG="access-tokens = github.com=$token"
    unset token
    exec ${pkgs.nix}/bin/nix run "$ref#atlas-hq" -- "$state"
  '';
in
pkgs.writeTextFile {
  name = "atlas-hq.service";
  destination = "/share/systemd/user/atlas-hq.service";
  text = ''
    [Unit]
    Description=Atlas HQ: the flake named by ${state}/app.ref, on its data directory
    After=network-online.target

    [Service]
    ExecStart=${launcher}/bin/atlas-hq-launch
    Restart=on-failure
    RestartSec=30

    [Install]
    WantedBy=default.target
  '';
}
