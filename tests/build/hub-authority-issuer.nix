##! Exercises the production Worker issuer with test-only persistent-storage faults.
##!
##! The artifact is the ordinary optimized Worker build. Only this check's copied
##! JavaScript subclasses expose synthetic storage read/write/reset and lost/held
##! acknowledgments. No provider binding, real credential, or hosted clock evidence
##! is present; successful lifecycle tests establish no dispatch or timing readiness.
{pkgs}:
pkgs.mkDerivation {
  pname = "hub-authority-issuer-lifecycle-check";
  version = "1";
  src = null;
  outputChecks = {};
  buildDeps = [pkgs.nodejs pkgs.miniflare pkgs.aos-hub-worker-dist pkgs.coreutils];
  phases = [
    {
      name = "check";
      script = ''
        set -eu
        mkdir -p "$out" "$TMPDIR/authority-lifecycle"
        ${pkgs.nodejs}/bin/node --check ${./_hub-authority-issuer/protocol.cjs}
        ${pkgs.nodejs}/bin/node --check ${./_hub-authority-issuer/fixture.mjs}

        # All persistence and fault routes belong to the disposable local fixture.
        # The ordinary artifact remains read-only in the store.
        if ${pkgs.coreutils}/bin/timeout 180 \
          ${pkgs.nodejs}/bin/node ${./_hub-authority-issuer/protocol.cjs} \
            ${pkgs.miniflare} ${pkgs.aos-hub-worker-dist} \
            ${./_hub-authority-issuer/fixture.mjs} \
            "$TMPDIR/authority-lifecycle" "$out/result.json" \
            > "$out/transcript" 2>&1; then
          cat "$out/transcript"
        else
          cat "$out/transcript" >&2
          exit 1
        fi
      '';
    }
  ];
}
