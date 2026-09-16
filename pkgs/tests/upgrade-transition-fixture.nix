##! Test-only service used to exercise system generation reconciliation.
{
  mkDerivation,
  bash,
  coreutils,
}:
mkDerivation {
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
    target = [];
    role = "build-input";
  };
  pname = "upgrade-transition-fixture";
  version = "0";
  src = null;

  runtimeDeps = [
    bash
    coreutils
  ];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"

        cat > "$out/bin/upgrade-transition-start" <<'SH'
        #!${bash}/bin/bash
        exit 0
        SH

        cat > "$out/bin/upgrade-transition-stop" <<'SH'
        #!${bash}/bin/bash
        exec ${coreutils}/bin/touch /run/removed-stop-ran
        SH

        chmod +x "$out/bin/upgrade-transition-start" \
          "$out/bin/upgrade-transition-stop"
      '';
    }
  ];

  abilities = ./_upgrade-transition-fixture/module.nix;

  meta = {
    description = "Test-only service for AOS generation reconciliation";
    license = "Apache-2.0";
  };
}
