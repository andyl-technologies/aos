##! Retains the controlled service fixture and its source-built command closure.
{
  mkDerivation,
  bash,
  coreutils,
  service-management,
  aos-filesystem-provider,
}:
mkDerivation {
  pname = "native-service-qualification";
  version = "1";
  src = ./module;
  module = ./module;
  moduleDeps = [service-management aos-filesystem-provider];
  buildDeps = [];
  runtimeDeps = [bash coreutils];
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        cat > "$out/bin/native-service-qualification" <<'SCRIPT'
        #!${bash}/bin/bash
        set -eu
        case "$1" in selected|foreign|deadline|deadline-remove|deadline-stop) ;; *) exit 64 ;; esac
        printf 'invoked\n' >> "/var/lib/aos/native-service-qualification/$1.invocations"
        exec ${coreutils}/bin/sleep infinity
        SCRIPT
        chmod 0555 "$out/bin/native-service-qualification"
      '';
    }
  ];
  meta = {
    description = "Controlled native service and identity qualification fixture";
    license = "Apache-2.0";
    mainProgram = "native-service-qualification";
  };
}
