##! Retains explicit native rollout policy and site observation programs.
{
  pkgs,
  guestTools ? false,
}: let
  drainHook = pkgs.writeShellScriptBin "aos-qualified-rollout-drain-hook" ''
    set -eu
    ${pkgs.coreutils}/bin/mkdir -p /var/lib/aos-test
    IFS= read -r boot_id < /proc/sys/kernel/random/boot_id
    printf '%s\n' "$boot_id" > /var/lib/aos-test/drained-boot-id
    ${pkgs.coreutils}/bin/sync -f /var/lib/aos-test/drained-boot-id
  '';
  drainObservation = pkgs.writeShellScriptBin "aos-qualified-rollout-drain-observation" ''
    set -eu
    test -f /var/lib/aos-test/drained-boot-id || exit 1
    IFS= read -r drained < /var/lib/aos-test/drained-boot-id
    IFS= read -r running < /proc/sys/kernel/random/boot_id
    test "$drained" = "$running"
  '';
  healthHook = pkgs.writeShellScriptBin "aos-qualified-rollout-health-hook" ''
    set -eu
    ${pkgs.coreutils}/bin/mkdir -p /var/lib/aos-test
    IFS= read -r boot_id < /proc/sys/kernel/random/boot_id
    booted=$(${pkgs.coreutils}/bin/readlink /run/current-system)
    configured=$(${pkgs.coreutils}/bin/readlink -f /var/lib/profiles/system/current/toplevel)
    printf '%s\t%s\t%s\n' "$boot_id" "$booted" "$configured" \
      >> /var/lib/aos-test/health-observations
    ${pkgs.coreutils}/bin/sync -f /var/lib/aos-test/health-observations
    if test -e /var/lib/aos-test/rollout-health-fail; then
      IFS= read -r unhealthy < /var/lib/aos-test/unhealthy-image-toplevel
      test "$booted" != "$unhealthy"
    fi
  '';
  executable = package: name: {
    path = "${package}/bin/${name}";
    arguments = [];
  };
  module = {
    aos.packages = {
      aos-qualified-rollout-drain-hook = {
        package = drainHook;
        bundle = true;
      };
      aos-qualified-rollout-drain-observation = {
        package = drainObservation;
        bundle = true;
      };
      aos-qualified-rollout-health-hook = {
        package = healthHook;
        bundle = true;
      };
    };
    aos.apm.drainScript = "${drainHook}/bin/aos-qualified-rollout-drain-hook";
    aos.apm.healthScript = "${healthHook}/bin/aos-qualified-rollout-health-hook";
    aos.imageRollout = {
      drain = executable drainHook "aos-qualified-rollout-drain-hook";
      drainObservation = executable drainObservation "aos-qualified-rollout-drain-observation";
    };
  };
  qualificationSetupBody = ''
    aos.apm.drainScript = ${builtins.toJSON module.aos.apm.drainScript};
    aos.apm.healthScript = ${builtins.toJSON module.aos.apm.healthScript};
    aos.imageRollout.drain = builtins.fromJSON ${builtins.toJSON (builtins.toJSON module.aos.imageRollout.drain)};
    aos.imageRollout.drainObservation = builtins.fromJSON ${builtins.toJSON (builtins.toJSON module.aos.imageRollout.drainObservation)};
  '';
in {
  inherit module qualificationSetupBody drainHook drainObservation healthHook;
  extraClosures = [pkgs.aos pkgs.aos.packageRuntime pkgs.coreutils pkgs.git pkgs.jq pkgs.nix pkgs.util-linux drainHook drainObservation healthHook];
  testPrelude = ''
    import base64
    import json
    import shlex

    APM = ${
      if guestTools
      then ''runtime.guest_tool("apm")''
      else builtins.toJSON "${pkgs.aos.apm}/bin/apm"
    }
    APR = ${
      if guestTools
      then ''runtime.guest_tool("apr")''
      else builtins.toJSON "${pkgs.aos.apr}/bin/apr"
    }
    COREUTILS = "${pkgs.coreutils}/bin"
    JQ = "${pkgs.jq}/bin/jq"
    NIX_BIN = "${pkgs.nix}/bin"

    def write_rollout_host(path, request, extra_module, qualified=True, restart=True, retire=False):
        encoded_request = json.dumps(json.dumps(request, separators=(",", ":")))
        if retire:
            intent = "aos.imageRollout.retiredRequests = [ (builtins.fromJSON " + encoded_request + ") ];\n"
        else:
            intent = (
                "aos.imageRollout.requests = [ { rollout = builtins.fromJSON "
                + encoded_request + "; qualified = " + str(qualified).lower()
                + "; restart = " + str(restart).lower() + "; } ];\n"
            )
        source = "{ lib, ... }: {\n" + intent + extra_module + "}\n"
        encoded = base64.b64encode(source.encode()).decode()
        runtime.succeed(f"printf %s {shlex.quote(encoded)} | {COREUTILS}/base64 -d > {shlex.quote(path)}")
  '';
}
