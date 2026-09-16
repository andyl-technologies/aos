##! Production package selection and operator intent for rollout qualification.
{
  pkgs,
  guestTools ? false,
  nativeAdapterMatrix ? null,
  cellId ? null,
}: let
  qualificationCell =
    if nativeAdapterMatrix == null && cellId == null
    then null
    else let
      matches = builtins.filter (cell: cell.id == cellId) nativeAdapterMatrix.applicable_cells;
    in
      assert nativeAdapterMatrix != null && cellId != null;
      assert builtins.length matches == 1;
        builtins.head matches;
  qualificationAdapter =
    if qualificationCell == null
    then null
    else let
      matches = builtins.filter (
        adapter: adapter.adapter == qualificationCell.adapter
      ) nativeAdapterMatrix.spec.surface.adapters;
    in
      assert builtins.length matches == 1;
        builtins.head matches;
  qualificationSubject =
    if qualificationCell == null
    then null
    else {
      cell = qualificationCell;
      adapter = qualificationAdapter;
    };
  packageProjection = pkgs.aos.contract.value;
  qualificationImplementations = map (name: {
    inherit name;
    qualification = packageProjection.qualification.implementations.${name};
  }) (builtins.attrNames packageProjection.qualification.implementations);
  rolloutQualifications = builtins.filter (
    entry: builtins.elem "rollout-durability" entry.qualification.conformance_families
  ) qualificationImplementations;
  rolloutQualification =
    assert builtins.length rolloutQualifications == 1;
      builtins.head rolloutQualifications;
  rolloutImplementations = builtins.filter (
    implementation: implementation.name == rolloutQualification.name
  ) packageProjection.implementation.providers;
  rolloutImplementation =
    assert builtins.length rolloutImplementations == 1;
      builtins.head rolloutImplementations;
  rolloutInterfaces = builtins.filter (
    interface: interface.descriptor == rolloutImplementation.interface.descriptor
  ) packageProjection.interface_documents;
  rolloutInterface =
    assert builtins.length rolloutInterfaces == 1;
      (builtins.head rolloutInterfaces).document;
  rolloutMethods = builtins.attrNames rolloutInterface.interface.methods;
  rolloutGuarantees = map (guarantee: guarantee.name) rolloutImplementation.guarantees;
  nixList = values: "[ ${builtins.concatStringsSep " " (map builtins.toJSON values)} ]";
  subjectMatchesPackage =
    qualificationSubject == null
    || (
      qualificationSubject.adapter.provider_implementation.contract
      == builtins.toString pkgs.aos.contract.document
      && qualificationSubject.adapter.interface_descriptor
      == rolloutImplementation.interface.descriptor
      && qualificationSubject.cell.adapter == qualificationSubject.adapter.adapter
      && qualificationSubject.cell.interface.descriptor
      == rolloutImplementation.interface.descriptor
    );

  drainHook = pkgs.writeShellScriptBin "aos-qualified-rollout-drain-hook" ''
    set -eu

    ${pkgs.coreutils}/bin/mkdir -p /var/lib/aos-test
    IFS= read -r boot_id < /proc/sys/kernel/random/boot_id
    printf '%s\n' "$boot_id" > /var/lib/aos-test/drained-boot-id
    ${pkgs.coreutils}/bin/sync -f /var/lib/aos-test/drained-boot-id
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
    if [ -e /var/lib/aos-test/rollout-health-fail ]; then
      while [ ! -e /var/lib/aos-test/allow-rollout-health-fail ]; do
        ${pkgs.coreutils}/bin/sleep 1
      done
      exit 1
    fi
  '';
  qualificationSetupBody = ''
    aos.apm.drainScript = "${drainHook}/bin/aos-qualified-rollout-drain-hook";
    aos.apm.healthScript = "${healthHook}/bin/aos-qualified-rollout-health-hook";
  '';
  extraClosures = [
    pkgs.aos
    pkgs.aos.contract.document
    pkgs.aos.packageRuntime
    pkgs.coreutils
    pkgs.gawk
    pkgs.git
    pkgs.jq
    pkgs.nix
    pkgs.util-linux
    drainHook
    healthHook
  ];
in
  assert subjectMatchesPackage; {
  inherit extraClosures qualificationSetupBody;

  qualificationCandidateRuntimeCompanions = [
    {
      name = "aos";
      primary = pkgs.aos;
      abilities = pkgs.aos.contract.document;
      originalRuntime = pkgs.aos.packageRuntime;
    }
  ];

  testPrelude =
    # python
    ''
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


      def write_rollout_host(path, request, extra_module, enabled=True):
          request_json = json.dumps(request, separators=(",", ":"))
          request_module = ""
          if enabled:
              request_module = (
                  "  aos.abilities.instances.rollout-qualification = {};\n"
                  "  aos.abilities.requirementTemplates.rollout =\n"
                  "    (lib.abilities.interfaceSelector {\n"
                  "      name = "
                  + ${builtins.toJSON (builtins.toJSON rolloutImplementation.interface.name)}
                  + ";\n"
                  "      abi = "
                  + ${builtins.toJSON (builtins.toString rolloutImplementation.interface.abi)}
                  + ";\n"
                  "    }) // {\n"
                  "      description = \"Qualifies the selected production A/B rollout provider.\";\n"
                  "      methods = "
                  + ${builtins.toJSON (nixList rolloutMethods)}
                  + ";\n"
                  "      guarantees = "
                  + ${builtins.toJSON (nixList rolloutGuarantees)}
                  + ";\n"
                  "      strength = \"required\";\n"
                  "      fallback = null;\n"
                  "    };\n"
                  "  aos.abilities.requests.rollout = {\n"
                  "    requirement = \"rollout\";\n"
                  "    consumer = \"rollout-qualification\";\n"
                  "    scope = [ \"qualification\" ];\n"
                  "    parameters = builtins.fromJSON "
                  + json.dumps(request_json)
                  + ";\n"
                  "  };\n"
              )
          module = "{ lib, ... }: {\n" + request_module + extra_module + "}\n"
          encoded = base64.b64encode(module.encode()).decode()
          target.succeed(
              f"printf %s {shlex.quote(encoded)} | "
              f"{COREUTILS}/base64 -d > {shlex.quote(path)}"
          )
    '';
}
