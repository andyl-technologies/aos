{
  lib,
  mkDerivation,
  k3s,
  aos-kubernetes-provider,
  containerd,
  runc,
  cni-plugins,
  iptables,
  ipset,
  conntrack-tools,
  socat,
  ethtool,
  iproute2,
  util-linux,
  kmod,
  coreutils,
  writeShellScriptBin,
}:
let
  pkgs = {
    inherit
      k3s
      containerd
      runc
      cni-plugins
      iptables
      ipset
      conntrack-tools
      socat
      ethtool
      iproute2
      util-linux
      kmod
      coreutils
      writeShellScriptBin
      ;
  };
  common = import ./_k3s-common.nix { inherit lib pkgs; };
in
{
  pname,
  evidenceSources,
}:
let
  roleSpec = (import ./_k3s-config/roles.nix).${pname};
  launcher = common.launcher pname roleSpec.command;
in
mkDerivation {
  inherit pname;
  inherit (k3s) version;
  qualification.packageProbe = lib.qualification.commandProbe {
    primary = {
      input = "The installed ${pname} role entry points.";
      operation = "Verify the role launcher and K3s payload are executable.";
      expected = "Both package-owned entry points are executable files.";
      files = { };
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              import os
              paths = ["@out@/bin/k3s-role-start", "@out@/libexec/k3s"]
              assert all(os.path.isfile(path) and os.access(path, os.X_OK) for path in paths)
              print("${pname} executables passed")
            ''
          ];
          exit_code = 0;
          stdout.exact = "${pname} executables passed\n";
          stderr.exact = "";
        }
      ];
      artifacts = [ ];
    };
    badInput = {
      input = "An unsupported K3s argument.";
      operation = "Invoke the packaged K3s payload with the unsupported argument.";
      expected = "K3s rejects the unsupported invocation.";
      files = { };
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              import subprocess, sys
              result = subprocess.run(
                  ["@out@/libexec/k3s", "--aos-qualification-invalid"],
                  capture_output=True,
              )
              assert result.returncode != 0
              sys.stderr.write("${pname} rejected invalid input\n")
              raise SystemExit(7)
            ''
          ];
          exit_code = 7;
          stdout.exact = "";
          stderr.exact = "${pname} rejected invalid input\n";
          observes_rejection = true;
        }
      ];
      artifacts = [ ];
    };
  };
  src = null;
  runtimeDeps = common.runtimePath ++ [ aos-kubernetes-provider ];

  abilities = ./_k3s-config;

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/libexec" "$out/share/${pname}"
        ln -s ${launcher}/bin/k3s-${pname}-start "$out/bin/k3s-role-start"
        ln -s ${k3s}/bin/k3s "$out/libexec/k3s"
        ln -s ${aos-kubernetes-provider}/bin/aos-kubernetes-provider \
          "$out/libexec/aos-kubernetes-object-effects"
        ln -s ${aos-kubernetes-provider}/bin/aos-kubernetes-provider \
          "$out/libexec/aos-k3s-configuration-effects"
        cp ${./_k3s-config/object-provider.nix} \
          "$out/share/${pname}/object-provider.nix"
        cp ${./_k3s-config/configuration-provider.nix} \
          "$out/share/${pname}/configuration-provider.nix"
        printf '%s\n' ${lib.escapeShellArg pname} > "$out/share/${pname}/payload.txt"
      '';
    }
  ];

  passthru.evidenceSources = evidenceSources ++ [
    ./_k3s-role-package.nix
    ./_k3s-common.nix
    ./_k3s-config
  ];

  meta = {
    description = roleSpec.description;
    license = "Apache-2.0";
  };

  checks =
    {
      pkgs,
      self,
      ...
    }:
    let
      buildPkgs = pkgs.buildPackages or pkgs;
      platform = pkgs.stdenv.hostPlatform;
    in
    {
      payload-consumption = lib.mkArtifactConsumptionAudit {
        inherit pkgs;
        name = "${pname}-k3s-payload";
        consumer = launcher;
        consumerPath = "/bin/k3s-${pname}-start";
        provider = pkgs.k3s;
        providerPath = "/bin/k3s";
        targetPlatform = {
          system = platform.constraints.os;
          architecture = platform.constraints.cpu;
        };
        mechanism = "helper-execution";
        arguments = [
          "verify-payload"
          "${pkgs.k3s}/bin/k3s"
        ];
        expectedOutputSha256 = "sha256:${builtins.hashString "sha256" "k3s-payload-ok\n"}";
        inspector = buildPkgs.aos;
      };
    };
}
