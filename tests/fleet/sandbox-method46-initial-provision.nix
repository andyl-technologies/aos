# Executes the actual manual producers with external history and host approval.
{
  lib,
  pkgs,
  systems,
  initialCut ? null,
  ...
} @ args: let
  baseline = import ./sandbox-funded-startup.nix args;
  # Public RFC 8032 test identities. Corresponding published test-vector seeds
  # are used only by the host driver, never delivered to an installed service.
  approvalPublicKeys = {
    controller = [215 90 152 1 130 177 10 183 213 75 254 211 201 100 7 58 14 225 114 243 218 166 35 37 175 2 26 104 247 7 81 26];
    storage = [61 64 23 195 232 67 137 90 146 183 10 167 77 27 126 188 156 152 44 207 46 196 150 140 192 205 85 241 42 244 102 12];
  };
  initial = import ./_sandbox-method46-initial-system.nix {
    inherit lib pkgs systems approvalPublicKeys;
  };
  # The test agent runs as init_t. Enter the existing administrative domains
  # through a test-only immutable SysV entrypoint, using the physical image
  # paths so neither transition requires changing a nosuid mount or policy.
  operatorLauncher = pkgs.writeTextFile {
    name = "method46-qualification-operator";
    executable = true;
    text = ''
      #!/usr/lib/aos${pkgs.bash}/bin/bash
      set -eu
      exec /usr/lib/aos${pkgs.util-linux}/bin/setpriv \
        --selinux-label system_u:system_r:unconfined_t \
        /usr/lib/aos${pkgs.python3}/bin/python3 "$@"
    '';
  };
  system = initial.extendModules {
    modules = [
      {
        environment.systemPackages = [pkgs.python3];
        environment.etc."rc.d/init.d/method46-qualification-operator".source = "${operatorLauncher}";
      }
    ];
  };
  preparation = import ./_method46-external-tpm-prepare.nix {inherit pkgs;};
  credentials = import ./_method46-external-credentials.nix {inherit lib pkgs;};
  history = import ./_method46-external-history.nix {inherit lib pkgs;};
  approval = import ./_method46-independent-approval.nix {inherit lib pkgs;};
  tools = {
    preparation = "${preparation}/bin/method46-external-tpm-prepare";
    credentials = "${credentials}/bin/aos-method46-external-credentials";
    history = "${history}/bin/aos-method46-external-history";
    approval = "${approval}/bin/aos-method46-independent-approval";
    debugfs = "${pkgs.e2fsprogs}/sbin/debugfs";
    tpm = "${pkgs.tpm2-tools}/bin";
    python = "${pkgs.python3}/bin/python3";
    operator = "/usr/lib/aos${operatorLauncher}";
  };
in
  assert initialCut == null || builtins.elem initialCut ["before-command" "after-response"]; {
    name =
      if initialCut == null
      then "sandbox-method46-initial-provision"
      else "sandbox-method46-initial-${initialCut}-power-loss";
    timeout =
      if initialCut == null
      then 1800
      else 3600;
    inherit (baseline) bootTimeout;
    machines.vm = baseline.machines.vm // {inherit system;};
    testScript =
      builtins.readFile ./_sandbox-startup-diagnostics.py
      + lib.optionalString (initialCut != null) (builtins.readFile ./_method46-tpm-command-gate.py)
      + ''
        initial_cut = ${builtins.toJSON (
          if initialCut == null
          then ""
          else initialCut
        )}
        tools = ${builtins.toJSON tools}
        approval_pins = ${builtins.toJSON approvalPublicKeys}
      ''
      + builtins.readFile ./_method46-initial-provision.py;
  }
