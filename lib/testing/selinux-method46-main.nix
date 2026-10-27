##! Native main-journal custody checks without linking production policy.
{pkgs}: let
  native = pkgs.buildPackages;
  support = ../../pkgs/security/_aos-selinux-production-policy;
  renderInitial = import (support + "/method46-initial.nix");
  initialPackages = {
    initialPackage = pkgs.aos-method46-floor-initializers;
    helperPackage = pkgs.aos-method46-initial-tpm-helpers;
  };
  initialCase = purposes: renderInitial (initialPackages // {inherit purposes;});
  rejectedInitial = args:
    !(builtins.tryEval (builtins.deepSeq (renderInitial args) true)).success;
  initialCases = builtins.toFile "method46-initial-policy-cases.json" (builtins.toJSON {
    defaultUnselected = renderInitial {};
    cases = map initialCase [[] ["controller"] ["storage"] ["controller" "storage"]];
    initialPackage = builtins.unsafeDiscardStringContext (toString initialPackages.initialPackage);
    helperPackage = builtins.unsafeDiscardStringContext (toString initialPackages.helperPackage);
    rejectedSelections =
      map
      (purposes: rejectedInitial (initialPackages // {inherit purposes;}))
      [["root"] ["controller" "controller"] ["storage" "controller"] "controller" null];
    rejectedPackages =
      map
      (args:
        rejectedInitial (initialPackages
          // {purposes = ["controller"];}
          // args))
      [
        {initialPackage = null;}
        {helperPackage = null;}
        {helperPackage = "/nix/store/00000000000000000000000000000000-aos-method46-initial-tpm-helpers-2";}
        {initialPackage = "/tmp/00000000000000000000000000000000-aos-method46-floor-initializers-0.1.0";}
        {initialPackage = "/nix/store/00000000000000000000000000000000-aos-method46-floor-initializers-0.1.1";}
        {initialPackage = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-aos-method46-floor-initializers-0.1.0";}
        {helperPackage = "/nix/store/00000000000000000000000000000000-aos-method46-initial-tpm-helpers-1/libexec";}
      ];
    # Compare label DATA to actual consumers without adding their build closure
    # or turning an unconfined fixture into production startup authority.
    credentialSource = builtins.readFile ../../crates/sandbox/controller/aos-sandbox-controller-domain/src/method46_initial_startup/credentials.rs;
    helperSource = builtins.readFile ../../pkgs/security/aos-method46-tpm-helper/initial_method46.c;
    approvalSource = builtins.readFile ../../crates/sandbox/controller/aos-sandbox-controller-domain/src/method46_initial_startup/approval_listener.rs;
    unitSource = builtins.readFile ../../modules/sandbox/method46-initial-floors.nix;
  });
in
  native.mkDerivation {
    pname = "selinux-method46-main-policy-check";
    version = "1";
    # Local Python caches are not source and must never satisfy imports in a
    # hermetic check, even when they happen to match source timestamps.
    src = builtins.path {
      path = support;
      name = "selinux-method46-custody-source";
      filter = path: _: builtins.baseNameOf path != "__pycache__";
    };
    buildDeps = [native.python3 native.setools native.libselinux native.checkpolicy native.tar native.xz];
    runtimeDeps = [];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          cp -R "$src" policy-check
          chmod u+w policy-check
          cd policy-check

          # Reuse the production emitter and class-map parser. No copied
          # permission list can silently omit a new selected kernel operation.
          tar --occurrence=1 -xOf ${pkgs.linux.src} \
            linux-${pkgs.linux.version}/security/selinux/include/classmap.h > classmap.h
          $CC -std=c17 -Wall -Wextra -Werror -I. kernel-classmap.c -o emit-classmap
          ./emit-classmap > kernel-classmap.tsv

          export PYTHONPATH=${native.setools}/lib/python3/site-packages
          export AOS_SELINUX_FILE_CONTEXTS_LIBRARY=${native.libselinux}/lib/libselinux.so.1
          export AOS_SELINUX_KERNEL_CLASSMAP="$PWD/kernel-classmap.tsv"
          ${native.python3}/bin/python3 -B method46_policy_test.py
          export AOS_METHOD46_INITIAL_POLICY_CASES=${initialCases}
          export AOS_METHOD46_CHECKMODULE=${native.checkpolicy}/bin/checkmodule
          export AOS_METHOD46_CHECKPOLICY=${native.checkpolicy}/bin/checkpolicy
          ${native.python3}/bin/python3 -B method46_initial_policy_test.py

          mkdir -p "$out"
          cp kernel-classmap.tsv "$out/kernel-classmap.tsv"
          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
  }
