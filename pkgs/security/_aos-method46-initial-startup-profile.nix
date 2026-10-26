##! Image comparison inputs for the two manually approved initial-floor purposes.
{
  mkDerivation,
  buildPackages,
  systemd,
  aos-selinux-production-policy,
  aos-selinux-kernel-policy-readback,
  initialPackage,
  normalPackage,
  purpose,
  unitContract,
  normalUnitFragment,
  normalArgv,
  controllerUid,
  controllerGid,
  approvalPublicKey,
}: let
  roles = {
    controller = {
      initial = "aos-sandbox-controller-floor-initialize";
      normal = "aos-sandboxd";
    };
    storage = {
      initial = "aos-sandbox-storage-floor-initialize";
      normal = "aos-storaged";
    };
  };
  role = roles.${purpose};
  sourcePolicy = "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
  support = ./_aos-selinux-production-policy;
  checker =
    if aos-selinux-production-policy.passthru ? effectivePolicyCheckerRelative
    then "${aos-selinux-production-policy}/${aos-selinux-production-policy.passthru.effectivePolicyCheckerRelative}"
    else "${support}/effective_policy.py";
  checkerArguments = aos-selinux-production-policy.passthru.effectivePolicyCheckerArguments or "";
in
  mkDerivation {
    pname = "aos-method46-initial-startup-profile";
    version = "3";
    src = ./aos-method46-initial-startup-profile.py;
    buildDeps = [buildPackages.python3 buildPackages.patchelf buildPackages.binutils buildPackages.setools];
    runtimeDeps = [];
    propagatedDeps = [];
    outputChecks = {};

    inherit unitContract;
    normalArgvJson = builtins.toJSON normalArgv;
    approvalPublicKeyJson = builtins.toJSON approvalPublicKey;
    exportReferencesGraph = {
      initialRuntimeClosure = [initialPackage];
      normalRuntimeClosure = [normalPackage];
    };
    nukeRefsKeep = [initialPackage normalPackage systemd aos-selinux-production-policy aos-selinux-kernel-policy-readback normalUnitFragment];

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          mkdir producer-tests
          cp "$src" producer-tests/aos-method46-initial-startup-profile.py
          cp ${./aos-method46-initial-startup-profile_test.py} producer-tests/aos-method46-initial-startup-profile_test.py
          cp ${./aos-normal-root-profile.py} producer-tests/aos-normal-root-profile.py
          ${buildPackages.python3}/bin/python3 -B producer-tests/aos-method46-initial-startup-profile_test.py

          export PYTHONPATH=${buildPackages.setools}/lib/python3/site-packages
          ${buildPackages.python3}/bin/python3 -B ${checker} ${checkerArguments} ${sourcePolicy} > effective-policy.tsv
          test -s effective-policy.tsv
          mkdir -p "$out"
          install -m 0444 effective-policy.tsv "$out/effective-policy.tsv"
          install -m 0444 ${sourcePolicy} "$out/source-policy.33"
          ${buildPackages.python3}/bin/python3 -B - "$NIX_ATTRS_JSON_FILE" <<'PY'
          import json
          import sys
          from pathlib import Path

          attrs = json.loads(Path(sys.argv[1]).read_text())
          Path("unit-contract").write_text(attrs["unitContract"])
          Path("normal-argv.json").write_text(attrs["normalArgvJson"])
          Path("approval-public-key.json").write_text(attrs["approvalPublicKeyJson"])
          PY
          ${buildPackages.python3}/bin/python3 -B "$src" \
            --purpose ${purpose} --attrs "$NIX_ATTRS_JSON_FILE" \
            --runtime-profile-helpers ${./aos-normal-root-profile.py} \
            --elf-helpers ${./aos-selinux-runtime-manifest.py} \
            --executable ${initialPackage}/bin/${role.initial} \
            --normal-executable ${normalPackage}/bin/${role.normal} \
            --normal-unit ${normalUnitFragment} --normal-argv normal-argv.json \
            --pid1 ${systemd}/lib/systemd/systemd \
            --canonical-policy ${aos-selinux-kernel-policy-readback}/policy.33 \
            --source-policy "$out/source-policy.33" --effective-matrix "$out/effective-policy.tsv" \
            --unit-contract unit-contract --approval-public-key approval-public-key.json \
            --controller-uid ${toString controllerUid} --controller-gid ${toString controllerGid} \
            --patchelf ${buildPackages.patchelf}/bin/patchelf \
            --readelf ${buildPackages.binutils}/bin/readelf --output "$out/profile.json"
          chmod 0444 "$out/profile.json"
        '';
      }
    ];
    passthru.evidenceSources = [
      ./aos-method46-initial-startup-profile.py
      ./aos-method46-initial-startup-profile_test.py
      ./aos-normal-root-profile.py
      ./aos-selinux-runtime-manifest.py
      support
      (builtins.path {
        path = ./_aos-method46-initial-startup-profile.nix;
        name = "aos-method46-initial-profile-recipe-source";
      })
    ];
    meta = {
      description = "Pinned manual initial METHOD46 image inputs; no floor or approval authority";
      license = "GPL-2.0-or-later";
    };
  }
