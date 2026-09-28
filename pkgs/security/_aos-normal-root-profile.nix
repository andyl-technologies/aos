##! Selected-image, nonauthorizing normal policy-authority startup evidence.
{
  mkDerivation,
  buildPackages,
  aos-sandboxd,
  systemd,
  aos-selinux-production-policy,
  aos-selinux-kernel-policy-readback,
  unitContract,
  identities,
}: let
  support = ./_aos-selinux-production-policy;
  sourcePolicy = "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
in
  mkDerivation {
    pname = "aos-normal-root-startup-profile";
    version = "1";
    src = ./aos-normal-root-profile.py;
    buildDeps = [buildPackages.python3 buildPackages.patchelf buildPackages.binutils buildPackages.setools];
    runtimeDeps = [];
    propagatedDeps = [];
    outputChecks = {};
    inherit unitContract;
    identitiesJson = builtins.toJSON identities;
    passAsFile = ["unitContract" "identitiesJson"];
    exportReferencesGraph.normalRootRuntimeClosure = [aos-sandboxd];
    nukeRefsKeep = [aos-sandboxd systemd aos-selinux-production-policy aos-selinux-kernel-policy-readback];

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          export PYTHONPATH=${buildPackages.setools}/lib/python3/site-packages
          # Run producer regressions in the same hermetic build that selects
          # the profile. Keeping the helpers adjacent preserves their imports.
          mkdir producer-tests
          cp "$src" producer-tests/aos-normal-root-profile.py
          cp ${./aos-normal-root-profile_test.py} producer-tests/aos-normal-root-profile_test.py
          cp ${./aos-selinux-runtime-manifest.py} producer-tests/aos-selinux-runtime-manifest.py
          ${buildPackages.python3}/bin/python3 -B producer-tests/aos-normal-root-profile_test.py

          # Rerun the same attribute-expanded checker on the selected final
          # binary. A marker or nonempty archived TSV alone is not success.
          ${buildPackages.python3}/bin/python3 -B ${support}/effective_policy.py \
            ${sourcePolicy} > effective-policy.tsv
          test -s effective-policy.tsv
          mkdir -p "$out"
          install -m 0444 effective-policy.tsv "$out/effective-policy.tsv"
          # The selected input is normally installed 0644. Retain its exact bytes
          # as a read-only profile evidence file; do not weaken shared immutable
          # measurement or grant Root generic access to other policy packages.
          install -m 0444 ${sourcePolicy} "$out/source-policy.33"
          ${buildPackages.python3}/bin/python3 -B "$src" \
            --attrs "$NIX_ATTRS_JSON_FILE" \
            --helpers ${./aos-selinux-runtime-manifest.py} \
            --executable ${aos-sandboxd}/bin/aos-sandbox-policy-authorityd \
            --pid1 ${systemd}/lib/systemd/systemd \
            --canonical-policy ${aos-selinux-kernel-policy-readback}/policy.33 \
            --source-policy "$out/source-policy.33" \
            --effective-matrix "$out/effective-policy.tsv" \
            --unit-contract "$unitContractPath" --identities "$identitiesJsonPath" \
            --patchelf ${buildPackages.patchelf}/bin/patchelf \
            --readelf ${buildPackages.binutils}/bin/readelf \
            --output "$out/profile.json"
          chmod 0444 "$out/profile.json"
        '';
      }
    ];
    passthru.evidenceSources = [
      ./aos-normal-root-profile.py
      ./aos-selinux-runtime-manifest.py
      support
      (builtins.path {
        path = ./_aos-normal-root-profile.nix;
        name = "aos-normal-root-profile-recipe-source";
      })
    ];
    meta = {
      description = "Exact normal Root startup comparison inputs; no live client/read grant";
      # The profile also co-retains the selected compiled Reference Policy.
      license = "GPL-2.0-or-later";
    };
  }
