##! Source-owned gem5 closed-profile bundle with genuine native continuation proofs
{
  mkDerivation,
  gem5,
  dmtcp,
  gem5-process-custody,
  gem5-process-image-inventory,
  coreutils,
  python3,
  python3-3_12,
  llvm,
  abseil-cpp,
}: let
  installed = "@out@/share/crucible/gem5";
  specification = builtins.toJSON {
    artifacts = {
      native_executable = "${gem5}/bin/gem5";
      controller = "${installed}/controller/native-owner.py";
      model = "${installed}/controller/native-owner-model.py";
      auditor = "${gem5-process-image-inventory}/bin/gem5-process-image-inventory";
      image_guard = "${gem5-process-custody}/lib/libcrucible-resource-custody.so";
      dmtcp_launch = "${dmtcp}/bin/dmtcp_launch";
      dmtcp_restart = "${dmtcp}/bin/dmtcp_restart";
      mtcp_restart = "${dmtcp}/bin/mtcp_restart";
      python = "${python3-3_12}/bin/python3.12";
      witness = "${installed}/controller/native-owner-check.py";
      auditor_source = "${gem5-process-image-inventory}/libexec/process-image-inventory.py";
    };
  };
in
  mkDerivation {
    pname = "gem5-closed-profile";
    version = "1";
    # Guest and controller bytes are authenticated before the final phases.
    dontStrip = true;
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    buildDeps = [coreutils python3 llvm];
    runtimeDeps = [gem5 dmtcp gem5-process-custody gem5-process-image-inventory python3-3_12];
    phases = [
      {
        name = "build";
        script = ''
          profile="$out/share/crucible/gem5"
          mkdir -p "$profile/controller" "$profile/guests" "$profile/models" "$profile/sources"
          cp ${./_gem5/native-owner.py} "$profile/controller/native-owner.py"
          cp ${./_gem5/native-owner-model.py} "$profile/controller/native-owner-model.py"
          cp ${./_gem5/native-owner-check.py} "$profile/controller/native-owner-check.py"
          cc -nostdlib -static -no-pie -Wl,--build-id=none \
            ${./_gem5/o3-memory-workload.S} -o "$profile/guests/x86_64.elf"
          ${llvm}/bin/clang --target=aarch64-linux-gnu -nostdlib -static \
            -fuse-ld=lld -Wl,--build-id=none \
            ${./_gem5/o3-memory-workload-aarch64.S} -o "$profile/guests/aarch64.elf"
          cp ${gem5.src} "$profile/sources/gem5-upstream.tar.gz"
          cp ${dmtcp.src} "$profile/sources/dmtcp-upstream.tar.gz"
          cp ${./gem5.nix} "$profile/sources/gem5.nix"
          cp ${../tools/dmtcp.nix} "$profile/sources/dmtcp.nix"
          cp ${gem5}/share/gem5/source-manifest.json "$profile/sources/gem5-source-manifest.json"
          cp -R ${./gem5-patches} "$profile/sources/gem5-patches"
          cp -R ${../tools/_dmtcp} "$profile/sources/dmtcp-patches"
          mkdir -p "$out/share/licenses/gem5-closed-profile"
          cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-closed-profile/LICENSE"
        '';
      }
      {
        name = "check";
        script = ''
          export PYTHONDONTWRITEBYTECODE=1
          export LD_LIBRARY_PATH="${abseil-cpp}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export CRUCIBLE_GEM5_REQUIRE_NATIVE_BIRTH=1
          export CRUCIBLE_GEM5_REQUIRE_FRESH_CLOSURE=1
          export CRUCIBLE_GEM5_IMAGE_AUDITOR=${gem5-process-image-inventory}/bin/gem5-process-image-inventory
          profile="$out/share/crucible/gem5"
          # DMTCP applies special rules to temporary resources. Use that same
          # namespace as installed owners so a /build-only pass cannot mask
          # a stale captured custody root after private reconstruction.
          witness_root="$(mktemp -d /tmp/crucible-gem5-closed-profile.XXXXXXXX)"
          for isa in x86_64 aarch64; do
            ${coreutils}/bin/timeout 600 ${python3}/bin/python3 -B \
              "$profile/controller/native-owner-check.py" \
              ${gem5}/bin/gem5 "$profile/controller/native-owner.py" "$isa" \
              "$profile/guests/$isa.elf" "$profile/guests/x86_64.elf" "$witness_root/$isa" \
              ${dmtcp} ${gem5-process-custody}/lib/libcrucible-resource-custody.so
          done
          cat > profile-inputs.json <<'EOF'
          ${specification}
          EOF
          ${python3}/bin/python3 -B ${./_gem5/closed-profile-manifest.py} \
            "$PWD/profile-inputs.json" "$out" "$witness_root/x86_64" "$witness_root/aarch64"
          rm -rf "$witness_root"
        '';
      }
    ];
    meta = {
      description = "Authenticates one fixed x86/ARM O3 checksum profile through complete opaque native capture and two source-death reconstructions";
      license = "MIT";
    };
  }
