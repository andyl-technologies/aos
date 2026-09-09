# tests/build/selinux-erofs-labels.nix - SELinux-labeled EROFS conformance
{
  lib,
  pkgs,
  system,
  ...
}: let
  policy = pkgs.aos-selinux-production-policy;
  policyRoot = "${policy}/etc/selinux/aos";
  policySupport = ../../pkgs/security/_aos-selinux-production-policy;
  composefsDump = ../../pkgs/system/build-composefs-dump.py;
  composefsDumpTest = ../../pkgs/system/build-composefs-dump_test.py;
  dynamicLinker = pkgs.stdenv.hostPlatform.dynamicLinker;
  legacySystem = system.extendModules {
    modules = [
      {system.build.immutableSelinuxPolicy = lib.mkForce null;}
    ];
  };
  legacyEtcDump = legacySystem.config.system.build.etcDump;
  legacyEtcImage = legacySystem.config.system.build.etcMetadataImage;
  labeledSystem = system.extendModules {
    modules = [
      {
        system.build.immutableSelinuxPolicy = lib.mkForce policy;
        environment.etc."selinux/runtime-prefix-fixture".text = ''
          runtime-prefix fixture
        '';
      }
    ];
  };
  labeledEtcDump = labeledSystem.config.system.build.etcDump;
  labeledEtcImage = labeledSystem.config.system.build.etcMetadataImage;
  labeledEtcPlan = labeledSystem.config.system.build.etcSelinuxContextPlan;
in
  pkgs.mkDerivation {
    pname = "selinux-erofs-labels-check";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.composefs
      pkgs.erofs-utils
      pkgs.libselinux
      pkgs.python3
      legacyEtcDump
      legacyEtcImage
      labeledEtcDump
      labeledEtcImage
      labeledEtcPlan
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "check";
        script = ''
          ${pkgs.python3}/bin/python3 -B ${policySupport}/context_plan_test.py
          ${pkgs.python3}/bin/python3 -B ${policySupport}/verify_context_dump_test.py
          ${pkgs.python3}/bin/python3 -B ${policySupport}/verify_erofs_contexts_test.py
          mkdir -p "$TMPDIR/composefs-test"
          cp ${composefsDump} "$TMPDIR/composefs-test/build-composefs-dump.py"
          cp ${composefsDumpTest} "$TMPDIR/composefs-test/build-composefs-dump_test.py"
          ${pkgs.python3}/bin/python3 -B \
            "$TMPDIR/composefs-test/build-composefs-dump_test.py"

          # The nullable module input preserves the existing unlabeled image,
          # while the enabled path labels and verifies its exact /etc inode
          # inventory before exposing the EROFS output.
          ${pkgs.composefs}/bin/composefs-info dump ${legacyEtcImage} \
            > module-legacy-observed.dump
          if grep -Fq 'security.selinux=' ${legacyEtcDump} \
            || grep -Fq 'security.selinux=' module-legacy-observed.dump; then
            echo 'null immutable policy unexpectedly labeled the /etc image' >&2
            exit 1
          fi

          grep -F 'security.selinux=' ${labeledEtcDump} >/dev/null
          ${pkgs.composefs}/bin/composefs-info dump ${labeledEtcImage} \
            > module-labeled-observed.dump
          ${pkgs.python3}/bin/python3 -B ${policySupport}/verify_context_dump.py \
            --dump module-labeled-observed.dump \
            --expected ${labeledEtcPlan}/context-map.json
          ${pkgs.python3}/bin/python3 -c '
          import json, sys
          document = json.load(open(sys.argv[1], encoding="utf-8"))
          entries = {entry["path"]: entry for entry in document["entries"]}
          fixture = entries["/selinux/runtime-prefix-fixture"]
          assert fixture["kind"] == "symlink", fixture
          assert fixture["context"].split(":", 3)[2] == "selinux_config_t", fixture
          assert "/etc/selinux/runtime-prefix-fixture" not in entries, entries
          ' ${labeledEtcPlan}/context-map.json

          root=$TMPDIR/root
          coreutils_store=/nix/store/$(basename ${pkgs.coreutils})
          glibc_store=/nix/store/$(basename ${pkgs.glibc})
          systemd_store=/nix/store/$(basename ${pkgs.systemd})
          loader_image="$glibc_store/lib/${dynamicLinker}"

          mkdir -p \
            "$root/etc" \
            "$root/lib64" \
            "$root/nix/store/$(basename ${pkgs.coreutils})/bin" \
            "$root/nix/store/$(basename ${pkgs.glibc})/lib" \
            "$root/nix/store/$(basename ${pkgs.systemd})/lib/systemd" \
            "$root/usr/bin" \
            "$root/usr/lib/systemd"

          printf 'path with an escaped space\n' > "$root/etc/space name"
          tab_path=$(printf '%s\t%s' "$root/etc/tab" 'name')
          ${pkgs.python3}/bin/python3 -c \
            'import os, sys; assert b"\x09" in os.fsencode(sys.argv[1])' \
            "$tab_path"
          printf 'path with an escaped tab\n' > "$tab_path"

          cp ${pkgs.coreutils}/bin/true "$root$coreutils_store/bin/true"
          cp ${pkgs.glibc}/lib/libc.so.6 "$root$glibc_store/lib/libc.so.6"
          cp ${pkgs.glibc}/lib/${dynamicLinker} "$root$loader_image"
          cp ${pkgs.systemd}/lib/systemd/systemd \
            "$root$systemd_store/lib/systemd/systemd"
          ln "$root$coreutils_store/bin/true" "$root$coreutils_store/bin/true-hardlink"

          ln -s "$coreutils_store/bin/true" "$root/usr/bin/true"
          ln -s "$systemd_store/lib/systemd/systemd" "$root/usr/lib/systemd/systemd"
          ln -s "$loader_image" "$root/lib64/${dynamicLinker}"

          ${pkgs.python3}/bin/python3 -B ${policySupport}/context_plan.py \
            --root "$root" \
            --file-contexts ${policyRoot}/contexts/files/file_contexts \
            --libselinux ${pkgs.libselinux}/lib/libselinux.so.1 \
            --dynamic-loader "$loader_image" \
            --output-file-contexts exact-file-contexts \
            --output-map expected-contexts.json

          # Compile against the loadable production policy. This validates
          # every generated type and the policy's actual non-MLS context shape.
          ${pkgs.libselinux}/sbin/sefcontext_compile \
            -p ${policyRoot}/policy/policy.33 \
            -o exact-file-contexts.bin \
            exact-file-contexts
          ${pkgs.python3}/bin/python3 -B \
            ${policySupport}/verify_context_lookups.py \
            --file-contexts exact-file-contexts \
            --libselinux ${pkgs.libselinux}/lib/libselinux.so.1 \
            --expected expected-contexts.json

          ${pkgs.erofs-utils}/bin/mkfs.erofs \
            --all-root \
            --file-contexts=exact-file-contexts \
            -T0 \
            -U bdfb6fc9-0000-4000-8000-000000000002 \
            image.erofs \
            "$root"
          ${pkgs.erofs-utils}/bin/fsck.erofs image.erofs
          ${pkgs.python3}/bin/python3 -B \
            ${policySupport}/verify_erofs_contexts.py \
            --dump-erofs ${pkgs.erofs-utils}/bin/dump.erofs \
            --image image.erofs \
            --expected expected-contexts.json

          # Exercise the composefs text codec through a real EROFS image too.
          # This tree exactly matches the root, parent, file, and symlink
          # records emitted from codec-config.json.
          codec_root=$TMPDIR/codec-root
          mkdir -p "$codec_root/etc"
          printf 'composefs SELinux xattr payload\n' > "$codec_root/etc/sample"
          ln -s sample "$codec_root/etc/link"
          cat > codec-config.json <<EOF
          [
            {
              "target": "/etc/sample",
              "source": "$codec_root/etc/sample",
              "mode": "0644",
              "uid": "0",
              "gid": "0"
            },
            {
              "target": "/etc/link",
              "source": "sample",
              "mode": "direct-symlink",
              "uid": "0",
              "gid": "0"
            }
          ]
          EOF
          ${pkgs.python3}/bin/python3 -B ${policySupport}/context_plan.py \
            --root "$codec_root" \
            --file-contexts ${policyRoot}/contexts/files/file_contexts \
            --libselinux ${pkgs.libselinux}/lib/libselinux.so.1 \
            --output-file-contexts codec-file-contexts \
            --output-map codec-contexts.json
          ${pkgs.python3}/bin/python3 -B ${composefsDump} \
            codec-config.json \
            --context-map codec-contexts.json \
            > codec-input.dump
          (
            cd "$codec_root"
            ${pkgs.composefs}/bin/mkcomposefs \
              --from-file "$TMPDIR/codec-input.dump" \
              "$TMPDIR/codec-image.erofs"
          )
          ${pkgs.erofs-utils}/bin/fsck.erofs codec-image.erofs
          ${pkgs.composefs}/bin/composefs-info dump codec-image.erofs \
            > codec-observed.dump
          ${pkgs.python3}/bin/python3 -B ${policySupport}/verify_context_dump.py \
            --dump codec-observed.dump \
            --expected codec-contexts.json

          grep -F 'system_u:object_r:init_exec_t' expected-contexts.json
          grep -F 'system_u:object_r:ld_so_t' expected-contexts.json
          if grep -Fq ':s0' expected-contexts.json; then
            echo 'non-MLS production policy unexpectedly produced an MLS range' >&2
            exit 1
          fi

          mkdir -p "$out/share/aos/selinux-erofs-labels"
          cp \
            exact-file-contexts \
            exact-file-contexts.bin \
            expected-contexts.json \
            image.erofs \
            codec-contexts.json \
            codec-input.dump \
            codec-observed.dump \
            module-legacy-observed.dump \
            module-labeled-observed.dump \
            "$out/share/aos/selinux-erofs-labels/"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Validates authoritative SELinux labels in EROFS images";
      license = "GPL-2.0-or-later";
    };
  }
