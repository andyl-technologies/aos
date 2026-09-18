# Exact-kernel capability qualification, independent of full-system services.
{
  lib,
  testing,
  pkgs,
}: let
  buildProtobuf = pkgs.buildPackages.protobuf;
  probeSource = builtins.path {
    path = ../sandbox/filesystem-capability-probe.c;
    name = "aos-sandbox-filesystem-capability-probe.c";
  };
  rustBackingProbe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-verity-backing-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-verity-backing-probe --bins";
    # The executable needs the real ext4/fs-verity fixture below, not build-time
    # mount privilege. It links only its Linux boundary and ordinary runtime.
    doCheck = false;
    buildDeps = [];
    runtimeDeps = [];
  };
  protectedStoreProbe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-network-protected-store-fixture";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-network-protected-store-fixture --bin aos-sandbox-network-protected-store-fixture";
    # Runtime requires the real ext4/fs-verity and bind-mount topology below.
    doCheck = false;
    buildDeps = [buildProtobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${buildProtobuf}/bin/protoc";
  };
in
  testing.mkVMTest {
    name = "sandbox-filesystem-kernel-capabilities";
    rootfsDeps = [
      probeSource
      rustBackingProbe
      protectedStoreProbe
      pkgs.linux-headers
      pkgs.e2fsprogs
      pkgs.jq
    ];
    memory = 256;
    testScript = ''
      test -c /dev/fuse
      echo 'Compiling the filesystem capability probe'
      cd /tmp
      gcc -std=c17 -Wall -Wextra -Werror \
        -isystem ${pkgs.linux-headers}/include ${probeSource} -o filesystem-probe
      unset LD_LIBRARY_PATH

      mkdir ext4 fuse
      echo 'Preparing an ext4 verity backing filesystem'
      truncate -s 128M ext4.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -q -b 4096 -O verity ext4.img
      mount -o loop,nosuid,nodev ext4.img ext4
      trap 'umount /tmp/ext4' EXIT
      printf 'aos-fuse-passthrough-proof\n' > ext4/payload
      sync ext4/payload

      echo 'Qualifying fs-verity'
      ./filesystem-probe fs-verity /tmp/ext4/payload > verity.json
      ${pkgs.jq}/bin/jq -e '
        .schema_version == "aos.sandbox.fs-verity-proof/v1" and
        (.architecture == "x86_64" or .architecture == "aarch64") and
        .hash_algorithm == 1 and
        (.digest | test("^[0-9a-f]{64}$")) and
        .verity_flag == true and .write_open_denied == true and
        .write_open_errno != 0
      ' verity.json

      echo 'Qualifying FUSE backing-file passthrough'
      ./filesystem-probe fuse-passthrough /tmp/fuse /tmp/ext4/payload > passthrough.json
      ${pkgs.jq}/bin/jq -e --slurpfile verity verity.json '
        . == {
          schema_version: "aos.sandbox.fuse-passthrough-proof/v1",
          architecture: $verity[0].architecture,
          fuse_protocol: "7.45",
          passthrough_offered: true,
          backing_registered: true,
          passthrough_read: true,
          userspace_read_requests: 0
        }
      ' passthrough.json
      cat verity.json passthrough.json

      mkdir /tmp/fake-verity
      ./filesystem-probe fake-verity /tmp/fake-verity \
        ${rustBackingProbe}/bin/aos-sandbox-verity-backing-probe > fake-verity.json
      ${pkgs.jq}/bin/jq -e '
        .schema_version == "aos.sandbox.fake-verity-proof/v1" and
        .fabricated_ioctl_accepted == true and
        .measurement_requests == 1 and .statfs_requests >= 2 and
        .ordinary_open_requests >= 3 and .userspace_reads == 0 and
        .backing_registered == false and .rust_rejected_both == true
      ' fake-verity.json
      cat fake-verity.json

      echo 'Qualifying fresh-inode fs-verity materialization'
      mkdir /tmp/ext4/materialize-private
      chmod 0700 /tmp/ext4/materialize-private
      ${rustBackingProbe}/bin/materialize \
        /tmp/ext4/materialize-private > materialize.json
      ${pkgs.jq}/bin/jq -e '
        . == {
          schema_version: "aos.sandbox.verity-materialize-proof/v1",
          descriptor_verified: true,
          fresh_inode: true,
          exact_size: true,
          exact_bytes: true,
          source_offset_unchanged: true,
          measurement_is_sha256: true,
          backing_verified: true,
          writable_open_denied: true,
          same_name_preserved: true,
          rename_conflict_preserved: true,
          durable_rename_preserved: true,
          old_private_absent: true,
          conflict_retry_succeeded: true,
          quota_rejected_before_create: true,
          existing_name_untouched: true,
          callback_failure_retained: true,
          retained_unsealed_writable: true,
          cross_directory_durable: true,
          cross_conflict_preserved: true,
          same_root_rejected: true,
          observed_sealed_positive: true,
          observed_oversize_rejected: true,
          observed_absence_exact: true,
          observed_unsealed_rejected: true,
          observed_wrong_mode_rejected: true,
          observed_extra_link_rejected: true,
          observed_symlink_rejected: true,
          observed_mount_crossing_rejected: true
        }
      ' materialize.json
      cat materialize.json

      echo 'Qualifying namespace-inspector protected stores on ext4'
      test -x ${protectedStoreProbe}/bin/aos-sandbox-network-protected-store-fixture
      mkdir -p \
        /tmp/ext4/inspector-store/expected-staging \
        /tmp/ext4/inspector-store/expected-final \
        /tmp/ext4/inspector-store/spent-staging \
        /tmp/ext4/inspector-store/spent-final \
        /tmp/ext4/inspector-store/ambiguous-spent-staging \
        /tmp/ext4/inspector-store/ambiguous-spent-final \
        /tmp/inspector-store-ambiguous-final
      chmod 0700 \
        /tmp/ext4/inspector-store/expected-staging \
        /tmp/ext4/inspector-store/expected-final \
        /tmp/ext4/inspector-store/spent-staging \
        /tmp/ext4/inspector-store/spent-final \
        /tmp/ext4/inspector-store/ambiguous-spent-staging \
        /tmp/ext4/inspector-store/ambiguous-spent-final \
        /tmp/inspector-store-ambiguous-final
      mount --bind \
        /tmp/ext4/inspector-store/ambiguous-spent-final \
        /tmp/inspector-store-ambiguous-final
      trap 'umount /tmp/inspector-store-ambiguous-final; umount /tmp/ext4' EXIT

      ${protectedStoreProbe}/bin/aos-sandbox-network-protected-store-fixture \
        --list > inspector-store-cases.json
      ${pkgs.jq}/bin/jq -e '
        length == 12 and . == [
          "genuine-five-fd-topology",
          "mismatched-expected-view-rejected",
          "aliased-physical-role-rejected",
          "expected-publish-exact-readback",
          "all-roots-reopened-for-expected-lookup",
          "exact-absence-after-reopen",
          "spent-first-claim",
          "all-roots-reopened-for-exact-replay",
          "spent-attempt-mismatch-rejected",
          "wrong-expected-record-role-rejected",
          "wrong-spent-record-role-rejected",
          "ambiguous-cross-mount-publish-rejected"
        ]
      ' inspector-store-cases.json

      ${protectedStoreProbe}/bin/aos-sandbox-network-protected-store-fixture \
        /tmp/ext4/inspector-store \
        /tmp/inspector-store-ambiguous-final > inspector-store.json
      ${pkgs.jq}/bin/jq -e '
        . == {
          schema_version: "aos.sandbox.namespace-inspector-protected-store-ext4-proof/v1",
          success_marker: "AOS_NAMESPACE_INSPECTOR_PROTECTED_STORE_EXT4_OK",
          policy_source: "internally-derived-synthetic-validated-ready-fixture",
          reopen_boundary: "all-store-values-dropped-and-roots-reopened",
          cases: [
            "genuine-five-fd-topology",
            "mismatched-expected-view-rejected",
            "aliased-physical-role-rejected",
            "expected-publish-exact-readback",
            "all-roots-reopened-for-expected-lookup",
            "exact-absence-after-reopen",
            "spent-first-claim",
            "all-roots-reopened-for-exact-replay",
            "spent-attempt-mismatch-rejected",
            "wrong-expected-record-role-rejected",
            "wrong-spent-record-role-rejected",
            "ambiguous-cross-mount-publish-rejected"
          ]
        }
      ' inspector-store.json
      cat inspector-store-cases.json inspector-store.json

      # This measured expectation is supplied by the trusted test coordinator;
      # it does not demonstrate a production publication-authorization catalog.
      # Run last because the owned-descriptor lifetime check unlinks payload.
      measurement=$(${pkgs.jq}/bin/jq -r .digest verity.json)
      ${rustBackingProbe}/bin/aos-sandbox-verity-backing-probe \
        /tmp/ext4 "$measurement" > backing.json
      ${pkgs.jq}/bin/jq -e '
        . == {
          schema_version: "aos.sandbox.verity-backing-proof/v1",
          read_verified: true,
          identity_verified: true,
          mapping_verified: true,
          wrong_size_rejected: true,
          over_limit_rejected: true,
          wrong_digest_rejected: true,
          unsealed_rejected: true,
          symlink_rejected: true,
          unlinked_pin_verified: true
        }
      ' backing.json
      cat backing.json
      umount /tmp/inspector-store-ambiguous-final
      umount /tmp/ext4
      trap - EXIT
    '';
  }
