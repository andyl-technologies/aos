# tests/vm/apm/image.nix - Image download VM tests
#
# Exercises the image maintainer and consumer workflow end to end:
#   * create a registry with apr
#   * publish a real sysroot store path with real image store paths
#   * generate a real static Nix cache
#   * sync the registry for user and system apm scopes
#   * delete the local image store path
#   * download, verify, import, and copy the image via apm install --image
{
  testing,
  apm,
  pkgs,
}: let
  fixtures = import ./fixtures.nix {
    pkgs = pkgs;
    aosPkg = apm;
  };

  nixRuntimeDeps = [
    pkgs.nix
    pkgs.brotli
    pkgs.curl
    pkgs.openssl
    pkgs.sqlite
    pkgs.boost
    pkgs.editline
    pkgs.libsodium
    pkgs.libarchive
    pkgs.gc
    pkgs.lowdown
    pkgs.bzip2
    pkgs.zlib
  ];

  nixLibPath = builtins.concatStringsSep ":" (map (pkg: "${pkg}/lib") nixRuntimeDeps);

  setupNixEnv = ''
    export NIX_REMOTE=""
    export NIX_CONF_DIR=/tmp/nix-conf
    export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    mkdir -p "$NIX_CONF_DIR" /nix/var/nix/db /nix/var/nix/gcroots
    cat > "$NIX_CONF_DIR/nix.conf" << 'NIXCONF'
    experimental-features = nix-command
    sandbox = false
    NIXCONF
    nix-store --init || true
    nix-store --load-db < /aos-registration
  '';

  mkImage = {
    format,
    sizeKiB ? 1024,
  }:
    pkgs.mkDerivation {
      pname = "apm-vm-image-${format}";
      version = "2026.03";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.jq pkgs.zstd];
      UKI_STORE_PATH = "${pkgs.systemd}/lib/systemd/boot/efi";
      UKI_FILENAME = "systemd-bootx64.efi";
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out"
            ${
              if format == "raw"
              then ''
                filename=aos-test.img.zst
                printf 'AOSRAW\n' > image.raw
                truncate -s ${builtins.toString sizeKiB}KiB image.raw
                logical_disk_sha256=$(sha256sum image.raw | cut -d ' ' -f1)
                zstd -19 -T1 --no-progress image.raw -o "$out/$filename"
              ''
              else if format == "qcow2"
              then ''
                filename=aos-test.qcow2
                printf 'QFI\373' > "$out/$filename"
                truncate -s ${builtins.toString sizeKiB}KiB "$out/$filename"
                logical_disk_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
              ''
              else ''
                filename="aos-test.${format}"
                printf 'AOS image ${format}\n' > "$out/$filename"
                logical_disk_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
              ''
            }
            image_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
            image_size=$(stat -c %s "$out/$filename")
            uki_path="$UKI_STORE_PATH/$UKI_FILENAME"
            uki_sha256=$(sha256sum "$uki_path" | cut -d ' ' -f1)
            uki_size=$(stat -c %s "$uki_path")
            ${pkgs.jq}/bin/jq -S -n \
              --arg format '${format}' \
              --arg filename "$filename" \
              --arg sha256 "$image_sha256" \
              --arg logicalDiskSha256 "$logical_disk_sha256" \
              --arg rootfsSha256 "$logical_disk_sha256" \
              --arg objectKey "images/sha256/$image_sha256/$filename" \
              --arg mediaType '${
              if format == "raw"
              then "application/vnd.aos.disk-image.raw+zstd"
              else "application/vnd.aos.disk-image.qcow2"
            }' \
              --arg ukiFilename "$UKI_FILENAME" \
              --arg ukiEspPath "EFI/Linux/$UKI_FILENAME" \
              --arg ukiSha256 "$uki_sha256" \
              --argjson byteSize "$image_size" \
              --argjson ukiSize "$uki_size" \
              --argjson targets '${
              if format == "raw"
              then ''["bare-metal"]''
              else ''["qemu-kvm","openstack"]''
            }' \
              '{schemaVersion: 1, name: "server", version: "2026.03",
                architecture: "x86_64", platform: "x86_64-linux",
                format: $format, filename: $filename, objectKey: $objectKey,
                mediaType: $mediaType, compression: "${
              if format == "raw"
              then "zstd"
              else "none"
            }", byteSize: $byteSize,
                virtualSizeBytes: ${builtins.toString sizeKiB} * 1024,
                sha256: $sha256, logicalDiskSha256: $logicalDiskSha256,
                rootfsSha256: $rootfsSha256, compatibleTargets: $targets,
                artifactBudgetsMiB: {root: 1, verity: 1, initrd: 1, uki: 1, esp: 34, runtimeClosure: 1, download: 2},
                partitionTable: "gpt", kernelParams: "",
                partitions: [{number: 1, label: "root-a", type: "root", filesystem: "fake", sizeMiB: 1, offsetBytes: 0, sizeBytes: 1048576}],
                esp: {uki: $ukiEspPath, sdBoot: "EFI/systemd/systemd-bootx64.efi"},
                uki: {filename: $ukiFilename, espPath: $ukiEspPath,
                  byteSize: $ukiSize, sha256: $ukiSha256, signed: false, measured: false}}' \
              > "$out/image-info.json"
          '';
        }
      ];
    };

  serverToplevel = pkgs.mkDerivation {
    pname = "apm-vm-server-toplevel";
    version = "2026.03";
    src = null;
    buildDeps = [pkgs.coreutils];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/etc"
          printf 'NAME=AOS VM image test\nVERSION=2026.03\n' > "$out/etc/aos-release"
        '';
      }
    ];
  };

  imageRaw = mkImage {format = "raw";};
  imageQcow2 = mkImage {format = "qcow2";};

  imageWorkflowDeps =
    fixtures.commonDeps
    ++ nixRuntimeDeps
    ++ [
      pkgs.findutils
      pkgs.iproute2
      pkgs.python3
      pkgs.zstd
      serverToplevel
      imageRaw
      imageQcow2
    ];

  setupImageRegistryWorkflow = ''
    ${fixtures.setupPreamble}
    ${setupNixEnv}

    mount -o remount,rw / || true

    IMAGE_RAW_STORE="${imageRaw}"
    IMAGE_QCOW2_STORE="${imageQcow2}"
    SERVER_STORE="${serverToplevel}"
    RAW_HASH=$(basename "$IMAGE_RAW_STORE" | cut -d- -f1)
    QCOW2_HASH=$(basename "$IMAGE_QCOW2_STORE" | cut -d- -f1)
    SERVER_HASH=$(basename "$SERVER_STORE" | cut -d- -f1)
    RAW_FILE="$IMAGE_RAW_STORE/aos-test.img.zst"
    QCOW2_FILE="$IMAGE_QCOW2_STORE/aos-test.qcow2"
    RAW_EXPECTED=$(sha256sum "$RAW_FILE" | cut -d' ' -f1)
    QCOW2_EXPECTED=$(sha256sum "$QCOW2_FILE" | cut -d' ' -f1)
    RAW_INFO_SHA=$(sha256sum "$IMAGE_RAW_STORE/image-info.json" | cut -d' ' -f1)
    QCOW2_INFO_SHA=$(sha256sum "$IMAGE_QCOW2_STORE/image-info.json" | cut -d' ' -f1)

    assert_store_valid() {
      path="$1"
      label="$2"
      if nix-store --check-validity "$path" > "/tmp/valid-$label.out" 2>&1; then
        pass "$label valid in store"
      else
        cat "/tmp/valid-$label.out"
        fail "$label should be valid in store"
      fi
    }

    delete_store_path() {
      path="$1"
      label="$2"
      if nix-store --delete --ignore-liveness "$path" > "/tmp/delete-$label.out" 2>&1; then
        pass "$label deleted before apm download"
      else
        cat "/tmp/delete-$label.out"
        fail "$label should be deletable before apm download"
        return 1
      fi

      if nix-store --check-validity "$path" > "/tmp/valid-after-delete-$label.out" 2>&1; then
        cat "/tmp/valid-after-delete-$label.out"
        fail "$label should be missing after delete"
      else
        pass "$label missing before apm download"
      fi
    }

    wait_for_cache_server() {
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -sf http://127.0.0.1:18084/nix-cache-info >/dev/null; then
          return 0
        fi
        sleep 1
      done
      return 1
    }

    echo "==> Maintainer: publish sysroot package and image artifacts"
    $APR create image-reg
    REG_DIR="$REG_STORAGE/image-reg"
    DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)

    $APR publish "$SERVER_STORE" \
      --name server \
      --version 2026.03 \
      --description "Server sysroot for image workflow tests" \
      --license MIT \
      --maintainer image-workflow@example.invalid \
      --sysroot \
      --image "$IMAGE_RAW_STORE" \
      --image-format raw \
      --image-uki '${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
      --image "$IMAGE_QCOW2_STORE" \
      --image-format qcow2 \
      --image-uki '${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
      --registry image-reg \
      --no-commit

    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "sysroot = true" "published package is marked as sysroot"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "$SERVER_HASH" "published package records server store hash"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "$RAW_HASH" "published package records raw image store hash"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "$QCOW2_HASH" "published package records qcow2 image store hash"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "format = \"raw\"" "published package records raw image format"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "format = \"qcow2\"" "published package records qcow2 image format"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "schema_version = 1" "published image catalog requires direct-delivery schema"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "images/sha256/$RAW_EXPECTED/aos-test.img.zst" \
      "signed raw catalog points at immutable disk bytes"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "images/sha256/$QCOW2_EXPECTED/aos-test.qcow2" \
      "signed QCOW2 catalog points at immutable disk bytes"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "application/vnd.aos.image-info+json" \
      "signed catalog carries per-format image-info references"
    assert_file_contains "$REG_DIR/packages/s/server.toml" \
      "compatible_targets = \[\"qemu-kvm\", \"openstack\"\]" \
      "signed QCOW2 catalog carries end-user target mapping"
    assert_file_exists \
      "$REG_DIR/.git/aos-image-staging/images/sha256/$RAW_EXPECTED/aos-test.img.zst" \
      "raw direct-delivery bytes are staged outside Git objects"
    assert_file_exists \
      "$REG_DIR/.git/aos-image-staging/images/sha256/$QCOW2_EXPECTED/aos-test.qcow2" \
      "QCOW2 direct-delivery bytes are staged outside Git objects"
    assert_file_exists \
      "$REG_DIR/.git/aos-image-staging/images/sha256/$RAW_EXPECTED/metadata/$RAW_INFO_SHA/image-info.json" \
      "raw encoding carries content-bound image-info"
    assert_file_exists \
      "$REG_DIR/.git/aos-image-staging/images/sha256/$QCOW2_EXPECTED/metadata/$QCOW2_INFO_SHA/image-info.json" \
      "QCOW2 encoding carries content-bound image-info"

    $APR cache generate \
      --registry image-reg \
      --output /tmp/image-cache \
      --cache-url http://127.0.0.1:18084 \
      --priority 44 \
      --no-commit
    assert_file_exists "/tmp/image-cache/$SERVER_HASH.narinfo" \
      "static cache has server narinfo"
    assert_file_exists "/tmp/image-cache/$RAW_HASH.narinfo" \
      "static cache has raw image narinfo"
    assert_file_exists "/tmp/image-cache/$QCOW2_HASH.narinfo" \
      "static cache has qcow2 image narinfo"
    assert_dir_exists "/tmp/image-cache/nar" "static cache has NAR directory"
    assert_file_contains "$REG_DIR/registry.toml" \
      "http://127.0.0.1:18084" "registry records cache URL"

    git -C "$REG_DIR" add -A
    git -C "$REG_DIR" commit -m "release: server 2026.03 images"
    git init --bare --object-format=sha256 /tmp/image-origin.git
    git -C "$REG_DIR" remote add origin /tmp/image-origin.git
    git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

    ${pkgs.iproute2}/sbin/ip link set lo up || true
    ${pkgs.iproute2}/sbin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
    PYTHONUNBUFFERED=1 python3 -m http.server 18084 --bind 127.0.0.1 \
      --directory /tmp/image-cache > /tmp/image-cache-http.log 2>&1 &
    CACHE_PID=$!
    if wait_for_cache_server; then
      pass "static cache HTTP server started"
    else
      cat /tmp/image-cache-http.log || true
      fail "static cache HTTP server started"
    fi

    echo "==> Consumer: sync user registry for apm show"
    export HOME=/tmp/image-consumer
    export USER=imageuser
    mkdir -p "$HOME"
    $APM registry add --no-verify file:///tmp/image-origin.git \
      --name image-reg \
      --branch "$DEFAULT_BRANCH" > /tmp/image-registry-add.out 2>&1 || {
      cat /tmp/image-registry-add.out
      fail "apm registry add syncs image registry"
    }
    cat /tmp/image-registry-add.out

    $APM show server > /tmp/image-show.out 2>&1 || {
      cat /tmp/image-show.out
      fail "apm show resolves the published sysroot package"
    }
    cat /tmp/image-show.out
    assert_file_contains /tmp/image-show.out "Package.*server" \
      "apm show displays server package"
    assert_file_contains /tmp/image-show.out "Version.*2026.03" \
      "apm show displays server version"
    assert_file_contains /tmp/image-show.out "Sysroot.*yes" \
      "apm show displays sysroot designation"
    assert_file_contains /tmp/image-show.out "Image formats.*raw, qcow2" \
      "apm show displays available image formats"

    echo "==> Consumer: sync system registry for apm install --system --image"
    mkdir -p /etc/apm/registries.d /var/lib/apm/registries /var/lib/apm/remote \
      /var/lib/apm/cache /var/lib/profiles/system
    cat > /etc/apm/registries.d/image-reg.toml << CFGEOF
    [registry]
    name = "image-reg"
    url = "file:///tmp/image-origin.git"
    priority = 500
    enabled = true
    branch = "$DEFAULT_BRANCH"
    CFGEOF
    git clone --branch "$DEFAULT_BRANCH" /tmp/image-origin.git /var/lib/apm/registries/image-reg
    ln -sfn /var/lib/apm/registries/image-reg /var/lib/apm/remote/image-reg

    assert_store_valid "$SERVER_STORE" "server sysroot"
    assert_store_valid "$IMAGE_RAW_STORE" "raw image"
    assert_store_valid "$IMAGE_QCOW2_STORE" "qcow2 image"
  '';

  mkImagePullTest = {
    format,
    output,
    storeVar,
    expectedVar,
    extraCheck ? "",
  }:
    testing.mkVMTest {
      name = "apm-image-pull-${format}";
      rootfsDeps = imageWorkflowDeps;
      memory = 1024;
      testScript = ''
        ${setupImageRegistryWorkflow}

        echo "==> Test: apm install server --system --image ${format}"
        $APM install server --system --registry image-reg --image ${format} \
          --output ${output} --dry-run > /tmp/image-${format}-dry-run.out 2>&1 || {
          cat /tmp/image-${format}-dry-run.out
          fail "dry-run plans ${format} image download"
        }
        cat /tmp/image-${format}-dry-run.out
        assert_file_contains /tmp/image-${format}-dry-run.out "Image format.*${format}" \
          "dry-run identifies ${format} image format"
        assert_file_contains /tmp/image-${format}-dry-run.out "Output.*${output}" \
          "dry-run shows ${format} output path"

        delete_store_path "${"$"}${storeVar}" "${format} image"
        rm -f ${output}

        $APM install server --system --registry image-reg --image ${format} \
          --output ${output} --yes > /tmp/image-${format}-install.out 2>&1 || {
          cat /tmp/image-${format}-install.out
          fail "apm downloads and writes ${format} image"
        }
        cat /tmp/image-${format}-install.out
        assert_file_contains /tmp/image-${format}-install.out "Fetching 1 narinfo" \
          "apm fetched ${format} image narinfo"
        assert_file_contains /tmp/image-${format}-install.out "Downloading" \
          "apm downloaded ${format} image NAR"
        assert_file_contains /tmp/image-${format}-install.out "written to ${output}" \
          "apm reported ${format} image output"
        assert_file_exists ${output} "${format} image output exists"

        ACTUAL_HASH=$(sha256sum ${output} | cut -d' ' -f1)
        if [ "$ACTUAL_HASH" = "${"$"}${expectedVar}" ]; then
          pass "${format} output matches original image hash"
        else
          fail "${format} output hash mismatch: $ACTUAL_HASH"
        fi

        ${extraCheck}

        if kill "$CACHE_PID" 2>/dev/null; then
          pass "static cache HTTP server stopped"
        fi
        check_fail
      '';
    };
in {
  image-pull-raw = mkImagePullTest {
    format = "raw";
    output = "/tmp/server.raw";
    storeVar = "IMAGE_RAW_STORE";
    expectedVar = "RAW_EXPECTED";
    extraCheck = ''
      if grep -q "AOSRAW" /tmp/server.raw; then
        pass "raw image payload marker is present"
      else
        fail "raw image payload marker should be present"
      fi
    '';
  };

  image-pull-qcow2 = mkImagePullTest {
    format = "qcow2";
    output = "/tmp/server.qcow2";
    storeVar = "IMAGE_QCOW2_STORE";
    expectedVar = "QCOW2_EXPECTED";
    extraCheck = ''
      MAGIC=$(dd if=/tmp/server.qcow2 bs=1 count=3 2>/dev/null)
      if [ "$MAGIC" = "QFI" ]; then
        pass "qcow2 magic bytes are present"
      else
        fail "qcow2 magic bytes should be present"
      fi
    '';
  };

  image-list = testing.mkVMTest {
    name = "apm-image-list";
    rootfsDeps = imageWorkflowDeps;
    memory = 1024;
    testScript = ''
      ${setupImageRegistryWorkflow}

      assert_file_not_contains() {
        if grep -q "$2" "$1" 2>/dev/null; then
          fail "$3 (pattern '$2' unexpectedly found in $1)"
          cat "$1" 2>/dev/null || true
        else
          pass "$3"
        fi
      }

      echo "==> Test: unavailable image format fails after package resolution"
      if $APM install server --system --registry image-reg --image vmdk \
        --output /tmp/server.vmdk --dry-run > /tmp/image-vmdk.out 2>&1; then
        cat /tmp/image-vmdk.out
        fail "vmdk image format should be rejected"
      else
        cat /tmp/image-vmdk.out
        pass "vmdk image format rejected"
      fi
      assert_file_contains /tmp/image-vmdk.out "not available" \
        "unavailable format error reports availability"
      assert_file_contains /tmp/image-vmdk.out "Available: raw, qcow2" \
        "unavailable format error lists raw and qcow2"
      if grep -q "package not found" /tmp/image-vmdk.out; then
        fail "unavailable format must not be reported as package not found"
      else
        pass "unavailable format reaches image validation"
      fi

      echo "==> Maintainer: validate and prune a missing image cache artifact"
      export HOME=/tmp
      export USER=root
      APM_CONFIG="$HOME/.config/apm"
      rm -f "/tmp/image-cache/$QCOW2_HASH.narinfo"

      if $APR validate --registry image-reg \
        --package server \
        --platform x86_64-linux \
        --jobs 2 > /tmp/image-validate-missing-qcow2.out 2>&1; then
        cat /tmp/image-validate-missing-qcow2.out
        fail "apr validate should fail when an image cache artifact is missing"
      else
        cat /tmp/image-validate-missing-qcow2.out
        pass "apr validate reports missing image cache artifact"
      fi
      assert_file_contains /tmp/image-validate-missing-qcow2.out \
        "not found in any cache" \
        "apr validate reports the missing qcow2 image"

      $APR validate --registry image-reg \
        --package server \
        --platform x86_64-linux \
        --jobs 2 \
        --fix > /tmp/image-validate-fix-qcow2.out 2>&1 || {
        cat /tmp/image-validate-fix-qcow2.out
        fail "apr validate --fix prunes only the missing image metadata"
      }
      cat /tmp/image-validate-fix-qcow2.out
      assert_file_contains /tmp/image-validate-fix-qcow2.out \
        "Removed 1 missing cache entry" \
        "apr validate --fix reports image metadata pruning"
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        'format = "raw"' \
        "validate fix keeps cache-backed raw image metadata"
      assert_file_not_contains "$REG_DIR/packages/s/server.toml" \
        'format = "qcow2"' \
        "validate fix removes missing qcow2 image metadata"
      assert_file_contains "$REG_DIR/packages/s/server.toml" \
        "$SERVER_HASH" \
        "validate fix keeps sysroot package metadata"

      $APR verify --registry image-reg > /tmp/image-verify-after-fix.out 2>&1 || {
        cat /tmp/image-verify-after-fix.out
        fail "apr verify accepts image registry after validate fix"
      }
      assert_file_contains /tmp/image-verify-after-fix.out "no errors" \
        "apr verify validates image registry after validate fix"
      git -C "$REG_DIR" status --short --untracked-files=all \
        > /tmp/image-validate-fix-status.out
      assert_file_contains /tmp/image-validate-fix-status.out \
        "packages/s/server.toml" \
        "validate fix leaves an image metadata changeset"
      git -C "$REG_DIR" add -A
      git -C "$REG_DIR" commit -m "registry: prune missing qcow2 image artifact" \
        > /tmp/image-validate-fix-commit.out 2>&1 || {
        cat /tmp/image-validate-fix-commit.out
        fail "maintainer commits pruned image changeset"
      }
      cat /tmp/image-validate-fix-commit.out
      git -C "$REG_DIR" push origin "$DEFAULT_BRANCH"

      echo "==> Consumer: sync pruned image metadata and download remaining image"
      export HOME=/tmp/image-consumer
      export USER=imageuser
      APM_CONFIG="$HOME/.config/apm"
      $APM update --registry image-reg > /tmp/image-update-after-fix.out 2>&1 || {
        cat /tmp/image-update-after-fix.out
        fail "apm update syncs pruned image metadata"
      }
      cat /tmp/image-update-after-fix.out
      $APM show server > /tmp/image-show-after-fix.out 2>&1 || {
        cat /tmp/image-show-after-fix.out
        fail "apm show resolves server after image prune"
      }
      assert_file_contains /tmp/image-show-after-fix.out "Image formats.*raw" \
        "apm show keeps raw image format after validate fix"
      assert_file_not_contains /tmp/image-show-after-fix.out "qcow2" \
        "apm show hides pruned qcow2 image format"

      git -C /var/lib/apm/registries/image-reg pull --ff-only origin "$DEFAULT_BRANCH" \
        > /tmp/image-system-pull-after-fix.out 2>&1 || {
        cat /tmp/image-system-pull-after-fix.out
        fail "system registry clone syncs pruned image metadata"
      }
      cat /tmp/image-system-pull-after-fix.out

      if $APM install server --system --registry image-reg --image qcow2 \
        --output /tmp/server.qcow2 --dry-run > /tmp/image-qcow2-after-fix.out 2>&1; then
        cat /tmp/image-qcow2-after-fix.out
        fail "pruned qcow2 image format should be rejected"
      else
        cat /tmp/image-qcow2-after-fix.out
        pass "pruned qcow2 image format is rejected"
      fi
      assert_file_contains /tmp/image-qcow2-after-fix.out "Available: raw" \
        "qcow2 rejection lists only remaining raw image"
      assert_file_not_contains /tmp/image-qcow2-after-fix.out "Available: raw, qcow2" \
        "qcow2 rejection does not advertise pruned image"

      delete_store_path "$IMAGE_RAW_STORE" "raw image after validate fix"
      rm -f /tmp/server-pruned.raw
      $APM install server --system --registry image-reg --image raw \
        --output /tmp/server-pruned.raw --yes \
        > /tmp/image-raw-after-fix-install.out 2>&1 || {
        cat /tmp/image-raw-after-fix-install.out
        fail "apm downloads remaining raw image after validate fix"
      }
      cat /tmp/image-raw-after-fix-install.out
      assert_file_contains /tmp/image-raw-after-fix-install.out "Downloading" \
        "raw image install downloads after validate fix"
      assert_file_contains /tmp/image-raw-after-fix-install.out \
        "written to /tmp/server-pruned.raw" \
        "raw image install reports output after validate fix"
      assert_file_exists /tmp/server-pruned.raw \
        "raw image output exists after validate fix"
      RAW_AFTER_FIX=$(sha256sum /tmp/server-pruned.raw | cut -d' ' -f1)
      if [ "$RAW_AFTER_FIX" = "$RAW_EXPECTED" ]; then
        pass "remaining raw image output matches original hash"
      else
        fail "remaining raw image hash mismatch: $RAW_AFTER_FIX"
      fi

      if kill "$CACHE_PID" 2>/dev/null; then
        pass "static cache HTTP server stopped"
      fi
      check_fail
    '';
  };
}
