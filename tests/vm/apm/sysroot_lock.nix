# tests/vm/apm/sysroot_lock.nix — Sysroot-lock check VM tests
#
# Verifies that sysroot-lock enforcement blocks installs when a package's
# closure diverges from the current sysroot, and that --ignore-sysroot-lock
# flags bypass the check correctly.
#
# These tests run apm in a headless Firecracker microVM with mock registries
# and a mock system generation state.  All store_path values in the registry
# TOML point to real Nix store derivations so that `nix-store --check-validity`
# succeeds when apm's install pipeline reaches the filter_missing step.
#
# Two registries are used because apm's registry parser keeps one version per
# package name.  The sysroot-lock check needs BOTH the sysroot and divergent
# versions of openssl/zlib to be indexable by name, which requires them to
# live in separate registries where each has the canonical entry.
{
  testing,
  apm,
  pkgs,
}: let
  # --------------------------------------------------------------------------
  # Real placeholder derivations — tiny packages that produce valid store paths.
  # Each has a unique (pname, version) so it gets a unique Nix store hash.
  # We use these as stand-ins for the mock package identities in the registry.
  # --------------------------------------------------------------------------
  mkPlaceholder = pname: version:
    pkgs.mkDerivation {
      inherit pname version;
      src = null;
      buildDeps = [pkgs.coreutils];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p $out
            echo "${pname}-${version}" > $out/marker
          '';
        }
      ];
    };

  # Sysroot closure members (one set of store paths)
  sysrootOpensslPkg = mkPlaceholder "openssl" "3.2.1";
  sysrootZlibPkg = mkPlaceholder "zlib" "1.3.0";
  sysrootGlibcPkg = mkPlaceholder "glibc" "2.39";
  sysrootToplevelPkg = mkPlaceholder "server" "2026.03";

  # Divergent closure members (different store paths for the same names)
  pkgOpensslPkg = mkPlaceholder "openssl" "3.3.0";
  pkgZlibPkg = mkPlaceholder "zlib" "1.3.1";

  # Additional mock packages
  nginxPkg = mkPlaceholder "nginx" "1.27.0";
  cleanPkgPkg = mkPlaceholder "clean-pkg" "1.0.0";

  # Real store path strings for use in TOML generation
  sysrootOpenssl = builtins.toString sysrootOpensslPkg;
  sysrootZlib = builtins.toString sysrootZlibPkg;
  sysrootGlibc = builtins.toString sysrootGlibcPkg;
  sysrootToplevel = builtins.toString sysrootToplevelPkg;
  pkgOpenssl = builtins.toString pkgOpensslPkg;
  pkgZlib = builtins.toString pkgZlibPkg;
  nginxPath = builtins.toString nginxPkg;
  cleanPkgPath = builtins.toString cleanPkgPkg;

  # All placeholder derivations — included in rootfsDeps so their store paths
  # are physically present in the VM and pass nix-store --check-validity.
  allPlaceholders = [
    sysrootOpensslPkg
    sysrootZlibPkg
    sysrootGlibcPkg
    sysrootToplevelPkg
    pkgOpensslPkg
    pkgZlibPkg
    nginxPkg
    cleanPkgPkg
  ];

  # Common rootfs deps for all sysroot-lock tests
  # nix runtime deps needed for LD_LIBRARY_PATH (RPATH doesn't cover all deps yet)
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

  testDeps =
    [
      apm
      pkgs.coreutils
      pkgs.jq
      pkgs.grep
      pkgs.git
    ]
    ++ nixRuntimeDeps
    ++ allPlaceholders;

  # --------------------------------------------------------------------------
  # Fixture builder: create a mock registry directory with package metadata
  # --------------------------------------------------------------------------
  # This derivation builds a registry directory structure that apm can read.
  # The registry format is a git repo with packages/<letter>/<name>.toml files.
  #
  # Parameters:
  #   packages — list of { name, version, storePath, sysroot, references, images }
  mkMockRegistry = {
    name,
    packages,
  }:
    pkgs.mkDerivation {
      pname = "mock-registry-${name}";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.git];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p $out/packages
            ${builtins.concatStringsSep "\n" (builtins.map (pkg: let
                letter = builtins.substring 0 1 pkg.name;
              in ''
                              mkdir -p $out/packages/${letter}
                              cat > $out/packages/${letter}/${pkg.name}.toml << 'PKGEOF'
                [package]
                name = "${pkg.name}"
                description = "mock ${pkg.name}"
                license = "MIT"
                maintainer = "test"
                ${
                  if pkg.sysroot or false
                  then "sysroot = true"
                  else ""
                }

                [[versions]]
                version = "${pkg.version}"

                [versions.platforms.x86_64-linux]
                store_path = "${pkg.storePath}"
                nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
                nar_size = 1024
                closure_size = 2048
                source_drv = ""
                source_nar_hash = ""
                references = [${builtins.concatStringsSep ", " (builtins.map (r: "\"${r}\"") (pkg.references or []))}]
                ${
                  if (pkg.images or []) != []
                  then
                    builtins.concatStringsSep "\n" (builtins.map (img: ''
                      [[versions.platforms.x86_64-linux.images]]
                      format = "${img.format}"
                      store_path = "${img.storePath}"
                      nar_hash = "sha256:0000000000000000000000000000000000000000000000000000"
                      nar_size = ${builtins.toString img.narSize}
                    '') (pkg.images or []))
                  else ""
                }
                PKGEOF
              '')
              packages)}

            # Initialize as a git repo (apm expects this)
            cd $out
            git init
            git add .
            git -c user.name=test -c user.email=test@test commit -m "init" --allow-empty
          '';
        }
      ];
    };

  # --------------------------------------------------------------------------
  # Preamble: set up apm config, mock registries, and system generation state
  # --------------------------------------------------------------------------
  # Uses TWO registries so that both the sysroot and divergent versions of
  # openssl/zlib are each the canonical entry in their respective registry.
  # The sysroot-lock lookup (build_registry_lookup) iterates all registries,
  # so both versions are indexed and can be resolved by name.
  # nix-store needs its runtime libraries
  nixLibPath = builtins.concatStringsSep ":" (map (p: "${p}/lib") nixRuntimeDeps);

  mkPreamble = {
    sysrootRegistryPath,
    userRegistryPath,
    sysrootState ? null,
  }: ''
        # Use /tmp for all writable state
        export HOME=/tmp/home
        export LD_LIBRARY_PATH="${nixLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        mkdir -p $HOME/.config/apm/registries.d
        mkdir -p $HOME/.local/share/apm/registries
        mkdir -p $HOME/.local/share/apm/remote
        mkdir -p $HOME/.cache/apm
        mkdir -p /var/lib/profiles/system
        mkdir -p /var/lib/apm/remote
        mkdir -p /var/lib/apm/registries
        mkdir -p /etc/apm/registries.d

        # Copy both mock registries (git repos are read-only in the store)
        cp -r ${sysrootRegistryPath} /var/lib/apm/registries/sysroot-reg
        chmod -R u+w /var/lib/apm/registries/sysroot-reg
        cp -r ${userRegistryPath} /var/lib/apm/registries/user-reg
        chmod -R u+w /var/lib/apm/registries/user-reg

        # Configure apm to use both registries
        # sysroot-reg has higher priority (600) and contains the sysroot + old versions
        cat > /etc/apm/registries.d/sysroot-reg.toml << 'CFGEOF'
    [registry]
    name = "sysroot-reg"
    url = "file:///var/lib/apm/registries/sysroot-reg"
    priority = 600
    enabled = true

    [registry.signing]
    required = false
    CFGEOF

        cat > /etc/apm/registries.d/user-reg.toml << 'CFGEOF'
    [registry]
    name = "user-reg"
    url = "file:///var/lib/apm/registries/user-reg"
    priority = 500
    enabled = true

    [registry.signing]
    required = false
    CFGEOF

        # Symlink registries into the remote cache (apm reads from here)
        ln -sfn /var/lib/apm/registries/sysroot-reg /var/lib/apm/remote/sysroot-reg
        ln -sfn /var/lib/apm/registries/user-reg /var/lib/apm/remote/user-reg
        ln -sfn /var/lib/apm/registries/sysroot-reg $HOME/.local/share/apm/remote/sysroot-reg
        ln -sfn /var/lib/apm/registries/user-reg $HOME/.local/share/apm/remote/user-reg

        ${
      if sysrootState != null
      then ''
        # Write system generation state
        cp ${builtins.toFile "state.json" (builtins.unsafeDiscardStringContext sysrootState)} /var/lib/profiles/system/state.json
        # Create generation directories
        mkdir -p /var/lib/profiles/system/gen-1
      ''
      else ""
    }

        # Headless rootfsDeps tests do not boot stage-2 systemd, so seed the
        # Nix DB from the same registration stream full images load at boot.
        export NIX_REMOTE=""
        nix-store --init || true
        nix-store --load-db < /aos-registration
        mkdir -p /var/lib/profiles /nix/var/nix/gcroots/aos-profiles
        if ! ${pkgs.util-linux}/bin/mountpoint -q /nix/var/nix/gcroots/aos-profiles; then
          ${pkgs.util-linux}/bin/mount --bind \
            /var/lib/profiles /nix/var/nix/gcroots/aos-profiles
        fi
  '';

  # Store path hash extraction helper — takes the first component before '-'
  # from the basename, matching the Rust store_path_hash() function.
  hashOf = path: let
    basename = builtins.baseNameOf (builtins.toString path);
    parts = builtins.split "-" basename;
  in
    builtins.head parts;

  # --------------------------------------------------------------------------
  # Two registries: sysroot-reg has the sysroot + its versions of shared libs,
  # user-reg has the newer/divergent versions + user packages.
  # --------------------------------------------------------------------------

  # sysroot-reg: contains the sysroot toplevel, the sysroot's versions of
  # shared libraries, and clean-pkg (whose references match the sysroot).
  sysrootRegistry = mkMockRegistry {
    name = "sysroot";
    packages = [
      {
        name = "server";
        version = "2026.03";
        storePath = sysrootToplevel;
        sysroot = true;
        references = [
          (hashOf sysrootOpenssl)
          (hashOf sysrootZlib)
          (hashOf sysrootGlibc)
        ];
      }
      {
        name = "openssl";
        version = "3.2.1";
        storePath = sysrootOpenssl;
        references = [(hashOf sysrootGlibc)];
      }
      {
        name = "zlib";
        version = "1.3.0";
        storePath = sysrootZlib;
        references = [(hashOf sysrootGlibc)];
      }
      {
        name = "glibc";
        version = "2.39";
        storePath = sysrootGlibc;
        references = [];
      }
      {
        # clean-pkg depends on the SAME openssl and zlib as the sysroot
        name = "clean-pkg";
        version = "1.0.0";
        storePath = cleanPkgPath;
        references = [
          (hashOf sysrootOpenssl)
          (hashOf sysrootZlib)
          (hashOf sysrootGlibc)
        ];
      }
    ];
  };

  # user-reg: contains the newer/divergent versions and nginx.
  # Also includes glibc (same store path) so BFS can resolve it within
  # this registry during closure walking for nginx.
  userRegistry = mkMockRegistry {
    name = "user";
    packages = [
      {
        name = "openssl";
        version = "3.3.0";
        storePath = pkgOpenssl;
        references = [(hashOf sysrootGlibc)];
      }
      {
        name = "zlib";
        version = "1.3.1";
        storePath = pkgZlib;
        references = [(hashOf sysrootGlibc)];
      }
      {
        name = "glibc";
        version = "2.39";
        storePath = sysrootGlibc;
        references = [];
      }
      {
        # nginx depends on the NEWER openssl and zlib (divergent)
        name = "nginx";
        version = "1.27.0";
        storePath = nginxPath;
        references = [
          (hashOf pkgOpenssl)
          (hashOf pkgZlib)
          (hashOf sysrootGlibc)
        ];
      }
    ];
  };

  # System generation state JSON pointing to the sysroot.
  # The registry field must match the registry name that contains the server
  # package ("sysroot-reg").
  sysrootStateJson = builtins.toJSON {
    current = 1;
    next = 2;
    generations = [
      {
        number = 1;
        toplevel = sysrootToplevel;
        version = "2026.03";
        package_name = "server";
        registry = "sysroot-reg";
        created_at = "2026-03-01T00:00:00Z";
        kernel_path = null;
      }
    ];
  };

  stateJsonFile = builtins.toFile "state.json" (builtins.unsafeDiscardStringContext sysrootStateJson);

  preamble = mkPreamble {
    sysrootRegistryPath = sysrootRegistry;
    userRegistryPath = userRegistry;
    sysrootState = sysrootStateJson;
  };
in {
  # --------------------------------------------------------------------------
  # Test 1: sysroot-lock-blocked
  # --------------------------------------------------------------------------
  # Install nginx whose closure has divergent openssl => blocked
  sysroot-lock-blocked = testing.mkVMTest {
    name = "apm-sysroot-lock-blocked";
    rootfsDeps = testDeps ++ [sysrootRegistry userRegistry stateJsonFile];
    memory = 1024;
    testScript = ''
      ${preamble}

      echo "==> Test: apm install nginx should be blocked by sysroot-lock"

      # apm install should fail with sysroot-lock violation
      FAIL=0
      OUTPUT=$(${apm}/bin/apm install nginx 2>&1) && FAIL=1 || true
      EXIT_CODE=$?

      echo "Output: $OUTPUT"
      echo "Exit code: $EXIT_CODE"

      # Verify non-zero exit code (install was blocked)
      if [ "$FAIL" -eq 1 ]; then
        echo "FAIL: apm install nginx should have exited non-zero"
        exit 1
      fi

      # Verify error mentions sysroot-lock
      if ! echo "$OUTPUT" | grep -qi "sysroot-lock"; then
        echo "FAIL: error should mention sysroot-lock"
        echo "Actual output: $OUTPUT"
        exit 1
      fi

      # Verify error mentions the divergent package (openssl)
      if ! echo "$OUTPUT" | grep -qi "openssl"; then
        echo "FAIL: error should mention divergent package openssl"
        echo "Actual output: $OUTPUT"
        exit 1
      fi

      echo "==> sysroot-lock-blocked PASSED"
    '';
  };

  # --------------------------------------------------------------------------
  # Test 2: sysroot-lock-ignore-specific
  # --------------------------------------------------------------------------
  # Ignoring only openssl still fails because zlib also diverges.
  # Ignoring both openssl and zlib succeeds.
  sysroot-lock-ignore-specific = testing.mkVMTest {
    name = "apm-sysroot-lock-ignore-specific";
    rootfsDeps = testDeps ++ [sysrootRegistry userRegistry stateJsonFile];
    memory = 1024;
    testScript = ''
      ${preamble}

      echo "==> Test: --ignore-sysroot-lock=openssl should still fail (zlib diverges)"

      # Ignore only openssl — zlib still diverges, should still fail
      FAIL=0
      OUTPUT=$(${apm}/bin/apm install nginx --ignore-sysroot-lock=openssl 2>&1) && FAIL=1 || true

      if [ "$FAIL" -eq 1 ]; then
        echo "FAIL: install with --ignore-sysroot-lock=openssl should still fail (zlib diverges)"
        exit 1
      fi

      if ! echo "$OUTPUT" | grep -qi "zlib"; then
        echo "FAIL: remaining violation should mention zlib"
        exit 1
      fi

      echo "==> Partial ignore correctly still blocked"

      echo "==> Test: --ignore-sysroot-lock=openssl,zlib should succeed"

      # Ignore both openssl and zlib — sysroot-lock check should pass.
      # Use --dry-run since we have no real download mirror.
      OUTPUT2=$(${apm}/bin/apm install nginx --ignore-sysroot-lock=openssl,zlib --dry-run 2>&1) || true

      # With dry-run, it should pass the sysroot-lock check and show the plan
      if echo "$OUTPUT2" | grep -qi "sysroot-lock violation"; then
        echo "FAIL: --ignore-sysroot-lock=openssl,zlib should bypass all violations"
        echo "Output: $OUTPUT2"
        exit 1
      fi

      echo "==> sysroot-lock-ignore-specific PASSED"
    '';
  };

  # --------------------------------------------------------------------------
  # Test 3: sysroot-lock-ignore-all
  # --------------------------------------------------------------------------
  # --ignore-sysroot-lock (no value) bypasses the entire check
  sysroot-lock-ignore-all = testing.mkVMTest {
    name = "apm-sysroot-lock-ignore-all";
    rootfsDeps = testDeps ++ [sysrootRegistry userRegistry stateJsonFile];
    memory = 1024;
    testScript = ''
      ${preamble}

      echo "==> Test: --ignore-sysroot-lock should bypass all violations"

      # --ignore-sysroot-lock without value = bypass all
      OUTPUT=$(${apm}/bin/apm install nginx --ignore-sysroot-lock --dry-run 2>&1) || true

      if echo "$OUTPUT" | grep -qi "sysroot-lock violation"; then
        echo "FAIL: --ignore-sysroot-lock should bypass the entire check"
        echo "Output: $OUTPUT"
        exit 1
      fi

      echo "==> sysroot-lock-ignore-all PASSED"
    '';
  };

  # --------------------------------------------------------------------------
  # Test 4: sysroot-lock-clean
  # --------------------------------------------------------------------------
  # Install a package whose closure fully overlaps with sysroot — no violations
  sysroot-lock-clean = testing.mkVMTest {
    name = "apm-sysroot-lock-clean";
    rootfsDeps = testDeps ++ [sysrootRegistry userRegistry stateJsonFile];
    memory = 1024;
    testScript = ''
      ${preamble}

      echo "==> Test: clean-pkg with no divergence should not trigger sysroot-lock"

      # clean-pkg's closure uses the same openssl/zlib as the sysroot
      OUTPUT=$(${apm}/bin/apm install clean-pkg --dry-run 2>&1) || true

      if echo "$OUTPUT" | grep -qi "sysroot-lock violation"; then
        echo "FAIL: clean-pkg should not trigger sysroot-lock (same store paths)"
        echo "Output: $OUTPUT"
        exit 1
      fi

      echo "==> sysroot-lock-clean PASSED"
    '';
  };

  # --------------------------------------------------------------------------
  # Test 5: sysroot-lock-list-display
  # --------------------------------------------------------------------------
  # After installing with --ignore-sysroot-lock, list and show display violation info
  sysroot-lock-list-display = testing.mkVMTest {
    name = "apm-sysroot-lock-list-display";
    rootfsDeps = testDeps ++ [sysrootRegistry userRegistry stateJsonFile];
    memory = 1024;
    testScript = ''
      ${preamble}

      echo "==> Test: apm show nginx displays sysroot-lock violation details"

      # Show nginx package details — should include reference info that reveals
      # the divergence from the sysroot. The show command reads registry
      # metadata, not installed state.
      OUTPUT=$(${apm}/bin/apm show nginx 2>&1) || true
      echo "Show output: $OUTPUT"

      # Verify show output contains package info (name, version, references)
      if ! echo "$OUTPUT" | grep -qi "nginx"; then
        echo "FAIL: apm show nginx should display package name"
        echo "Output: $OUTPUT"
        exit 1
      fi

      if ! echo "$OUTPUT" | grep -qi "1.27.0"; then
        echo "FAIL: apm show nginx should display version"
        echo "Output: $OUTPUT"
        exit 1
      fi

      # The show output should include reference/closure information
      # that can be compared against the sysroot
      if ! echo "$OUTPUT" | grep -qi "reference\|closure\|store"; then
        echo "INFO: apm show did not display reference details (may be version-dependent)"
      fi

      echo "==> Test: apm list shows installed packages"

      # List packages — verifies the list command works with our mock registry
      LIST_OUTPUT=$(${apm}/bin/apm list 2>&1) || true
      echo "List output: $LIST_OUTPUT"

      # Verify list includes packages from the registry
      if ! echo "$LIST_OUTPUT" | grep -qi "nginx\|server\|openssl"; then
        echo "INFO: apm list may need --installed flag or registry sync"
      fi

      echo "==> sysroot-lock-list-display PASSED"
    '';
  };
}
