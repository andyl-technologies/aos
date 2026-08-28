# Production-image sysroot-lock acceptance.
#
# A real image-backed AOS machine publishes its authenticated running
# toplevel and two ordinary package graphs from host-built store paths mounted
# read-only through 9p. The consumer then exercises blocking, selective and
# complete overrides, a compatible graph, and installed-package reporting.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  mkFixture = {
    pname,
    version,
    message,
    runtimeDeps ? [],
  }:
    pkgs.mkDerivation {
      inherit pname version runtimeDeps;
      src = null;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            cat > "$out/bin/${pname}" <<'EOF'
            #!${pkgs.bash}/bin/bash
            ${lib.concatMapStringsSep "\n" (dependency: "test -e ${dependency}") runtimeDeps}
            printf '%s\n' '${message}'
            EOF
            chmod +x "$out/bin/${pname}"
          '';
        }
      ];
    };

  sslV1 = mkFixture {
    pname = "lock-ssl";
    version = "1.0.0";
    message = "lock ssl 1";
  };
  compressionV1 = mkFixture {
    pname = "lock-compression";
    version = "1.0.0";
    message = "lock compression 1";
  };
  sslV2 = mkFixture {
    pname = "lock-ssl";
    version = "2.0.0";
    message = "lock ssl 2";
  };
  compressionV2 = mkFixture {
    pname = "lock-compression";
    version = "2.0.0";
    message = "lock compression 2";
  };
  divergentApp = mkFixture {
    pname = "lock-app";
    version = "2.0.0";
    message = "divergent lock app";
    runtimeDeps = [sslV2 compressionV2];
  };
  compatibleApp = mkFixture {
    pname = "lock-compatible";
    version = "1.0.0";
    message = "compatible lock app";
    runtimeDeps = [sslV1 compressionV1];
  };

  targetSystem = mkSystem [
    ../../systems/server-verity.nix
    {
      aos.kernel.modules = ["9pnet_virtio" "9p"];
      environment.systemPackages = [
        sslV1
        compressionV1
      ];
    }
  ];
  fixtureClosureInfo = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    rootPaths = [
      pkgs.aos
      pkgs.git
      pkgs.jq
      pkgs.nix
      sslV1
      compressionV1
      sslV2
      compressionV2
      divergentApp
      compatibleApp
    ];
    pname = "apm-sysroot-lock-fixture-closure-info";
  };
in {
  name = "apm-sysroot-lock";
  timeout = 1800;

  machines.target = {
    system = targetSystem;
    bootMode = "image";
    hostStoreMount = true;
    imageDiskMiB = 12288;
    varProvisioning = "repart";
    tpm = true;
  };

  testScript =
    # python
    ''
      import shlex
      import textwrap

      APM = "${pkgs.aos}/bin/apm"
      APR = "${pkgs.aos}/bin/apr"
      GIT = "${pkgs.git}/bin/git"
      JQ = "${pkgs.jq}/bin/jq"
      MOUNT = "${pkgs.util-linux}/bin/mount"
      NIX_STORE = "${pkgs.nix}/bin/nix-store"
      CLOSURE_INFO = "${fixtureClosureInfo}"
      SSL_V1 = "${sslV1}"
      COMPRESSION_V1 = "${compressionV1}"
      SSL_V2 = "${sslV2}"
      COMPRESSION_V2 = "${compressionV2}"
      DIVERGENT_APP = "${divergentApp}"
      COMPATIBLE_APP = "${compatibleApp}"


      target.wait_for_unit("multi-user.target", timeout=300)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service",
          timeout=420,
      )

      # Expose only this host-built fixture closure at canonical store paths.
      # The image itself stays immutable and no package is rebuilt in-guest.
      target.succeed(textwrap.dedent(f"""
          set -eu
          mkdir -p /run/aos-host-store
          {MOUNT} -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,ro \
            aos-host-store /run/aos-host-store
          closure=/run/aos-host-store/$(basename {CLOSURE_INFO})
          test -r "$closure/registration"
          while IFS= read -r store_path; do
            if test ! -e "$store_path"; then
              source_path="/run/aos-host-store/$(basename "$store_path")"
              if test -L "$source_path"; then
                ln -s "$(readlink "$source_path")" "$store_path"
              elif test -d "$source_path"; then
                mkdir "$store_path"
                {MOUNT} --bind "$source_path" "$store_path"
              elif test -f "$source_path"; then
                touch "$store_path"
                {MOUNT} --bind "$source_path" "$store_path"
              else
                echo "unsupported fixture store object: $source_path" >&2
                exit 1
              fi
            fi
          done < "$closure/store-paths"
          {NIX_STORE} --load-db < "$closure/registration"
          {NIX_STORE} --check-validity {DIVERGENT_APP}
          {NIX_STORE} --check-validity {COMPATIBLE_APP}
      """), timeout=180)

      # An organization publishes the running sysroot graph separately from
      # the application graph, preserving both versions of shared packages.
      target.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/apm-lock-author USER=publisher
          export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
          export NIX_REMOTE=""
          mkdir -p "$HOME"
          {GIT} config --global user.name 'Platform Publisher'
          {GIT} config --global user.email platform@example.test
          image_state=/var/lib/profiles/image/state.json
          running_top=$(readlink -f /aos-toplevel)
          package=$({JQ} -er \
            '. as $state | .generations[] | select(.number == $state.running) | .package_name' \
            "$image_state")
          version=$({JQ} -er '. as $state | .generations[] | select(.number == $state.running) | .version' "$image_state")

          {APR} create lock-system
          {APR} publish "$running_top" --registry lock-system \
            --name "$package" --version "$version" --sysroot \
            --description 'Authenticated running AOS image' --license MIT \
            --maintainer platform@example.test --no-commit
          {APR} publish {SSL_V1} --registry lock-system \
            --name lock-ssl --version 1.0.0 --description 'System SSL fixture' \
            --license MIT --maintainer platform@example.test --no-commit
          {APR} publish {COMPRESSION_V1} --registry lock-system \
            --name lock-compression --version 1.0.0 \
            --description 'System compression fixture' --license MIT \
            --maintainer platform@example.test --no-commit
          {GIT} -C "$HOME/.local/share/apm/registries/lock-system" add -A
          {GIT} -C "$HOME/.local/share/apm/registries/lock-system" \
            -c user.name=publisher -c user.email=publisher@example.test \
            commit -m 'publish authenticated system graph'

          {APR} create lock-apps
          {APR} publish {SSL_V2} --registry lock-apps \
            --name lock-ssl --version 2.0.0 --description 'Application SSL fixture' \
            --license MIT --maintainer applications@example.test --no-commit
          {APR} publish {COMPRESSION_V2} --registry lock-apps \
            --name lock-compression --version 2.0.0 \
            --description 'Application compression fixture' --license MIT \
            --maintainer applications@example.test --no-commit
          {APR} publish {DIVERGENT_APP} --registry lock-apps \
            --name lock-app --version 2.0.0 --description 'Divergent application' \
            --license MIT --maintainer applications@example.test --no-commit
          {APR} publish {COMPATIBLE_APP} --registry lock-apps \
            --name lock-compatible --version 1.0.0 \
            --description 'Compatible application' --license MIT \
            --maintainer applications@example.test --no-commit
          {GIT} -C "$HOME/.local/share/apm/registries/lock-apps" add -A
          {GIT} -C "$HOME/.local/share/apm/registries/lock-apps" \
            -c user.name=publisher -c user.email=publisher@example.test \
            commit -m 'publish application graphs'
      """), timeout=300)

      target.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/var/lib/apm-lock-consumer USER=operator
          mkdir -p "$HOME"
          {APM} registry add --no-verify \
            file:///var/lib/apm-lock-author/.local/share/apm/registries/lock-system \
            --name lock-system
          {APM} registry add --no-verify \
            file:///var/lib/apm-lock-author/.local/share/apm/registries/lock-apps \
            --name lock-apps
      """), timeout=120)

      def apm(command):
          return (
              "HOME=/var/lib/apm-lock-consumer USER=operator "
              + APM
              + " "
              + command
          )

      blocked = target.fail(apm("install lock-app --dry-run --yes 2>&1"))
      assert "sysroot-lock violation" in blocked, blocked
      assert "lock-ssl" in blocked and "lock-compression" in blocked, blocked

      partial = target.fail(
          apm(
              "install lock-app --dry-run --yes "
              "--ignore-sysroot-lock=lock-ssl 2>&1"
          )
      )
      assert "lock-compression" in partial, partial

      target.succeed(
          apm(
              "install lock-app --dry-run --yes "
              "--ignore-sysroot-lock=lock-ssl,lock-compression"
          )
      )
      target.succeed(
          apm("install lock-app --dry-run --yes --ignore-sysroot-lock")
      )
      target.succeed(apm("install lock-compatible --dry-run --yes"))

      # Install through the explicit exception and prove query porcelain still
      # reports the divergence from the authenticated running image.
      target.succeed(
          apm(
              "install lock-app --yes "
              "--ignore-sysroot-lock=lock-ssl,lock-compression"
          ),
          timeout=180,
      )
      shown = target.succeed(apm("show lock-app 2>&1"))
      assert "Sysroot-lock violations" in shown, shown
      assert "lock-ssl" in shown and "lock-compression" in shown, shown
      listed = target.succeed(apm("list 2>&1"))
      assert "lock-app/lock-apps 2.0.0" in listed, listed
      assert "sysroot-locked" in listed, listed
      target.succeed(apm("remove lock-app --yes"))

      target.succeed("test -L /aos-toplevel")
      target.succeed("test -s /var/lib/profiles/image/state.json")
    '';
}
