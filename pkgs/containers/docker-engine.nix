##! docker-engine — Docker container daemon
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
  bash,
  pkg-config,
  btrfs-progs,
  containerd,
  e2fsprogs,
  fuse-overlayfs,
  git-minimal,
  iproute2,
  iptables,
  libseccomp,
  lvm2,
  nftables,
  procps-ng,
  rootlesskit,
  runc,
  slirp4netns,
  sqlite,
  systemd,
  tini,
  util-linux,
  xfsprogs,
  xz,
}: let
  # 29.7 requires Go 1.26.3. This is the newest daemon release compatible
  # with the self-hosted Go 1.26.0 toolchain.
  version = "29.6.2";
  runtimePath = builtins.concatStringsSep ":" (map (package: "${package}/bin:${package}/sbin") [
    e2fsprogs
    fuse-overlayfs
    git-minimal
    iproute2
    iptables
    nftables
    procps-ng
    rootlesskit
    slirp4netns
    util-linux
    xfsprogs
    xz
  ]);
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "docker-engine";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Dockerd accepts the complete JSON configuration and exits after validation.";
        "files" = {
          "daemon.json" = "{\n  \"data-root\": \"/var/lib/aos-qualification-docker\",\n  \"exec-root\": \"/run/aos-qualification-docker\",\n  \"debug\": false\n}\n";
        };
        "input" = "A daemon configuration selecting fixed local state directories.";
        "operation" = "Validate the configuration without starting the daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/dockerd\", \"--validate\", \"--config-file\", \"daemon.json\"], capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert \"configuration OK\" in result.stdout\nprint(\"docker-engine operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "docker-engine operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Dockerd rejects the unknown directive.";
        "files" = {
          "daemon.json" = "{\"aos-unknown-setting\": true}\n";
        };
        "input" = "A daemon configuration containing an unknown directive.";
        "operation" = "Validate the malformed configuration without starting the daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/dockerd\", \"--validate\", \"--config-file\", \"daemon.json\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"docker-engine rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "docker-engine rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://github.com/moby/moby/archive/refs/tags/docker-v${version}.tar.gz"];
      hash = "sha256-i2Svt1YjR9LOnxAn4ybOmkXI9BpIYQbOIDT36xq+Dg8=";
    };

    buildDeps = [gnumake buildPackages.go bash pkg-config];
    runtimeDeps = [
      bash
      btrfs-progs
      containerd
      e2fsprogs
      fuse-overlayfs
      git-minimal
      iproute2
      iptables
      libseccomp
      lvm2
      nftables
      procps-ng
      rootlesskit
      runc
      slirp4netns
      sqlite
      systemd
      tini
      util-linux
      xfsprogs
      xz
    ];
    propagatedDeps = [];
    disallowedReferences = [buildPackages.go];

    abilities = ./_docker-engine;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd moby-docker-v${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # Source-tree scripts run on the build platform. The installed
          # rootless entry point receives its target shell during installation.
          find hack contrib -type f -exec sed -i \
            -e "1s|^#!/usr/bin/env bash|#!$CONFIG_SHELL|" \
            -e "1s|^#!/bin/bash|#!$CONFIG_SHELL|" \
            -e "1s|^#!/usr/bin/env sh|#!$CONFIG_SHELL|" \
            -e "1s|^#!/bin/sh|#!$CONFIG_SHELL|" {} +
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH="$TMPDIR/go"
          export GOCACHE="$TMPDIR/go-cache"
          export GOFLAGS="-trimpath -mod=vendor"
          export GOPROXY=off
          export CGO_ENABLED=1
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          export AUTO_GOPATH=1
          export VERSION="${version}"
          export DOCKER_GITCOMMIT="v${version}"
          export DOCKER_BUILDTAGS="journald seccomp"
          mkdir -p "$GOPATH" "$GOCACHE"
          ./hack/make.sh dynbinary
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/libexec/docker"
          install -m 755 bundles/dynbinary-daemon/dockerd "$out/libexec/docker/dockerd"
          install -m 755 bundles/dynbinary-daemon/docker-proxy "$out/libexec/docker/docker-proxy"

          ln -s ${containerd}/bin/containerd "$out/libexec/docker/containerd"
          ln -s ${containerd}/bin/containerd-shim-runc-v2 "$out/libexec/docker/containerd-shim-runc-v2"
          ln -s ${runc}/sbin/runc "$out/libexec/docker/runc"
          ln -s ${tini}/bin/tini-static "$out/libexec/docker/docker-init"

          cat > "$out/bin/dockerd" <<'EOF_WRAPPER'
          #!${bash}/bin/bash
          export PATH="@out@/libexec/docker:${runtimePath}''${PATH:+:$PATH}"
          exec "@out@/libexec/docker/dockerd" "$@"
          EOF_WRAPPER
          sed -i "s|@out@|$out|g" "$out/bin/dockerd"
          chmod 755 "$out/bin/dockerd"

          install -m 755 contrib/dockerd-rootless.sh "$out/libexec/docker/dockerd-rootless.sh"
          sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/libexec/docker/dockerd-rootless.sh"
          cat > "$out/bin/dockerd-rootless" <<'EOF_WRAPPER'
          #!${bash}/bin/bash
          export PATH="@out@/libexec/docker:${runtimePath}''${PATH:+:$PATH}"
          exec "@out@/libexec/docker/dockerd-rootless.sh" "$@"
          EOF_WRAPPER
          sed -i "s|@out@|$out|g" "$out/bin/dockerd-rootless"
          chmod 755 "$out/bin/dockerd-rootless"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-docker-engine";
        tool = self;
        command = "dockerd --version && ${self}/libexec/docker/docker-proxy --version";
      };
    };

    meta = {
      description = "Docker container daemon with rootless and storage drivers";
      homepage = "https://mobyproject.org/";
      license = "Apache-2.0";
      mainProgram = "dockerd";
    };
  }
