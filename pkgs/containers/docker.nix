##! docker — Docker-compatible container engine and CLI
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
  bash,
  docker-engine,
  docker-buildx,
  docker-compose,
}: let
  version = "29.6.2";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "docker";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The Docker client returns success and reports its version.";
        "files" = {};
        "input" = "The packaged Docker client's release identity.";
        "operation" = "Request its version without contacting a daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/docker\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"Docker version\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"docker operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "docker operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The Docker client rejects the unsupported option.";
        "files" = {};
        "input" = "A Docker invocation containing an unknown global option.";
        "operation" = "Parse the invalid option before contacting a daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/docker\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"docker rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "docker rejected invalid input\n";
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
      urls = ["https://github.com/docker/cli/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-Ea7zSEw4050pGlSnOk2d0rs8AA2aP8OGK9A/6JlZTyw=";
    };

    buildDeps = [gnumake buildPackages.go];
    runtimeDeps = [bash docker-engine docker-buildx docker-compose];
    propagatedDeps = [];
    disallowedReferences = [buildPackages.go];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cli-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${./docker-cli-plugin-dirs.patch}

          find scripts -type f -exec sed -i \
            -e "1s|^#!/usr/bin/env bash|#!${bash}/bin/bash|" \
            -e "1s|^#!/bin/bash|#!${bash}/bin/bash|" \
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
          export DISABLE_WARN_OUTSIDE_CONTAINER=1
          export GITCOMMIT="v${version}"
          export VERSION="${version}"
          export BUILDTIME="1970-01-01T00:00:00Z"
          mkdir -p "$GOPATH/src/github.com/docker" "$GOCACHE"
          ln -s "$PWD" "$GOPATH/src/github.com/docker/cli"
          make dynbinary
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/libexec/docker"
          install -m 755 build/docker "$out/libexec/docker/docker"

          cat > "$out/bin/docker" <<'EOF_WRAPPER'
          #!${bash}/bin/bash
          export DOCKER_CLI_PLUGIN_DIRS="${docker-buildx}/libexec/docker/cli-plugins:${docker-compose}/libexec/docker/cli-plugins''${DOCKER_CLI_PLUGIN_DIRS:+:$DOCKER_CLI_PLUGIN_DIRS}"
          exec "@out@/libexec/docker/docker" "$@"
          EOF_WRAPPER
          sed -i "s|@out@|$out|g" "$out/bin/docker"
          chmod 755 "$out/bin/docker"
          ln -s ${docker-engine}/bin/dockerd "$out/bin/dockerd"
          ln -s ${docker-engine}/bin/dockerd-rootless "$out/bin/dockerd-rootless"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-docker";
        tool = self;
        command = "docker --version && docker buildx version && docker compose version";
      };
    };

    meta = {
      description = "Docker-compatible container command-line interface";
      homepage = "https://www.docker.com/";
      license = "Apache-2.0";
      mainProgram = "docker";
    };
  }
