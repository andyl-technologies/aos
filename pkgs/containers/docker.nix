##! docker — Docker-compatible container engine and CLI
{
  mkDerivation,
  fetchurl,
  gnumake,
  go,
  bash,
  docker-engine,
  docker-buildx,
  docker-compose,
}: let
  version = "29.6.2";
in
  mkDerivation {
    pname = "docker";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/docker/cli/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-Ea7zSEw4050pGlSnOk2d0rs8AA2aP8OGK9A/6JlZTyw=";
    };

    buildDeps = [gnumake go];
    runtimeDeps = [bash docker-engine docker-buildx docker-compose];
    propagatedDeps = [];
    disallowedReferences = [go];

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
