##! Source-built programs used by K3s's embedded addon manifests.
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
  bash,
}: let
  # Match the addon versions in the pinned K3s release. These are source
  # archives and module caches; no upstream container layers enter the build.
  buildProgram = {
    pname,
    version,
    repository,
    sourceHash,
    moduleHash,
    command ? ".",
    versionFlags,
    patchScript ? "",
    additionalRuntimeDeps ? [],
  }: let
    src = fetchurl {
      name = "${pname}-${version}.tar.gz";
      urls = ["https://github.com/${repository}/archive/refs/tags/v${version}.tar.gz"];
      hash = sourceHash;
    };
    modules = fetchGoModules {
      inherit src;
      name = "k3s-${pname}-go-modules";
      hash = moduleHash;
    };
  in
    mkDerivation {
      inherit pname version src;
      buildDeps = [buildPackages.go];
      runtimeDeps = additionalRuntimeDeps;
      passthru.evidenceSources = [src modules];

      phases = [
        {
          name = "unpack";
          script = ''
            mkdir source
            tar xf "$src" --strip-components=1 -C source
            cd source
            ${patchScript}
          '';
        }
        {
          name = "build";
          script = ''
            export GOPATH="${modules}"
            export GOCACHE="$TMPDIR/go-cache"
            export GOPROXY=off
            export GOTOOLCHAIN=local
            export GOFLAGS=-mod=readonly
            export CGO_ENABLED=0
            export GOMAXPROCS="$NIX_BUILD_CORES"
            if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
              export GOOS="$AOS_GOOS"
              export GOARCH="$AOS_GOARCH"
            fi
            mkdir -p "$GOCACHE"

            go build -p "$NIX_BUILD_CORES" -trimpath \
              -ldflags "-s -w ${versionFlags}" \
              -o ${pname} ${command}
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/share/licenses/${pname}"
            install -m 0755 ${pname} "$out/bin/${pname}"
            cp LICENSE "$out/share/licenses/${pname}/"
          '';
        }
      ];

      meta = {
        description = "${pname} for the source-built K3s addon images";
        homepage = "https://github.com/${repository}";
        license = "Apache-2.0";
      };
    };
in {
  coredns = buildProgram {
    pname = "coredns";
    version = "1.14.1";
    repository = "coredns/coredns";
    sourceHash = "sha256-7IFOLeMEyqqr29wMF06PXhZoJ02MPaOH12y7m5H6rWY=";
    moduleHash = "sha256-PZH9CjgKYrM//iCGRCjJ8qP2G2Yw0/kFUzfug9ILfgo=";
    versionFlags = "-X github.com/coredns/coredns/coremain.GitCommit=v1.14.1";
  };

  metrics-server = buildProgram {
    pname = "metrics-server";
    version = "0.8.1";
    repository = "kubernetes-sigs/metrics-server";
    sourceHash = "sha256-fhj7PyAB7+pqaVjcEaVZfKzhEwK5qEDhgwnI6KRhvXE=";
    moduleHash = "sha256-uRBSDJh8FgcOCgHwNYKQ652hXqWW9lajqgzVNzy/ktA=";
    command = "./cmd/metrics-server";
    versionFlags = "-X k8s.io/client-go/pkg/version.gitVersion=v0.8.1 -X k8s.io/client-go/pkg/version.gitCommit=v0.8.1";
  };

  local-path-provisioner = buildProgram {
    pname = "local-path-provisioner";
    version = "0.0.34";
    repository = "rancher/local-path-provisioner";
    sourceHash = "sha256-eVmFXIvWP9It4YI9R9+gZH9xj+s+Z+AwFSmqHIGZ2n0=";
    moduleHash = "sha256-Wr8NKrpAy30ly1Dv/bPs91IaX4Oo179QLzwer44Sy5U=";
    versionFlags = "-X main.VERSION=v0.0.34";
    additionalRuntimeDeps = [bash];
    patchScript = ''
      # Helper pods carry the AOS shell at its immutable store path.
      sed -i 's|"/bin/sh"|"${bash}/bin/bash"|g' provisioner.go
    '';
  };
}
