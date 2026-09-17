##! k3s — Lightweight Kubernetes distribution
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
  gnumake,
  callPackage,
  lib,
  bash,
}: let
  version = "1.35.1-k3s1";
  srcVersion = "1.35.1+k3s1";
  src = fetchurl {
    urls = [
      "https://github.com/k3s-io/k3s/archive/v${srcVersion}/k3s-${version}.tar.gz"
    ];
    hash = "sha256-DopUJRV2vMGG174kAH0BSF/tXZD15X14YXSvLrTYCNc=";
  };

  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-IgBM6UOEzIAssm2/LPKfWFpgkzN5nC3/lvDH42PsZrQ=";
  };
  addons = callPackage ./_k3s-addon-images.nix {};
  addonInputs = builtins.toJSON (builtins.mapAttrs (_: addon: {
      inherit (addon) reference;
      manifest = "${addon.image}/manifest.json";
    })
    addons);
  charts = {
    traefik = fetchurl {
      name = "traefik-38.0.201-up38.0.2.tgz";
      urls = ["https://k3s.io/k3s-charts/assets/traefik/traefik-38.0.201+up38.0.2.tgz"];
      hash = "sha256-W+Iqxncnjdh+YtabLbdjf95XYRS2CdOdJJbr15CXf5o=";
    };
    traefik-crd = fetchurl {
      name = "traefik-crd-38.0.201-up38.0.2.tgz";
      urls = ["https://k3s.io/k3s-charts/assets/traefik-crd/traefik-crd-38.0.201+up38.0.2.tgz"];
      hash = "sha256-jVntDHAx6CTVvaeI86zS0pqweFsK4Jg6sNymgmZts7s=";
    };
  };
in
  mkDerivation {
    pname = "k3s";
    inherit version;
    inherit src;

    buildDeps = [
      gnumake
      buildPackages.go
      buildPackages.python3
    ];
    runtimeDeps = [];
    passthru.evidenceSources =
      [src goModules ./_k3s-bundle.py]
      ++ builtins.attrValues charts
      ++ lib.concatMap (addon: addon.evidenceSources) (builtins.attrValues addons);

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd k3s-*

          # Drop the vendored containerd's btrfs snapshot plugin
          # import. cmd/server pulls in `pkg/containerd` (under
          # the `ctrd` tag), and `pkg/containerd/builtins_linux.go`
          # blank-imports
          # `github.com/containerd/containerd/v2/plugins/snapshots/btrfs/plugin`.
          # Every file in that vendored package carries
          # `//go:build linux && !no_btrfs && cgo`, so with our
          # `no_btrfs` tag the package is empty and the import
          # fails with "build constraints exclude all Go files".
          # AOS doesn't expose btrfs as a snapshotter — the rootfs
          # is ext4 and containerd uses the overlay snapshotter —
          # so dropping the import is the right semantic.
          # Alternative would be to drop `no_btrfs` and link
          # against `btrfs-progs`, but AOS doesn't ship that
          # package and the dep chain (lzo, zstd, libgcrypt, …)
          # is disproportionate to the runtime use case (none).
          sed -i \
            '/snapshots\/btrfs\/plugin/d' \
            pkg/containerd/builtins_linux.go

          # Bind the defaults before embedding them. Missing addon images leave
          # the aggregated metrics API unavailable and block namespace cleanup.
          printf '%s\n' ${lib.escapeShellArg addonInputs} > "$TMPDIR/addon-inputs.json"
          python3 ${./_k3s-bundle.py} "$PWD" "$TMPDIR/addon-inputs.json" ${bash}/bin/bash
          cp -av manifests/* pkg/deploy/embed/
          mkdir -p pkg/static/embed/charts
          cp ${charts.traefik} pkg/static/embed/charts/traefik-38.0.201+up38.0.2.tgz
          cp ${charts.traefik-crd} pkg/static/embed/charts/traefik-crd-38.0.201+up38.0.2.tgz
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH="${goModules}"
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=1
          # Kine queries SQLite's dbstat virtual table for datastore status.
          # Match the feature flags in K3s's source build script.
          export CGO_CFLAGS="''${CGO_CFLAGS:--O2 -g} -DSQLITE_ENABLE_DBSTAT_VTAB=1 -DSQLITE_USE_ALLOCA=1"
          export GOPROXY=off
          export GOFLAGS="-mod=readonly"
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOCACHE"

          # Build from cmd/server, NOT from the repo root. The root
          # main.go (cmd/k3s/main.go) is a thin multi-call shim that
          # `os.Exit`s into a tarball it expects to find embedded at
          # `pkg/data/embed/k3s-data-*.tar.zst`. The upstream build
          # pipeline writes that tarball before `go build`; we don't
          # run that pipeline (we'd have to repackage runc, the
          # containerd shim, and CNI plugins into a tarball just so
          # k3s could un-tar them at runtime). cmd/server wires the
          # subcommands directly to `server.Run` / `agent.Run` etc.
          # via reexec dispatch — no extraction, no `pkg/data` import.
          # Behaviourally this matches what `k3s server` /
          # `k3s agent` do once their thin shim has finished
          # extracting and re-execing into the bundled `k3s-server` /
          # `k3s-agent` binaries — we cut out the no-op detour.
          #
          # Tag notes:
          #   - `ctrd`: load-bearing; gates the real
          #     `pkg/containerd.Main()` registered as a reexec at
          #     cmd/server/main.go:32. Without it, k3s wouldn't
          #     embed containerd.
          #   - `no_btrfs`: NOT a no-op in this tree (despite what a
          #     `grep no_btrfs` in the k3s repo might suggest). The
          #     tag is consumed by the vendored
          #     `k3s-io/containerd/v2/plugins/snapshots/btrfs/...`
          #     module, which keys its `//go:build` lines on it.
          #     We pair the tag with the unpack-phase sed above
          #     that drops the plugin's blank-import from k3s's
          #     `pkg/containerd/builtins_linux.go`; without that,
          #     the empty package would make Go fail with "build
          #     constraints exclude all Go files".
          # `UpstreamGolang` is consulted at startup by
          # `pkg/cli/cmds.ValidateGolang` (called from
          # `MustValidateGolang` on every k3s subcommand). If unset,
          # k3s exits with "kubernetes golang build version not set
          # - see 'golang: upstream version' in
          # https://github.com/kubernetes/kubernetes/blob/<v>/build/dependencies.yaml".
          # Upstream's build script fetches the value from
          # `kubernetes/kubernetes@<VERSION_K8S>/.go-version`; we
          # can't curl during a sandboxed Nix build. Instead we set
          # it to the actual Go version used to compile here (which
          # is also `runtime.Version()` at run time), so the
          # validation `UpstreamGolang == runtime.Version()`
          # tautologically passes. This loses the upstream-sanity
          # check against the Kubernetes-recommended Go but is the
          # right trade for a hermetic build that pins go via the
          # AOS package set instead of upstream's preference.
          GO_VERSION="$(go version | awk '{print $3}')"
          helm_job_reference="$(cat aos-helm-job-reference)"
          service_lb_reference="$(cat aos-service-lb-reference)"
          go build -trimpath \
            -tags "ctrd,no_btrfs" \
            -ldflags "-s -w \
              -X github.com/k3s-io/k3s/pkg/version.Version=v${srcVersion} \
              -X github.com/k3s-io/k3s/pkg/version.GitCommit=v${srcVersion} \
              -X github.com/k3s-io/k3s/pkg/version.UpstreamGolang=$GO_VERSION \
              -X github.com/k3s-io/helm-controller/pkg/controllers/chart.DefaultJobImage=$helm_job_reference \
              -X github.com/k3s-io/k3s/pkg/cloudprovider.DefaultLBImage=$service_lb_reference" \
            -o k3s ./cmd/server
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 k3s $out/bin/

          # Symlinks for the multi-call binary's `reexec.Register`
          # entries (cmd/server/main.go:32-37). When invoked via
          # `argv[0]==kubectl`, the first thing main() does is
          # `reexec.Init()` which dispatches to the registered
          # function and returns true; the subcommand path never
          # runs. `containerd` lands here too — k3s embeds it.
          for cmd in kubectl crictl ctr; do
            ln -s k3s "$out/bin/$cmd"
          done

          # Retain the image bytes in the published runtime closure. The role
          # launchers import these archives before kubelet starts scheduling.
          mkdir -p "$out/share/k3s/images"
          cp aos-addon-images.json "$out/share/k3s/"
          ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: addon: ''
              ln -s ${addon.image}/image.oci.tar "$out/share/k3s/images/${name}.tar"
              ln -s ${addon.image}/manifest.json "$out/share/k3s/images/${name}.manifest.json"
            '')
            addons)}
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-k3s";
        tool = self;
        command = "k3s --version";
      };
    };

    meta = {
      description = "k3s — lightweight Kubernetes distribution";
      homepage = "https://k3s.io";
      license = "Apache-2.0";
    };
  }
