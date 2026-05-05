##! k3s — Lightweight Kubernetes distribution
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  gnumake,
  go,
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
in
  mkDerivation {
    pname = "k3s";
    inherit version;
    inherit src;

    buildDeps = [
      gnumake
      go
    ];
    runtimeDeps = [];

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

          # Stage k3s's bootstrap manifests into pkg/deploy/embed/
          # so they get baked into the binary via the `//go:embed embed/*`
          # directive in pkg/deploy/stage.go. Upstream's package-cli
          # script does this just before `go build`; AOS hits the same
          # need. The contents include rolebindings.yaml, which creates
          # the ClusterRole + ClusterRoleBinding for `system:k3s-controller`.
          # Without it, the agent-side flannel daemon's call into
          # `pkg/agent/flannel.Run` (setup.go:105) hits
          # `WaitForRBACReady` and polls for 15 minutes (the
          # `DefaultAPIServerReadyTimeout`) before giving up, because
          # the kubelet's NodeAuthorizer denies `list nodes` and the
          # k3s-controller fallback credential has no permissions
          # either. The other manifests (coredns, traefik, ccm,
          # local-storage, metrics-server, runtimes) are best-effort
          # addons; their charts come from a separate static/embed/
          # path that AOS doesn't populate today, so the deploy
          # controller will fail to render them at apply time but
          # that doesn't block the RBAC manifest.
          cp -av manifests/* pkg/deploy/embed/
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH="${goModules}"
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=1
          export GOPROXY=off
          export GOFLAGS="-mod=readonly"
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
          go build -trimpath \
            -tags "ctrd,no_btrfs" \
            -ldflags "-s -w \
              -X github.com/k3s-io/k3s/pkg/version.Version=v${srcVersion} \
              -X github.com/k3s-io/k3s/pkg/version.GitCommit=v${srcVersion} \
              -X github.com/k3s-io/k3s/pkg/version.UpstreamGolang=$GO_VERSION" \
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
