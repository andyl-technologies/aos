##! Cilium — eBPF-based networking, security, and observability for Kubernetes
{
  mkDerivation,
  fetchurl,
  gnumake,
  go,
  llvm,
}: let
  version = "1.17.3";
in
  mkDerivation {
    pname = "cilium";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/cilium/cilium/archive/v${version}/cilium-${version}.tar.gz"
      ];
      hash = "sha256-jYxKIhURmUmLVeRz1wCzqakY42zA/pDHqzLLBZf71Zc=";
    };

    buildDeps = [
      gnumake
      go
      llvm
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cilium-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          mkdir -p "$GOPATH" "$GOCACHE"

          # Build BPF datapath programs
          export PATH="${llvm}/bin:$PATH"

          # Suppress clang 22 warning for uninitialized const pointer in SRv6 code
          # Append after -Wimplicit-fallthrough (last warning flag) so it comes after -Werror
          sed -i '/-Wimplicit-fallthrough/a CLANG_FLAGS += -Wno-uninitialized-const-pointer' bpf/Makefile.bpf

          make -C bpf SHELL="$CONFIG_SHELL" \
            CLANG="${llvm}/bin/clang" \
            LLC="${llvm}/bin/llc" \
            STRIP="${llvm}/bin/llvm-strip"

          mkdir -p _bin

          # Build cilium-agent
          go build -trimpath -mod=vendor \
            -ldflags "-s -w -X github.com/cilium/cilium/pkg/version.ciliumVersion=${version}" \
            -o _bin/cilium-agent ./daemon

          # Build cilium-dbg CLI
          go build -trimpath -mod=vendor \
            -ldflags "-s -w -X github.com/cilium/cilium/pkg/version.ciliumVersion=${version}" \
            -o _bin/cilium-dbg ./cilium-dbg
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/lib/bpf $out/share
          install -m 755 _bin/cilium-agent _bin/cilium-dbg $out/bin/

          # Install compiled BPF programs
          cp -r bpf/out/* $out/lib/bpf/ 2>/dev/null || true
          printf '%s\n' '${builtins.toJSON {inherit version;}}' > $out/share/cilium-package.json
        '';
      }
    ];

    configModule = {
      src = ./_cilium-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "cilium.enable"
        "cilium.kubeProxyReplacement"
        "cilium.operatorReplicas"
        "k3s.integrations.cni.cilium"
        "k3s.integrations.resources.cilium"
      ];
      ownsRoots = [
        {
          root = "cilium";
          interfaceAbi = 1;
        }
      ];
      contributes = [
        {
          root = "k3s";
          interfaceAbi = 2;
          paths = [
            "integrations.cni.cilium"
            "integrations.resources.cilium"
          ];
        }
      ];
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-cilium";
        tool = self;
        command = "cilium-dbg version";
      };
    };

    meta = {
      description = "Cilium — eBPF-based networking, security, and observability";
      homepage = "https://cilium.io";
      license = "Apache-2.0";
    };
  }
