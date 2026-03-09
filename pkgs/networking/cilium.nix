##! Cilium — eBPF-based networking, security, and observability for Kubernetes
{
  mkDerivation,
  fetchurl,
  gnumake,
  go,
  llvm,
}:
let
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
  runtimeDeps = [ ];

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
        make -C bpf SHELL="$CONFIG_SHELL" \
          CLANG="${llvm}/bin/clang" \
          LLC="${llvm}/bin/llc" \
          STRIP="${llvm}/bin/llvm-strip"

        # Build cilium-agent
        go build -trimpath \
          -ldflags "-s -w -X github.com/cilium/cilium/pkg/version.ciliumVersion=${version}" \
          -o cilium-agent ./daemon/cmd

        # Build cilium CLI
        go build -trimpath \
          -ldflags "-s -w -X github.com/cilium/cilium/pkg/version.ciliumVersion=${version}" \
          -o cilium ./cilium
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin $out/lib/bpf
        install -m 755 cilium-agent cilium $out/bin/

        # Install compiled BPF programs
        cp -r bpf/out/* $out/lib/bpf/ 2>/dev/null || true
      '';
    }
  ];

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-cilium";
        tool = self;
        command = "cilium version --client";
      };
    };

  meta = {
    description = "Cilium — eBPF-based networking, security, and observability";
    homepage = "https://cilium.io";
    license = "Apache-2.0";
  };
}
