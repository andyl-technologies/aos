##! Cilium — eBPF-based networking, security, and observability for Kubernetes
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
}: let
  version = "1.17.3";
in
  mkDerivation {
    pname = "cilium";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The client returns success and identifies Cilium.";
        "files" = {};
        "input" = "The packaged Cilium debugging client's version command.";
        "operation" = "Print local version information without contacting an agent.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/cilium-dbg\", \"version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"cilium\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"cilium operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cilium operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The client rejects the unsupported operation.";
        "files" = {};
        "input" = "A cilium-dbg invocation naming an unknown operation.";
        "operation" = "Parse the unsupported operation without contacting an agent.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/cilium-dbg\", \"aos-invalid-operation\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"cilium rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cilium rejected invalid input\n";
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
      urls = [
        "https://github.com/cilium/cilium/archive/v${version}/cilium-${version}.tar.gz"
      ];
      hash = "sha256-jYxKIhURmUmLVeRz1wCzqakY42zA/pDHqzLLBZf71Zc=";
    };

    buildDeps = [
      gnumake
      buildPackages.go
      buildPackages.llvm
    ];
    runtimeDeps = [];

    # One module owns Cilium's configuration and provider-neutral ability
    # requirements. Its typed requests are the desired-state source.
    abilities = ./_cilium-abilities;

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
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOPATH" "$GOCACHE"

          # Build BPF datapath programs
          export PATH="${buildPackages.llvm}/bin:$PATH"

          # Suppress clang 22 warning for uninitialized const pointer in SRv6 code
          # Append after -Wimplicit-fallthrough (last warning flag) so it comes after -Werror
          sed -i '/-Wimplicit-fallthrough/a CLANG_FLAGS += -Wno-uninitialized-const-pointer' bpf/Makefile.bpf

          make -C bpf SHELL="$CONFIG_SHELL" \
            CLANG="${buildPackages.llvm}/bin/clang" \
            LLC="${buildPackages.llvm}/bin/llc" \
            STRIP="${buildPackages.llvm}/bin/llvm-strip"

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
          mkdir -p $out/bin $out/lib/bpf
          install -m 755 _bin/cilium-agent _bin/cilium-dbg $out/bin/

          # Install compiled BPF programs
          cp -r bpf/out/* $out/lib/bpf/ 2>/dev/null || true
        '';
      }
    ];

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
