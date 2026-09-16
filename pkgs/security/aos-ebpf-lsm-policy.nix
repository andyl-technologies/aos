##! aos-ebpf-lsm-policy — Load fleet-managed BPF-LSM policy artifacts
{
  lib,
  mkDerivation,
  stdenv,
  linux-headers,
  llvm,
  pkg-config,
  libbpf,
  json-c,
  buildPackages,
}: let
  targetArchBySystem = {
    "x86_64-linux" = "x86";
    "aarch64-linux" = "arm64";
  };
  targetArch =
    targetArchBySystem.${stdenv.system}
    or (throw "aos-ebpf-lsm-policy: unsupported system '${stdenv.system}'");
  bpfSource = ./aos-ebpf-lsm-policy.bpf.c;
  loaderSource = ./aos-ebpf-lsm-policy.c;
in
  mkDerivation {
    pname = "aos-ebpf-lsm-policy";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The loader accepts the packaged JSON schema and BPF object metadata.";
        "files" = {};
        "input" = "The packaged task-audit policy and matching BPF object.";
        "operation" = "Validate the policy-object pair without loading it into the kernel.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/aos-ebpf-lsm-policy\", \"validate\", \"--policy\", \"@out@/share/aos/ebpf-lsm/aos-task-audit.json\", \"--object\", \"@out@/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o\"], capture_output=True)\nassert result.returncode == 0, result.stderr\nprint(\"aos-ebpf-lsm-policy operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-ebpf-lsm-policy operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The loader rejects the malformed JSON before kernel attachment.";
        "files" = {
          "policy.json" = "{\"version\":\n";
        };
        "input" = "A truncated JSON policy paired with the packaged BPF object.";
        "operation" = "Validate the malformed policy.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos-ebpf-lsm-policy\", \"validate\", \"--policy\", \"policy.json\", \"--object\", \"@out@/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos-ebpf-lsm-policy rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-ebpf-lsm-policy rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "0";
    src = null;

    buildDeps = [
      linux-headers
      llvm
      pkg-config
    ];
    runtimeDeps = [
      libbpf
      json-c
    ];
    propagatedDeps = [];
    disallowedReferences = [bpfSource loaderSource];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/bin $out/lib/bpf $out/share/aos/ebpf-lsm
          cp ${bpfSource} aos-ebpf-lsm-policy.bpf.c

          ${buildPackages.llvm}/bin/clang -target bpf -O2 -g \
            -D__TARGET_ARCH_${targetArch} \
            -I${linux-headers}/include \
            -I${libbpf}/include \
            -Wall -Wextra -Werror -Wno-unused-parameter \
            -c aos-ebpf-lsm-policy.bpf.c \
            -o $out/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o

          # clang -g emits BTF (for CO-RE) but also DWARF embedding the
          # kernel-headers path. Strip DWARF; .BTF is retained, CO-RE works.
          ${buildPackages.llvm}/bin/llvm-strip -g $out/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o

          $CC -O2 -Wall -Wextra -Werror \
            -I${linux-headers}/include \
            -o $out/bin/aos-ebpf-lsm-policy \
            ${loaderSource} \
            $(pkg-config --cflags --libs libbpf json-c)

          cat > $out/share/aos/ebpf-lsm/aos-task-audit.json <<'JSON'
          {
            "version": 1,
            "name": "aos-lsm-task-audit",
            "programs": ["aos_lsm_file_mprotect"]
          }
          JSON
        '';
      }
    ];

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-ebpf-lsm-policy.nix;
        name = "aos-ebpf-lsm-policy.nix";
      })
      (builtins.path {
        path = bpfSource;
        name = "aos-ebpf-lsm-policy.bpf.c";
      })
      (builtins.path {
        path = loaderSource;
        name = "aos-ebpf-lsm-policy.c";
      })
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      policy-consumption = lib.mkArtifactConsumptionAudit {
        inherit pkgs;
        name = "ebpf-lsm-immutable-policy";
        consumer = self;
        consumerPath = "/bin/aos-ebpf-lsm-policy";
        provider = self;
        providerPath = "/share/aos/ebpf-lsm/aos-task-audit.json";
        targetPlatform = {
          system = stdenv.hostPlatform.constraints.os;
          architecture = stdenv.hostPlatform.constraints.cpu;
        };
        mechanism = "immutable-data-input";
        arguments = [
          "validate"
          "--policy"
          "${self}/share/aos/ebpf-lsm/aos-task-audit.json"
          "--object"
          "${self}/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
        ];
        expectedOutputSha256 = "sha256:${builtins.hashString "sha256" ""}";
        inspector = pkgs.buildPackages.aos;
      };

      validate = pkgs.runCommand "security-aos-ebpf-lsm-policy-validate" {} ''
        ${self}/bin/aos-ebpf-lsm-policy validate \
          --policy ${self}/share/aos/ebpf-lsm/aos-task-audit.json \
          --object ${self}/lib/bpf/aos-ebpf-lsm-task-audit.bpf.o
        touch $out
      '';
    };

    meta = {
      description = "Load fleet-managed BPF-LSM policy artifacts";
      license = "MIT";
    };
  }
