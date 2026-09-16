##! nerdctl — Docker-compatible CLI for containerd
{
  lib,
  mkGoPackage,
  mkGithubUpstream,
  fetchGoModules,
  cni-plugins,
  bash,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "nerdctl-2";
    family = "nerdctl";
    stream = "2";
    owner = "pkgs/containers/nerdctl.nix";
    version = "2.3.5";
    upstreamId = "v2.3.5";
    repository = "containerd/nerdctl";
    provider = "github-releases";
    tagPrefix = "v";
    major = 2;
    source = {
      authority = "github.com";
      path = [
        "containerd"
        "nerdctl"
        "archive"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "nerdctl-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-oiXdGAklsz4MYPPlCUjS2hfXhFFcNF5ru8ZAr8s3UZ0=";
    };
    artifacts.goModules = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-cG6P8OCQTgGEBi9t72RRcs5TizPbfRS6zLy7ePdMbwU=";
      materializer = {
        kind = "go-modules";
        sourceRoot = ".";
        moduleRoots = ["."];
        builder = "fetchGoModules/v1";
      };
    };
  };
  inherit (upstream) version;
  src = upstream.components.main.sources.source;
  goModules = fetchGoModules {
    inherit src;
    hash = upstream.artifacts.goModules.hash;
  };
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "nerdctl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Nerdctl returns a Bash function wired to its completion endpoint.";
        "files" = {};
        "input" = "A request for nerdctl's Bash completion program.";
        "operation" = "Generate the completion program without contacting containerd.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/nerdctl\", \"completion\", \"bash\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"__start_nerdctl\" in result.stdout and \"complete -o default\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"nerdctl operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "nerdctl operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Nerdctl rejects the unknown command.";
        "files" = {};
        "input" = "A nerdctl invocation naming an unknown top-level command.";
        "operation" = "Parse the unsupported command without contacting containerd.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/nerdctl\", \"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"nerdctl rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "nerdctl rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    inherit goModules;
    update = upstream.updateWithArtifacts {inherit goModules;};

    goPackage = "./cmd/nerdctl";
    goOutput = "nerdctl";
    ldflags = "-s -w -X github.com/containerd/nerdctl/v2/pkg/version.Version=v${version}";
    doCheck = false;

    # CNI plugins implement Linux network namespaces.  Darwin nerdctl remains
    # useful as a client for remote containerd endpoints without that runtime
    # integration.
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then []
      else [cni-plugins bash];

    postInstall =
      if stdenv.hostPlatform.isDarwin
      then ""
      else ''
            # Wrap nerdctl to set CNI_PATH
            mv "$out/bin/nerdctl" "$out/bin/.nerdctl-unwrapped"
            cat > "$out/bin/nerdctl" << WRAPPER
        #!${bash}/bin/bash
        export CNI_PATH="${cni-plugins}/bin"
        exec "\$(dirname "\$0")/.nerdctl-unwrapped" "\$@"
        WRAPPER
            chmod +x "$out/bin/nerdctl"
      '';

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-nerdctl";
        tool = self;
        command = "nerdctl --version";
      };
    };

    meta = {
      description = "nerdctl — Docker-compatible CLI for containerd";
      homepage = "https://github.com/containerd/nerdctl";
      license = "Apache-2.0";
    };
  }
