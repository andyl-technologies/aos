##! timoni — Package manager for Kubernetes powered by CUE
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  git,
}: let
  version = "0.36.0";
  src = fetchurl {
    name = "timoni-${version}.tar.gz";
    urls = ["https://github.com/stefanprodan/timoni/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-tiWgv5CfSZUbBskBVx0lfNQ5aySHWIiS5EC7XIbElLk=";
  };
in
  mkGoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };

    pname = "timoni";
    # Timoni is pre-1.0 and its module and bundle APIs are still v1alpha1.
    version = "~${version}";
    inherit src;

    # Timoni embeds the CUE evaluator as a Go library pinned by its own
    # go.mod; it does not run the separately packaged cue command.
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-VgYsEn/69xNYy9gknRQmhiceQdmPcOtMUHD3CZx/FLE=";
    };
    goPackage = "./cmd/timoni";
    goOutput = "timoni";
    ldflags = "-s -w -X main.VERSION=${version}";

    # The OCI metadata tests create Git repositories. At runtime Git remains
    # an optional PATH lookup that only annotates pushed module artifacts.
    buildDeps = [git];

    # The command-package suite starts a Kubernetes API server and etcd
    # through controller-runtime envtest in TestMain. The engine, OCI,
    # runtime, and API packages run without a cluster.
    goTestFlags = "./api/... ./internal/...";

    # `timoni mod init` pulls its template from an OCI registry. Ship the
    # upstream example module, with its vendored Kubernetes schemas, so a
    # module can be built and inspected offline. The module links the core
    # Timoni schemas from the source tree; copy their contents instead.
    postInstall = ''
      mkdir -p "$out/share/licenses/timoni" "$out/share/timoni/examples"
      cp LICENSE "$out/share/licenses/timoni/"
      cp -RL examples/minimal "$out/share/timoni/examples/"
    '';

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The packaged minimal example module and its default values.";
        operation = "Render an instance of the module offline.";
        expected = "Timoni renders Kubernetes objects named after the instance.";
        files = {
          "probe.py" = ''
            import subprocess

            rendered = subprocess.run(
                ["@out@/bin/timoni", "build", "probe",
                 "@out@/share/timoni/examples/minimal", "--namespace", "aos"],
                check=True, capture_output=True, text=True,
            ).stdout
            assert "kind: Deployment" in rendered, rendered
            assert "name: probe" in rendered, rendered
            assert "namespace: aos" in rendered, rendered
            print("timoni module build passed")
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "timoni module build passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A directory that is not a Timoni module.";
        operation = "Build an instance from the directory.";
        expected = "Timoni rejects the module path without rendering objects.";
        files = {
          "empty/README" = "not a module\n";
          "probe.py" = ''
            import subprocess, sys

            result = subprocess.run(
                ["@out@/bin/timoni", "build", "probe", "./empty"], capture_output=True
            )
            assert result.returncode != 0
            assert b"kind:" not in result.stdout
            sys.stderr.write("timoni rejected invalid input\n")
            raise SystemExit(7)
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "timoni rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };

    checks = {
      testing,
      self,
      ...
    }: {
      module-build = testing.mkToolCheck {
        pname = "tool-timoni";
        tool = self;
        command = ''
          timoni version
          cp -R ${self}/share/timoni/examples/minimal /tmp/minimal
          chmod -R u+w /tmp/minimal
          timoni mod vet /tmp/minimal
          timoni build probe /tmp/minimal --namespace aos | grep -q 'kind: Deployment'
          echo "timoni module build passed"
        '';
      };
    };

    meta = {
      description = "Package manager for Kubernetes, powered by CUE and inspired by Helm";
      homepage = "https://timoni.sh/";
      license = "Apache-2.0";
      mainProgram = "timoni";
    };
  }
