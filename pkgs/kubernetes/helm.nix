##! helm — Kubernetes package manager for charts and releases
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  git,
}: let
  version = "4.3.1";
  src = fetchurl {
    name = "helm-${version}.tar.gz";
    urls = ["https://github.com/helm/helm/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-57gDtqJIwYrqBn28ysr2UcKZRtt10F+yPzGP8vFZYcY=";
  };

  # Upstream's Makefile stamps the release through these variables. An empty
  # metadata field marks a tagged release; a source archive has no commit.
  versionPackage = "helm.sh/helm/v4/internal/version";
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

    pname = "helm";
    # Helm follows SemVer for its CLI and SDK within a major series.
    # https://helm.sh/docs/topics/version_skew/
    inherit version src;

    # The K3s Helm job builds Helm 3 with reviewed dependency locks for the
    # helm-controller plugin lifecycle (see _k3s-helm-programs.nix). This is
    # the general-purpose Helm 4 CLI. Helm 4 derives its default Kubernetes
    # capabilities from the client-go module in build info, so it needs none
    # of the Helm 3 version link flags.
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-f/i6yoWPBwr9IPIkNz74IIjrnvxDXBfONLt0d1t/k9g=";
    };
    goPackage = "./cmd/helm";
    goOutput = "helm";
    ldflags = lib.concatStringsSep " " [
      "-s -w"
      "-X ${versionPackage}.version=v${version}"
      "-X ${versionPackage}.metadata="
      "-X ${versionPackage}.gitTreeState=clean"
    ];

    # Plugin tests execute shell scripts from testdata and install plugins
    # from local Git repositories. At runtime Git stays an optional PATH
    # lookup used only by `helm plugin install` for VCS sources.
    buildDeps = [git];

    # The sandbox has no network. Skip the tests that resolve a public chart
    # repository or DNS name, and the Wasm plugin test that downloads its
    # separate guest module while building it.
    postPatch = ''
      for scripts in internal/plugin/testdata pkg/cmd/testdata pkg/postrenderer/testdata; do
        patchShebangs "$scripts"
      done

      skipTest() {
        sed -i "/^func $2(t \*testing.T) {\$/a\\\\tt.Skip(\"$3\")" "$1"
        grep -q "t.Skip(\"$3\")" "$1"
      }
      skipTest pkg/action/pull_test.go TestPullRun_ChartNotFound "requires charts.helm.sh"
      skipTest pkg/engine/engine_test.go TestRenderWithDNS "requires DNS resolution"
      skipTest internal/plugin/runtime_extismv1_test.go TestRuntimeExtismV1InvokePlugin \
        "downloads the Wasm guest module"
    '';

    # The chart lint rules suite temporarily renames a template inside
    # testdata that the parent lint package reads, so the two packages race
    # when Go tests packages concurrently.
    doParallelCheck = false;

    # Several tests write Helm's XDG configuration and cache under HOME.
    preBuild = ''
      export HOME="$TMPDIR/home"
      mkdir -p "$HOME"
    '';

    postInstall = ''
      mkdir -p "$out/share/licenses/helm"
      cp LICENSE "$out/share/licenses/helm/"
    '';

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A minimal local chart with one templated ConfigMap.";
        operation = "Lint the chart and render it offline with an overridden value.";
        expected = "Helm renders the ConfigMap with the release name and override.";
        files = {
          "demo/Chart.yaml" = "apiVersion: v2\nname: demo\nversion: 0.1.0\n";
          "demo/values.yaml" = "greeting: hello\n";
          "demo/templates/configmap.yaml" = ''
            apiVersion: v1
            kind: ConfigMap
            metadata:
              name: {{ .Release.Name }}-demo
            data:
              greeting: {{ .Values.greeting | quote }}
          '';
          "probe.py" = ''
            import os, subprocess

            env = dict(os.environ, HOME=os.getcwd())
            subprocess.run(
                ["@out@/bin/helm", "lint", "demo"],
                check=True, capture_output=True, env=env,
            )
            rendered = subprocess.run(
                ["@out@/bin/helm", "template", "probe", "demo", "--set", "greeting=aos"],
                check=True, capture_output=True, text=True, env=env,
            ).stdout
            assert "name: probe-demo" in rendered, rendered
            assert 'greeting: "aos"' in rendered, rendered
            print("helm chart render passed")
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "helm chart render passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A chart whose template contains an unterminated action.";
        operation = "Render the malformed chart.";
        expected = "Helm reports the template parse error and renders nothing.";
        files = {
          "broken/Chart.yaml" = "apiVersion: v2\nname: broken\nversion: 0.1.0\n";
          "broken/templates/configmap.yaml" = "kind: ConfigMap\nname: {{ .Release.Name\n";
          "probe.py" = ''
            import os, subprocess, sys

            env = dict(os.environ, HOME=os.getcwd())
            result = subprocess.run(
                ["@out@/bin/helm", "template", "probe", "broken"],
                capture_output=True, env=env,
            )
            assert result.returncode != 0
            assert b"kind: ConfigMap" not in result.stdout
            sys.stderr.write("helm rejected invalid input\n")
            raise SystemExit(7)
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "helm rejected invalid input\n";
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
      chart = testing.mkToolCheck {
        pname = "tool-helm";
        tool = self;
        command = ''
          export HOME=/tmp
          helm version --short | grep -qx 'v${version}'
          cd /tmp
          helm create demo
          helm lint demo
          helm template probe demo | grep -q 'name: probe-demo'
          helm package demo
          echo "helm chart lifecycle passed"
        '';
      };
    };

    meta = {
      description = "Package manager for Kubernetes charts and releases";
      homepage = "https://helm.sh/";
      license = "Apache-2.0";
      mainProgram = "helm";
    };
  }
