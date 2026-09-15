##! kubelet — Kubernetes node agent
{
  lib,
  mkGoPackage,
  kubeSource,
}:
mkGoPackage {
  pname = "kubelet";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "Kubelet returns a Bash function wired to its completion endpoint.";
      "files" = {};
      "input" = "A request for Kubelet's Bash completion program.";
      "operation" = "Generate the completion program without starting the node agent.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess\nresult = subprocess.run([\"@out@/bin/kubelet\", \"completion\", \"bash\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"__start_kubelet\" in result.stdout and \"complete -o default\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"kubelet operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "kubelet operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "Kubelet rejects the unknown command.";
      "files" = {};
      "input" = "A Kubelet invocation naming an unknown top-level command.";
      "operation" = "Parse the unsupported command without starting the node agent.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/kubelet\", \"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"kubelet rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "kubelet rejected invalid input\n";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

  inherit (kubeSource) version src;

  goPackage = "./cmd/kubelet";
  goOutput = "kubelet";
  ldflags = "-s -w -X k8s.io/component-base/version.gitVersion=v${kubeSource.version}";
  doCheck = false;
  abilities = ./_kubelet-config/module.nix;

  checks = {
    testing,
    self,
    ...
  }: {
    version = testing.mkToolCheck {
      pname = "tool-kubelet";
      tool = self;
      command = "kubelet --version";
    };
  };

  meta = {
    description = "kubelet — Kubernetes node agent that manages pods";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
