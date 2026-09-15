##! kubectl — Kubernetes command-line tool
{
  lib,
  mkGoPackage,
  kubeSource,
}:
mkGoPackage {
  pname = "kubectl";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "Kubectl prints the created ConfigMap resource name without contacting a cluster.";
      "files" = {};
      "input" = "A ConfigMap named qualification with the literal answer=42.";
      "operation" = "Construct the object locally through kubectl's client-side dry run.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/kubectl"
            "create"
            "configmap"
            "qualification"
            "--from-literal=answer=42"
            "--dry-run=client"
            "-o"
            "name"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "configmap/qualification\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "Kubectl rejects the duplicate data key with status 1.";
      "files" = {};
      "input" = "Two literal values with the same ConfigMap key.";
      "operation" = "Construct the conflicting object through kubectl's client-side dry run.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/kubectl"
            "create"
            "configmap"
            "qualification"
            "--from-literal=answer=42"
            "--from-literal=answer=43"
            "--dry-run=client"
            "-o"
            "name"
          ];
          "exit_code" = 1;
          "observes_rejection" = true;
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

  inherit (kubeSource) version src;

  goPackage = "./cmd/kubectl";
  goOutput = "kubectl";
  ldflags = "-s -w -X k8s.io/component-base/version.gitVersion=v${kubeSource.version}";
  doCheck = false;

  checks = {
    testing,
    self,
    pkgs,
  }: {
    version = testing.mkToolCheck {
      pname = "tool-kubectl";
      tool = self;
      command = "kubectl version --client 2>&1";
    };
  };

  meta = {
    description = "kubectl — Kubernetes command-line interface";
    homepage = "https://kubernetes.io";
    license = "Apache-2.0";
  };
}
