##! Exercises additional Q-through-Z system tools without privileged effects.
{testing}: {
  runc = testing.mkQualificationPackageProbe {
    name = "runc";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "runc";
      primary = {
        input = "An empty bundle directory requesting runc's rootless OCI template.";
        operation = "Generate config.json and validate its core OCI fields independently.";
        expected = "Runc emits a rootless process configuration using rootfs as the root path.";
        files."verify.py" = ''
          import json

          config = json.load(open("config.json", encoding="utf-8"))
          assert config["ociVersion"].startswith("1.")
          assert config["root"]["path"] == "rootfs"
          assert config["process"]["args"]
          print("runc specification passed")
        '';
        steps = [
          {
            argv = ["@out@/bin/runc" "--root" "@work@/primary/state" "spec" "--rootless"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "verify.py"];
            exit_code = 0;
            stdout.exact = "runc specification passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A bundle directory in which config.json already exists.";
        operation = "Attempt to generate a second OCI configuration over the existing file.";
        expected = "Runc refuses to overwrite the existing bundle configuration.";
        files."config.json" = "{}\n";
        steps = [
          {
            argv = ["@out@/bin/runc" "--root" "@work@/bad-input/state" "spec" "--rootless"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [
          {
            path = "config.json";
            text = "{}\n";
          }
        ];
      };
    };
  };

  sudo = testing.mkQualificationPackageProbe {
    name = "sudo";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "sudo";
      primary = {
        input = "A sudoers policy granting root one explicit command.";
        operation = "Check the policy with visudo's noninteractive parser.";
        expected = "Visudo accepts the syntactically valid policy.";
        files."sudoers" = "root ALL=(ALL:ALL) /bin/true\n";
        steps = [
          {
            argv = ["@out@/sbin/visudo" "-c" "-f" "sudoers"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A sudoers policy with an unterminated run-as group.";
        operation = "Check the malformed policy with visudo.";
        expected = "Visudo rejects the syntax error with a failure status.";
        files."sudoers" = "root ALL=(ALL: /bin/true\n";
        steps = [
          {
            argv = ["@out@/sbin/visudo" "-c" "-f" "sudoers"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
