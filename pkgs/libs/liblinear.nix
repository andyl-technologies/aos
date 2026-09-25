##! liblinear — Library for large linear classification
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "2.50";
  sourceVersion = "250";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "liblinear";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The fitted model predicts each sample's original label.";
        "files" = {
          "primary.cc" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"liblinear primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"liblinear rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <linear.h>\nstatic void discard_training_output(const char *) {}\nint main() {\n    feature_node positive[] = {{1, 1.0}, {-1, 0.0}};\n    feature_node negative[] = {{1, -1.0}, {-1, 0.0}};\n    feature_node *samples[] = {positive, negative};\n    double labels[] = {1.0, -1.0};\n    problem training = {2, 1, labels, samples, -1.0};\n    parameter settings = {};\n    settings.solver_type = L2R_LR;\n    settings.eps = 0.01;\n    settings.C = 1.0;\n    settings.p = 0.1;\n    settings.nu = 0.5;\n    settings.regularize_bias = 1;\n    if (check_parameter(&training, &settings) != NULL) return 2;\n    set_print_string_function(discard_training_output);\n    model *fitted = train(&training, &settings);\n    if (fitted == NULL) return 3;\n    int ok = predict(fitted, positive) == 1.0 && predict(fitted, negative) == -1.0;\n    free_and_destroy_model(&fitted);\n    return ok ? pass() : 4;\n}\n\n";
        };
        "input" = "Two labeled one-dimensional training samples on opposite sides of zero.";
        "operation" = "Train a logistic-regression model and classify both samples.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "primary.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llinear"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "liblinear primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "liblinear returns a diagnostic instead of accepting the parameters.";
        "files" = {
          "bad-input.cc" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"liblinear primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"liblinear rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <linear.h>\nint main() {\n    feature_node sample[] = {{1, 1.0}, {-1, 0.0}}; feature_node *samples[] = {sample}; double labels[] = {1.0};\n    problem training = {1, 1, labels, samples, -1.0};\n    parameter settings = {};\n    settings.solver_type = L2R_LR;\n    settings.eps = 0.01;\n    settings.C = -1.0;\n    settings.p = 0.1;\n    settings.nu = 0.5;\n    settings.regularize_bias = 1;\n    if (check_parameter(&training, &settings) == NULL) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A training parameter set with a negative regularization cost.";
        "operation" = "Validate the parameter set through check_parameter.";
        "steps" = [
          {
            "argv" = [
              "@cxx@"
              "bad-input.cc"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llinear"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "liblinear rejected invalid input\n";
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
        "https://github.com/cjlin1/liblinear/archive/refs/tags/v${sourceVersion}.tar.gz"
      ];
      hash = "sha256-yHW6tNWuU6W0ipEIHGbzmgvSUk9J6TTc2u2QKE3WBeQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd liblinear-${sourceVersion}
        '';
      }
      {
        name = "build";
        script = ''
          # The upstream Makefile calls uname on the Linux build machine.
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              make -j"$NIX_BUILD_CORES" OS=Darwin \
                SHARED_LIB_FLAG="-dynamiclib -Wl,-install_name,$out/lib/liblinear.so.6" \
                lib train predict CC="$CC" CXX="$CXX"
            ''
            else ''
              make -j"$NIX_BUILD_CORES" lib train predict \
                CC="$CC" CXX="$CXX"
            ''
          }
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/include" "$out/lib"
          cp linear.h "$out/include/"
          cp liblinear.so.6 "$out/lib/"
          ln -s liblinear.so.6 "$out/lib/liblinear.so"
          cp train "$out/bin/liblinear-train"
          cp predict "$out/bin/liblinear-predict"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-liblinear";
        library = self;
        libs = ["-llinear"];
        testSource = ''
          #include <linear.h>

          int main(void) {
              return liblinear_version == 250 ? 0 : 1;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-liblinear";
        tool = self;
        command = "printf '1 1:1\n-1 1:-1\n' >/tmp/train && liblinear-train -q /tmp/train /tmp/model && test -s /tmp/model";
      };
    };

    meta = {
      description = "Library for large linear classification";
      homepage = "https://www.csie.ntu.edu.tw/~cjlin/liblinear/";
      license = "BSD-3-Clause";
    };
  }
