##! Exercises Q-through-Z language runtimes and compiler toolchains.
{testing}: let
  mkRustProbe = package:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "A Rust program that sorts integers and prints their sum.";
          operation = "Compile the program with rustc, then execute the generated binary.";
          expected = "The compiler produces a runnable binary that prints the fixed result 42.";
          files."answer.rs" = ''
            fn main() {
                let mut values = [23, 19];
                values.sort();
                println!("{}", values.iter().sum::<i32>());
            }
          '';
          steps = [
            {
              argv = ["@out@/bin/rustc" "answer.rs" "-o" "answer"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
            }
            {
              argv = ["@work@/primary/answer"];
              exit_code = 0;
              stdout.exact = "42\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A Rust function with a missing expression after an addition operator.";
          operation = "Compile the malformed source with rustc.";
          expected = "rustc rejects the syntax error with its compilation-failure status.";
          files."invalid.rs" = "fn main() { let answer = 19 + ; println!(\"{}\", answer); }\n";
          steps = [
            {
              argv = ["@out@/bin/rustc" "invalid.rs" "-o" "invalid"];
              exit_code = 1;
              stdout.exact = "";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in
  {
    ruby = testing.mkQualificationPackageProbe {
      name = "ruby";
      spec = {
        schema_version = "aos.release.package-probe/v1";
        package = "ruby";
        primary = {
          input = "A Ruby program that maps and sums two integers.";
          operation = "Execute the program with the packaged Ruby interpreter.";
          expected = "Ruby prints the exact integer result 42.";
          files."answer.rb" = "puts [19, 23].map { |value| value }.sum\n";
          steps = [
            {
              argv = ["@out@/bin/ruby" "answer.rb"];
              exit_code = 0;
              stdout.exact = "42\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A Ruby method definition with an unclosed parameter list.";
          operation = "Ask Ruby to check the malformed program's syntax.";
          expected = "Ruby rejects the program with its syntax-error status.";
          files."invalid.rb" = "def answer(\n  42\nend\n";
          steps = [
            {
              argv = ["@out@/bin/ruby" "-c" "invalid.rb"];
              exit_code = 1;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

    tcl = testing.mkQualificationPackageProbe {
      name = "tcl";
      spec = {
        schema_version = "aos.release.package-probe/v1";
        package = "tcl";
        primary = {
          input = "A Tcl program that adds two integers.";
          operation = "Evaluate the arithmetic expression with tclsh.";
          expected = "Tcl prints the exact integer result 42.";
          files."answer.tcl" = "puts [expr {19 + 23}]\n";
          steps = [
            {
              argv = ["@out@/bin/tclsh9.0" "answer.tcl"];
              exit_code = 0;
              stdout.exact = "42\n";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A Tcl arithmetic expression ending in an operator.";
          operation = "Evaluate the malformed expression with tclsh.";
          expected = "Tcl reports an expression parse failure and exits unsuccessfully.";
          files."invalid.tcl" = "expr {19 +}\n";
          steps = [
            {
              argv = ["@out@/bin/tclsh9.0" "invalid.tcl"];
              exit_code = 1;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

    zsh = testing.mkQualificationPackageProbe {
      name = "zsh";
      spec = {
        schema_version = "aos.release.package-probe/v1";
        package = "zsh";
        primary = {
          input = "A Zsh program using an array and arithmetic expansion.";
          operation = "Execute the program with the packaged shell.";
          expected = "Zsh selects the second array value and prints the sum 42.";
          files = {};
          steps = [
            {
              argv = ["@out@/bin/zsh" "-c" "values=(19 23); print -- $((values[1] + values[2]))"];
              exit_code = 0;
              stdout.exact = "42\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = "A Zsh conditional with no closing delimiter.";
          operation = "Ask Zsh to parse the malformed program.";
          expected = "Zsh rejects the syntax error with its parse-failure status.";
          files."invalid.zsh" = "if [[ -n value ]]; then\n  print broken\n";
          steps = [
            {
              argv = ["@out@/bin/zsh" "-n" "invalid.zsh"];
              exit_code = 1;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
  }
  // builtins.listToAttrs (
    map (package: {
      name = package;
      value = mkRustProbe package;
    }) [
      "rust"
      "rust-1_74"
      "rust-1_75"
      "rust-1_76"
      "rust-1_77"
      "rust-1_78"
      "rust-1_79"
      "rust-1_80"
      "rust-1_81"
      "rust-1_82"
      "rust-1_83"
      "rust-1_84"
      "rust-1_85"
      "rust-1_86"
      "rust-1_87"
      "rust-1_88"
      "rust-1_89"
      "rust-1_90"
      "rust-1_91"
      "rust-1_92"
      "rust-1_93"
      "rust-1_94"
      "rust-1_95"
      "rust-1_96"
      "rust-1_97"
    ]
  )
