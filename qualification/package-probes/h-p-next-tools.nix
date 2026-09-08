##! Exercises a second H-through-P command slice with local deterministic inputs.
{testing}: let
  mkCommandProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryFiles ? {},
    primarySteps,
    primaryArtifacts ? [],
    badInput,
    badOperation,
    badExpected,
    badFiles ? {},
    badSteps,
    badArtifacts ? [],
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = primaryFiles;
          steps = primarySteps;
          artifacts = primaryArtifacts;
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = badSteps;
          artifacts = badArtifacts;
        };
      };
    };
in {
  "json-glib" = mkCommandProbe {
    package = "json-glib";
    primaryInput = "A JSON object mapping answer to the number 42.";
    primaryOperation = "Parse and validate the document through json-glib-validate.";
    primaryExpected = "JSON-GLib accepts the complete document.";
    primaryFiles."answer.json" = "{\"answer\":42}\n";
    primarySteps = [
      {
        argv = ["@out@/bin/json-glib-validate" "answer.json"];
        exit_code = 0;
        stdout.exact = "";
      }
    ];
    badInput = "A JSON object with an unquoted member name and no closing brace.";
    badOperation = "Parse and validate the malformed document through json-glib-validate.";
    badExpected = "JSON-GLib rejects the syntax with status 1.";
    badFiles."invalid.json" = "{answer:42\n";
    badSteps = [
      {
        argv = ["@out@/bin/json-glib-validate" "invalid.json"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  libtool = mkCommandProbe {
    package = "libtool";
    primaryInput = "A C translation unit defining one function.";
    primaryOperation = "Compile the source into a libtool object through --mode=compile.";
    primaryExpected = "Libtool invokes the harness compiler and creates answer.lo.";
    primaryFiles."answer.c" = "int answer(void) { return 42; }\n";
    primarySteps = [
      {
        argv = ["@out@/bin/libtool" "--tag=CC" "--mode=compile" "@cc@" "-c" "answer.c" "-o" "answer.lo"];
        exit_code = 0;
      }
      {
        argv = ["@python@" "-c" "assert open('answer.lo').read().startswith('# answer.lo - a libtool object file')"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    badInput = "A libtool invocation naming an unsupported operation mode.";
    badOperation = "Parse the invalid mode through libtool's command dispatcher.";
    badExpected = "Libtool rejects the mode with status 1.";
    badSteps = [
      {
        argv = ["@out@/bin/libtool" "--tag=CC" "--mode=qualification-invalid" "@cc@" "answer.c"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
    badFiles."answer.c" = "int answer(void) { return 42; }\n";
  };

  lowdown = mkCommandProbe {
    package = "lowdown";
    primaryInput = "A Markdown heading and paragraph containing the value 42.";
    primaryOperation = "Render the document as HTML through Lowdown.";
    primaryExpected = "Lowdown emits the exact heading and paragraph elements.";
    primaryFiles."answer.md" = "# Answer\n\n42\n";
    primarySteps = [
      {
        argv = ["@out@/bin/lowdown" "-Thtml" "answer.md"];
        exit_code = 0;
        stdout.exact = "<h1 id=\"answer\">Answer</h1>\n<p>42</p>\n";
        stderr.exact = "";
      }
    ];
    badInput = "A request for a Lowdown output format that does not exist.";
    badOperation = "Parse the unsupported formatter name.";
    badExpected = "Lowdown rejects the formatter with status 1.";
    badFiles."answer.md" = "42\n";
    badSteps = [
      {
        argv = ["@out@/bin/lowdown" "-Tqualification-invalid" "answer.md"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  mandoc = mkCommandProbe {
    package = "mandoc";
    primaryInput = "A minimal mdoc document with its required title and name sections.";
    primaryOperation = "Validate the document through mandoc's lint formatter.";
    primaryExpected = "Mandoc accepts the document without diagnostics.";
    primaryFiles."answer.1" = ''
      .Dd September 8, 2026
      .Dt ANSWER 1
      .Os
      .Sh NAME
      .Nm answer
      .Nd print the value 42
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/mandoc" "-Tlint" "answer.1"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    badInput = "A request for a mandoc output format that does not exist.";
    badOperation = "Parse the unsupported formatter name.";
    badExpected = "Mandoc rejects the formatter with status 5.";
    badFiles."answer.1" = ".Dd September 8, 2026\n";
    badSteps = [
      {
        argv = ["@out@/bin/mandoc" "-Tqualification-invalid" "answer.1"];
        exit_code = 5;
        observes_rejection = true;
      }
    ];
  };

  meson = mkCommandProbe {
    package = "meson";
    primaryInput = "A Meson project that configures one text file without a compiler.";
    primaryOperation = "Configure the project through meson setup.";
    primaryExpected = "Meson creates a build directory containing answer=42.";
    primaryFiles."meson.build" = ''
      project('qualification')
      configure_file(input: 'answer.in', output: 'answer.txt', copy: true)
    '';
    primaryFiles."answer.in" = "answer=42\n";
    primarySteps = [
      {
        argv = ["@out@/bin/meson" "setup" "build"];
        exit_code = 0;
      }
    ];
    primaryArtifacts = [
      {
        path = "build/answer.txt";
        text = "answer=42\n";
      }
    ];
    badInput = "A Meson build definition with an unterminated project call.";
    badOperation = "Configure the malformed project through meson setup.";
    badExpected = "Meson rejects the syntax with status 1.";
    badFiles."meson.build" = "project('qualification'\n";
    badSteps = [
      {
        argv = ["@out@/bin/meson" "setup" "build"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  ninja = mkCommandProbe {
    package = "ninja";
    primaryInput = "A Ninja graph whose sole rule writes answer=42.";
    primaryOperation = "Execute the default edge through Ninja.";
    primaryExpected = "Ninja creates the exact declared output artifact.";
    primaryFiles."build.ninja" = ''
      rule answer
        command = @bash@ -c "printf answer=42 > $out"
      build answer.txt: answer
      default answer.txt
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/ninja" "-f" "build.ninja"];
        exit_code = 0;
      }
    ];
    primaryArtifacts = [
      {
        path = "answer.txt";
        text = "answer=42";
      }
    ];
    badInput = "A Ninja build edge missing the colon after its output.";
    badOperation = "Parse the malformed build graph through Ninja.";
    badExpected = "Ninja rejects the graph with status 1.";
    badFiles."build.ninja" = "build answer.txt answer\n";
    badSteps = [
      {
        argv = ["@out@/bin/ninja" "-f" "build.ninja"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  nginx = mkCommandProbe {
    package = "nginx";
    primaryInput = "A minimal Nginx configuration with empty events and HTTP blocks.";
    primaryOperation = "Parse and validate the configuration through nginx -t.";
    primaryExpected = "Nginx reports successful configuration validation.";
    primaryFiles."nginx.conf" = ''
      daemon off;
      master_process off;
      error_log stderr;
      pid @work@/primary/nginx.pid;
      events {}
      http {}
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/nginx" "-t" "-p" "@work@/primary/" "-c" "nginx.conf"];
        exit_code = 0;
      }
    ];
    badInput = "An Nginx configuration containing an unknown top-level directive.";
    badOperation = "Parse and validate the malformed configuration through nginx -t.";
    badExpected = "Nginx rejects the unknown directive with status 1.";
    badFiles."nginx.conf" = "qualification_directive_does_not_exist on;\n";
    badSteps = [
      {
        argv = ["@out@/bin/nginx" "-t" "-p" "@work@/bad-input/" "-c" "nginx.conf"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };

  parallel = mkCommandProbe {
    package = "parallel";
    primaryInput = "The ordered values 1 and 2 supplied as standard input.";
    primaryOperation = "Run one formatting job per value through GNU Parallel.";
    primaryExpected = "Parallel preserves input order and prints both exact results.";
    primaryFiles."emit.sh" = ''
      printf 'answer=%s\n' "$1"
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/parallel" "--keep-order" "@bash@" "emit.sh" "{}"];
        stdin = "1\n2\n";
        exit_code = 0;
        stdout.exact = "answer=1\nanswer=2\n";
        stderr.exact = "";
      }
    ];
    badInput = "A pipe-part input pathname that does not exist.";
    badOperation = "Open the missing input through GNU Parallel's pipe-part mode.";
    badExpected = "Parallel rejects the missing file with status 255.";
    badSteps = [
      {
        argv = ["@out@/bin/parallel" "--pipepart" "-a" "missing-qualification-file" "@bash@" "emit.sh" "{}"];
        exit_code = 255;
        observes_rejection = true;
      }
    ];
  };

  pip = mkCommandProbe {
    package = "pip";
    primaryInput = "A local file containing the bytes answer=42 followed by a newline.";
    primaryOperation = "Hash the file through pip hash.";
    primaryExpected = "Pip prints the exact SHA-256 requirement fragment.";
    primaryFiles."answer.txt" = "answer=42\n";
    primarySteps = [
      {
        argv = ["@out@/bin/pip" "hash" "answer.txt"];
        exit_code = 0;
        stdout.exact = "answer.txt:\n--hash=sha256:24cab0d01b67b184d0a737de3a5b5d47b8b69b36203273296d5ef763f7fdcf68\n";
        stderr.exact = "";
      }
    ];
    badInput = "A pathname that does not exist.";
    badOperation = "Hash the missing file through pip hash.";
    badExpected = "Pip rejects the missing input with status 2.";
    badSteps = [
      {
        argv = ["@out@/bin/pip" "hash" "missing-qualification-file"];
        exit_code = 2;
        observes_rejection = true;
      }
    ];
  };

  "procps-ng" = mkCommandProbe {
    package = "procps-ng";
    primaryInput = "The Linux kernel.ostype sysctl key.";
    primaryOperation = "Read the value through procps-ng sysctl.";
    primaryExpected = "The kernel reports the exact operating-system type Linux.";
    primarySteps = [
      {
        argv = ["@out@/sbin/sysctl" "-n" "kernel.ostype"];
        exit_code = 0;
        stdout.exact = "Linux\n";
        stderr.exact = "";
      }
    ];
    badInput = "A sysctl key absent from the kernel namespace.";
    badOperation = "Read the unknown key through procps-ng sysctl.";
    badExpected = "Sysctl rejects the key with status 1.";
    badSteps = [
      {
        argv = ["@out@/sbin/sysctl" "qualification.key.does.not.exist"];
        exit_code = 1;
        observes_rejection = true;
      }
    ];
  };
}
