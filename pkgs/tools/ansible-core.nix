##! ansible-core — Agentless IT automation engine and command-line tools
{
  lib,
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
  stdenv,
  glibc-locales,
  openssh,
  packaging,
  python3-cffi,
  python3-cryptography,
  python3-jinja2,
  python3-markupsafe,
  python3-pycparser,
  python3-pyyaml,
  python3-resolvelib,
}: let
  version = "2.21.5";
  sitePackages = "lib/python3.14/site-packages";

  # Runtime import closure from requirements.txt, including the modules the
  # direct requirements import in turn. Every command searches these
  # site-packages directories after ansible-core's own.
  pythonDeps = [
    python3-jinja2
    python3-markupsafe
    python3-pyyaml
    python3-cryptography
    python3-cffi
    python3-pycparser
    packaging
    python3-resolvelib
  ];
  pythonPath = map (dep: "${dep}/${sitePackages}") pythonDeps;
in
  mkDerivation {
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
      target = [];
      role = "public-package";
    };

    pname = "ansible-core";
    # ansible-core minor releases may remove deprecated features; patch
    # releases within a series carry bug and security fixes only.
    # https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html
    version = "~${version}";

    src = fetchurl {
      urls = ["https://files.pythonhosted.org/packages/source/a/ansible-core/ansible_core-${version}.tar.gz"];
      hash = "sha256-ZbsxSMWOu4Q81QdABMgF9ATxUhFNmEdt2CMyRhbJxss=";
    };

    buildDeps = [buildPackages.python3 buildPackages.setuptools];
    runtimeDeps = [python3 glibc-locales openssh] ++ pythonDeps;
    propagatedDeps = [python3] ++ pythonDeps;

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd ansible_core-${version}
          '';
        }
        {
          name = "build";
          script = ''
            # Build through the declared backend so package data and console
            # entry points match the upstream wheel.
            PYTHONPATH=${buildPackages.setuptools}/${sitePackages} \
              ${buildPackages.python3}/bin/python3 -c \
                'from setuptools.build_meta import build_wheel; build_wheel("dist")'
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/${sitePackages}" "$out/bin" "$out/share/licenses/ansible-core"

            # Unpack the wheel and write one launcher per console entry point.
            # Launchers pin the source-built interpreter and dependency paths
            # and fall back to the packaged OpenSSH client for SSH connections
            # when the caller's PATH has none. Ansible refuses to start
            # without a UTF-8 locale, so launchers also default LOCPATH to the
            # packaged locale data; an explicit LOCPATH remains in effect.
            ${buildPackages.python3}/bin/python3 - <<'PY'
            import configparser
            import os
            from pathlib import Path
            from zipfile import ZipFile

            out = Path(os.environ["out"])
            site = out / "${sitePackages}"
            wheel, = Path("dist").glob("*.whl")
            with ZipFile(wheel) as archive:
                archive.extractall(site)

            entry_points, = site.glob("ansible_core-*.dist-info/entry_points.txt")
            parser = configparser.ConfigParser()
            parser.optionxform = str
            parser.read(entry_points)

            search_path = [str(site)] + ${builtins.toJSON pythonPath}
            for name, target in parser["console_scripts"].items():
                module, function = target.split(":")
                launcher = out / "bin" / name
                launcher.write_text(
                    "#!${python3}/bin/python3\n"
                    "import os\n"
                    "import sys\n"
                    f"sys.path[0:0] = {search_path!r}\n"
                    "os.environ.setdefault('LOCPATH', '${glibc-locales}/lib/locale')\n"
                    "os.environ['PATH'] = os.pathsep.join(\n"
                    "    filter(None, [os.environ.get('PATH'), '${openssh}/bin'])\n"
                    ")\n"
                    f"from {module} import {function}\n"
                    f"sys.exit({function}())\n"
                )
                launcher.chmod(0o755)
            PY

            cp COPYING "$out/share/licenses/ansible-core/"
            cp licenses/*.txt "$out/share/licenses/ansible-core/"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            export HOME="$TMPDIR/home" LC_ALL=C.UTF-8
            mkdir -p "$HOME"
            "$out/bin/ansible" --version | grep -q '^ansible \[core ${version}\]'

            # Run a local play to exercise templating, the YAML loader,
            # module packaging, and a module executed by the source-built
            # interpreter.
            cat > "$TMPDIR/play.yml" <<'EOF'
            - hosts: localhost
              connection: local
              gather_facts: false
              tasks:
                - ansible.builtin.copy:
                    dest: "{{ lookup('env', 'TMPDIR') }}/rendered.txt"
                    content: "{{ 'aos' | upper }}-{{ [1, 2, 3] | sum }}\n"
            EOF
            "$out/bin/ansible-playbook" -i localhost, \
              -e ansible_python_interpreter=${python3}/bin/python3 \
              "$TMPDIR/play.yml"
            grep -qx 'AOS-6' "$TMPDIR/rendered.txt"
          '';
        }
      ];

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A local playbook that templates a file from inventory variables.";
        operation = "Run the playbook against localhost with the local connection.";
        expected = "The rendered file contains the templated value.";
        files = {
          "inventory.ini" = "localhost ansible_connection=local greeting=aos\n";
          "play.yml" = ''
            - hosts: localhost
              gather_facts: false
              tasks:
                - ansible.builtin.copy:
                    dest: "{{ playbook_dir }}/rendered.txt"
                    content: "{{ greeting | upper }}-{{ [1, 2, 3] | sum }}\n"
          '';
          "probe.py" = ''
            import os, subprocess, sys

            env = dict(os.environ, HOME=os.getcwd(), LC_ALL="C.UTF-8", ANSIBLE_NOCOLOR="1")
            subprocess.run(
                ["@out@/bin/ansible-playbook", "-i", "inventory.ini",
                 "-e", "ansible_python_interpreter=" + sys.executable, "play.yml"],
                check=True, capture_output=True, env=env,
            )
            with open("rendered.txt") as handle:
                assert handle.read() == "AOS-6\n"
            print("ansible playbook passed")
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "ansible playbook passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A playbook whose YAML has an unterminated flow sequence.";
        operation = "Check the playbook syntax.";
        expected = "ansible-playbook rejects the file before running any task.";
        files = {
          "play.yml" = "- hosts: [localhost\n";
          "probe.py" = ''
            import os, subprocess, sys

            env = dict(os.environ, HOME=os.getcwd(), LC_ALL="C.UTF-8", ANSIBLE_NOCOLOR="1")
            result = subprocess.run(
                ["@out@/bin/ansible-playbook", "-i", "localhost,", "--syntax-check", "play.yml"],
                capture_output=True, env=env,
            )
            assert result.returncode != 0
            sys.stderr.write("ansible rejected invalid input\n")
            raise SystemExit(7)
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "ansible rejected invalid input\n";
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
      local-play = testing.mkToolCheck {
        pname = "tool-ansible-core";
        tool = self;
        command = ''
          export HOME=/tmp LC_ALL=C.UTF-8
          ansible --version
          cat > /tmp/play.yml <<'EOF'
          - hosts: localhost
            connection: local
            gather_facts: true
            tasks:
              - ansible.builtin.copy:
                  dest: /tmp/rendered.txt
                  content: "{{ ansible_facts.system }}\n"
              - ansible.builtin.command: cat /tmp/rendered.txt
                register: rendered
              - ansible.builtin.assert:
                  that: rendered.stdout == "Linux"
          EOF
          ansible-playbook -i localhost, \
            -e 'ansible_python_interpreter={{ ansible_playbook_python }}' /tmp/play.yml
          echo "ansible local play passed"
        '';
      };
    };

    meta = {
      description = "Radically simple IT automation engine with ansible-playbook and friends";
      homepage = "https://www.ansible.com/";
      license = "GPL-3.0-or-later";
      mainProgram = "ansible";
    };
  }
