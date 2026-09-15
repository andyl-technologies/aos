##! tmux — Terminal multiplexer
{
  lib,
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gnumake,
  bison,
  pkg-config,
  libevent,
  ncurses,
  utf8proc,
  libutempter,
  systemd,
  glibc-locales,
}: let
  version = "3.7c";
in
  mkDerivation {
    pname = "tmux";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Tmux preserves and reports the exact session option value.";
        "files" = {};
        "input" = "A detached session named qualification with a fixed status-left value.";
        "operation" = "Create the session on an isolated socket, set the option, read it back, and stop the server.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nenvironment = os.environ.copy()\nenvironment[\"TMUX_TMPDIR\"] = str(pathlib.Path(\"socket-dir\").resolve())\nclosure = json.loads(environment[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\nlocale = next(path for path in closure if \"-glibc-locales-\" in path)\nenvironment[\"LOCPATH\"] = str(pathlib.Path(locale) / \"lib/locale\")\nenvironment[\"LC_ALL\"] = \"C.UTF-8\"\npathlib.Path(environment[\"TMUX_TMPDIR\"]).mkdir()\ncommand = [\"@out@/bin/tmux\", \"-L\", \"qualification\"]\ntry:\n    created = subprocess.run(command + [\"new-session\", \"-d\", \"-s\", \"qualification\"], env=environment, capture_output=True)\n    assert created.returncode == 0, created.stderr\n    assert subprocess.run(command + [\"set-option\", \"-t\", \"qualification\", \"status-left\", \"qualified\"], env=environment).returncode == 0\n    shown = subprocess.run(command + [\"show-option\", \"-v\", \"-t\", \"qualification\", \"status-left\"], env=environment, capture_output=True, text=True)\n    assert shown.returncode == 0 and shown.stdout == \"qualified\\n\"\nfinally:\n    subprocess.run(command + [\"kill-server\"], env=environment, capture_output=True)\nprint(\"tmux operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "tmux operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Tmux rejects the unknown command before creating a server.";
        "files" = {};
        "input" = "A tmux command name outside the command table.";
        "operation" = "Dispatch the unsupported command on an isolated socket.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport json, os, pathlib, subprocess\nenvironment = os.environ.copy()\nclosure = json.loads(environment[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\nlocale = next(path for path in closure if \"-glibc-locales-\" in path)\nenvironment[\"LOCPATH\"] = str(pathlib.Path(locale) / \"lib/locale\")\nenvironment[\"LC_ALL\"] = \"C.UTF-8\"\nresult = subprocess.run([\"@out@/bin/tmux\", \"qualification-invalid-command\"], env=environment, capture_output=True, text=True)\nassert result.returncode != 0 and \"unknown command\" in result.stderr\n\nsys.stderr.write(\"tmux rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "tmux rejected invalid input\n";
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
      urls = ["https://github.com/tmux/tmux/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-XnsPUztm5WM+K3Kp1IP5U0o0OrcBHrJiG2MJ37pVPao=";
    };

    buildDeps = [autoconf automake libtool gnumake bison pkg-config];
    runtimeDeps = [libevent ncurses utf8proc libutempter systemd glibc-locales];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd tmux-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          ACLOCAL_PATH="${pkg-config}/share/aclocal" autoreconf -fi
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --sysconfdir=/etc \
            --localstatedir=/var \
            --enable-systemd \
            --enable-sixel \
            --enable-utempter \
            --enable-utf8proc
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-tmux";
        tool = self;
        command = "LOCPATH=${glibc-locales}/lib/locale LC_ALL=C.UTF-8 tmux -V";
        extraDeps = [glibc-locales];
      };
    };

    meta = {
      description = "Terminal multiplexer";
      homepage = "https://tmux.github.io/";
      license = "ISC";
      mainProgram = "tmux";
    };
  }
