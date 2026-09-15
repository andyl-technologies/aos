##! polkit — System service authorization framework
{
  lib,
  mkDerivation,
  fetchurl,
  meson,
  ninja,
  pkg-config,
  gettext,
  perl,
  python3,
  python3-dbus,
  python3-dbusmock,
  glib,
  glibWithIntrospection,
  expat,
  linux-pam,
  dbus,
  duktape,
  systemd,
  util-linux,
  gobject-introspection,
  gtk-doc,
  libxslt,
  docbook-xml,
  docbook-xsl,
  coreutils,
  gcc-libs,
  buildPackages,
}: let
  version = "127";
in
  mkDerivation {
    pname = "polkit";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Pkaction reports Polkit version 127.";
        "files" = {};
        "input" = "The pkaction command's compiled release identity.";
        "operation" = "Request the version without contacting the authorization daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/pkaction\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"127\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"polkit operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "polkit operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Pkaction rejects the unsupported option.";
        "files" = {};
        "input" = "A pkaction invocation containing an unsupported option.";
        "operation" = "Parse the invalid option without contacting the authorization daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/pkaction\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"polkit rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "polkit rejected invalid input\n";
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
      urls = ["https://github.com/polkit-org/polkit/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-m3vBbwhkedzGJsV1l2VoukqF00KXp1DYqz0uV/bYuYg=";
    };

    buildDeps = [
      meson
      ninja
      pkg-config
      gettext
      perl
      python3
      python3-dbus
      python3-dbusmock
      glib.dev
      glib.tools
      util-linux
      gobject-introspection
      glibWithIntrospection
      gtk-doc
      libxslt
      docbook-xml
      docbook-xsl
      coreutils
    ];
    runtimeDeps = [glib expat linux-pam dbus duktape systemd gcc-libs];
    propagatedDeps = [glib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd polkit-${version}

          # Install into the immutable package while compiling the paths at
          # which the assembled system exposes policy data and privileged
          # helpers.
          sed -i \
            "s|'-DPACKAGE_SYSCONF_DIR=\"@0@\"'.format(pk_prefix / pk_sysconfdir)|'-DPACKAGE_SYSCONF_DIR=\"/etc\"'|" \
            src/polkitbackend/meson.build
          sed -i \
            "s|'-DPACKAGE_DATA_DIR=\"@0@\"'.format(pk_prefix / pk_datadir)|'-DPACKAGE_DATA_DIR=\"/run/current-system/sw/share\"'|" \
            src/polkitbackend/meson.build
          sed -i \
            's|PACKAGE_PREFIX "/lib/polkit-1/|"/run/wrappers/bin/|' \
            src/polkitagent/polkitagentsession.c
          sed -i \
            -e "s|sysusers_dir = '/usr/lib/sysusers.d'|sysusers_dir = '$out/lib/sysusers.d'|" \
            -e "s|tmpfiles_dir = '/usr/lib/tmpfiles.d'|tmpfiles_dir = '$out/lib/tmpfiles.d'|" \
            meson.build

          find . -type f -name '*.py' | while read file; do
            if head -1 "$file" | grep -Eq '^#!/usr/bin/(env )?python3'; then
              sed -i '1s|.*|#!${python3}/bin/python3|' "$file"
            fi
          done

          # Keep the helper-spawning policy tests hermetic. The test fixture
          # deliberately invokes success and failure executables by absolute
          # path, so point those paths at AOS coreutils.
          sed -i \
            -e 's|"/bin/true"|"${coreutils}/bin/true"|g' \
            -e 's|"/bin/false"|"${coreutils}/bin/false"|g' \
            test/data/etc/polkit-1/rules.d/10-testing.rules
        '';
      }
      {
        name = "configure";
        script = ''
          export PKG_CONFIG_SYSTEMD_SYSUSERS_DIR="$out/lib/sysusers.d"
          export PKG_CONFIG_SYSTEMD_TMPFILES_DIR="$out/lib/tmpfiles.d"
          export XML_CATALOG_FILES="${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml ${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml"
          meson setup build \
            $mesonFlags \
            --prefix="$out" \
            --sysconfdir=etc \
            --localstatedir=var \
            --buildtype=release \
            -Dsession_tracking=logind \
            -Dsystemdsystemunitdir="$out/lib/systemd/system" \
            -Dpolkitd_user=polkitd \
            -Dauthfw=pam \
            -Dos_type=lfs \
            -Dtests=true \
            -Dintrospection=true \
            -Dgtk_doc=true \
            -Dman=true \
            -Dgettext=true
        '';
      }
      {
        name = "build";
        script = ''
          export GI_GIR_PATH=${glibWithIntrospection}/share/gir-1.0
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          export GI_GIR_PATH=${glibWithIntrospection}/share/gir-1.0
          export PYTHONPATH=${python3-dbusmock}/lib/python3.14/site-packages:${python3-dbus}/lib/python3.14/site-packages:${buildPackages.meson}/lib/python3/site-packages
          ${python3}/bin/python3 -m mesonbuild.mesonmain \
            test -C build --print-errorlogs
        '';
      }
      {
        name = "install";
        script = ''
          export GI_GIR_PATH=${glibWithIntrospection}/share/gir-1.0
          PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
            ninja -C build install

          # Privilege is granted only by the runtime wrapper module.
          chmod u-s "$out/bin/pkexec" "$out/lib/polkit-1/polkit-agent-helper-1"
          "$out/bin/pkaction" --version
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-polkit";
        library = self;
        includes = [
          "${self}/include/polkit-1"
          "${glib.dev}/include/glib-2.0"
          "${glib.dev}/lib/glib-2.0/include"
        ];
        extraDeps = [glib glib.dev];
        libs = ["-lpolkit-gobject-1" "-lgobject-2.0" "-lglib-2.0"];
        testSource = ''
          #include <polkit/polkit.h>

          int main(void) {
              PolkitSubject *subject = polkit_unix_process_new_for_owner(1, 0, 0);
              g_object_unref(subject);
              return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-polkit";
        tool = self;
        command = "pkaction --version && pkcheck --version";
      };
    };

    meta = {
      description = "Framework for controlling system-wide privileges";
      homepage = "https://github.com/polkit-org/polkit";
      license = "LGPL-2.0-or-later";
      mainProgram = "pkcheck";
    };
  }
