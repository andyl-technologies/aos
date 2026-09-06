##! sudo — Delegated privilege execution and auditing
{
  mkDerivation,
  fetchurl,
  gnumake,
  linux-pam,
  audit,
  libselinux,
  openldap,
  cyrus-sasl,
  openssl,
  zlib,
  coreutils,
}: let
  version = "1.9.17p2";
in
  mkDerivation {
    pname = "sudo";
    inherit version;

    src = fetchurl {
      urls = ["https://www.sudo.ws/dist/sudo-${version}.tar.gz"];
      hash = "sha256-SjihqzrbEZklftwqfEor1xRmXrYFsENohDsG2tos/Ps=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [linux-pam audit libselinux openldap cyrus-sasl openssl zlib];
    propagatedDeps = [];
    configureFlags = builtins.concatStringsSep " " [
      "--with-env-editor"
      "--with-editor=/run/current-system/sw/bin/vi"
      "--with-rundir=/run/sudo"
      "--with-vardir=/var/db/sudo"
      "--with-logpath=/var/log/sudo.log"
      "--with-iologdir=/var/log/sudo-io"
      "--with-sendmail=/run/current-system/sw/bin/sendmail"
      "--with-pam"
      "--with-linux-audit"
      "--with-selinux"
      "--with-ldap"
      "--enable-zlib=system"
      "--enable-tmpfiles.d=no"
    ];

    postPatch = ''
      # Privilege is assigned to a runtime wrapper by the system module.
      sed -i 's/04755/0755/g' src/Makefile.in plugins/sudoers/Makefile.in
    '';

    postConfigure = ''
      cat >> pathnames.h <<'EOF'
      #undef _PATH_MV
      #define _PATH_MV "${coreutils}/bin/mv"
      EOF

      # The sandbox's user namespace reports uid 0 but does not permit chown on
      # store outputs. Ownership is applied to runtime wrappers at activation.
      find . -name Makefile -exec sed -i 's/^INSTALL_OWNER =.*$/INSTALL_OWNER =/' {} +

      installFlags="INSTALL_OWNER= sudoers_uid=0 sudoers_gid=0 \
        sysconfdir=$out/etc rundir=$TMPDIR/run vardir=$TMPDIR/var DESTDIR=/"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-sudo";
        tool = self;
        command = "sudo -V > /tmp/sudo-version && grep -q 'Sudo version' /tmp/sudo-version && grep -q 'PAM' /tmp/sudo-version && grep -q 'SELinux' /tmp/sudo-version && grep -q 'Linux audit' /tmp/sudo-version && grep -q 'LDAP' /tmp/sudo-version";
      };
    };

    meta = {
      description = "Executes commands as another user under a configurable policy";
      homepage = "https://www.sudo.ws/";
      license = "Sudo AND BSD-2-Clause AND BSD-3-Clause AND Zlib";
      mainProgram = "sudo";
    };
  }
