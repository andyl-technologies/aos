##! Audit — Linux auditing framework
{
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
  linux-headers,
  libcap,
}: let
  version = "4.0.2";
in
  mkDerivation {
    pname = "audit";
    inherit version;

    src = fetchurl {
      urls = [
        "https://people.redhat.com/sgrubb/audit/audit-${version}.tar.gz"
      ];
      hash = "sha256-1dG11Q7kotDReHW8aua9an1bNNlVfqhHo5+uxTH6qgo=";
    };

    buildDeps = [gnumake linux-headers];
    runtimeDeps = [libcap];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd audit-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # IPX support was removed from Linux kernel headers (6.x+).
          # Define the missing struct so auparse/interpret.c compiles.
          sed -i '1i\
          #ifndef _LINUX_IPX_H\
          #define _LINUX_IPX_H\
          #include <stdint.h>\
          struct sockaddr_ipx { short sipx_family; uint16_t sipx_port; uint32_t sipx_network; };\
          #endif' auparse/interpret.c

          # auparse/Makefile.in and lib/Makefile.in both compile
          # gen_tables.c into `<dir>/gen_flagtabs_h-gen_tables.o` with
          # *different* `-DTABLE_H=` macros. Automake happens to write
          # both object files to the SAME path: `lib/gen_flagtabs_h-gen_tables.o`
          # (auparse/Makefile.in writes it at `../lib/...`). The second
          # compile stomps the first, so the `gen_flagtabs_h` binary that
          # eventually generates lib/flagtabs.h ends up linked against
          # auparse's flagtab.h (RHEL4 record flags: "follow", "directory",
          # "continue"…) instead of lib's (filter names: "task", "exit",
          # "user", "exclude", "filesystem"). The runtime effect is that
          # `audit_name_to_flag("exit")` returns -1, so `auditctl -a always,exit`
          # sends `rule->flags = -1 (0xFFFFFFFF)` on the netlink wire and
          # the kernel rejects every syscall rule with EINVAL.
          #
          # Fix: rename auparse's copy of that object file so it lands
          # inside auparse/ and doesn't collide with lib/'s copy.
          sed -i \
            -e 's|../lib/gen_flagtabs_h-gen_tables\.\$(OBJEXT)|gen_flagtabs_h-gen_tables.\$(OBJEXT)|g' \
            -e 's|../lib/gen_flagtabs_h-gen_tables\.o|gen_flagtabs_h-gen_tables.o|g' \
            -e 's|../lib/\$(DEPDIR)/gen_flagtabs_h-gen_tables|\$(DEPDIR)/gen_flagtabs_h-gen_tables|g' \
            auparse/Makefile.in
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --sbindir=$out/sbin \
            --runstatedir=/run \
            --disable-zos-remote \
            --without-python \
            --without-python3 \
            --without-golang \
            ${
            if stdenv.hostPlatform.isAarch64
            then "--with-aarch64"
            else ""
          } \
            --enable-shared \
            --disable-static
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "Linux Audit — userspace auditing framework";
      homepage = "https://people.redhat.com/sgrubb/audit/";
      license = "LGPL-2.1-or-later";
    };
  }
