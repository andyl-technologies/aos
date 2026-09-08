##! Exercises additional A-G tools through offline source and image formats.
{testing}: {
  autoconf = testing.mkQualificationPackageProbe {
    name = "autoconf";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "autoconf";
      primary = {
        input = "A configure.ac declaring a boolean feature option.";
        operation = "Generate configure, then execute it with the feature enabled.";
        expected = "Autoconf generates a runnable script that accepts the declared option.";
        files."configure.ac" = ''
          AC_INIT([aos-probe], [1.0])
          AC_CONFIG_SRCDIR([configure.ac])
          AC_ARG_ENABLE([feature], [AS_HELP_STRING([--enable-feature], [enable probe feature])])
          AS_IF([test "x$enable_feature" != xyes], [AC_MSG_ERROR([feature was not enabled])])
          AC_MSG_NOTICE([autoconf feature passed])
          AC_OUTPUT
        '';
        steps = [
          {
            argv = ["@out@/bin/autoconf" "--output=configure" "configure.ac"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@bash@" "configure" "--enable-feature"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "An Autoconf source with an unterminated M4 quotation.";
        operation = "Generate configure from the malformed macro source.";
        expected = "Autoconf rejects the source with a failure status.";
        files."invalid.ac" = "AC_INIT([aos-probe], [1.0])\nAC_MSG_NOTICE([unterminated)\nAC_OUTPUT\n";
        steps = [
          {
            argv = ["@out@/bin/autoconf" "--output=configure" "invalid.ac"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  automake = testing.mkQualificationPackageProbe {
    name = "automake";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "automake";
      primary = {
        input = "A minimal foreign Automake project containing one C program.";
        operation = "Generate Makefile.in and required helper scripts with automake.";
        expected = "Automake accepts the declarations and emits Makefile.in.";
        files."configure.ac" = ''
          AC_INIT([aos-probe], [1.0])
          AM_INIT_AUTOMAKE([foreign])
          AC_PROG_CC
          AC_CONFIG_FILES([Makefile])
          AC_OUTPUT
        '';
        files."Makefile.am" = ''
          bin_PROGRAMS = probe
          probe_SOURCES = probe.c
        '';
        files."probe.c" = "int main(void) { return 0; }\n";
        steps = [
          {
            argv = ["@out@/bin/aclocal" "--system-acdir=@out@/share/aclocal"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/automake" "--add-missing" "--foreign"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A Makefile.am containing text that is not an assignment or rule.";
        operation = "Generate Makefile.in from the malformed declaration.";
        expected = "Automake rejects the invalid syntax with status 1.";
        files."configure.ac" = ''
          AC_INIT([aos-probe], [1.0])
          AM_INIT_AUTOMAKE([foreign])
          AC_CONFIG_FILES([Makefile])
          AC_OUTPUT
        '';
        files."Makefile.am" = "this is not automake syntax\n";
        steps = [
          {
            argv = ["@out@/bin/automake" "--add-missing" "--foreign"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  bind = testing.mkQualificationPackageProbe {
    name = "bind";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "bind";
      primary = {
        input = "A complete authoritative DNS zone with SOA, NS, and address records.";
        operation = "Load and validate the zone with named-checkzone.";
        expected = "BIND accepts the zone and its serial and record relationships.";
        files."example.zone" = ''
          $ORIGIN example.test.
          @ 3600 IN SOA ns.example.test. hostmaster.example.test. (
            1 3600 600 86400 60
          )
          @   IN NS ns.example.test.
          ns  IN A  192.0.2.53
          www IN A  192.0.2.42
        '';
        steps = [
          {
            argv = ["@out@/bin/named-checkzone" "example.test" "example.zone"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A DNS zone containing an IPv4 octet outside the valid range.";
        operation = "Load the malformed zone with named-checkzone.";
        expected = "BIND rejects the invalid address with status 1.";
        files."invalid.zone" = ''
          $ORIGIN example.test.
          @ 3600 IN SOA ns.example.test. hostmaster.example.test. (1 3600 600 86400 60)
          @  IN NS ns.example.test.
          ns IN A 999.0.2.53
        '';
        steps = [
          {
            argv = ["@out@/bin/named-checkzone" "example.test" "invalid.zone"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  btrfs-progs = testing.mkQualificationPackageProbe {
    name = "btrfs-progs";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "btrfs-progs";
      primary = {
        input = "A sparse 128 MiB regular file.";
        operation = "Create a Btrfs filesystem and inspect its superblock.";
        expected = "Mkfs writes a valid filesystem that dump-super can decode.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "with open('filesystem.img', 'wb') as image: image.truncate(128 * 1024 * 1024)"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/mkfs.btrfs" "--force" "filesystem.img"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/btrfs" "inspect-internal" "dump-super" "filesystem.img"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A sparse one MiB file, below Btrfs's minimum device size.";
        operation = "Attempt to create a Btrfs filesystem on the undersized file.";
        expected = "Mkfs rejects the device size with status 1.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "with open('undersized.img', 'wb') as image: image.truncate(1024 * 1024)"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/mkfs.btrfs" "--force" "undersized.img"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  checkpolicy = testing.mkQualificationPackageProbe {
    name = "checkpolicy";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "checkpolicy";
      primary = {
        input = "A loadable SELinux policy module granting one file permission.";
        operation = "Compile the module source with checkmodule.";
        expected = "Checkmodule accepts the declarations and emits binary policy.";
        files."probe.te" = ''
          module aos_probe 1.0;

          require {
              type init_t;
              class file read;
          }

          allow init_t init_t:file read;
        '';
        steps = [
          {
            argv = ["@out@/bin/checkmodule" "-M" "-m" "-o" "probe.mod" "probe.te"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A policy module whose allow rule omits its terminating semicolon.";
        operation = "Compile the malformed module source with checkmodule.";
        expected = "Checkmodule rejects the syntax error with status 1.";
        files."invalid.te" = ''
          module aos_bad 1.0;
          require { type init_t; class file read; }
          allow init_t init_t:file read
        '';
        steps = [
          {
            argv = ["@out@/bin/checkmodule" "-M" "-m" "-o" "invalid.mod" "invalid.te"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  chrony = testing.mkQualificationPackageProbe {
    name = "chrony";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "chrony";
      primary = {
        input = "An offline chronyd configuration with a server and step threshold.";
        operation = "Parse and print the configuration without starting chronyd.";
        expected = "Chronyd accepts and normalizes all directives.";
        files."chrony.conf" = ''
          server 192.0.2.1 iburst offline
          makestep 1.0 3
          driftfile @work@/primary/chrony.drift
        '';
        steps = [
          {
            argv = ["@out@/sbin/chronyd" "-p" "-f" "chrony.conf"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A chronyd configuration containing an unknown directive.";
        operation = "Parse the malformed configuration without starting chronyd.";
        expected = "Chronyd rejects the unknown directive with status 1.";
        files."invalid.conf" = "aos_unknown_directive 42\n";
        steps = [
          {
            argv = ["@out@/sbin/chronyd" "-p" "-f" "invalid.conf"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  cryptsetup = testing.mkQualificationPackageProbe {
    name = "cryptsetup";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "cryptsetup";
      primary = {
        input = "A sparse 16 MiB file and a fixed passphrase.";
        operation = "Format a LUKS2 container and inspect its metadata.";
        expected = "Cryptsetup creates and recognizes the encrypted-container header.";
        files."key" = "correct horse battery staple\n";
        steps = [
          {
            argv = ["@python@" "-c" "with open('container.img', 'wb') as image: image.truncate(16 * 1024 * 1024)"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/cryptsetup" "luksFormat" "--batch-mode" "--type=luks2" "--key-file=key" "container.img"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/cryptsetup" "luksDump" "container.img"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A LUKS2 container and a passphrase different from the enrolled key.";
        operation = "Test the wrong passphrase without creating a device mapping.";
        expected = "Cryptsetup rejects the passphrase with status 2.";
        files = {
          "key" = "correct horse battery staple\n";
          "wrong-key" = "incorrect passphrase\n";
        };
        steps = [
          {
            argv = ["@python@" "-c" "with open('container.img', 'wb') as image: image.truncate(16 * 1024 * 1024)"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/cryptsetup" "luksFormat" "--batch-mode" "--type=luks2" "--key-file=key" "container.img"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/cryptsetup" "open" "--test-passphrase" "--key-file=wrong-key" "container.img"];
            exit_code = 2;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  docutils = testing.mkQualificationPackageProbe {
    name = "docutils";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "docutils";
      primary = {
        input = "A reStructuredText document with a heading and emphasized text.";
        operation = "Parse and transform the document to Docutils pseudo-XML.";
        expected = "Docutils emits a successful document-tree representation.";
        files."document.rst" = ''
          Heading
          =======

          A **bold** word.
        '';
        steps = [
          {
            argv = ["@out@/bin/rst2pseudoxml" "document.rst"];
            exit_code = 0;
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A reStructuredText document containing an unknown directive.";
        operation = "Parse the document with errors configured to halt transformation.";
        expected = "Docutils rejects the unknown directive with status 1.";
        files."invalid.rst" = ".. aos-unknown-directive:: value\n";
        steps = [
          {
            argv = ["@out@/bin/rst2pseudoxml" "--halt=2" "invalid.rst"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  dwarves = testing.mkQualificationPackageProbe {
    name = "dwarves";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "dwarves";
      primary = {
        input = "A C object containing debug information for a named structure.";
        operation = "Compile the object and inspect the structure layout with pahole.";
        expected = "Pahole finds and decodes the requested DWARF type.";
        files."layout.c" = ''
          struct ProbeLayout {
              char tag;
              long value;
          };

          struct ProbeLayout qualification_layout;
        '';
        steps = [
          {
            argv = ["@cc@" "-g" "-c" "layout.c" "-o" "layout.o"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/pahole" "--class_name=ProbeLayout" "layout.o"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A text file that is not an ELF object.";
        operation = "Inspect the malformed object with pahole.";
        expected = "Pahole rejects the file with status 1.";
        files."invalid.o" = "not an ELF object\n";
        steps = [
          {
            argv = ["@out@/bin/pahole" "invalid.o"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  e2fsprogs = testing.mkQualificationPackageProbe {
    name = "e2fsprogs";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "e2fsprogs";
      primary = {
        input = "A request for a 4 MiB ext2 filesystem image.";
        operation = "Create the filesystem and check it read-only with e2fsck.";
        expected = "E2fsprogs creates a consistent filesystem image.";
        files = {};
        steps = [
          {
            argv = ["@out@/sbin/mke2fs" "-q" "-t" "ext2" "-F" "filesystem.img" "4096"];
            exit_code = 0;
          }
          {
            argv = ["@out@/sbin/e2fsck" "-f" "-n" "filesystem.img"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A request for an ext2 filesystem containing only one block.";
        operation = "Attempt to construct the undersized filesystem.";
        expected = "Mke2fs rejects the invalid geometry with status 1.";
        files = {};
        steps = [
          {
            argv = ["@out@/sbin/mke2fs" "-q" "-t" "ext2" "-F" "undersized.img" "1"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  erofs-utils = testing.mkQualificationPackageProbe {
    name = "erofs-utils";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "erofs-utils";
      primary = {
        input = "A directory tree containing a fixed text payload.";
        operation = "Build an EROFS image and validate it with fsck.erofs.";
        expected = "The checker accepts the generated read-only filesystem.";
        files."tree/payload.txt" = "EROFS qualification payload\n";
        steps = [
          {
            argv = ["@out@/bin/mkfs.erofs" "filesystem.erofs" "tree"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/fsck.erofs" "filesystem.erofs"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A text file without an EROFS superblock.";
        operation = "Validate the malformed image with fsck.erofs.";
        expected = "The checker rejects the image with status 1.";
        files."invalid.erofs" = "not an EROFS filesystem\n";
        steps = [
          {
            argv = ["@out@/bin/fsck.erofs" "invalid.erofs"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  gettext = testing.mkQualificationPackageProbe {
    name = "gettext";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "gettext";
      primary = {
        input = "A portable-object catalog with one translated message.";
        operation = "Compile the PO source and decode the resulting MO catalog.";
        expected = "Gettext accepts both source and compiled catalog representations.";
        files."catalog.po" = ''
          msgid ""
          msgstr ""
          "Content-Type: text/plain; charset=UTF-8\n"

          msgid "hello"
          msgstr "qualified"
        '';
        steps = [
          {
            argv = ["@out@/bin/msgfmt" "--check" "--output-file=catalog.mo" "catalog.po"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/msgunfmt" "--no-wrap" "catalog.mo"];
            exit_code = 0;
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A portable-object catalog with an unterminated message string.";
        operation = "Compile the malformed catalog with msgfmt.";
        expected = "Msgfmt rejects the syntax error with status 1.";
        files."invalid.po" = "msgid \"hello\"\nmsgstr \"unterminated\n";
        steps = [
          {
            argv = ["@out@/bin/msgfmt" "--check" "--output-file=invalid.mo" "invalid.po"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  gnupg = testing.mkQualificationPackageProbe {
    name = "gnupg";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "gnupg";
      primary = {
        input = "A fixed binary payload.";
        operation = "ASCII-armor the payload with GnuPG, then decode the armor.";
        expected = "The decoded artifact exactly reproduces the original bytes.";
        files."payload.bin" = "GnuPG qualification payload\n";
        steps = [
          {
            argv = ["@out@/bin/gpg" "--batch" "--yes" "--enarmor" "--output" "payload.asc" "payload.bin"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/gpg" "--batch" "--yes" "--dearmor" "--output" "recovered.bin" "payload.asc"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
        artifacts = [
          {
            path = "recovered.bin";
            text = "GnuPG qualification payload\n";
          }
        ];
      };
      bad_input = {
        input = "An ASCII-armored block containing invalid Base64 data.";
        operation = "Decode the malformed armor with GnuPG.";
        expected = "GnuPG rejects the armored data with status 2.";
        files."invalid.asc" = ''
          -----BEGIN PGP ARMORED FILE-----

          %%%not-base64%%%
          -----END PGP ARMORED FILE-----
        '';
        steps = [
          {
            argv = ["@out@/bin/gpg" "--batch" "--yes" "--dearmor" "--output" "invalid.bin" "invalid.asc"];
            exit_code = 2;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
