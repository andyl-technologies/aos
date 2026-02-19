# stdenv/bootstrap/stage3-sed409.nix — GNU sed 4.0.9 from TCC
#
# Built with TCC + make382. Uses live-bootstrap's custom Makefile.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh.
#
{
  tinycc, # Output of stage2 (TCC 0.9.27 with Mes libc)
  make382, # Output of stage3-make382.nix
  mescc-tools, # Output of stage0 (provides untar, ungz, etc.)
  system ? "x86_64-linux",
}: let
  src = builtins.derivation {
    name = "sed-4.0.9.tar.gz";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.0.9.tar.gz";
    outputHash = "sha256-WQNP4I8FozFLRtD6AWb9mMKBkCbz5pDuY8LjRoKVAb0=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # Custom Makefile for sed (from live-bootstrap)
  sed-makefile = builtins.toFile "sed-Makefile" ''
    CC = tcc
    AR = tcc -ar

    CPPFLAGS = -DENABLE_NLS=0 \
             -DHAVE_FCNTL_H \
             -DHAVE_ALLOCA_H \
             -DSED_FEATURE_VERSION=\"4.0\" \
             -DVERSION=\"4.0.9\" \
             -DPACKAGE=\"sed\"
    CFLAGS = -I . -I lib
    LDFLAGS = -L . -lsed -static

    .PHONY: all

    LIB_SRC = getline getopt1 getopt utils regex obstack strverscmp mkstemp
    LIB_OBJ = $(addprefix lib/, $(addsuffix .o, $(LIB_SRC)))

    SED_SRC = compile execute regexp fmt sed
    SED_OBJ = $(addprefix sed/, $(addsuffix .o, $(SED_SRC)))

    all: sed/sed

    lib/regex.h: lib/regex_.h
    	cp $< $@

    lib/regex.o: lib/regex.h

    libsed.a: $(LIB_OBJ)
    	$(AR) cr $@ $^

    sed/sed: libsed.a $(SED_OBJ)
    	$(CC) $^ $(LDFLAGS) -o $@
  '';

in
  builtins.derivation {
    name = "sed-4.0.9";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${tinycc}/bin/tcc

      cd ''${TMPDIR}
      ''${TOOLS}/ungz --file ${src} --output ''${TMPDIR}/sed.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/sed.tar
      cd ''${TMPDIR}/sed-4.0.9

      # Empty config.h
      ''${TOOLS}/catm config.h

      # Copy in the live-bootstrap Makefile
      ''${TOOLS}/cp ${sed-makefile} ''${TMPDIR}/sed-4.0.9/Makefile

      # Copy regex_.h to regex.h (make needs /bin/sh for cp recipe, so do it here)
      ''${TOOLS}/cp ''${TMPDIR}/sed-4.0.9/lib/regex_.h ''${TMPDIR}/sed-4.0.9/lib/regex.h

      # Compile library objects directly with TCC (bypassing make for shell deps)
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/getline.o lib/getline.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/getopt1.o lib/getopt1.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/getopt.o lib/getopt.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/utils.o lib/utils.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/regex.o lib/regex.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/obstack.o lib/obstack.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/strverscmp.o lib/strverscmp.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o lib/mkstemp.o lib/mkstemp.c

      # Create libsed.a
      ''${CC} -ar cr libsed.a lib/getline.o lib/getopt1.o lib/getopt.o lib/utils.o lib/regex.o lib/obstack.o lib/strverscmp.o lib/mkstemp.o

      # Compile sed objects
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o sed/compile.o sed/compile.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o sed/execute.o sed/execute.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o sed/regexp.o sed/regexp.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o sed/fmt.o sed/fmt.c
      ''${CC} -c -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_ALLOCA_H -DSED_FEATURE_VERSION=\"4.0\" -DVERSION=\"4.0.9\" -DPACKAGE=\"sed\" -I. -Ilib -o sed/sed.o sed/sed.c

      # Link sed
      ''${CC} sed/compile.o sed/execute.o sed/regexp.o sed/fmt.o sed/sed.o -L. -lsed -static -o sed/sed

      # Install
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${TOOLS}/cp sed/sed ''${out}/bin/sed
      ''${TOOLS}/chmod ''${out}/bin/sed

      echo "sed 4.0.9 built successfully"
    '';
  }
  // {
    meta = {
      description = "GNU sed 4.0.9 — built from TCC for bootstrap";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux"];
    };
  }
