##! acl — POSIX Access Control Lists userspace library and tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  attr,
}: let
  version = "2.3.2";
in
  mkDerivation {
    pname = "acl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.savannah.gnu.org/releases/acl/acl-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/acl/acl-${version}.tar.gz"
      ];
      hash = "sha256-XyvbrWKXB6p9hcYj+ZSqih0t7FWnPeUgW6wL9gWKL3w=";
    };

    buildDeps = [
      gnumake
      gettext
    ];
    runtimeDeps = [attr];
    propagatedDeps = [attr];

    # libacl's variable-length objects use a `char s_str[0]` trailing array
    # (libacl/libobj.h) that __acl_to_any_text fills via `strncpy(text_p, str,
    # size)` with `size` = the remaining malloc'd space. -fstrict-flex-arrays=3
    # narrows `[0]` to a fixed zero-length array, so __builtin_object_size(s_str)
    # is 0 and _FORTIFY_SOURCE's __strncpy_chk aborts ("buffer overflow
    # detected") whenever an ACL is formatted to text — e.g. systemd-tmpfiles
    # applying an `a` (ACL) entry such as `a /var/log/journal`. The write is in
    # fact bounded by the allocation; step down to level 1 (where `[0]` is still
    # honoured as a flexible array) so the check sees the real size. fortify3 and
    # the rest of the hardening stay on. Mirrors the systemd/dbus step-down.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd acl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --disable-nls
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
      description = "POSIX Access Control Lists userspace library and tools";
      homepage = "https://savannah.nongnu.org/projects/acl/";
      license = "LGPL-2.1-or-later";
    };
  }
