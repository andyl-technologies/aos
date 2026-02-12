# sbsigntools — UEFI Secure Boot signing tools
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
}:

let
  version = "0.9.5";
in
mkDerivation {
  pname = "sbsigntools";
  inherit version;

  src = fetchurl {
    urls = [
      "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git/snapshot/sbsigntools-${version}.tar.gz"
    ];
    hash = "sha256-ojI+VL5tF/UM6zJTym7QYxcaW8tweb+llACM0q63/eo=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ openssl ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd sbsigntools-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out
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
    description = "sbsigntools — UEFI Secure Boot signing tools";
    homepage = "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git";
    license = "GPL-3.0-only";
  };
}
