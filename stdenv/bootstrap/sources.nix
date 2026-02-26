# stdenv/bootstrap/sources.nix — Centralized source definitions
#
# Single source of truth for all bootstrap package versions, URLs, and hashes.
# Both TCC-compiled (stage 4) and GCC-compiled (stage 5) builds reference
# these entries, ensuring identical source versions throughout the bootstrap.
#
{
  bash = {
    version = "2.05b";
    url = "https://mirrors.kernel.org/gnu/bash/bash-2.05b.tar.gz";
    # tarballHash: flat hash for builtin:fetchurl (kaem build)
    tarballHash = "sha256-ugPUEpmMxUvQsPLWwyEAln0xNwmK/9wtMubnwRsWP+Q=";
    # sha256: unpacked hash for builtins.fetchTarball (bash-builder stages)
    sha256 = "sha256-TsSxfIbg+xOIMfOVzjszOKbEG7Hj4b19D8oqMg0ek0g=";
  };

  gnumake = {
    version = "3.79.1";
    url = "https://mirrors.kernel.org/gnu/make/make-3.79.1.tar.gz";
    sha256 = "sha256-0ATEyqEsirZxYPdk1ifsRqXp1KUWPLrtGgAmw/QYgYI=";
  };

  sed = {
    version = "4.0.9";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.0.9.tar.gz";
    sha256 = "sha256-k2YhQtIAYx0rPNFootM1VKppNsaoJsaTFpJ34SSPkIk=";
  };

  grep = {
    version = "2.4";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.4.tar.gz";
    sha256 = "sha256-v9xxK5dLi3FxvpCbRjPorpK+bPNcAXwj/jgX4eslWxI=";
  };

  patch = {
    version = "2.5.9";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.9.tar.gz";
    sha256 = "sha256-LiyweTmLg8H9PeHjwfJAPO34y//rF+mD+7IdsozDzLM=";
  };

  coreutils = {
    version = "5.0";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-5.0.tar.gz";
    sha256 = "sha256-VtfMrIYHZZ4YT21zYxctKfFEvGXDKerxOvCO7mmOPlA=";
  };

  diffutils = {
    version = "2.7";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-2.7.tar.gz";
    sha256 = "sha256-AdsuvMN3btb0J5q9xxJs2zrSSO8+V7gd7yBMO4LVpxs=";
  };

  gzip = {
    version = "1.2.4";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.2.4.tar.gz";
    sha256 = "sha256-s2cf/BeNFNWkTRjMvJU2F9PKGNrLwxWK3RtK67AcXNo=";
  };

  tar = {
    version = "1.12";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.12.tar.gz";
    sha256 = "sha256-5LM4ezQqPKZECBwzpVjxpe923L358cGsdH6jHyCdpLY=";
  };

  findutils = {
    version = "4.1";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.1.tar.gz";
    sha256 = "sha256-XVes58P0wJTpxxncOaQRSGJnE8a5lTOAmCxPoPo0R4A=";
  };

  gawk = {
    version = "3.0.6";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.0.6.tar.gz";
    sha256 = "sha256-KxjOpC2yN3DtY3HOcoe+/Ze71nE+BegC8mYxld6qu7c=";
  };

  binutils = {
    version = "2.20.1a";
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.20.1a.tar.bz2";
    sha256 = "sha256-CZWJSyqtTcbeB9I4Htimq4qTM7AiZlu2qV4x3xlnGH4=";
  };

  gcc = {
    version = "2.95.3";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-2.95.3/gcc-core-2.95.3.tar.gz";
    sha256 = "sha256-GTd54N/wNHJMk9wQoDSAr6m9mzF23/mqSNSHNELDWfk=";
  };

  glibc = {
    version = "2.2.5";
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.2.5.tar.gz";
    sha256 = "sha256-uLegtbw5wiSzpPsQdgKEGlzYGlw/iTrDIHC6jFIvkpY=";
    linuxthreads = {
      url = "https://mirrors.kernel.org/gnu/glibc/glibc-linuxthreads-2.2.5.tar.gz";
      sha256 = "sha256-shPjUdeUYDsvDgCXWCvYF5uSnI+4+sRmaESf9vQKLtg=";
    };
  };

  linuxHeaders = {
    version = "4.14.336";
    url = "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.14.336.tar.xz";
    sha256 = "sha256-yY2ahTYhcwjUg26E6/kPfer4SQSxldZ1y63Eo39yCDo=";
  };
}
