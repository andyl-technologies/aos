##! Target-library inputs for the selected public Nix C++ library consumers.
##!
##! Headers and pkg-config metadata describe the target libraries, not native
##! build tools. Nix does not propagate its public/private pkg-config deps.
{
  nix,
  nlohmann-json,
  boost,
  libarchive,
  openssl,
  libsodium,
  brotli,
  curl,
  libseccomp,
  sqlite,
  gcc-libs,
}: [
  nix
  nix.dev
  nlohmann-json
  boost.dev
  libarchive
  openssl
  libsodium
  brotli
  curl
  libseccomp
  sqlite
  gcc-libs
]
