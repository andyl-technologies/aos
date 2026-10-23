##! Declares native TLS, SSH and compression libraries shared by host families.
{pkgs}: {
  openssl = {
    package = pkgs.openssl;
    libraryFile = "lib/libssl.so";
    pkgConfigFiles = ["lib/pkgconfig/openssl.pc" "lib/pkgconfig/libssl.pc"];
    pkgConfigDependencies = ["crypto"];
  };
  crypto = {
    package = pkgs.openssl;
    libraryFile = "lib/libcrypto.so";
    pkgConfigFiles = ["lib/pkgconfig/libcrypto.pc"];
  };
  ssh = {
    package = pkgs.libssh2;
    libraryFile = "lib/libssh2.so";
    pkgConfigFiles = ["lib/pkgconfig/libssh2.pc"];
    pkgConfigDependencies = ["crypto" "zlib"];
  };
  zlib = {
    package = pkgs.zlib;
    libraryFile = "lib/libz.so";
    compilerResponseFile = true;
    pkgConfigFiles = ["lib/pkgconfig/zlib.pc"];
  };
  zstd = {
    package = pkgs.zstdStaticMultithread;
    libraryFile = "lib/libzstd.a";
    linkage = "static";
    pkgConfigFiles = ["lib/pkgconfig/libzstd.pc"];
  };
}
