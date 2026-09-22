##! Pinned GIFLIB source including fixes newer than the 6.1.3 release.
{
  buildPackages,
  stdenv,
}: let
  revision = "a8e3114a81f0987a61d06a41c99fd7cc2d58232c";
in
  builtins.derivation {
    name = "giflib-source-${revision}";
    system = stdenv.buildPlatform.system;
    builder = "${buildPackages.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -euo pipefail
        export PATH="${buildPackages.git}/bin:${buildPackages.coreutils}/bin"
        export GIT_SSL_CAINFO="${buildPackages.ca-certificates}/etc/ssl/certs/ca-bundle.crt"
        export HOME="$TMPDIR"
        git init checkout
        cd checkout
        git remote add origin https://git.code.sf.net/p/giflib/code
        git fetch --depth=1 origin ${revision}
        git checkout --detach FETCH_HEAD
        test "$(git rev-parse HEAD)" = ${revision}
        rm -rf .git
        cp -R . "$out"
      ''
    ];
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";
    outputHash = "sha256-0LCfDlSYOj8nLBaZ26OKcLtNvVU7lkoVgpn5P9Q9cjA=";
  }
