##! tmux — Terminal multiplexer
{
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gnumake,
  bison,
  pkg-config,
  libevent,
  ncurses,
  utf8proc,
  libutempter,
  systemd,
  glibc-locales,
}: let
  version = "3.6a";
in
  mkDerivation {
    pname = "tmux";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/tmux/tmux/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-zY2X80TNL6qJ5BNYQos62og+THL9fU9DzKyT2uwUQus=";
    };

    buildDeps = [autoconf automake libtool gnumake bison pkg-config];
    runtimeDeps = [libevent ncurses utf8proc libutempter systemd glibc-locales];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd tmux-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          ACLOCAL_PATH="${pkg-config}/share/aclocal" autoreconf -fi
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --sysconfdir=/etc \
            --localstatedir=/var \
            --enable-systemd \
            --enable-sixel \
            --enable-utempter \
            --enable-utf8proc
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-tmux";
        tool = self;
        command = "LOCPATH=${glibc-locales}/lib/locale LC_ALL=C.UTF-8 tmux -V";
        extraDeps = [glibc-locales];
      };
    };

    meta = {
      description = "Terminal multiplexer";
      homepage = "https://tmux.github.io/";
      license = "ISC";
      mainProgram = "tmux";
    };
  }
