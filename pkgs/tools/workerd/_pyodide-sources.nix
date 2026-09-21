##! Source inputs pinned by Pyodide 314.0.0 and Emscripten 5.0.3.
{fetchurl}: {
  version = "314.0.0";
  src = fetchurl {
    urls = ["https://github.com/pyodide/pyodide/archive/refs/tags/314.0.0.tar.gz"];
    hash = "12kdn18dcz4kvl5284lz6jwz2grdmi49m9rgd37wb57zldjidak8";
  };
  python = fetchurl {
    urls = ["https://www.python.org/ftp/python/3.14.2/Python-3.14.2.tgz"];
    hash = "13a4rmgp4rcm2lg0yrygjk6n1bsyrpxglsnbpb3f545bmmwf02f6";
  };
  libffi = fetchurl {
    urls = ["https://github.com/libffi/libffi/archive/f08493d249d2067c8b3207ba46693dd858f95db3.tar.gz"];
    hash = "0y2pc6i03n8zyrvrdn3anc9bwrha7s5djbc7xc0bj8cynx3mckhc";
  };
  hiwire = fetchurl {
    urls = ["https://github.com/pyodide/hiwire/archive/6a1e67280a15d929ebeceee54a6358c9c8d5f697.tar.gz"];
    hash = "0g69hp8jbz2z6ak15hwj0kf6zhf66cc44lbm2nyy63cw2i7i8r0d";
  };
  xz = fetchurl {
    urls = ["https://github.com/xz-mirror/xz/releases/download/v5.2.2/xz-5.2.2.tar.gz"];
    hash = "18h2k4jndhzjs8ln3a54qdnfv59y6spxiwh9gpaqniph6iflvpvk";
  };
  zstd = fetchurl {
    urls = ["https://github.com/python/cpython-source-deps/archive/refs/tags/zstd-1.5.7.tar.gz"];
    hash = "13lw95ppxvf6zpknvcypa7d5lqihqpk99k2gzblndx0j1m3m4jzj";
  };
  sqlite = fetchurl {
    urls = ["https://www.sqlite.org/2022/sqlite-autoconf-3390000.tar.gz"];
    hash = "1qh9xpjf3g1vkxzh3wf0mv8bzjgkcmmpz1jfxv6kz0fmdppwl2z9";
  };
  # These are Emscripten's port sources, built for Wasm during the runtime build.
  bzip2 = fetchurl {
    urls = ["https://github.com/emscripten-ports/bzip2/archive/1.0.6.zip"];
    hash = "1inyqnk9i6ram0zrjkbv18n6ahf29wd9q8fiw5f366c7b6yffa4n";
  };
  zlib = fetchurl {
    urls = ["https://github.com/madler/zlib/archive/refs/tags/v1.3.1.tar.gz"];
    hash = "0p6h2i9ajdp46lckdpibfqy4vz5nh5r22bqq96mp41k0ydiqis0p";
  };
}
