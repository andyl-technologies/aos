##! Pinned sources for the Linux-hosted GNU cross toolchain.
{
  binutils = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.41.tar.xz";
    sha256 = "0shr30dgkifjzlgqgsf0f0nmb8ffbqrkh93w54bnz4sk4v0s7lgi";
  };

  gcc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-14.3.0/gcc-14.3.0.tar.xz";
    sha256 = "18slj57b3zizzmc1bn4b6x8rygijfjjmwfzipdvyyzrbspaa5x21";
  };

  gmp = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfr = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  isl = builtins.fetchTarball {
    url = "https://downloads.sourceforge.net/project/libisl/isl-0.26.tar.xz";
    sha256 = "01krva4ax8zvi365akpzdv8r3a3gdl8sqcdgsg2kxmcy810gay0k";
  };

  glibc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.39.tar.xz";
    sha256 = "0zr0lk75rvkxp0xplfsggaj4fcv1xjpsvg5qrvp6yifim77q2mn0";
  };

  linux = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.tar.xz";
    sha256 = "1dnxa60qxkjb8yqadbb1aglj8p57pqkmmg8ikdmlqxlb4vh7vnz3";
  };
}
