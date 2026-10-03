# Rust source pins and Meson overlays shipped by Mesa 26.1.4.
{fetchurl}: [
  {
    directory = "bitflags-2.9.1";
    patchDirectory = "bitflags-2-rs";
    src = fetchurl {
      name = "bitflags-2.9.1.tar.gz";
      urls = ["https://crates.io/api/v1/crates/bitflags/2.9.1/download"];
      hash = "sha256-G45WmF7GLRfpwQAdyJyI7NfcCOR+ul7Hwpx7Xu7N6Wc=";
    };
  }
  {
    directory = "cfg-if-1.0.0";
    patchDirectory = "cfg-if-1-rs";
    src = fetchurl {
      name = "cfg-if-1.0.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/cfg-if/1.0.0/download"];
      hash = "sha256-uvHeQzl2FYi8Bhnjy8ASDuWC67dLU7Tvv3kRe9LaQP0=";
    };
  }
  {
    directory = "equivalent-1.0.1";
    patchDirectory = "equivalent-1-rs";
    src = fetchurl {
      name = "equivalent-1.0.1.tar.gz";
      urls = ["https://crates.io/api/v1/crates/equivalent/1.0.1/download"];
      hash = "sha256-VEOAfW3/aTc9Qzq571N4rY31DKYpjK8V3m5S4kqvVNU=";
    };
  }
  {
    directory = "errno-0.3.12";
    patchDirectory = "errno-0.3-rs";
    src = fetchurl {
      name = "errno-0.3.12.tar.gz";
      urls = ["https://crates.io/api/v1/crates/errno/0.3.12/download"];
      hash = "sha256-zqFO+TVeO+qwY3A6qdqxWv0l8GZ8NBMQweUnS7HQ2hg=";
    };
  }
  {
    directory = "hashbrown-0.14.1";
    patchDirectory = "hashbrown-0.14-rs";
    src = fetchurl {
      name = "hashbrown-0.14.1.tar.gz";
      urls = ["https://crates.io/api/v1/crates/hashbrown/0.14.1/download"];
      hash = "sha256-ff2mKhL1Xa6uUBX4GwuuoUU5HLRSD4bCSPxhXXJkDRI=";
    };
  }
  {
    directory = "indexmap-2.2.6";
    patchDirectory = "indexmap-2-rs";
    src = fetchurl {
      name = "indexmap-2.2.6.tar.gz";
      urls = ["https://crates.io/api/v1/crates/indexmap/2.2.6/download"];
      hash = "sha256-Fo+3Fd2kchXjYJEsCWZJ0j1Yvzkqxi9zkZ6DF0XkDyY=";
    };
  }
  {
    directory = "libc-0.2.171";
    patchDirectory = "libc-0.2-rs";
    src = fetchurl {
      name = "libc-0.2.171.tar.gz";
      urls = ["https://crates.io/api/v1/crates/libc/0.2.171/download"];
      hash = "sha256-wZk3IW6dOqmVbZu438CwyL62BY/E96TcTYUO34aiN9Y=";
    };
  }
  {
    directory = "log-0.4.27";
    patchDirectory = "log-0.4-rs";
    src = fetchurl {
      name = "log-0.4.27.tar.gz";
      urls = ["https://crates.io/api/v1/crates/log/0.4.27/download"];
      hash = "sha256-E9wt81HjICeDof4NRDdfcpX/tASSZ7DzAYNG3BIqHZQ=";
    };
  }
  {
    directory = "once_cell-1.8.0";
    patchDirectory = "once_cell-1-rs";
    src = fetchurl {
      name = "once_cell-1.8.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/once_cell/1.8.0/download"];
      hash = "sha256-aS/LY7ZLF1gCngqW7mPgSc6MWUhYfy9yCN8EYl5fa1Y=";
    };
  }
  {
    directory = "paste-1.0.14";
    patchDirectory = "paste-1-rs";
    src = fetchurl {
      name = "paste-1.0.14.tar.gz";
      urls = ["https://crates.io/api/v1/crates/paste/1.0.14/download"];
      hash = "sha256-3jFFrwgCTeqfqZFPOBoXuPxgNN+wDzqEAT9/9D8p7Uw=";
    };
  }
  {
    directory = "pest-2.8.0";
    patchDirectory = "pest-2-rs";
    src = fetchurl {
      name = "pest-2.8.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/pest/2.8.0/download"];
      hash = "sha256-GY23RTHVjHCjYcQiAe/efiWR6XbVGMr3ZipH3Fcg57Y=";
    };
  }
  {
    directory = "pest_derive-2.8.0";
    patchDirectory = "pest_derive-2-rs";
    src = fetchurl {
      name = "pest_derive-2.8.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/pest_derive/2.8.0/download"];
      hash = "sha256-1yXZz9eeh9zMk0Gi7znRtvY1PWjEszwXf+u+GkAsl8U=";
    };
  }
  {
    directory = "pest_generator-2.8.0";
    patchDirectory = "pest_generator-2-rs";
    src = fetchurl {
      name = "pest_generator-2.8.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/pest_generator/2.8.0/download"];
      hash = "sha256-230Bcmvoq2arMvnfRnrosRSJBmhbvnXILR5l1/Wz+EE=";
    };
  }
  {
    directory = "pest_meta-2.8.0";
    patchDirectory = "pest_meta-2-rs";
    src = fetchurl {
      name = "pest_meta-2.8.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/pest_meta/2.8.0/download"];
      hash = "sha256-f5+DJHBJSQbR/KUyn4q1eRzGC+sjDHSBXf9UHL0rXKA=";
    };
  }
  {
    directory = "proc-macro2-1.0.86";
    patchDirectory = "proc-macro2-1-rs";
    src = fetchurl {
      name = "proc-macro2-1.0.86.tar.gz";
      urls = ["https://crates.io/api/v1/crates/proc-macro2/1.0.86/download"];
      hash = "sha256-XnGejfZl3w0cj7/SOAFXRHNhUdREXsCDa45iiq4QO3c=";
    };
  }
  {
    directory = "quote-1.0.35";
    patchDirectory = "quote-1-rs";
    src = fetchurl {
      name = "quote-1.0.35.tar.gz";
      urls = ["https://crates.io/api/v1/crates/quote/1.0.35/download"];
      hash = "sha256-KR7Jq179k0qvUDpkZsXVJRU10QjudHRyw5d8xazIaO8=";
    };
  }
  {
    directory = "remain-0.2.12";
    patchDirectory = "remain-0.2-rs";
    src = fetchurl {
      name = "remain-0.2.12.tar.gz";
      urls = ["https://crates.io/api/v1/crates/remain/0.2.12/download"];
      hash = "sha256-GtXgESMMrSdNBTJGDFq2mCjqR651aBtCqEFmPv/695Q=";
    };
  }
  {
    directory = "roxmltree-0.20.0";
    patchDirectory = "roxmltree-0.20-rs";
    src = fetchurl {
      name = "roxmltree-0.20.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/roxmltree/0.20.0/download"];
      hash = "sha256-bCC2eTtcL6ZVOyUBVLeNbQ2zfnJwCuNfrZOHpG9IfJc=";
    };
  }
  {
    directory = "rustc-hash-2.1.1";
    patchDirectory = "rustc-hash-2-rs";
    src = fetchurl {
      name = "rustc-hash-2.1.1.tar.gz";
      urls = ["https://crates.io/api/v1/crates/rustc-hash/2.1.1/download"];
      hash = "sha256-NXcD1BNltLJ8WQ4+2R6rsbZj8HxMCECV5gy+1DYt/w0=";
    };
  }
  {
    directory = "rustix-1.1.2";
    patchDirectory = "rustix-1-rs";
    src = fetchurl {
      name = "rustix-1.1.2.tar.gz";
      urls = ["https://crates.io/api/v1/crates/rustix/1.1.2/download"];
      hash = "sha256-zRX4osVVGoTVbv3BzQSQieQJrBmjBy1QN6F/1wcZ/z4=";
    };
  }
  {
    directory = "syn-2.0.87";
    patchDirectory = "syn-2-rs";
    src = fetchurl {
      name = "syn-2.0.87.tar.gz";
      urls = ["https://crates.io/api/v1/crates/syn/2.0.87/download"];
      hash = "sha256-JapM40bQOm3NaN2LQBC8t05U5iyQxXPzlMRurpmroy0=";
    };
  }
  {
    directory = "thiserror-2.0.11";
    patchDirectory = "thiserror-2-rs";
    src = fetchurl {
      name = "thiserror-2.0.11.tar.gz";
      urls = ["https://crates.io/api/v1/crates/thiserror/2.0.11/download"];
      hash = "sha256-1FLyhLc+bXbdNnWKDIaEsdW+MfkridB/1YIhdXMiBvw=";
    };
  }
  {
    directory = "thiserror-impl-2.0.11";
    patchDirectory = "thiserror-impl-2-rs";
    src = fetchurl {
      name = "thiserror-impl-2.0.11.tar.gz";
      urls = ["https://crates.io/api/v1/crates/thiserror-impl/2.0.11/download"];
      hash = "sha256-Jq/BuuqKmJM37rUrbnKgOXgM5Fw+38ycW50RL+6xc8I=";
    };
  }
  {
    directory = "ucd-trie-0.1.6";
    patchDirectory = "ucd-trie-0.1-rs";
    src = fetchurl {
      name = "ucd-trie-0.1.6.tar.gz";
      urls = ["https://crates.io/api/v1/crates/ucd-trie/0.1.6/download"];
      hash = "sha256-7WRikv/IGI746k0eDgFQ+xWlwuEq2bj8GRrnqKfzxLk=";
    };
  }
  {
    directory = "unicode-ident-1.0.12";
    patchDirectory = "unicode-ident-1-rs";
    src = fetchurl {
      name = "unicode-ident-1.0.12.tar.gz";
      urls = ["https://crates.io/api/v1/crates/unicode-ident/1.0.12/download"];
      hash = "sha256-M1S5rD+uH/Z1XLbbU2g622YWNPZ1V5Qt6k+s6+wP7ks=";
    };
  }
  {
    directory = "windows-link-0.2.0";
    patchDirectory = "windows-link-0.2-rs";
    src = fetchurl {
      name = "windows-link-0.2.0.tar.gz";
      urls = ["https://crates.io/api/v1/crates/windows-link/0.2.0/download"];
      hash = "sha256-ReRsBmGrtxgOe5woHbEVMF1JyhcJq4JCrfCWZtIXPGU=";
    };
  }
  {
    directory = "windows-sys-0.61.1";
    patchDirectory = "windows-sys-0.6-rs";
    src = fetchurl {
      name = "windows-sys-0.61.1.tar.gz";
      urls = ["https://crates.io/api/v1/crates/windows-sys/0.61.1/download"];
      hash = "sha256-bxCeQd1KPISJB+uD1aQuqYs3aUlVl0UM9tFTUHsWbw8=";
    };
  }
  {
    directory = "zerocopy-0.8.13";
    patchDirectory = "zerocopy-0.8-rs";
    src = fetchurl {
      name = "zerocopy-0.8.13.tar.gz";
      urls = ["https://crates.io/api/v1/crates/zerocopy/0.8.13/download"];
      hash = "sha256-Z5FKtFHzv9Lmnl6dLvOFhITnB01j8gT9Fm7DkbVN4h0=";
    };
  }
  {
    directory = "zerocopy-derive-0.8.13";
    patchDirectory = "zerocopy-derive-0.8-rs";
    src = fetchurl {
      name = "zerocopy-derive-0.8.13.tar.gz";
      urls = ["https://crates.io/api/v1/crates/zerocopy-derive/0.8.13/download"];
      hash = "sha256-eYjXOkMDyiid8DMWvEkOk0rM83Gva8dFOTzzwsXE8l0=";
    };
  }
]
