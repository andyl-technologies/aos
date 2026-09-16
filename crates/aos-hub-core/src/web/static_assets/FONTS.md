# Hub fonts

Geist Sans and Geist Mono are self-hosted variable WOFF2 fonts. Both use the
SIL Open Font License in [OFL.txt](OFL.txt). The files are vendored UI assets;
neither the build nor the browser fetches fonts from a CDN.

Source: [`vercel/geist-font` at `10dc7658f13c38a474cde201bb09a4617267545b`](https://github.com/vercel/geist-font/tree/10dc7658f13c38a474cde201bb09a4617267545b).

| Local file | Upstream file | SHA-256 |
|---|---|---|
| `Geist-Variable.woff2` | `fonts/Geist/webfonts/Geist[wght].woff2` | `2ffebe993e969069a9789d15164b7715d42491b5835516c5e3b935d5f81b05f1` |
| `GeistMono-Variable.woff2` | `fonts/GeistMono/webfonts/GeistMono[wght].woff2` | `afaacc4c5fbba89d2ebf7a02dc4070208540874592a5504d57175782fe893101` |

The normal faces contain weights 100–900. Sans owns prose and interface text;
Mono owns code, configuration editors, hashes, and machine identifiers. Font
URLs use bounded caching, so replacing the files does not require immutable
URL compatibility.
