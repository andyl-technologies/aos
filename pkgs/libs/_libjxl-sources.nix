##! JPEG XL release sources and exact upstream submodule revisions.
{fetchurl}: let
  githubSource = repository: revision: hash:
    fetchurl {
      urls = ["https://github.com/${repository}/archive/${revision}.tar.gz"];
      inherit hash;
    };
in {
  version = "0.12.0";
  src = githubSource "libjxl/libjxl" "v0.12.0" "14n9rm2vy46fa7azpaqzjansiknpnql579wxalgh3r0bldlvxs83";

  # These revisions come from the release's gitlinks. Test fixtures remain
  # paired with the codec revision rather than following upstream HEAD.
  skcms = githubSource "google/skcms" "96d9171c94b937a1b5f0293de7309ac16311b722" "09s6sy54k432w4d1cia91jicj8qysq9zg7yf5dn4zh5pl2xvbd4v";
  sjpeg = githubSource "webmproject/sjpeg" "94e0df6d0f8b44228de5be0ff35efb9f946a13c9" "0z92w17a37diqipc0scqiia5mkamxhily10ypzm799j5wxzr355c";
  googletest = githubSource "google/googletest" "6910c9d9165801d8827d628cb72eb7ea9dd538c5" "028zkz1xy1v4xs4djm91lja6648psxvmsrki76ygqh9qgyz23qmx";
  testdata = githubSource "libjxl/testdata" "73695d303670c90e4d506ea89d9901b081385089" "0083ck9cimiznf0amyn93j9rgvic7ip6h7pdy4s3sl8i1s4mh2iq";
}
