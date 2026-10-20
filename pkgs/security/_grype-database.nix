##! Reviewed schema-v6 advisory corpus, separate from the scanner runtime closure
{fetchurl}:
fetchurl {
  name = "grype-db-2026-10-02.tar.zst";
  urls = [
    "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-10-02T00:35:12Z_1790922713.tar.zst"
  ];
  # Authenticated by https://grype.anchore.io/databases/v6/latest.json on
  # 2026-10-02; the upstream manifest records built=2026-10-02T06:31:53Z.
  # Delivery CI must keep freshness validation enabled when importing it.
  hash = "sha256-PDaN9cNiT+CDrWRso75ZUlc53+nKpLbRTH8lLRVfvZg=";
}
