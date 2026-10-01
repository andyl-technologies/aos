##! Reviewed schema-v6 advisory corpus, separate from the scanner runtime closure
{fetchurl}:
fetchurl {
  name = "grype-db-2026-09-28.tar.zst";
  urls = [
    "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-09-28T00:37:02Z_1790577750.tar.zst"
  ];
  # Authenticated by https://grype.anchore.io/databases/v6/latest.json on
  # 2026-09-28; the upstream manifest records built=2026-09-28T06:42:30Z.
  # Delivery CI must keep freshness validation enabled when importing it.
  hash = "sha256-3yMWCvbi1nzzpbbMvH4d4MLE7NFcvX3GEn70+QEOpxQ=";
}
