;;; ANDYL OS -- Configuration System Tests
(define-module (andyl tests config)
  #:use-module (srfi srfi-64)
  #:use-module (andyl config)
  #:use-module (andyl toml))

(test-begin "config")

;; TOML parser tests
(test-assert "parse-toml returns alist"
  (list? (parse-toml "[section]\nkey = \"value\"")))

(test-equal "parse-toml basic string"
  "value"
  (toml-ref (parse-toml "[section]\nkey = \"value\"") "section.key"))

(test-equal "parse-toml integer"
  42
  (toml-ref (parse-toml "num = 42") "num"))

(test-equal "parse-toml boolean true"
  #t
  (toml-ref (parse-toml "flag = true") "flag"))

(test-equal "parse-toml boolean false"
  #f
  (toml-ref (parse-toml "flag = false") "flag"))

(test-equal "parse-toml nested table"
  "bar"
  (toml-ref (parse-toml "[a]\n[a.b]\nfoo = \"bar\"") "a.b.foo"))

(test-equal "parse-toml array"
  '(1 2 3)
  (toml-ref (parse-toml "arr = [1, 2, 3]") "arr"))

;; toml-merge tests
(test-equal "toml-merge override"
  "new"
  (toml-ref (toml-merge (parse-toml "key = \"old\"")
                         (parse-toml "key = \"new\""))
            "key"))

(test-equal "toml-merge deep merge"
  "overridden"
  (toml-ref (toml-merge (parse-toml "[a]\nfoo = \"original\"\nbar = \"kept\"")
                         (parse-toml "[a]\nfoo = \"overridden\""))
            "a.foo"))

;; toml-ref with default
(test-equal "toml-ref default when missing"
  "fallback"
  (toml-ref/default (parse-toml "") "missing.path" "fallback"))

;; Config loading tests (requires ANDYL_IMAGE env var)
(test-assert "current-image-name returns string"
  (string? (current-image-name)))

(test-assert "config-data loads without error"
  (begin
    (set! %config #f)  ; Reset cache
    (list? (config-data))))

(test-assert "config-version returns string for gcc"
  (string? (config-version "toolchain" "gcc")))

(test-equal "config-version gcc is 13.3.0"
  "13.3.0"
  (config-version "toolchain" "gcc"))

(test-assert "config-ref returns value for kernel.linux"
  (string? (config-ref "versions.kernel.linux")))

(test-equal "config-ref with default on missing key"
  "default-val"
  (config-ref "nonexistent.key.path" "default-val"))

(test-assert "config-ref/list returns list"
  (list? (config-ref/list "boot.kernel-args.base" '())))

(test-end "config")
