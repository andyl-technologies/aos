;;; ANDYL OS -- Configuration System
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; Image-driven TOML configuration with subtree imports.
;;;
;;; Image manifests in images/<name>.toml declare imports (paths under config/).
;;; The config tree under config/ is organized by topic in subdirectories.
;;; Root-level config files (config/*.toml) are always loaded as universal base.
;;;
;;; Namespace rule: file path relative to config/ -> dotted prefix.
;;;   config/versions.toml          -> versions.*
;;;   config/boot/partitions.toml   -> boot.partitions.*
;;;   config/boot/server/kernel-args.toml -> boot.kernel-args.*  (overrides)
;;;
;;; Subtree imports: for import "boot/server", walk config/boot/ then
;;; config/boot/server/.  Files at each level share namespace
;;; <import-root>.<filename>.  Deeper files override shallower ones.
;;;
;;; API:
;;;   (config-ref "versions.toolchain.gcc")        => "13.3.0"
;;;   (config-ref "versions.toolchain.gcc" "12.0") => "13.3.0" (with default)
;;;   (config-version "toolchain" "gcc")           => "13.3.0"
;;;   (config-ref/list "security.ssh.ciphers")     => ("chacha20-..." ...)
;;;   (config-ref/alist "security.sysctl")         => (("net.ipv4..." . "0") ...)

(define-module (andyl config)
  #:use-module (andyl toml)
  #:use-module (ice-9 ftw)
  #:use-module (ice-9 textual-ports)
  #:use-module (srfi srfi-1)
  #:export (config-ref
            config-ref/list
            config-ref/alist
            config-version
            current-image-name
            load-image-config
            %config
            config-data))


;;;
;;; Project root detection
;;;

(define (find-project-root)
  "Find the project root by walking up from this module's file path.
The module lives at channel/andyl/config.scm, so root is three levels up."
  (let ((module-file (or (current-filename)
                         (search-path %load-path "andyl/config.scm"))))
    (if module-file
        (dirname (dirname (dirname module-file)))
        (getcwd))))


;;;
;;; Image name resolution
;;;

(define (current-image-name)
  "Return the current image name from ANDYL_IMAGE env var.
Defaults to \"base\"."
  (or (getenv "ANDYL_IMAGE") "base"))


;;;
;;; String utilities
;;;

(define (toml-file? filename)
  "Return #t if FILENAME ends with .toml."
  (let ((len (string-length filename)))
    (and (> len 5)
         (string=? ".toml" (substring filename (- len 5))))))

(define (strip-toml-extension filename)
  "Remove .toml extension from FILENAME."
  (substring filename 0 (- (string-length filename) 5)))


;;;
;;; Directory scanning
;;;

(define (list-toml-files dir)
  "List .toml filenames in DIR sorted alphabetically.
Returns empty list if DIR doesn't exist."
  (if (and (file-exists? dir)
           (eq? 'directory (stat:type (stat dir))))
      (or (scandir dir toml-file?) '())
      '()))


;;;
;;; Namespace wrapping
;;;

(define (wrap-namespace namespace data)
  "Wrap parsed TOML data under a dotted NAMESPACE.
Example: (wrap-namespace \"boot.partitions\" '((\"esp-mib\" . 1024)))
  => ((\"boot\" . ((\"partitions\" . ((\"esp-mib\" . 1024))))))"
  (let ((keys (string-split namespace #\.)))
    (fold-right (lambda (key inner)
                  (list (cons key inner)))
                data
                keys)))


;;;
;;; Load .toml files from a directory with namespace wrapping
;;;

(define (load-dir-files dir namespace-root)
  "Load all .toml files in DIR.  Each file's data is wrapped under
NAMESPACE-ROOT.FILENAME (sans .toml).  When NAMESPACE-ROOT is empty,
wraps under just FILENAME.  Returns a merged alist."
  (let ((files (list-toml-files dir)))
    (fold (lambda (filename merged)
            (let* ((path (string-append dir "/" filename))
                   (name (strip-toml-extension filename))
                   (namespace (if (string=? namespace-root "")
                                  name
                                  (string-append namespace-root "." name)))
                   (data (parse-toml-file path))
                   (wrapped (wrap-namespace namespace data)))
              (toml-merge merged wrapped)))
          '()
          files)))


;;;
;;; Import processing
;;;

(define (load-import config-dir import-path)
  "Load a subtree import.  For import \"boot/server\":
1. Split into components: (\"boot\" \"server\")
2. Namespace root = first component: \"boot\"
3. Walk config/boot/ -> config/boot/server/
4. At each level, load .toml files wrapped under boot.<filename>
5. Deeper files override shallower (same namespace, higher priority)"
  (let* ((components (string-split import-path #\/))
         (namespace-root (car components)))
    (let loop ((remaining components)
               (current-dir config-dir)
               (merged '()))
      (if (null? remaining)
          merged
          (let* ((next-dir (string-append current-dir "/" (car remaining)))
                 (dir-data (load-dir-files next-dir namespace-root))
                 (new-merged (toml-merge merged dir-data)))
            (loop (cdr remaining) next-dir new-merged))))))


;;;
;;; Main entry point
;;;

(define (load-image-config image-name)
  "Load and merge the complete config tree for IMAGE-NAME.
1. Load root config files (config/*.toml) as universal base
2. Read images/<image-name>.toml for the imports list
3. For each import, walk the subtree and merge
4. Later imports override earlier ones"
  (let* ((root (find-project-root))
         (config-dir (string-append root "/config"))
         (images-dir (string-append root "/images"))
         ;; 1. Universal base: root-level config files
         (base (load-dir-files config-dir ""))
         ;; 2. Load image manifest
         (manifest-path (string-append images-dir "/" image-name ".toml"))
         (manifest (if (file-exists? manifest-path)
                       (parse-toml-file manifest-path)
                       '()))
         (image-section (or (toml-ref manifest "image") '()))
         (imports (if (list? image-section)
                      (let ((imp (assoc "imports" image-section)))
                        (if imp (cdr imp) '()))
                      '())))
    ;; 3. Merge: base -> import1 -> import2 -> ...
    (fold (lambda (import-path merged)
            (let ((import-data (load-import config-dir import-path)))
              (toml-merge merged import-data)))
          base
          (if (list? imports) imports '()))))


;;;
;;; Module-level cached config
;;;

(define %config #f)

(define (config-data)
  "Return the loaded configuration data, loading on first access."
  (unless %config
    (set! %config (load-image-config (current-image-name))))
  %config)

(define (ensure-config)
  "Ensure configuration is loaded."
  (config-data))


;;;
;;; Public API
;;;

(define* (config-ref path #:optional default)
  "Look up a dotted path in the ANDYL OS configuration.
PATH is a dotted string like \"versions.toolchain.gcc\".
Returns DEFAULT (or #f) if not found."
  (let ((data (ensure-config)))
    (or (toml-ref data path)
        default)))

(define* (config-version section key #:optional default)
  "Shorthand for looking up a package version.
Equivalent to (config-ref \"versions.SECTION.KEY\")."
  (config-ref (string-append "versions." section "." key)
              default))

(define* (config-ref/list path #:optional (default '()))
  "Look up a path that should return a list.
Returns DEFAULT if not found or not a list."
  (let ((val (config-ref path)))
    (if (list? val) val default)))

(define* (config-ref/alist path #:optional (default '()))
  "Look up a path that should return an alist (TOML table).
Returns DEFAULT if not found or not an alist."
  (let ((val (config-ref path)))
    (if (and (list? val) (or (null? val) (pair? (car val))))
        val
        default)))
