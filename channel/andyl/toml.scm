;;; ANDYL OS -- TOML Parser
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; Minimal TOML parser for ANDYL OS configuration files.
;;; Uses Guile's (ice-9 rdelim) and manual recursive descent parsing.
;;; No external dependencies beyond Guile core.
;;;
;;; Supports:
;;;   - Tables: [section] and [section.subsection]
;;;   - Key-value pairs: key = "value"
;;;   - Strings (basic), integers, floats, booleans
;;;   - Arrays: [1, 2, 3] and ["a", "b"]
;;;   - Comments: # line comment
;;;   - Dotted keys: a.b.c = "value"
;;;
;;; Returns a nested alist structure.

(define-module (andyl toml)
  #:use-module (ice-9 rdelim)
  #:use-module (ice-9 regex)
  #:use-module (ice-9 textual-ports)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:export (parse-toml
            parse-toml-file
            toml-ref
            toml-ref/default
            toml-merge))


;;;
;;; String utilities
;;;

(define (string-trim-both str)
  "Remove leading and trailing whitespace from STR."
  (let* ((len (string-length str))
         (start (let loop ((i 0))
                  (if (and (< i len) (char-whitespace? (string-ref str i)))
                      (loop (+ i 1))
                      i)))
         (end (let loop ((i (- len 1)))
                (if (and (>= i start) (char-whitespace? (string-ref str i)))
                    (loop (- i 1))
                    (+ i 1)))))
    (if (>= start end)
        ""
        (substring str start end))))

(define (string-trim-left str)
  "Remove leading whitespace from STR."
  (let* ((len (string-length str))
         (start (let loop ((i 0))
                  (if (and (< i len) (char-whitespace? (string-ref str i)))
                      (loop (+ i 1))
                      i))))
    (if (= start 0) str (substring str start))))

(define (string-prefix? prefix str)
  "Return #t if STR starts with PREFIX."
  (let ((plen (string-length prefix))
        (slen (string-length str)))
    (and (<= plen slen)
         (string=? prefix (substring str 0 plen)))))

(define (string-contains-char str ch)
  "Return the index of CH in STR, or #f."
  (let ((len (string-length str)))
    (let loop ((i 0))
      (cond
       ((>= i len) #f)
       ((char=? (string-ref str i) ch) i)
       (else (loop (+ i 1)))))))


;;;
;;; Value parsing
;;;

(define (parse-toml-value str)
  "Parse a TOML value string into a Scheme value."
  (let ((s (string-trim-both str)))
    (cond
     ;; Empty
     ((string=? s "") "")

     ;; Boolean
     ((string=? s "true") #t)
     ((string=? s "false") #f)

     ;; Basic string (double-quoted)
     ((and (> (string-length s) 1)
           (char=? (string-ref s 0) #\"))
      (parse-toml-string s))

     ;; Single-quoted string (literal)
     ((and (> (string-length s) 1)
           (char=? (string-ref s 0) #\'))
      (let ((end (string-index s #\' 1)))
        (if end
            (substring s 1 end)
            (substring s 1))))

     ;; Array
     ((char=? (string-ref s 0) #\[)
      (parse-toml-array s))

     ;; Integer or float
     ((or (char-numeric? (string-ref s 0))
          (char=? (string-ref s 0) #\-)
          (char=? (string-ref s 0) #\+))
      (if (string-contains-char s #\.)
          (let ((val (string->number s)))
            (or val s))
          (let ((val (string->number s)))
            (or val s))))

     ;; Fall through: return as string
     (else s))))

(define (parse-toml-string s)
  "Parse a double-quoted TOML string, handling escape sequences."
  (let* ((len (string-length s))
         (result '())
         (i 1))  ;; skip opening quote
    (let loop ((i i) (acc '()))
      (cond
       ((>= i len)
        (list->string (reverse acc)))
       ((char=? (string-ref s i) #\")
        (list->string (reverse acc)))
       ((char=? (string-ref s i) #\\)
        (if (< (+ i 1) len)
            (let ((next (string-ref s (+ i 1))))
              (loop (+ i 2)
                    (cons (case next
                            ((#\n) #\newline)
                            ((#\t) #\tab)
                            ((#\r) #\return)
                            ((#\\) #\\)
                            ((#\") #\")
                            (else next))
                          acc)))
            (loop (+ i 1) acc)))
       (else
        (loop (+ i 1) (cons (string-ref s i) acc)))))))

(define (parse-toml-array s)
  "Parse a TOML array string into a Scheme list."
  (let* ((content (string-trim-both
                   (substring s 1 (- (string-length s)
                                     (if (char=? (string-ref s (- (string-length s) 1)) #\])
                                         1 0)))))
         (elements (split-array-elements content)))
    (map (lambda (elem) (parse-toml-value (string-trim-both elem)))
         (filter (lambda (e) (not (string=? (string-trim-both e) "")))
                 elements))))

(define (split-array-elements str)
  "Split a comma-separated array body, respecting nested brackets and quotes."
  (let ((len (string-length str)))
    (let loop ((i 0) (depth 0) (in-string #f) (start 0) (result '()))
      (cond
       ((>= i len)
        (reverse (cons (substring str start len) result)))
       ((and (not in-string) (char=? (string-ref str i) #\"))
        (loop (+ i 1) depth #t start result))
       ((and in-string (char=? (string-ref str i) #\")
             (or (= i 0) (not (char=? (string-ref str (- i 1)) #\\))))
        (loop (+ i 1) depth #f start result))
       (in-string
        (loop (+ i 1) depth in-string start result))
       ((char=? (string-ref str i) #\[)
        (loop (+ i 1) (+ depth 1) in-string start result))
       ((char=? (string-ref str i) #\])
        (loop (+ i 1) (- depth 1) in-string start result))
       ((and (char=? (string-ref str i) #\,) (= depth 0))
        (loop (+ i 1) depth in-string (+ i 1)
              (cons (substring str start i) result)))
       (else
        (loop (+ i 1) depth in-string start result))))))


;;;
;;; Key parsing
;;;

(define (parse-key-path key-str)
  "Parse a dotted key string into a list of key segments.
Handles quoted keys like \"a.b\".c."
  (let ((len (string-length key-str)))
    (let loop ((i 0) (in-quote #f) (quote-char #f) (current '()) (result '()))
      (cond
       ((>= i len)
        (reverse (cons (string-trim-both (list->string (reverse current))) result)))
       ((and (not in-quote)
             (or (char=? (string-ref key-str i) #\")
                 (char=? (string-ref key-str i) #\')))
        (loop (+ i 1) #t (string-ref key-str i) current result))
       ((and in-quote (char=? (string-ref key-str i) quote-char))
        (loop (+ i 1) #f #f current result))
       ((and (not in-quote) (char=? (string-ref key-str i) #\.))
        (loop (+ i 1) #f #f '()
              (cons (string-trim-both (list->string (reverse current))) result)))
       (else
        (loop (+ i 1) in-quote quote-char
              (cons (string-ref key-str i) current) result))))))


;;;
;;; Line classification
;;;

(define (strip-comment line)
  "Remove inline comments from a line (outside of strings)."
  (let ((len (string-length line)))
    (let loop ((i 0) (in-string #f))
      (cond
       ((>= i len) line)
       ((and (not in-string) (char=? (string-ref line i) #\"))
        (loop (+ i 1) #t))
       ((and in-string (char=? (string-ref line i) #\")
             (or (= i 0) (not (char=? (string-ref line (- i 1)) #\\))))
        (loop (+ i 1) #f))
       ((and (not in-string) (char=? (string-ref line i) #\#))
        (string-trim-both (substring line 0 i)))
       (else
        (loop (+ i 1) in-string))))))

(define (table-header? line)
  "If LINE is a [table] header, return the table name. Otherwise #f."
  (let ((s (string-trim-both line)))
    (and (> (string-length s) 2)
         (char=? (string-ref s 0) #\[)
         (not (char=? (string-ref s 1) #\[))  ;; not array-of-tables
         (char=? (string-ref s (- (string-length s) 1)) #\])
         (string-trim-both (substring s 1 (- (string-length s) 1))))))

(define (key-value-pair? line)
  "If LINE is a key=value pair, return (key . value-string). Otherwise #f."
  (let* ((s (string-trim-both line))
         (eq-pos (find-equals-position s)))
    (and eq-pos
         (> eq-pos 0)
         (cons (string-trim-both (substring s 0 eq-pos))
               (string-trim-both (substring s (+ eq-pos 1)))))))

(define (find-equals-position str)
  "Find the position of the first = not inside a string."
  (let ((len (string-length str)))
    (let loop ((i 0) (in-string #f) (quote-char #f))
      (cond
       ((>= i len) #f)
       ((and (not in-string)
             (or (char=? (string-ref str i) #\")
                 (char=? (string-ref str i) #\')))
        (loop (+ i 1) #t (string-ref str i)))
       ((and in-string (char=? (string-ref str i) quote-char)
             (or (= i 0) (not (char=? (string-ref str (- i 1)) #\\))))
        (loop (+ i 1) #f #f))
       ((and (not in-string) (char=? (string-ref str i) #\=))
        i)
       (else
        (loop (+ i 1) in-string quote-char))))))


;;;
;;; Alist deep-set and deep-merge
;;;

(define (alist-deep-set alist keys value)
  "Set VALUE at the nested KEYS path in ALIST, creating intermediate alists."
  (if (null? (cdr keys))
      ;; Base case: set the value at this key
      (let ((existing (assoc (car keys) alist)))
        (if existing
            (map (lambda (pair)
                   (if (string=? (car pair) (car keys))
                       (cons (car keys) value)
                       pair))
                 alist)
            (append alist (list (cons (car keys) value)))))
      ;; Recursive case: descend into sub-alist
      (let* ((key (car keys))
             (existing (assoc key alist))
             (sub-alist (if (and existing (list? (cdr existing)))
                            (cdr existing)
                            '()))
             (new-sub (alist-deep-set sub-alist (cdr keys) value)))
        (if existing
            (map (lambda (pair)
                   (if (string=? (car pair) key)
                       (cons key new-sub)
                       pair))
                 alist)
            (append alist (list (cons key new-sub)))))))

(define (toml-merge base override)
  "Deep-merge two TOML alists. Override values take precedence.
Lists are replaced, not appended."
  (fold (lambda (pair result)
          (let* ((key (car pair))
                 (val (cdr pair))
                 (existing (assoc key result)))
            (cond
             ;; Both are alists: recursively merge
             ((and existing
                   (list? val) (pair? val) (pair? (car val))
                   (list? (cdr existing)) (pair? (cdr existing))
                   (pair? (car (cdr existing))))
              (map (lambda (p)
                     (if (string=? (car p) key)
                         (cons key (toml-merge (cdr p) val))
                         p))
                   result))
             ;; Override existing value
             (existing
              (map (lambda (p)
                     (if (string=? (car p) key)
                         pair
                         p))
                   result))
             ;; New key
             (else
              (append result (list pair))))))
        base
        override))


;;;
;;; Main parser
;;;

(define (parse-toml str)
  "Parse a TOML string into a nested alist."
  (let ((lines (string-split str #\newline)))
    (let loop ((lines lines) (current-table '()) (result '()))
      (if (null? lines)
          result
          (let* ((raw-line (car lines))
                 (line (strip-comment raw-line))
                 (trimmed (string-trim-both line)))
            (cond
             ;; Empty line or comment-only line
             ((or (string=? trimmed "")
                  (and (> (string-length trimmed) 0)
                       (char=? (string-ref trimmed 0) #\#)))
              (loop (cdr lines) current-table result))

             ;; Table header
             ((table-header? trimmed)
              => (lambda (table-name)
                   (let ((table-keys (parse-key-path table-name)))
                     (loop (cdr lines) table-keys result))))

             ;; Key-value pair
             ((key-value-pair? trimmed)
              => (lambda (kv)
                   (let* ((key-str (car kv))
                          (val-str (cdr kv))
                          ;; Handle multiline arrays
                          (val+rest (if (and (> (string-length val-str) 0)
                                             (char=? (string-ref val-str 0) #\[)
                                             (not (string-contains-char val-str #\])))
                                        (collect-multiline-array val-str (cdr lines))
                                        (cons val-str (cdr lines))))
                          (full-val (car val+rest))
                          (remaining (cdr val+rest))
                          (key-parts (parse-key-path key-str))
                          (full-path (append current-table key-parts))
                          (value (parse-toml-value full-val))
                          (new-result (alist-deep-set result full-path value)))
                     (loop remaining current-table new-result))))

             ;; Unknown line, skip
             (else
              (loop (cdr lines) current-table result))))))))

(define (collect-multiline-array first-line remaining-lines)
  "Collect a multiline array starting with FIRST-LINE.
Returns (full-value . remaining-lines)."
  (let loop ((lines remaining-lines) (acc first-line))
    (if (null? lines)
        (cons acc '())
        (let* ((line (string-trim-both (strip-comment (car lines)))))
          (if (string-contains-char line #\])
              (cons (string-append acc " " line) (cdr lines))
              (loop (cdr lines) (string-append acc " " line)))))))


;;;
;;; File parser
;;;

(define (parse-toml-file filename)
  "Parse a TOML file and return a nested alist."
  (let ((content (call-with-input-file filename get-string-all)))
    (parse-toml content)))


;;;
;;; Accessor utilities
;;;

(define* (toml-ref data path #:optional default)
  "Look up a dotted path in parsed TOML data.
PATH is a string like \"section.key\" or a list of strings.
Returns DEFAULT (or #f) if not found."
  (let ((keys (if (string? path) (parse-key-path path) path)))
    (let loop ((keys keys) (data data))
      (cond
       ((null? keys) data)
       ((not (list? data)) (or default #f))
       (else
        (let ((entry (assoc (car keys) data)))
          (if entry
              (loop (cdr keys) (cdr entry))
              (or default #f))))))))

(define* (toml-ref/default data path default)
  "Look up a dotted path in parsed TOML data with an explicit default."
  (let ((result (toml-ref data path)))
    (if result result default)))
