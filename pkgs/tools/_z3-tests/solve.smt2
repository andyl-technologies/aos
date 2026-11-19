; Mixed integer and bit-vector constraints with exactly one model, followed
; by an integer contradiction in a fresh assertion scope.
(set-option :produce-models true)
(set-logic ALL)

(declare-const x Int)
(declare-const y Int)
(declare-const b (_ BitVec 8))

(push 1)
(assert (= (+ x y) 10))
(assert (= (- x y) 2))
; 3 is odd and therefore invertible modulo 2^8, so b is unique.
(assert (= (bvmul b #x03) #x2d))
(assert (= ((_ extract 3 0) b) #xf))
(check-sat)
(get-value (x y b))
(pop 1)

; No integer lies strictly between 0 and 1/2.
(assert (> x 0))
(assert (< (* 2 x) 1))
(check-sat)
