# Eval-only COMPUTE benchmark suite (RFC-0007 doc 15: "Nix as a real
# programming language" workloads).
#
# Each attribute is a trivial derivation whose `result` environment variable
# is `builtins.toJSON` of a real computation, so instantiating the .drv forces
# the whole computation AND the existing byte-parity + nix-bench machinery
# gates the computed value for free: a wrong answer changes the .drv bytes.
#
# The derivations are never built; `builder = "/bin/sh"` is a placeholder
# string that only exists to make the derivation well-formed (same idea as
# tests/bench/wide.nix, but self-contained: no pkgs, so the measured eval is
# pure compute with no package-set instantiation in the way).
#
# Every workload is self-contained pure Nix (no lib, no imports) and sized so
# C++ nix-instantiate spends roughly 0.2-2s on it. Sizes come from `defaults`
# below and can be overridden per-benchmark via the `scale` argument, e.g.
# `import ./compute.nix {scale.fib = 30;}`.
{scale ? {}}: let
  defaults = {
    fib = 28;
    tak = {
      x = 24;
      y = 16;
      z = 8;
    };
    sum-fold = 1500000;
    qsort = 100000;
    string-builder = {
      # Incremental `acc + chunk` growth: O(n^2) bytes copied.
      appendN = 20000;
      # Linear concatStringsSep over a generated list.
      sepN = 900000;
    };
    attr-fixpoint = {
      # Repeated `//` growth: O(n^2) attr copies.
      mergeN = 8000;
      # Overlay stack depth (fix + extends chain). Forcing the fixpoint
      # recurses once per layer; C++ Nix survives 2000 layers within its
      # max-call-depth (10000), but the native tree-walk evaluator's worker
      # thread stack overflows between 750 and 1000 layers, so this stays
      # comfortably under that bound. (Real overlay stacks are tens deep.)
      layerN = 512;
    };
    lambda-interp = 1000000;
    hash-loop = 1000000;
    all-any = 600000;
  };
  params = defaults // scale;

  # Truncating integer modulus (Nix `/` on ints truncates toward zero).
  mod = a: b: a - b * (a / b);

  mkBench = name: payload:
    builtins.derivation {
      name = "bench-compute-${name}";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [];
      result = builtins.toJSON payload;
    };

  # 1. fib-naive: exponential double recursion. Pure call overhead plus
  #    small-integer arithmetic; the classic tier-up torture test.
  fib = n:
    if n < 2
    then n
    else fib (n - 1) + fib (n - 2);

  # 2. tak (Takeuchi): deep 3-argument recursion where almost every call
  #    spawns three more. Stresses multi-argument call frames.
  tak = x: y: z:
    if y < x
    then
      tak
      (tak (x - 1) y z)
      (tak (y - 1) z x)
      (tak (z - 1) x y)
    else z;

  # 3. sum-fold: foldl' arithmetic over a genList of ints. Loop-shaped
  #    straight-line arithmetic; the JIT's best case.
  sumFold = n:
    builtins.foldl'
    (acc: i: mod (acc + i * i + 2654435761) 1000000007)
    0
    (builtins.genList (i: i) n);

  # 4. qsort: quicksort over a pseudo-random list. Recursion + list
  #    allocation + 2n filter-lambda calls per level. The generator applies
  #    the LCG step twice: a single step is monotonic in i until the first
  #    modulus wrap, which would give first-element-pivot quicksort its
  #    quadratic worst case (and a call-depth overflow).
  lcg = i: mod (1 + (mod (1 + i * 48271) 2147483647) * 48271) 2147483647;
  qsort = xs:
    if builtins.length xs < 2
    then xs
    else let
      pivot = builtins.head xs;
      rest = builtins.tail xs;
    in
      qsort (builtins.filter (x: x < pivot) rest)
      ++ [pivot]
      ++ qsort (builtins.filter (x: x >= pivot) rest);
  checksum = xs:
    builtins.foldl' (acc: x: mod (acc * 31 + x) 1000000007) 0 xs;
  qsortBench = n: let
    sorted = qsort (builtins.genList lcg n);
  in {
    length = builtins.length sorted;
    first = builtins.head sorted;
    last = builtins.elemAt sorted (n - 1);
    checksum = checksum sorted;
  };

  # 5. string-builder: incremental string append (quadratic copying) plus a
  #    linear concatStringsSep join. String/alloc heavy.
  stringBuilder = {
    appendN,
    sepN,
  }: let
    grown =
      builtins.foldl'
      (acc: i: acc + "seg-" + builtins.toString i + ";")
      ""
      (builtins.genList (i: i) appendN);
    joined =
      builtins.concatStringsSep ","
      (builtins.genList (i: "item${builtins.toString i}") sepN);
  in {
    grownLen = builtins.stringLength grown;
    grownHash = builtins.hashString "sha256" grown;
    joinedLen = builtins.stringLength joined;
    joinedHash = builtins.hashString "sha256" joined;
  };

  # 6. attr-fixpoint: attrset machinery. A quadratic `//` merge chain plus a
  #    lib.fix/extends-style overlay stack (self-contained reimplementation).
  attrFixpoint = {
    mergeN,
    layerN,
  }: let
    merged =
      builtins.foldl'
      (acc: i: acc // {"k${builtins.toString i}" = i * i;})
      {}
      (builtins.genList (i: i) mergeN);
    mergedSum =
      builtins.foldl'
      (acc: name: mod (acc + merged.${name}) 1000000007)
      0
      (builtins.attrNames merged);
    fix = f: let
      x = f x;
    in
      x;
    extends = overlay: f: final: let
      prev = f final;
    in
      prev // overlay final prev;
    overlay = i: final: prev: {
      counter = mod (prev.counter * 31 + i) 1000000007;
      entries =
        prev.entries
        // {"layer${builtins.toString i}" = prev.counter;};
    };
    base = final: {
      counter = 1;
      entries = {};
    };
    stacked =
      fix
      (builtins.foldl'
        (f: i: extends (overlay i) f)
        base
        (builtins.genList (i: i) layerN));
  in {
    inherit mergedSum;
    counter = stacked.counter;
    layers = builtins.length (builtins.attrNames stacked.entries);
  };

  # 7. lambda-interp: a brainfuck interpreter running a nonterminating
  #    counter program for exactly `steps` steps. Handler-table dispatch on
  #    closures, per-step attrset state churn — the megamorphic tier-2 case.
  bfInterp = steps: let
    # Infinite loop: cell0 stays 1, cells 1-3 count up mod 256 forever, the
    # pointer walks right and back every iteration. All hot opcodes covered.
    program = "+[->+>+>+<<<+]";
    progLen = builtins.stringLength program;
    at = i: builtins.substring i 1 program;
    scan = i: stack: jumps:
      if i >= progLen
      then jumps
      else if at i == "["
      then scan (i + 1) ([i] ++ stack) jumps
      else if at i == "]"
      then let
        open = builtins.head stack;
      in
        scan (i + 1) (builtins.tail stack) (jumps
          // {
            "${builtins.toString open}" = i;
            "${builtins.toString i}" = open;
          })
      else scan (i + 1) stack jumps;
    jumps = scan 0 [] {};
    handlers = {
      # Cell writes are forced via seq: a cell that is written every
      # iteration but only read at the very end would otherwise accumulate
      # an unbounded chain of pending `mod (prev + 1) 256` thunks and blow
      # the call depth when the final state is serialized.
      "+" = st: cur: let
        v = mod (cur + 1) 256;
      in
        builtins.seq v (st
          // {
            ip = st.ip + 1;
            tape = st.tape // {"${builtins.toString st.ptr}" = v;};
          });
      "-" = st: cur: let
        v = mod (cur + 255) 256;
      in
        builtins.seq v (st
          // {
            ip = st.ip + 1;
            tape = st.tape // {"${builtins.toString st.ptr}" = v;};
          });
      ">" = st: cur:
        st
        // {
          ip = st.ip + 1;
          ptr = st.ptr + 1;
        };
      "<" = st: cur:
        st
        // {
          ip = st.ip + 1;
          ptr = st.ptr - 1;
        };
      "[" = st: cur:
        st
        // {
          ip =
            if cur == 0
            then jumps.${builtins.toString st.ip} + 1
            else st.ip + 1;
        };
      "]" = st: cur:
        st
        // {
          ip =
            if cur == 0
            then st.ip + 1
            else jumps.${builtins.toString st.ip} + 1;
        };
    };
    step = st:
      if st.ip >= progLen
      then st
      else handlers.${at st.ip} st (st.tape.${builtins.toString st.ptr} or 0);
    final =
      builtins.foldl'
      (st: _: step st)
      {
        ip = 0;
        ptr = 0;
        tape = {};
      }
      (builtins.genList (i: i) steps);
  in {
    inherit steps;
    ip = final.ip;
    ptr = final.ptr;
    tape = final.tape;
  };

  # 8. hash-loop: chained builtins.hashString over generated strings.
  #    Primop-dominated control — the "JIT can't help here" baseline.
  hashLoop = n:
    builtins.foldl'
    (acc: i: builtins.hashString "sha256" (acc + "-" + builtins.toString i))
    "seed"
    (builtins.genList (i: i) n);

  # 9. all-any: unary predicates over one shared, forced list. The four cases
  #    distinguish exhaustion from a last-element short circuit for both
  #    operations while keeping list construction out of the comparison.
  allAny = n: let
    values = builtins.genList (i: i) n;
  in {
    allExhausts = builtins.all (x: x < n) values;
    allStopsLast = builtins.all (x: x < n - 1) values;
    anyStopsLast = builtins.any (x: x == n - 1) values;
    anyExhausts = builtins.any (x: x == n) values;
  };
in {
  fib = mkBench "fib" {
    n = params.fib;
    value = fib params.fib;
  };
  tak = mkBench "tak" {
    inherit (params.tak) x y z;
    value = tak params.tak.x params.tak.y params.tak.z;
  };
  sum-fold = mkBench "sum-fold" {
    n = params.sum-fold;
    value = sumFold params.sum-fold;
  };
  qsort = mkBench "qsort" ({n = params.qsort;} // qsortBench params.qsort);
  string-builder = mkBench "string-builder" (stringBuilder params.string-builder);
  attr-fixpoint = mkBench "attr-fixpoint" (attrFixpoint params.attr-fixpoint);
  lambda-interp = mkBench "lambda-interp" (bfInterp params.lambda-interp);
  hash-loop = mkBench "hash-loop" {
    n = params.hash-loop;
    value = hashLoop params.hash-loop;
  };
  all-any = mkBench "all-any" ({n = params.all-any;} // allAny params.all-any);
}
