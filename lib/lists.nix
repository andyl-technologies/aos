##! lib/lists.nix — List utility functions
##!
##! Comprehensive list manipulation functions. All functions are pure
##! and operate on Nix lists (which are immutable linked lists).

rec {
  ## # Basic accessors

  ## Return the first element of a list. Throws on empty list.
  ## # Type
  ## `[a] -> a`
  head =
    list:
    assert builtins.length list > 0;
    builtins.elemAt list 0;

  ## Return all elements except the first. Throws on empty list.
  ## # Type
  ## `[a] -> [a]`
  tail =
    list:
    assert builtins.length list > 0;
    let
      len = builtins.length list;
    in
    genList (i: builtins.elemAt list (i + 1)) (len - 1);

  ## Return the last element of a list. Throws on empty list.
  ## # Type
  ## `[a] -> a`
  last =
    list:
    let
      len = builtins.length list;
    in
    assert len > 0;
    builtins.elemAt list (len - 1);

  ## Return all elements except the last. Throws on empty list.
  ## # Type
  ## `[a] -> [a]`
  init =
    list:
    let
      len = builtins.length list;
    in
    assert len > 0;
    genList (i: builtins.elemAt list i) (len - 1);

  ## # Type
  ## `[a] -> int`
  length = builtins.length;

  ## # Type
  ## `a -> bool`
  isList = builtins.isList;

  ## # Searching

  ## Test whether a value is an element of a list.
  ## # Type
  ## `a -> [a] -> bool`
  elem = x: list: builtins.any (e: e == x) list;

  ## Find the first element matching a predicate, or return the default.
  ## # Type
  ## `(a -> bool) -> a -> [a] -> a`
  findFirst =
    pred: default: list:
    let
      len = builtins.length list;
      go =
        i:
        if i >= len then
          default
        else
          let
            e = builtins.elemAt list i;
          in
          if pred e then e else go (i + 1);
    in
    go 0;

  ## Find the index of the first element matching a predicate.
  ## # Type
  ## `(a -> bool) -> null -> [a] -> int | null`
  findFirstIndex =
    pred: default: list:
    let
      len = builtins.length list;
      go =
        i:
        if i >= len then
          default
        else if pred (builtins.elemAt list i) then
          i
        else
          go (i + 1);
    in
    go 0;

  ## # Transformations

  ## # Type
  ## `(a -> b) -> [a] -> [b]`
  map = builtins.map;

  ## Map with index.
  ## # Type
  ## `(int -> a -> b) -> [a] -> [b]`
  imap = f: list: genList (i: f i (builtins.elemAt list i)) (builtins.length list);

  ## # Type
  ## `(a -> bool) -> [a] -> [a]`
  filter = builtins.filter;

  ## Strict left fold.
  ## # Type
  ## `(b -> a -> b) -> b -> [a] -> b`
  foldl' = builtins.foldl';

  ## Right fold.
  ## # Type
  ## `(a -> b -> b) -> b -> [a] -> b`
  foldr =
    f: z: list:
    let
      len = builtins.length list;
      go = i: if i >= len then z else f (builtins.elemAt list i) (go (i + 1));
    in
    go 0;

  ## # Flattening and concatenation

  ## # Type
  ## `(a -> [b]) -> [a] -> [b]`
  concatMap = f: list: builtins.concatLists (builtins.map f list);

  ## # Type
  ## `[[a]] -> [a]`
  concatLists = builtins.concatLists;

  ## Recursively flatten a nested list structure.
  ## # Type
  ## `nested list -> [a]`
  flatten = x: if builtins.isList x then builtins.concatLists (builtins.map flatten x) else [ x ];

  ## # Ordering

  ## Sort a list. The comparison function should return true if the first
  ## argument is strictly less than the second.
  ## # Type
  ## `(a -> a -> bool) -> [a] -> [a]`
  sort = builtins.sort;

  ## # Type
  ## `[a] -> [a]`
  reverseList =
    list:
    let
      len = builtins.length list;
    in
    genList (i: builtins.elemAt list (len - i - 1)) len;

  ## # Uniqueness

  ## Remove duplicate elements, preserving first occurrence order.
  ## # Type
  ## `[a] -> [a]`
  unique =
    list:
    let
      go =
        acc: remaining:
        if remaining == [ ] then
          acc
        else
          let
            h = builtins.elemAt remaining 0;
            t = tail remaining;
          in
          if elem h acc then go acc t else go (acc ++ [ h ]) t;
    in
    go [ ] list;

  ## # Partitioning

  ## Split a list into two based on a predicate.
  ## Elements satisfying the predicate go into `right`, others into `wrong`.
  ## # Type
  ## `(a -> bool) -> [a] -> { right :: [a]; wrong :: [a]; }`
  partition = pred: list: builtins.partition pred list;

  ## # Subtraction and intersection

  ## Remove all occurrences of an element from a list.
  ## # Type
  ## `a -> [a] -> [a]`
  remove = x: builtins.filter (e: e != x);

  ## Remove elements of the first list from the second.
  ##
  ## `subtractLists [2 3] [1 2 3 4] == [1 4]`
  ## # Type
  ## `[a] -> [a] -> [a]`
  subtractLists = toRemove: list: builtins.filter (x: !elem x toRemove) list;

  ## Return elements present in both lists.
  ## # Type
  ## `[a] -> [a] -> [a]`
  intersectLists = a: b: builtins.filter (x: elem x b) a;

  ## # Predicates

  ## # Type
  ## `(a -> bool) -> [a] -> bool`
  any = builtins.any;

  ## # Type
  ## `(a -> bool) -> [a] -> bool`
  all = builtins.all;

  ## # Generators

  ## Generate a list of integers from `from` to `to` inclusive.
  ## # Type
  ## `int -> int -> [int]`
  range = from: to: if from > to then [ ] else genList (i: from + i) (to - from + 1);

  ## # Type
  ## `(int -> a) -> int -> [a]`
  genList = builtins.genList;

  ## Generate a list containing n copies of the same element.
  ## # Type
  ## `int -> a -> [a]`
  replicate = n: x: genList (_: x) n;

  ## # Zipping

  ## Zip two lists into a list of pairs. Truncates to the shorter list.
  ## # Type
  ## `[a] -> [b] -> [{ fst :: a; snd :: b; }]`
  zipLists =
    a: b:
    let
      len = if builtins.length a < builtins.length b then builtins.length a else builtins.length b;
    in
    genList (i: {
      fst = builtins.elemAt a i;
      snd = builtins.elemAt b i;
    }) len;

  ## Zip two lists with a combining function.
  ## # Type
  ## `(a -> b -> c) -> [a] -> [b] -> [c]`
  zipListsWith =
    f: a: b:
    let
      len = if builtins.length a < builtins.length b then builtins.length a else builtins.length b;
    in
    genList (i: f (builtins.elemAt a i) (builtins.elemAt b i)) len;

  ## # Grouping

  ## Group list elements by a key function.
  ## # Type
  ## `(a -> string) -> [a] -> { ${key} :: [a]; }`
  groupBy =
    keyFn: list:
    builtins.foldl' (
      acc: elem:
      let
        key = keyFn elem;
      in
      acc
      // {
        ${key} = (acc.${key} or [ ]) ++ [ elem ];
      }
    ) { } list;

  ## Take the first n elements.
  ## # Type
  ## `int -> [a] -> [a]`
  take =
    n: list:
    let
      len = builtins.length list;
      count =
        if n > len then
          len
        else if n < 0 then
          0
        else
          n;
    in
    genList (i: builtins.elemAt list i) count;

  ## Drop the first n elements.
  ## # Type
  ## `int -> [a] -> [a]`
  drop =
    n: list:
    let
      len = builtins.length list;
      start =
        if n < 0 then
          0
        else if n > len then
          len
        else
          n;
    in
    genList (i: builtins.elemAt list (start + i)) (len - start);

  ## Count elements satisfying a predicate.
  ## # Type
  ## `(a -> bool) -> [a] -> int`
  count = pred: list: builtins.foldl' (acc: x: if pred x then acc + 1 else acc) 0 list;

  ## Return a singleton list or empty list based on condition.
  ## # Type
  ## `bool -> a -> [a]`
  optional = cond: elem: if cond then [ elem ] else [ ];

  ## Return the list or empty list based on condition.
  ## # Type
  ## `bool -> [a] -> [a]`
  optionals = cond: list: if cond then list else [ ];

  ## Wrap a non-list value in a singleton list, pass lists through.
  ## # Type
  ## `a | [a] -> [a]`
  toList = x: if builtins.isList x then x else [ x ];
}
