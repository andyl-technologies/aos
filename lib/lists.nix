# lib/lists.nix — List utility functions
#
# Comprehensive list manipulation functions. All functions are pure
# and operate on Nix lists (which are immutable linked lists).
#

rec {
  # -- Basic accessors --

  # head :: [a] -> a
  # Return the first element of a list. Throws on empty list.
  head =
    list:
    assert builtins.length list > 0;
    builtins.elemAt list 0;

  # tail :: [a] -> [a]
  # Return all elements except the first. Throws on empty list.
  tail =
    list:
    assert builtins.length list > 0;
    let
      len = builtins.length list;
    in
    genList (i: builtins.elemAt list (i + 1)) (len - 1);

  # last :: [a] -> a
  # Return the last element of a list. Throws on empty list.
  last =
    list:
    let
      len = builtins.length list;
    in
    assert len > 0;
    builtins.elemAt list (len - 1);

  # init :: [a] -> [a]
  # Return all elements except the last. Throws on empty list.
  init =
    list:
    let
      len = builtins.length list;
    in
    assert len > 0;
    genList (i: builtins.elemAt list i) (len - 1);

  # length :: [a] -> int
  length = builtins.length;

  # isList :: a -> bool
  isList = builtins.isList;

  # -- Searching --

  # elem :: a -> [a] -> bool
  # Test whether a value is an element of a list.
  elem = x: list: builtins.any (e: e == x) list;

  # findFirst :: (a -> bool) -> a -> [a] -> a
  # Find the first element matching a predicate, or return the default.
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

  # findFirstIndex :: (a -> bool) -> null -> [a] -> int | null
  # Find the index of the first element matching a predicate.
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

  # -- Transformations --

  # map :: (a -> b) -> [a] -> [b]
  map = builtins.map;

  # imap :: (int -> a -> b) -> [a] -> [b]
  # Map with index.
  imap = f: list: genList (i: f i (builtins.elemAt list i)) (builtins.length list);

  # filter :: (a -> bool) -> [a] -> [a]
  filter = builtins.filter;

  # foldl' :: (b -> a -> b) -> b -> [a] -> b
  # Strict left fold.
  foldl' = builtins.foldl';

  # foldr :: (a -> b -> b) -> b -> [a] -> b
  # Right fold.
  foldr =
    f: z: list:
    let
      len = builtins.length list;
      go = i: if i >= len then z else f (builtins.elemAt list i) (go (i + 1));
    in
    go 0;

  # -- Flattening and concatenation --

  # concatMap :: (a -> [b]) -> [a] -> [b]
  concatMap = f: list: builtins.concatLists (builtins.map f list);

  # concatLists :: [[a]] -> [a]
  concatLists = builtins.concatLists;

  # flatten :: nested list -> [a]
  # Recursively flatten a nested list structure.
  flatten = x: if builtins.isList x then builtins.concatLists (builtins.map flatten x) else [ x ];

  # -- Ordering --

  # sort :: (a -> a -> bool) -> [a] -> [a]
  # Sort a list. The comparison function should return true if the first
  # argument is strictly less than the second.
  sort = builtins.sort;

  # reverseList :: [a] -> [a]
  reverseList =
    list:
    let
      len = builtins.length list;
    in
    genList (i: builtins.elemAt list (len - i - 1)) len;

  # -- Uniqueness --

  # unique :: [a] -> [a]
  # Remove duplicate elements, preserving first occurrence order.
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

  # -- Partitioning --

  # partition :: (a -> bool) -> [a] -> { right :: [a]; wrong :: [a]; }
  # Split a list into two based on a predicate.
  # Elements satisfying the predicate go into `right`, others into `wrong`.
  partition = pred: list: builtins.partition pred list;

  # -- Subtraction and intersection --

  # remove :: a -> [a] -> [a]
  # Remove all occurrences of an element from a list.
  remove = x: builtins.filter (e: e != x);

  # subtractLists :: [a] -> [a] -> [a]
  # Remove elements of the first list from the second.
  # subtractLists [2 3] [1 2 3 4] == [1 4]
  subtractLists = toRemove: list: builtins.filter (x: !elem x toRemove) list;

  # intersectLists :: [a] -> [a] -> [a]
  # Return elements present in both lists.
  intersectLists = a: b: builtins.filter (x: elem x b) a;

  # -- Predicates --

  # any :: (a -> bool) -> [a] -> bool
  any = builtins.any;

  # all :: (a -> bool) -> [a] -> bool
  all = builtins.all;

  # -- Generators --

  # range :: int -> int -> [int]
  # Generate a list of integers from `from` to `to` inclusive.
  range = from: to: if from > to then [ ] else genList (i: from + i) (to - from + 1);

  # genList :: (int -> a) -> int -> [a]
  genList = builtins.genList;

  # replicate :: int -> a -> [a]
  # Generate a list containing n copies of the same element.
  replicate = n: x: genList (_: x) n;

  # -- Zipping --

  # zipLists :: [a] -> [b] -> [{ fst :: a; snd :: b; }]
  # Zip two lists into a list of pairs. Truncates to the shorter list.
  zipLists =
    a: b:
    let
      len = if builtins.length a < builtins.length b then builtins.length a else builtins.length b;
    in
    genList (i: {
      fst = builtins.elemAt a i;
      snd = builtins.elemAt b i;
    }) len;

  # zipListsWith :: (a -> b -> c) -> [a] -> [b] -> [c]
  # Zip two lists with a combining function.
  zipListsWith =
    f: a: b:
    let
      len = if builtins.length a < builtins.length b then builtins.length a else builtins.length b;
    in
    genList (i: f (builtins.elemAt a i) (builtins.elemAt b i)) len;

  # -- Grouping --

  # groupBy :: (a -> string) -> [a] -> { ${key} :: [a]; }
  # Group list elements by a key function.
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

  # take :: int -> [a] -> [a]
  # Take the first n elements.
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

  # drop :: int -> [a] -> [a]
  # Drop the first n elements.
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

  # count :: (a -> bool) -> [a] -> int
  # Count elements satisfying a predicate.
  count = pred: list: builtins.foldl' (acc: x: if pred x then acc + 1 else acc) 0 list;

  # optional :: bool -> a -> [a]
  # Return a singleton list or empty list based on condition.
  optional = cond: elem: if cond then [ elem ] else [ ];

  # optionals :: bool -> [a] -> [a]
  # Return the list or empty list based on condition.
  optionals = cond: list: if cond then list else [ ];

  # toList :: a | [a] -> [a]
  # Wrap a non-list value in a singleton list, pass lists through.
  toList = x: if builtins.isList x then x else [ x ];
}
