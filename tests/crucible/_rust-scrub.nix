# Masks Rust comments and quoted strings while preserving source offsets.
# Retain raw-string parser state across lines; bounded fragments preserve the
# upstream scanner fix without treating raw-string contents as code.
{lib}: content: let
  scrubChunk = chunkState: chunk: let
    length = builtins.stringLength chunk;
    charAt = index:
      if index < length
      then builtins.substring index 1 chunk
      else "";
    spaces = count: builtins.concatStringsSep "" (builtins.genList (_: " ") count);
    countHashes = index:
      if charAt index == "#"
      then 1 + countHashes (index + 1)
      else 0;
    rawStartAt = index: let
      prefixLength =
        if charAt index == "r"
        then 1
        else if charAt index == "b" && charAt (index + 1) == "r"
        then 2
        else 0;
      hashStart = index + prefixLength;
      hashes = countHashes hashStart;
      openerLength = prefixLength + hashes + 1;
    in
      if prefixLength > 0 && charAt (hashStart + hashes) == "\""
      then {inherit hashes openerLength;}
      else null;
    rawClosesAt = hashes: index:
      charAt index
      == "\""
      && builtins.all
      (offset: charAt (index + 1 + offset) == "#")
      (builtins.genList (offset: offset) hashes);
    charLiteralLengthAt = index:
      if charAt index != "'"
      then 0
      else if charAt (index + 1) == "\\" && charAt (index + 3) == "'"
      then 4
      else if charAt (index + 2) == "'"
      then 3
      else 0;
    indexes = builtins.genList (index: index) length;
    folded = builtins.foldl' step chunkState indexes;
    step = state: index:
      if state.skip > 0
      then
        state
        // {
          skip = state.skip - 1;
        }
      else let
        ch = charAt index;
        next = charAt (index + 1);
        rawStart = rawStartAt index;
        charLiteralLength = charLiteralLengthAt index;
      in
        if state.mode == "code"
        then
          if ch == "/" && next == "/"
          then
            state
            // {
              out = state.out + "  ";
              mode = "line";
              skip = 1;
            }
          else if ch == "/" && next == "*"
          then
            state
            // {
              out = state.out + "  ";
              mode = "block";
              depth = 1;
              skip = 1;
            }
          else if rawStart != null
          then
            state
            // {
              out = state.out + spaces rawStart.openerLength;
              mode = "raw";
              rawHashes = rawStart.hashes;
              skip = rawStart.openerLength - 1;
            }
          else if charLiteralLength > 0
          then
            state
            // {
              out = state.out + spaces charLiteralLength;
              skip = charLiteralLength - 1;
            }
          else if ch == "\""
          then
            state
            // {
              out = state.out + " ";
              mode = "string";
            }
          else
            state
            // {
              out = state.out + ch;
            }
        else if state.mode == "line"
        then
          if ch == "\n"
          then
            state
            // {
              out = state.out + "\n";
              mode = "code";
            }
          else
            state
            // {
              out = state.out + " ";
            }
        else if state.mode == "block"
        then
          if ch == "/" && next == "*"
          then
            state
            // {
              out = state.out + "  ";
              depth = state.depth + 1;
              skip = 1;
            }
          else if ch == "*" && next == "/"
          then
            state
            // {
              out = state.out + "  ";
              mode =
                if state.depth == 1
                then "code"
                else "block";
              depth =
                if state.depth == 1
                then 0
                else state.depth - 1;
              skip = 1;
            }
          else
            state
            // {
              out =
                state.out
                + (
                  if ch == "\n"
                  then "\n"
                  else " "
                );
            }
        else if state.mode == "string"
        then
          if ch == "\\" && next != ""
          then
            state
            // {
              out =
                state.out
                + " "
                + (
                  if next == "\n"
                  then "\n"
                  else " "
                );
              skip = 1;
            }
          else if ch == "\""
          then
            state
            // {
              out = state.out + " ";
              mode = "code";
            }
          else
            state
            // {
              out =
                state.out
                + (
                  if ch == "\n"
                  then "\n"
                  else " "
                );
            }
        else if state.mode == "raw"
        then
          if rawClosesAt state.rawHashes index
          then
            state
            // {
              out = state.out + spaces (state.rawHashes + 1);
              mode = "code";
              skip = state.rawHashes;
            }
          else
            state
            // {
              out =
                state.out
                + (
                  if ch == "\n"
                  then "\n"
                  else " "
                );
            }
        else throw "invalid source scrubber state";
  in
    # Force the accumulated output flat before the next chunk so thunk
    # depth stays bounded by the longest line, not the whole file.
    builtins.seq (builtins.stringLength folded.out) folded;
  lines = lib.splitString "\n" content;
  lineCount = builtins.length lines;
  chunkAt = index:
    builtins.elemAt lines index
    + (
      if index + 1 < lineCount
      then "\n"
      else ""
    );
  result =
    builtins.foldl'
    (state: index: let
      # Keep character concatenation local to one line. Carrying the whole
      # file into each character copies an ever-growing prefix repeatedly.
      chunk = scrubChunk {
        inherit (state) mode depth rawHashes skip;
        out = "";
      } (chunkAt index);
      # A forced binding lets list entries share the flat string. A lazy
      # selection captures this step's environment and every prior chunk list.
      fragment = chunk.out;
      chunks = [fragment] ++ state.chunks;
    in
      # Force every parser field as well as the text. Lazy inherited fields
      # otherwise retain the preceding line's character states indefinitely.
      builtins.deepSeq chunk (builtins.seq fragment (builtins.seq (builtins.length chunks) {
        inherit (chunk) mode depth rawHashes skip;
        inherit chunks;
      })))
    {
      chunks = [];
      mode = "code";
      depth = 0;
      rawHashes = 0;
      skip = 0;
    }
    (builtins.genList (index: index) lineCount);
in
  builtins.concatStringsSep "" (lib.reverseList result.chunks)
