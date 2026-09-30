# Masks Rust comments and quoted strings while preserving source offsets.
# Parser state crosses line boundaries; output is assembled once from bounded
# line fragments so large module trees do not repeatedly copy file prefixes.
{lib}: content: let
  scrubChunk = chunkState: chunk: let
    length = builtins.stringLength chunk;
    charAt = index: builtins.substring index 1 chunk;
    indexes = builtins.genList (index: index) length;
    folded = builtins.foldl' step chunkState indexes;
    step = state: index:
      if state.skip
      then
        state
        // {
          skip = false;
        }
      else let
        ch = charAt index;
        next =
          if (index + 1) < length
          then charAt (index + 1)
          else "";
      in
        if state.mode == "code"
        then
          if ch == "/" && next == "/"
          then
            state
            // {
              out = state.out + "  ";
              mode = "line";
              skip = true;
            }
          else if ch == "/" && next == "*"
          then
            state
            // {
              out = state.out + "  ";
              mode = "block";
              depth = 1;
              skip = true;
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
              skip = true;
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
              skip = true;
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
        else if ch == "\\" && next != ""
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
            skip = true;
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
          };
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
        inherit (state) mode depth skip;
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
        inherit (chunk) mode depth skip;
        inherit chunks;
      })))
    {
      chunks = [];
      mode = "code";
      depth = 0;
      skip = false;
    }
    (builtins.genList (index: index) lineCount);
in
  builtins.concatStringsSep "" (lib.reverseList result.chunks)
