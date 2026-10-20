//! Line-oriented parser for AOS Nix doc comments.
//!
//! AOS uses a lightweight doc comment convention in `.nix` files, parsed
//! without a full Nix grammar:
//!
//! - `##!` lines at the top of a file form the module-level doc
//! - A block of `##` lines immediately above a `name = ...` binding
//!   documents that binding
//! - A standalone `## # Heading` line starts a grouping section that is
//!   attached to all following items
//!
//! Doc bodies are markdown and may contain structured `# Type`,
//! `# Parameters`, `# Examples`, `# See Also`, `# Since`, and
//! `# Deprecated` sections, which are parsed into the corresponding
//! [`ItemDoc`] fields. [`parse_file`] is the sole entry point; it never
//! fails, returning an empty [`ParsedFile`] for content with no doc
//! comments.

/// Result of parsing a single Nix file for doc comments.
#[derive(Debug, Clone)]
pub struct ParsedFile {
    /// Module-level documentation from `##!` comments at the start of the file.
    pub module_doc: Option<ModuleDoc>,
    /// Per-binding documentation from `##` comments.
    pub items: Vec<ItemDoc>,
}

/// Module-level doc extracted from `##!` lines at the file start.
#[derive(Debug, Clone)]
pub struct ModuleDoc {
    /// First paragraph of the module doc.
    pub summary: String,
    /// Additional markdown prose after the summary.
    pub body: String,
}

/// Documentation for a single binding, extracted from `##` comment blocks.
#[derive(Debug, Clone)]
pub struct ItemDoc {
    /// The binding name (identifier before `=`).
    pub name: String,
    /// First paragraph of the doc block.
    pub summary: String,
    /// Additional markdown prose after the summary, excluding structured sections.
    pub body: String,
    /// From `# Type` section.
    pub type_sig: Option<String>,
    /// From `# Parameters` section: (name, description).
    pub parameters: Vec<(String, String)>,
    /// From `# Examples` section (each fenced code block).
    pub examples: Vec<String>,
    /// From `# See Also` section.
    pub see_also: Vec<String>,
    /// From `# Since` section.
    pub since: Option<String>,
    /// From `# Deprecated` section.
    pub deprecated: Option<String>,
    /// Grouping section this item belongs to (from `## # Heading` markers).
    pub section: Option<String>,
    /// Line number of the binding in the source file (1-based).
    pub source_line: usize,
}

/// Parses a Nix source file and extracts all doc comments.
///
/// Recognizes:
/// - `##!` at file start for module-level docs
/// - `##` above bindings for item-level docs
/// - `## # Heading` for section groupings
///
/// This function is infallible: malformed or absent doc comments simply
/// produce fewer (or no) items.
pub fn parse_file(content: &str) -> ParsedFile {
    let lines: Vec<&str> = content.lines().collect();
    let module_doc = parse_module_doc(&lines);
    let items = parse_items(&lines);
    ParsedFile { module_doc, items }
}

/// Extracts `##!` lines from the start of the file (leading blank lines are
/// allowed before the block; any other line terminates it).
fn parse_module_doc(lines: &[&str]) -> Option<ModuleDoc> {
    let mut doc_lines = Vec::new();

    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with("##!") {
            // Strip the `##! ` or `##!` prefix.
            let content = trimmed
                .strip_prefix("##! ")
                .unwrap_or(trimmed.strip_prefix("##!").unwrap_or(""));
            doc_lines.push(content);
        } else if trimmed.is_empty() && doc_lines.is_empty() {
            // Allow leading blank lines before `##!` block.
            continue;
        } else {
            break;
        }
    }

    if doc_lines.is_empty() {
        return None;
    }

    let content = doc_lines.join("\n");
    let (summary, body) = split_summary_and_body(&content);
    Some(ModuleDoc { summary, body })
}

/// Parses item doc blocks and their associated bindings.
///
/// Accumulates consecutive `##` lines into a buffer, then resolves the
/// buffer when a non-comment line is reached: if the line is a binding
/// (`name = ...`), the buffer becomes that binding's [`ItemDoc`]; if the
/// buffer was a lone `# Heading`, it updates the current section instead.
/// A blank line between two `##` blocks (tracked via `had_gap`) separates
/// a standalone section heading from the doc block that follows it.
fn parse_items(lines: &[&str]) -> Vec<ItemDoc> {
    let mut items = Vec::new();
    let mut current_section: Option<String> = None;
    let mut doc_buffer: Vec<String> = Vec::new();
    // Track whether a non-## blank line was seen since the last ## line.
    // This separates standalone section headings from multi-part doc blocks.
    let mut had_gap = false;
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Skip module-level doc comments at the top.
        if trimmed.starts_with("##!") {
            i += 1;
            continue;
        }

        // Check for `##` doc comment line.
        if trimmed.starts_with("##") && !trimmed.starts_with("##!") {
            let content = strip_doc_prefix(trimmed);

            // If there was a gap (blank non-## line) since the last ## line,
            // the pending buffer is a separate block. If it was just a section
            // heading, save it before starting the new block.
            if had_gap && !doc_buffer.is_empty() {
                maybe_set_section(&doc_buffer, &mut current_section);
                doc_buffer.clear();
            }
            had_gap = false;

            doc_buffer.push(content);
            i += 1;
            continue;
        }

        // Non-## line encountered.
        if !doc_buffer.is_empty() {
            // Skip blank lines between doc block and binding.
            if trimmed.is_empty() {
                had_gap = true;
                i += 1;
                continue;
            }

            if let Some(name) = extract_binding_name(trimmed) {
                let body = doc_buffer.join("\n");
                let parsed = parse_doc_sections(&body);
                items.push(ItemDoc {
                    name,
                    summary: parsed.summary,
                    body: parsed.body,
                    type_sig: parsed.type_sig,
                    parameters: parsed.parameters,
                    examples: parsed.examples,
                    see_also: parsed.see_also,
                    since: parsed.since,
                    deprecated: parsed.deprecated,
                    section: current_section.clone(),
                    source_line: i + 1, // 1-based
                });
                doc_buffer.clear();
            } else {
                // Not a binding — check if buffer was a section heading.
                maybe_set_section(&doc_buffer, &mut current_section);
                doc_buffer.clear();
            }
            had_gap = false;
        }

        i += 1;
    }

    items
}

/// If the buffer contains only a section heading (a single non-empty line
/// starting with `# `), update `current_section`. Otherwise do nothing.
fn maybe_set_section(buffer: &[String], section: &mut Option<String>) {
    let non_empty: Vec<&String> = buffer.iter().filter(|l| !l.trim().is_empty()).collect();
    if non_empty.len() == 1 && is_section_heading(non_empty[0]) {
        let heading = non_empty[0]
            .strip_prefix("# ")
            .or_else(|| non_empty[0].strip_prefix("#"))
            .unwrap_or(non_empty[0])
            .trim()
            .to_string();
        *section = Some(heading);
    }
}

/// Strips the `## ` or `##` prefix from a doc comment line (at most one
/// leading space is removed so indented markdown survives).
fn strip_doc_prefix(line: &str) -> String {
    let after_hashes = line.strip_prefix("##").unwrap_or(line);
    // Strip at most one leading space after `##`.
    after_hashes
        .strip_prefix(' ')
        .unwrap_or(after_hashes)
        .to_string()
}

/// Checks if doc content represents a section heading (`# Heading`).
fn is_section_heading(content: &str) -> bool {
    let trimmed = content.trim();
    trimmed.starts_with("# ")
        || (trimmed.starts_with('#') && trimmed.len() > 1 && !trimmed.starts_with("##"))
}

/// Tries to extract a binding name from a line like `name = ...` or `  name = ...`.
/// Also handles `name =` at end of line (value on next line). Returns
/// `None` for lines whose left-hand side is not a simple Nix identifier
/// (quoted attributes like `"foo.bar"` are not recognized).
fn extract_binding_name(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Try ` = ` first (inline value), then ` =` at end of line (multiline value).
    let eq_pos = trimmed.find(" = ").or_else(|| {
        if trimmed.ends_with(" =") {
            Some(trimmed.len() - 2)
        } else {
            None
        }
    })?;
    let candidate = &trimmed[..eq_pos];

    // The identifier must be a valid Nix identifier: [a-zA-Z_][a-zA-Z0-9_'-]*
    // It may also be a quoted attribute like `"foo.bar"`, but we handle the simple case.
    if is_valid_nix_identifier(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

/// Checks if a string is a valid Nix identifier
/// (`[a-zA-Z_][a-zA-Z0-9_'-]*`).
fn is_valid_nix_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '\'' || c == '-')
}

/// Parsed sections from a doc block's markdown content.
struct ParsedSections {
    summary: String,
    body: String,
    type_sig: Option<String>,
    parameters: Vec<(String, String)>,
    examples: Vec<String>,
    see_also: Vec<String>,
    since: Option<String>,
    deprecated: Option<String>,
}

/// Parses structured sections from a doc block's markdown.
///
/// Recognized headings: `# Type`, `# Parameters`, `# Examples`,
/// `# See Also`, `# Since`, `# Deprecated`. Headings inside fenced code
/// blocks are ignored. The text before the first heading is the main body,
/// whose first paragraph becomes the summary. The returned `body` contains
/// only subsequent main-body paragraphs; recognized sections are represented
/// by their structured fields instead.
fn parse_doc_sections(raw: &str) -> ParsedSections {
    let mut sections: Vec<(String, String)> = Vec::new();
    let mut current_heading: Option<String> = None;
    let mut current_body = String::new();
    let mut in_fence = false;

    for line in raw.lines() {
        // Track fenced code blocks — don't interpret `# ` as headings inside them.
        if line.trim().starts_with("```") {
            in_fence = !in_fence;
        }

        if !in_fence && line.starts_with("# ") {
            // Save previous section.
            let heading_text = line.strip_prefix("# ").unwrap().trim().to_string();
            if let Some(prev) = current_heading.take() {
                sections.push((prev, current_body.trim().to_string()));
            } else if !current_body.trim().is_empty() {
                sections.push((String::new(), current_body.trim().to_string()));
            }
            current_heading = Some(heading_text);
            current_body = String::new();
        } else {
            if !current_body.is_empty() || !line.is_empty() {
                if !current_body.is_empty() {
                    current_body.push('\n');
                }
                current_body.push_str(line);
            }
        }
    }

    // Save final section.
    if let Some(prev) = current_heading.take() {
        sections.push((prev, current_body.trim().to_string()));
    } else if !current_body.trim().is_empty() {
        sections.push((String::new(), current_body.trim().to_string()));
    }

    // The first unnamed section is the main body/summary.
    let main_body = sections
        .iter()
        .find(|(h, _)| h.is_empty())
        .map(|(_, b)| b.clone())
        .unwrap_or_default();

    let (summary, main_body) = split_summary_and_body(&main_body);

    let type_sig = find_section(&sections, "Type").and_then(|s| extract_backtick_content(&s));
    let parameters = find_section(&sections, "Parameters")
        .map(|s| parse_parameter_list(&s))
        .unwrap_or_default();
    let examples = find_section(&sections, "Examples")
        .map(|s| extract_fenced_blocks(&s))
        .unwrap_or_default();
    let see_also = find_section(&sections, "See Also")
        .map(|s| parse_see_also(&s))
        .unwrap_or_default();
    let since = find_section(&sections, "Since").map(|s| s.trim().to_string());
    let deprecated = find_section(&sections, "Deprecated").map(|s| s.trim().to_string());
    let body = unstructured_body(&main_body, &sections);

    ParsedSections {
        summary,
        body,
        type_sig,
        parameters,
        examples,
        see_also,
        since,
        deprecated,
    }
}

/// Combines additional main prose with headings that are not typed sections.
fn unstructured_body(main_body: &str, sections: &[(String, String)]) -> String {
    let mut parts = Vec::new();
    if !main_body.is_empty() {
        parts.push(main_body.to_string());
    }

    for (heading, content) in sections {
        if heading.is_empty() || is_structured_heading(heading) {
            continue;
        }

        let section = if content.is_empty() {
            format!("# {heading}")
        } else {
            format!("# {heading}\n\n{content}")
        };
        parts.push(section);
    }

    parts.join("\n\n")
}

/// Returns whether a heading is represented by a structured item field.
fn is_structured_heading(heading: &str) -> bool {
    [
        "Type",
        "Parameters",
        "Examples",
        "See Also",
        "Since",
        "Deprecated",
    ]
    .iter()
    .any(|name| heading.eq_ignore_ascii_case(name))
}

/// Finds a named section's content (heading match is case-insensitive).
fn find_section(sections: &[(String, String)], name: &str) -> Option<String> {
    sections
        .iter()
        .find(|(h, _)| h.eq_ignore_ascii_case(name))
        .map(|(_, b)| b.clone())
}

/// Extracts the first paragraph (text before the first blank line),
/// joining its lines with single spaces.
fn extract_first_paragraph(text: &str) -> String {
    let mut result = String::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !result.is_empty() {
                break;
            }
            continue;
        }
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(line.trim());
    }
    result
}

/// Splits markdown into a one-line summary and the remaining prose.
fn split_summary_and_body(text: &str) -> (String, String) {
    let trimmed = text.trim();
    let summary = extract_first_paragraph(trimmed);
    let lines: Vec<&str> = trimmed.lines().collect();
    let body = lines
        .iter()
        .position(|line| line.trim().is_empty())
        .map(|separator| lines[separator + 1..].join("\n").trim().to_string())
        .unwrap_or_default();

    (summary, body)
}

/// Extracts the type signature text from a `# Type` section.
/// Tries a fenced code block first, then inline backticks, then falls back
/// to the raw (trimmed) text; returns `None` only for empty content.
fn extract_backtick_content(text: &str) -> Option<String> {
    // Try fenced block first.
    let blocks = extract_fenced_blocks(text);
    if let Some(block) = blocks.into_iter().next() {
        return Some(block);
    }

    // Try inline backticks.
    let trimmed = text.trim();
    if trimmed.starts_with('`') && trimmed.ends_with('`') && trimmed.len() > 2 {
        return Some(trimmed[1..trimmed.len() - 1].to_string());
    }

    // Return raw text if non-empty.
    if !trimmed.is_empty() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Parses a parameter list in the format `- \`name\` -- description`.
/// Non-list lines after an item are treated as continuations of its
/// description.
fn parse_parameter_list(text: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_desc = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            // Save previous parameter.
            if let Some(name) = current_name.take() {
                params.push((name, current_desc.trim().to_string()));
                current_desc.clear();
            }

            let item = &trimmed[2..];
            // Extract backtick-quoted name.
            if let Some((name, desc)) = parse_param_item(item) {
                current_name = Some(name);
                current_desc = desc;
            }
        } else if current_name.is_some() && !trimmed.is_empty() {
            // Continuation line.
            current_desc.push(' ');
            current_desc.push_str(trimmed);
        }
    }

    if let Some(name) = current_name {
        params.push((name, current_desc.trim().to_string()));
    }

    params
}

/// Parses a single parameter item: `` `name` `` followed by a separator
/// (em dash, hyphen, or colon) and the description.
fn parse_param_item(item: &str) -> Option<(String, String)> {
    let trimmed = item.trim();
    if !trimmed.starts_with('`') {
        return None;
    }
    let end_tick = trimmed[1..].find('`')?;
    let name = trimmed[1..=end_tick].to_string();
    let rest = &trimmed[end_tick + 2..];
    // Skip separator: ` — `, ` - `, `: `, etc.
    let desc = rest
        .trim_start_matches(|c: char| c == '—' || c == '-' || c == ':' || c == ' ')
        .trim()
        .to_string();
    Some((name, desc))
}

/// Extracts the contents of fenced code blocks (with or without a language
/// tag); the fence lines themselves are not included.
fn extract_fenced_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut block_lines: Vec<&str> = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_block {
                blocks.push(block_lines.join("\n"));
                block_lines.clear();
                in_block = false;
            } else {
                in_block = true;
            }
        } else if in_block {
            block_lines.push(line);
        }
    }

    blocks
}

/// Parses a `# See Also` section into a list of references.
/// Expects backtick-wrapped names separated by commas or newlines; the
/// backticks are stripped from each reference.
fn parse_see_also(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    // Split on commas and newlines, then extract backtick-quoted names.
    for part in text.split(|c: char| c == ',' || c == '\n') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Strip surrounding backticks if present.
        let name = trimmed
            .strip_prefix('`')
            .and_then(|s| s.strip_suffix('`'))
            .unwrap_or(trimmed);
        if !name.is_empty() {
            refs.push(name.to_string());
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_module_doc() {
        let content = "##! Module summary line.\n##!\n##! More details here.\n\n{ lib }:\n";
        let parsed = parse_file(content);
        let module = parsed.module_doc.unwrap();
        assert_eq!(module.summary, "Module summary line.");
        assert_eq!(module.body, "More details here.");
    }

    #[test]
    fn test_parse_item_doc() {
        let content = "\
## Add an element to the front of a list.
##
## # Type
##
## `a -> [a] -> [a]`
##
## # Examples
##
## ```nix
## prepend 1 [2 3]
## # => [1 2 3]
## ```
prepend = x: xs: [x] ++ xs;
";
        let parsed = parse_file(content);
        assert_eq!(parsed.items.len(), 1);
        let item = &parsed.items[0];
        assert_eq!(item.name, "prepend");
        assert_eq!(item.summary, "Add an element to the front of a list.");
        assert!(item.body.is_empty());
        assert_eq!(item.type_sig.as_deref(), Some("a -> [a] -> [a]"));
        assert_eq!(item.examples.len(), 1);
        assert!(item.examples[0].contains("prepend 1 [2 3]"));
    }

    #[test]
    fn item_body_excludes_summary_and_structured_sections() {
        let content = "\
## Summary with `formatting`.
##
## Additional prose.
##
## # Notes
##
## Preserved custom section.
##
## # Examples
##
## ```nix
## example
## ```
value = true;
";
        let parsed = parse_file(content);
        let item = &parsed.items[0];

        assert_eq!(item.summary, "Summary with `formatting`.");
        assert_eq!(
            item.body,
            "Additional prose.\n\n# Notes\n\nPreserved custom section."
        );
        assert_eq!(item.examples, ["example"]);
        assert!(!item.body.contains("# Examples"));
    }

    #[test]
    fn test_parse_section_heading() {
        let content = "\
## # List operations

## Return the first element.
head = xs: builtins.elemAt xs 0;

## # String operations

## Concatenate strings.
concat = builtins.concatStringsSep;
";
        let parsed = parse_file(content);
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].section.as_deref(), Some("List operations"));
        assert_eq!(
            parsed.items[1].section.as_deref(),
            Some("String operations")
        );
    }

    #[test]
    fn test_parse_parameters() {
        let content = "\
## Map a function over a list.
##
## # Parameters
##
## - `f` — The function to apply
## - `xs` — The input list
map = f: xs: builtins.map f xs;
";
        let parsed = parse_file(content);
        assert_eq!(parsed.items.len(), 1);
        let item = &parsed.items[0];
        assert_eq!(item.parameters.len(), 2);
        assert_eq!(item.parameters[0].0, "f");
        assert_eq!(item.parameters[0].1, "The function to apply");
        assert_eq!(item.parameters[1].0, "xs");
    }

    #[test]
    fn test_parse_see_also_and_since() {
        let content = "\
## Check if a list is empty.
##
## # See Also
##
## `head`, `tail`, `length`
##
## # Since
##
## 0.1.0
isEmpty = xs: xs == [];
";
        let parsed = parse_file(content);
        let item = &parsed.items[0];
        assert_eq!(item.see_also, vec!["head", "tail", "length"]);
        assert_eq!(item.since.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn test_empty_file() {
        let parsed = parse_file("");
        assert!(parsed.module_doc.is_none());
        assert!(parsed.items.is_empty());
    }

    #[test]
    fn test_no_doc_comments() {
        let content = "{ lib }:\n{ foo = 1; bar = 2; }\n";
        let parsed = parse_file(content);
        assert!(parsed.module_doc.is_none());
        assert!(parsed.items.is_empty());
    }

    #[test]
    fn test_binding_detection() {
        assert!(is_valid_nix_identifier("foo"));
        assert!(is_valid_nix_identifier("foo-bar"));
        assert!(is_valid_nix_identifier("foo'"));
        assert!(is_valid_nix_identifier("_private"));
        assert!(!is_valid_nix_identifier("123"));
        assert!(!is_valid_nix_identifier(""));
    }
}
