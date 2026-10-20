//! Small bounded XML reader for closed provider multipart response schemas.

use anyhow::{ensure, Result};

pub(super) struct Node<'a> {
    pub name: &'a str,
    pub text: &'a str,
    pub children: Vec<Node<'a>>,
}

pub(super) fn parse(xml: &str, maximum_bytes: usize) -> Result<Node<'_>> {
    ensure!(
        xml.len() <= maximum_bytes,
        "multipart response exceeds limit"
    );
    let mut parser = Parser {
        remaining: xml.trim(),
        nodes: 0,
    };
    if parser.remaining.starts_with("<?xml ") {
        let (declaration, rest) = parser
            .remaining
            .split_once("?>")
            .ok_or_else(|| anyhow::anyhow!("invalid multipart XML declaration"))?;
        ensure!(
            matches!(
                declaration,
                "<?xml version=\"1.0\""
                    | "<?xml version=\"1.0\" encoding=\"UTF-8\""
                    | "<?xml version='1.0'"
                    | "<?xml version='1.0' encoding='UTF-8'"
            ),
            "invalid multipart XML declaration"
        );
        parser.remaining = rest.trim_start();
    }
    let node = parser.node(0)?;
    ensure!(
        parser.remaining.trim().is_empty(),
        "trailing multipart XML data"
    );
    Ok(node)
}

struct Parser<'a> {
    remaining: &'a str,
    nodes: usize,
}

impl<'a> Parser<'a> {
    fn node(&mut self, depth: usize) -> Result<Node<'a>> {
        ensure!(
            depth <= 4 && self.nodes < 16_000,
            "multipart XML structure exceeds limit"
        );
        self.nodes += 1;
        let input = self
            .remaining
            .strip_prefix('<')
            .ok_or_else(|| anyhow::anyhow!("invalid multipart XML start"))?;
        let (start, mut rest) = input
            .split_once('>')
            .ok_or_else(|| anyhow::anyhow!("invalid multipart XML start"))?;
        let empty = start.ends_with('/');
        let start = start.strip_suffix('/').unwrap_or(start);
        let mut fields = start.splitn(2, char::is_whitespace);
        let name = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("invalid multipart XML name"))?;
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name.bytes().all(|b| b.is_ascii_alphanumeric())
                && name.as_bytes()[0].is_ascii_alphabetic(),
            "invalid multipart XML name"
        );
        if let Some(attributes) = fields.next() {
            ensure!(
                depth == 0
                    && matches!(
                        attributes.trim(),
                        "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""
                            | "xmlns='http://s3.amazonaws.com/doc/2006-03-01/'"
                    ),
                "unsupported multipart XML attribute"
            );
        }
        if empty {
            self.remaining = rest;
            return Ok(Node {
                name,
                text: "",
                children: Vec::new(),
            });
        }

        let mut children = Vec::new();
        let mut text = "";
        loop {
            let next = rest
                .find('<')
                .ok_or_else(|| anyhow::anyhow!("unterminated multipart XML element"))?;
            let segment = &rest[..next];
            rest = &rest[next..];
            if let Some(end) = rest.strip_prefix("</") {
                let (close, tail) = end
                    .split_once('>')
                    .ok_or_else(|| anyhow::anyhow!("invalid multipart XML end"))?;
                ensure!(close == name, "multipart XML end mismatch");
                if children.is_empty() {
                    text = segment;
                } else {
                    ensure!(segment.trim().is_empty(), "mixed multipart XML text");
                }
                self.remaining = tail;
                return Ok(Node {
                    name,
                    text,
                    children,
                });
            }
            ensure!(segment.trim().is_empty(), "mixed multipart XML text");
            self.remaining = rest;
            children.push(self.node(depth + 1)?);
            rest = self.remaining;
        }
    }
}

impl Node<'_> {
    pub(super) fn scalar(&self) -> Result<String> {
        ensure!(
            self.children.is_empty() && self.text.len() <= 8192,
            "invalid multipart XML scalar"
        );
        let mut output = String::with_capacity(self.text.len());
        let mut rest = self.text;
        while let Some(index) = rest.find('&') {
            output.push_str(&rest[..index]);
            let (entity, next) = rest[index + 1..]
                .split_once(';')
                .ok_or_else(|| anyhow::anyhow!("invalid multipart XML entity"))?;
            let character = match entity {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ if entity.starts_with("#x") => char::from_u32(
                    u32::from_str_radix(&entity[2..], 16)
                        .map_err(|_| anyhow::anyhow!("invalid multipart XML entity"))?,
                )
                .ok_or_else(|| anyhow::anyhow!("invalid multipart XML entity"))?,
                _ if entity.starts_with('#') => char::from_u32(
                    entity[1..]
                        .parse::<u32>()
                        .map_err(|_| anyhow::anyhow!("invalid multipart XML entity"))?,
                )
                .ok_or_else(|| anyhow::anyhow!("invalid multipart XML entity"))?,
                _ => anyhow::bail!("unsupported multipart XML entity"),
            };
            ensure!(!character.is_control(), "invalid multipart XML entity");
            output.push(character);
            rest = next;
        }
        output.push_str(rest);
        ensure!(
            !output.chars().any(char::is_control),
            "invalid multipart XML scalar"
        );
        Ok(output)
    }
}
