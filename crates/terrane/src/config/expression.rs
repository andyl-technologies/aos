//! Parses the store-expression syntax from specification 11.
//!
//! Parsing establishes only the expression's shape. It cannot infer whether a
//! disk or remote is an authority; STORE-27 and STORE-28 require backend probes
//! in the later store implementation. Nesting is bounded before recursion.
//!
//! ```text
//! routed[shared-dir(/objects), remote(unix:///run/terrane.sock)]
//! guard(policy=warehouse)(bucket(s3://example/prefix))
//! replicated(3, ack=2)[disk(/a), disk(/b), disk(/c)]
//! ```

use std::fmt;

/// Stores one syntactically valid backend or combinator expression.
#[derive(Debug, Eq, PartialEq)]
pub struct StoreExpression {
    name: String,
    arguments: Vec<String>,
    children: Vec<Self>,
}

impl StoreExpression {
    /// Parses the closed backend and combinator vocabulary.
    ///
    /// # Errors
    ///
    /// Returns a syntax error for unknown names, missing or empty arguments,
    /// malformed child lists, invalid replication counts, trailing input, or
    /// nesting beyond 64 expressions. Capability validation is performed later.
    pub fn parse(input: &str) -> Result<Self, ExpressionError> {
        let mut parser = Parser { remaining: input };
        let result = parser.expression(0)?;
        parser.whitespace();
        if !parser.remaining.is_empty() {
            return Err(ExpressionError::Syntax);
        }

        Ok(result)
    }

    /// Returns the registered backend or combinator name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns backend locators, policies, or numeric combinator arguments.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// Returns the combinator's children in configuration order.
    pub fn children(&self) -> &[Self] {
        &self.children
    }
}

/// Describes malformed or excessively nested store expressions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionError {
    /// Rejects input outside the specification's expression grammar.
    Syntax,
    /// Rejects nesting that would exhaust the parser's bounded stack.
    NestingLimit,
}

impl fmt::Display for ExpressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Syntax => "expected a store expression from specification 11",
            Self::NestingLimit => "store expression exceeds 64 nesting levels",
        })
    }
}

impl std::error::Error for ExpressionError {}

struct Parser<'a> {
    remaining: &'a str,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        self.remaining = self.remaining.trim_start();
    }

    fn take(&mut self, expected: char) -> Result<(), ExpressionError> {
        self.whitespace();
        self.remaining = self
            .remaining
            .strip_prefix(expected)
            .ok_or(ExpressionError::Syntax)?;
        Ok(())
    }

    fn arguments(&mut self) -> Result<Vec<String>, ExpressionError> {
        self.take('(')?;
        let (arguments, remaining) = self
            .remaining
            .split_once(')')
            .ok_or(ExpressionError::Syntax)?;
        if arguments.contains(['(', '[', ']']) {
            return Err(ExpressionError::Syntax);
        }

        let values: Vec<String> = arguments
            .split(',')
            .map(|value| value.trim().to_owned())
            .collect();
        if values.iter().any(String::is_empty) {
            return Err(ExpressionError::Syntax);
        }
        self.remaining = remaining;
        Ok(values)
    }

    fn expression(&mut self, depth: usize) -> Result<StoreExpression, ExpressionError> {
        if depth >= 64 {
            return Err(ExpressionError::NestingLimit);
        }
        self.whitespace();
        let length = self
            .remaining
            .find(|c: char| !(c.is_ascii_lowercase() || c == '-'))
            .unwrap_or(self.remaining.len());
        let (name, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;

        let (arguments, children) = match name {
            "bucket" | "disk" | "shared-dir" | "blockdev" | "remote" => {
                let arguments = self.arguments()?;
                if name != "blockdev" && arguments.len() != 1 {
                    return Err(ExpressionError::Syntax);
                }
                (arguments, Vec::new())
            }
            "guard" | "cache" => {
                let arguments = self.arguments()?;
                if arguments.len() != 1 {
                    return Err(ExpressionError::Syntax);
                }
                self.take('(')?;
                let child = self.expression(depth + 1)?;
                self.take(')')?;
                (arguments, vec![child])
            }
            "routed" => (Vec::new(), self.children(depth)?),
            "replicated" | "striped" => {
                let arguments = self.arguments()?;
                validate_counts(name, &arguments)?;
                (arguments, self.children(depth)?)
            }
            _ => return Err(ExpressionError::Syntax),
        };

        Ok(StoreExpression {
            name: name.to_owned(),
            arguments,
            children,
        })
    }

    fn children(&mut self, depth: usize) -> Result<Vec<StoreExpression>, ExpressionError> {
        self.take('[')?;
        let mut children = vec![self.expression(depth + 1)?];
        loop {
            self.whitespace();
            if self.remaining.starts_with(']') {
                self.take(']')?;
                return Ok(children);
            }
            self.take(',')?;
            self.whitespace();
            if self.remaining.starts_with(']') {
                self.take(']')?;
                return Ok(children);
            }
            children.push(self.expression(depth + 1)?);
        }
    }
}

fn validate_counts(name: &str, arguments: &[String]) -> Result<(), ExpressionError> {
    let [count, second] = arguments else {
        return Err(ExpressionError::Syntax);
    };
    let prefix = if name == "replicated" {
        "ack="
    } else {
        "parity="
    };
    let count: u32 = count.parse().map_err(|_| ExpressionError::Syntax)?;
    let second: u32 = second
        .strip_prefix(prefix)
        .ok_or(ExpressionError::Syntax)?
        .trim()
        .parse()
        .map_err(|_| ExpressionError::Syntax)?;
    if count == 0 || second == 0 || (name == "replicated" && second > count) {
        return Err(ExpressionError::Syntax);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registered_expression_shapes() {
        for expression in [
            "bucket(file:///tmp/store)",
            "disk(/tmp/cache)",
            "blockdev(/dev/a,/dev/b)",
            "guard(policy=warehouse)(bucket(s3://example/prefix))",
            "routed[shared-dir(/objects), remote(unix:///run/terrane.sock),]",
            "cache(policy)(disk(/tmp/cache))",
            "replicated(3,ack=2)[disk(/a),disk(/b),disk(/c)]",
            "striped(2,parity=1)[disk(/a),disk(/b),disk(/c)]",
        ] {
            assert!(StoreExpression::parse(expression).is_ok(), "{expression}");
        }
    }

    #[test]
    fn rejects_malformed_and_excessively_nested_expressions() {
        for expression in [
            "",
            "unknown(/tmp)",
            "disk()",
            "disk(/a,/b)",
            "routed[]",
            "disk(/a)garbage",
            "replicated(1,ack=2)[disk(/a)]",
        ] {
            assert_eq!(
                StoreExpression::parse(expression),
                Err(ExpressionError::Syntax),
                "{expression}"
            );
        }
        let expression = format!(
            "{}disk(/tmp){}",
            "guard(policy)(".repeat(65),
            ")".repeat(65)
        );
        assert_eq!(
            StoreExpression::parse(&expression),
            Err(ExpressionError::NestingLimit)
        );
    }
}
