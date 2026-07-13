//! `.env` file parser (spec F4.2). Messy files are the norm, not the
//! exception — this handles every documented edge case and is fuzz-tested to
//! never panic and never hang on arbitrary input:
//!
//! - `export FOO=bar` prefixes
//! - single- and double-quoted values, including multi-line quoted values
//! - escape sequences in double quotes (`\n`, `\t`, `\r`, `\"`, `\\`)
//! - `#` comments (full-line and trailing on unquoted values)
//! - blank lines, `KEY=` with empty value, values containing `=`
//! - duplicate keys (later wins, earlier recorded for the preview)
//! - CRLF line endings, missing trailing newline, a leading BOM
//!
//! Parsing is infallible: malformed lines become warnings, never errors —
//! an importer that refuses a file over one bad line helps nobody.

use crate::secret::SecretValue;

#[derive(Debug)]
pub struct EnvEntry {
    pub key: String,
    pub value: SecretValue,
    /// 1-based line number where this entry started.
    pub line: usize,
    /// Set when a later entry overrode this key (dotenv convention:
    /// last one wins). The preview shows these greyed out.
    pub overridden: bool,
}

#[derive(Debug, Default)]
pub struct ParsedEnv {
    pub entries: Vec<EnvEntry>,
    /// Human-readable notes about lines that could not be understood.
    pub warnings: Vec<String>,
}

impl ParsedEnv {
    /// Entries that survive deduplication (the ones an import would use).
    pub fn effective_entries(&self) -> impl Iterator<Item = &EnvEntry> {
        self.entries.iter().filter(|e| !e.overridden)
    }
}

pub fn parse(content: &str) -> ParsedEnv {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut parsed = ParsedEnv::default();

    // Manual line iteration (not `.lines()`) so quoted values can consume
    // multiple lines and we can report accurate line numbers.
    let lines: Vec<&str> = content.split('\n').collect();
    let mut i = 0usize;

    while i < lines.len() {
        let line_no = i + 1;
        let raw = lines[i].strip_suffix('\r').unwrap_or(lines[i]);
        let trimmed = raw.trim_start();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }

        let body = trimmed
            .strip_prefix("export ")
            .unwrap_or(trimmed)
            .trim_start();

        let Some(eq) = body.find('=') else {
            parsed
                .warnings
                .push(format!("line {line_no}: no '=' found — skipped"));
            i += 1;
            continue;
        };

        let key = body[..eq].trim().to_string();
        if !is_valid_key(&key) {
            parsed.warnings.push(format!(
                "line {line_no}: {key:?} is not a valid variable name — skipped"
            ));
            i += 1;
            continue;
        }

        let after_eq = &body[eq + 1..];
        let (value, consumed_extra_lines, warning) = parse_value(after_eq, &lines[i + 1..]);
        if let Some(w) = warning {
            parsed.warnings.push(format!("line {line_no}: {w}"));
        }
        i += 1 + consumed_extra_lines;

        // Duplicate handling: later wins; keep earlier rows for the preview.
        for prior in parsed.entries.iter_mut().filter(|e| e.key == key) {
            prior.overridden = true;
        }
        parsed.entries.push(EnvEntry {
            key,
            value: SecretValue::new(value),
            line: line_no,
            overridden: false,
        });
    }

    parsed
}

fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a value starting right after `=`. Returns (value, extra lines
/// consumed for multi-line quoted values, optional warning).
fn parse_value(after_eq: &str, rest: &[&str]) -> (String, usize, Option<String>) {
    let s = after_eq.trim_start();

    match s.chars().next() {
        Some(q @ ('"' | '\'')) => {
            // Quoted: scan for the closing quote, possibly across lines.
            let mut value = String::new();
            let mut escaped = false;
            let mut chars: Vec<char> = s[q.len_utf8()..].chars().collect();
            let mut extra = 0usize;
            let mut idx = 0usize;

            loop {
                if idx >= chars.len() {
                    // Quote still open at end of this line: consume the next.
                    if extra < rest.len() {
                        value.push('\n');
                        let next = rest[extra].strip_suffix('\r').unwrap_or(rest[extra]);
                        chars = next.chars().collect();
                        extra += 1;
                        idx = 0;
                        continue;
                    }
                    // EOF with unterminated quote: take what we have.
                    return (
                        value,
                        extra,
                        Some("unterminated quote — value taken to end of file".into()),
                    );
                }
                let c = chars[idx];
                idx += 1;

                if q == '"' {
                    if escaped {
                        value.push(match c {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other, // \" \\ \' and unknown escapes
                        });
                        escaped = false;
                        continue;
                    }
                    if c == '\\' {
                        escaped = true;
                        continue;
                    }
                }
                if c == q {
                    // Closing quote: anything after it on the line is ignored
                    // (commonly a trailing comment).
                    return (value, extra, None);
                }
                value.push(c);
            }
        }
        _ => {
            // Unquoted: value runs to end of line; ` #` starts a comment.
            let val = match s.find(" #") {
                Some(pos) => &s[..pos],
                None => s,
            };
            (val.trim().to_string(), 0, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'a>(p: &'a ParsedEnv, key: &str) -> &'a EnvEntry {
        p.effective_entries()
            .find(|e| e.key == key)
            .unwrap_or_else(|| panic!("missing key {key}"))
    }

    #[test]
    fn plain_and_export_lines() {
        let p = parse("FOO=bar\nexport BAZ=qux\n");
        assert_eq!(get(&p, "FOO").value.expose(), "bar");
        assert_eq!(get(&p, "BAZ").value.expose(), "qux");
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn quoted_values_and_escapes() {
        let p = parse(concat!(
            "DQ=\"hello world\"\n",
            "SQ='single $literal'\n",
            "ESC=\"line1\\nline2\\t\\\"quoted\\\"\"\n",
        ));
        assert_eq!(get(&p, "DQ").value.expose(), "hello world");
        assert_eq!(get(&p, "SQ").value.expose(), "single $literal");
        assert_eq!(get(&p, "ESC").value.expose(), "line1\nline2\t\"quoted\"");
    }

    #[test]
    fn multiline_quoted_value() {
        let p = parse("PEM=\"-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\"\nNEXT=1\n");
        assert_eq!(
            get(&p, "PEM").value.expose(),
            "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----"
        );
        assert_eq!(get(&p, "NEXT").value.expose(), "1");
    }

    #[test]
    fn comments_blank_lines_and_trailing_comments() {
        let p = parse(concat!(
            "# full line comment\n",
            "   # indented comment\n",
            "\n",
            "A=1 # trailing comment\n",
            "B=\"kept # not a comment\"\n",
        ));
        assert_eq!(get(&p, "A").value.expose(), "1");
        assert_eq!(get(&p, "B").value.expose(), "kept # not a comment");
        assert_eq!(p.entries.len(), 2);
    }

    #[test]
    fn empty_value_and_value_with_equals() {
        let p = parse("EMPTY=\nURL=postgres://u:p@h/db?a=1&b=2\n");
        assert_eq!(get(&p, "EMPTY").value.expose(), "");
        assert_eq!(get(&p, "URL").value.expose(), "postgres://u:p@h/db?a=1&b=2");
    }

    #[test]
    fn duplicate_keys_later_wins_earlier_marked() {
        let p = parse("K=first\nK=second\n");
        assert_eq!(get(&p, "K").value.expose(), "second");
        let dupes: Vec<_> = p.entries.iter().filter(|e| e.overridden).collect();
        assert_eq!(dupes.len(), 1);
        assert_eq!(dupes[0].line, 1);
    }

    #[test]
    fn crlf_bom_and_missing_trailing_newline() {
        let p = parse("\u{feff}A=1\r\nB=2\r\nC=3");
        assert_eq!(get(&p, "A").value.expose(), "1");
        assert_eq!(get(&p, "B").value.expose(), "2");
        assert_eq!(get(&p, "C").value.expose(), "3");
    }

    #[test]
    fn whitespace_around_key_and_value() {
        let p = parse("  SPACED  =  padded value  \n");
        assert_eq!(get(&p, "SPACED").value.expose(), "padded value");
    }

    #[test]
    fn malformed_lines_become_warnings_not_errors() {
        let p = parse("no equals here\n1BAD=key\nGOOD=yes\n");
        assert_eq!(p.warnings.len(), 2);
        assert_eq!(get(&p, "GOOD").value.expose(), "yes");
    }

    #[test]
    fn unterminated_quote_is_a_warning_with_best_effort_value() {
        let p = parse("K=\"never closed\nMORE=stuff");
        assert_eq!(p.warnings.len(), 1);
        // Best effort: everything until EOF belongs to K.
        assert_eq!(get(&p, "K").value.expose(), "never closed\nMORE=stuff");
    }
}
