use std::collections::HashSet;
use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::Regex;

/// Built-in detector names, kept in a stable upstream-like order.
pub const PLUGIN_NAMES: &[&str] = &[
    "KeywordDetector",
    "Base64HighEntropyString",
    "HexHighEntropyString",
    "AWSKeyDetector",
    "GitHubTokenDetector",
    "GitLabTokenDetector",
    "NpmDetector",
    "JwtTokenDetector",
    "PrivateKeyDetector",
    "SlackDetector",
];

/// Raw in-memory finding. This must not be serialized directly.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
struct RawFinding {
    pub detector_name: &'static str,
    pub secret_type: &'static str,
    pub secret: String,
}

#[derive(Clone, Debug)]
pub struct DetectorSet {
    detectors: Vec<Detector>,
}

impl DetectorSet {
    pub fn new(disabled_plugins: &[String]) -> anyhow::Result<Self> {
        let disabled = disabled_plugins
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let detectors = all_detectors()?
            .into_iter()
            .filter(|detector| !disabled.contains(&detector.name.to_ascii_lowercase()))
            .collect();
        Ok(Self { detectors })
    }

    pub fn plugin_names(&self) -> Vec<String> {
        self.detectors
            .iter()
            .map(|detector| detector.name.to_string())
            .collect()
    }

    #[cfg(test)]
    fn detect_line(&self, line: &str) -> Vec<RawFinding> {
        let mut findings = Vec::new();
        self.visit_line("test.txt", line, |detector_name, secret_type, secret| {
            findings.push(RawFinding {
                detector_name,
                secret_type,
                secret: secret.to_string(),
            });
        });
        findings
    }

    pub(crate) fn visit_line(
        &self,
        filename: &str,
        line: &str,
        mut visit: impl FnMut(&'static str, &'static str, &str),
    ) {
        for detector in &self.detectors {
            detector.visit_line(filename, line, &mut visit);
        }
    }
}

#[derive(Clone, Debug)]
struct Detector {
    name: &'static str,
    secret_type: &'static str,
    prefilter: Prefilter,
    matcher: Matcher,
}

impl Detector {
    fn visit_line(
        &self,
        filename: &str,
        line: &str,
        visit: &mut impl FnMut(&'static str, &'static str, &str),
    ) {
        if !self.prefilter.is_match(filename, line) {
            return;
        }

        match &self.matcher {
            Matcher::Regex(regex) => {
                for matched in regex.find_iter(line) {
                    visit(self.name, self.secret_type, matched.as_str());
                }
            }
            Matcher::CaptureRegexes(regexes) => {
                for capture_regex in regexes {
                    for captures in capture_regex.regex.captures_iter(line) {
                        if let Some(matched) = captures.get(capture_regex.group) {
                            visit(self.name, self.secret_type, matched.as_str());
                        }
                    }
                }
            }
            Matcher::Keyword => {
                visit_keyword_candidates(line, self.name, self.secret_type, visit);
            }
            Matcher::Entropy {
                charset,
                threshold,
                min_len,
            } => {
                for candidate in QuotedStrings::new(line) {
                    visit_entropy_candidate(
                        self.name,
                        self.secret_type,
                        *charset,
                        *threshold,
                        *min_len,
                        candidate,
                        visit,
                    );
                }
                if is_yaml_like(filename) {
                    for candidate in ScalarValues::new(line) {
                        visit_entropy_candidate(
                            self.name,
                            self.secret_type,
                            *charset,
                            *threshold,
                            *min_len,
                            candidate,
                            visit,
                        );
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Prefilter {
    Keyword,
    AnyLiteral(&'static [&'static str]),
    Entropy,
}

impl Prefilter {
    fn is_match(self, filename: &str, line: &str) -> bool {
        match self {
            Self::Keyword => may_contain_keyword(line),
            Self::AnyLiteral(literals) => literals.iter().any(|literal| line.contains(literal)),
            Self::Entropy => {
                line.contains(['\'', '"']) || (is_yaml_like(filename) && line.contains([':', '=']))
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Matcher {
    Regex(Regex),
    CaptureRegexes(Vec<CaptureRegex>),
    Keyword,
    Entropy {
        charset: EntropyCharset,
        threshold: f64,
        min_len: usize,
    },
}

#[derive(Clone, Copy, Debug)]
enum EntropyCharset {
    Base64,
    Hex,
}

#[derive(Clone, Debug)]
struct CaptureRegex {
    regex: Regex,
    group: usize,
}

fn all_detectors() -> anyhow::Result<Vec<Detector>> {
    Ok(vec![
        Detector {
            name: "KeywordDetector",
            secret_type: "Secret Keyword",
            prefilter: Prefilter::Keyword,
            matcher: Matcher::Keyword,
        },
        Detector {
            name: "Base64HighEntropyString",
            secret_type: "Base64 High Entropy String",
            prefilter: Prefilter::Entropy,
            matcher: Matcher::Entropy {
                charset: EntropyCharset::Base64,
                threshold: 4.5,
                min_len: 23,
            },
        },
        Detector {
            name: "HexHighEntropyString",
            secret_type: "Hex High Entropy String",
            prefilter: Prefilter::Entropy,
            matcher: Matcher::Entropy {
                charset: EntropyCharset::Hex,
                threshold: 3.0,
                min_len: 9,
            },
        },
        Detector {
            name: "AWSKeyDetector",
            secret_type: "AWS Access Key",
            prefilter: Prefilter::AnyLiteral(&[
                "AKIA", "ASIA", "ABIA", "ACCA", "A3T", "aws", "AWS",
            ]),
            matcher: Matcher::CaptureRegexes(vec![
                CaptureRegex {
                    regex: Regex::new(r#"\b((?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16})\b"#)?,
                    group: 1,
                },
                CaptureRegex {
                    regex: Regex::new(
                        r#"(?i)aws.{0,20}?(?:key|pwd|pw|password|pass|token).{0,20}?['"]([0-9a-zA-Z/+]{40})['"]"#,
                    )?,
                    group: 1,
                },
            ]),
        },
        Detector {
            name: "GitHubTokenDetector",
            secret_type: "GitHub Token",
            prefilter: Prefilter::AnyLiteral(&["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]),
            matcher: Matcher::CaptureRegexes(vec![CaptureRegex {
                regex: Regex::new(r#"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36})\b"#)?,
                group: 1,
            }]),
        },
        Detector {
            name: "GitLabTokenDetector",
            secret_type: "GitLab Token",
            prefilter: Prefilter::AnyLiteral(&[
                "glpat-",
                "gldt-",
                "glft-",
                "glsoat-",
                "glrt-",
                "GR1348941",
                "glcbt-",
                "glimt-",
                "glptt-",
                "glagent-",
                "gloas-",
            ]),
            matcher: Matcher::CaptureRegexes(vec![
                CaptureRegex {
                    regex: Regex::new(
                        r#"\b((?:glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_-]{20,50})\b"#,
                    )?,
                    group: 1,
                },
                CaptureRegex {
                    regex: Regex::new(r#"\b(GR1348941[A-Za-z0-9_-]{20,50})\b"#)?,
                    group: 1,
                },
                CaptureRegex {
                    regex: Regex::new(r#"\b(glcbt-(?:[0-9a-fA-F]{2}_)?[A-Za-z0-9_-]{20,50})\b"#)?,
                    group: 1,
                },
                CaptureRegex {
                    regex: Regex::new(r#"\b(glimt-[A-Za-z0-9_-]{25})\b"#)?,
                    group: 1,
                },
                CaptureRegex {
                    regex: Regex::new(r#"\b(glptt-[A-Za-z0-9_-]{40})\b"#)?,
                    group: 1,
                },
                CaptureRegex {
                    regex: Regex::new(r#"\b(glagent-[A-Za-z0-9_-]{50,1024})\b"#)?,
                    group: 1,
                },
                CaptureRegex {
                    regex: Regex::new(r#"\b(gloas-[A-Za-z0-9_-]{64})\b"#)?,
                    group: 1,
                },
            ]),
        },
        Detector {
            name: "NpmDetector",
            secret_type: "NPM tokens",
            prefilter: Prefilter::AnyLiteral(&["_authToken"]),
            matcher: Matcher::CaptureRegexes(vec![CaptureRegex {
                regex: Regex::new(r#"//.+/:_authToken=\s*((?:npm_.+)|(?:[A-Fa-f0-9-]{36})).*"#)?,
                group: 1,
            }]),
        },
        Detector {
            name: "JwtTokenDetector",
            secret_type: "JSON Web Token",
            prefilter: Prefilter::AnyLiteral(&["eyJ"]),
            matcher: Matcher::Regex(Regex::new(r#"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?"#)?),
        },
        Detector {
            name: "PrivateKeyDetector",
            secret_type: "Private Key",
            prefilter: Prefilter::AnyLiteral(&["PRIVATE KEY"]),
            matcher: Matcher::Regex(Regex::new(
                r#"BEGIN (?:(?:DSA|EC|OPENSSH|PGP|RSA|SSH2 ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?"#,
            )?),
        },
        Detector {
            name: "SlackDetector",
            secret_type: "Slack Token",
            prefilter: Prefilter::AnyLiteral(&["xox", "hooks.slack.com/services"]),
            matcher: Matcher::Regex(Regex::new(
                r#"(?i)\b(?:xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)\b"#,
            )?),
        },
    ])
}

fn visit_keyword_candidates(
    line: &str,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    let bytes = line.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if !is_word_byte(bytes[index]) {
            index += 1;
            continue;
        }

        let word_start = index;
        index += 1;
        while index < bytes.len() && is_word_byte(bytes[index]) {
            index += 1;
        }
        let word_end = index;

        if !is_keyword_word(&bytes[word_start..word_end]) {
            continue;
        }

        visit_forward_keyword(line, word_end, detector_name, secret_type, visit);
        visit_reverse_keyword(line, word_start, detector_name, secret_type, visit);
        visit_keyword_call(line, word_end, detector_name, secret_type, visit);
        visit_keyword_quoted_statement(line, word_end, detector_name, secret_type, visit);
    }
}

fn visit_forward_keyword(
    line: &str,
    word_end: usize,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    let bytes = line.as_bytes();
    let mut index = skip_keyword_closing(bytes, word_end);
    index = skip_ascii_whitespace(bytes, index);

    let Some(after_operator) = parse_assignment_operator(bytes, index) else {
        return;
    };

    index = skip_ascii_whitespace(bytes, after_operator);
    if index < bytes.len() && bytes[index] == b'@' {
        index += 1;
    }

    visit_keyword_value(line, index, detector_name, secret_type, visit);
}

fn visit_reverse_keyword(
    line: &str,
    word_start: usize,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    let bytes = line.as_bytes();
    let operator_end = skip_ascii_whitespace_back(bytes, word_start);
    let Some(operator_start) = parse_comparison_operator_back(bytes, operator_end) else {
        return;
    };

    let close_quote_index = skip_ascii_whitespace_back(bytes, operator_start);
    if close_quote_index == 0 {
        return;
    }

    let quote = bytes[close_quote_index - 1];
    if !matches!(quote, b'\'' | b'"') {
        return;
    }

    let Some(open_quote_index) = bytes[..close_quote_index - 1]
        .iter()
        .rposition(|byte| *byte == quote)
    else {
        return;
    };

    emit_quoted_keyword_secret(
        &line[open_quote_index + 1..close_quote_index - 1],
        detector_name,
        secret_type,
        visit,
    );
}

fn visit_keyword_call(
    line: &str,
    word_end: usize,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    let bytes = line.as_bytes();
    let mut index = word_end;

    if bytes[index..].starts_with(b".assign") {
        index += b".assign".len();
    }
    if index >= bytes.len() || bytes[index] != b'(' {
        return;
    }

    index = skip_ascii_whitespace(bytes, index + 1);
    visit_quoted_keyword_value(line, index, detector_name, secret_type, visit);
}

fn visit_keyword_quoted_statement(
    line: &str,
    word_end: usize,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    let bytes = line.as_bytes();
    let mut index = word_end;
    let mut skipped_non_whitespace = 0;

    while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
        if skipped_non_whitespace == 50 {
            return;
        }
        skipped_non_whitespace += 1;
        index += 1;
    }

    index = skip_ascii_whitespace(bytes, index);
    let Some((secret_start, secret_end, close_quote)) = quoted_value_span(bytes, index) else {
        return;
    };
    if close_quote + 1 < bytes.len() && bytes[close_quote + 1] == b';' {
        emit_quoted_keyword_secret(
            &line[secret_start..secret_end],
            detector_name,
            secret_type,
            visit,
        );
    }
}

fn visit_keyword_value(
    line: &str,
    index: usize,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    let bytes = line.as_bytes();
    if index >= bytes.len() {
        return;
    }

    if matches!(bytes[index], b'\'' | b'"') {
        visit_quoted_keyword_value(line, index, detector_name, secret_type, visit);
        return;
    }

    if !is_secret_start(bytes[index]) {
        return;
    }

    let mut end = bytes.len();
    while end > index && matches!(bytes[end - 1], b',' | b'\'' | b'"' | b'`') {
        end -= 1;
    }
    if end > index {
        emit_unquoted_keyword_secret(&line[index..end], detector_name, secret_type, visit);
    }
}

fn visit_quoted_keyword_value(
    line: &str,
    index: usize,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    let Some((secret_start, secret_end, _)) = quoted_value_span(line.as_bytes(), index) else {
        return;
    };
    emit_quoted_keyword_secret(
        &line[secret_start..secret_end],
        detector_name,
        secret_type,
        visit,
    );
}

fn quoted_value_span(bytes: &[u8], quote_index: usize) -> Option<(usize, usize, usize)> {
    let quote = *bytes.get(quote_index)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }

    let secret_start = quote_index + 1;
    let relative_end = bytes[secret_start..]
        .iter()
        .position(|byte| *byte == quote)?;
    let secret_end = secret_start + relative_end;
    Some((secret_start, secret_end, secret_end))
}

fn emit_quoted_keyword_secret(
    secret: &str,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    if !is_quoted_keyword_secret(secret) {
        return;
    }

    emit_keyword_secret(secret, detector_name, secret_type, visit);
}

fn emit_unquoted_keyword_secret(
    secret: &str,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    if secret
        .as_bytes()
        .first()
        .is_none_or(|byte| !is_secret_start(*byte))
    {
        return;
    }

    emit_keyword_secret(secret, detector_name, secret_type, visit);
}

fn emit_keyword_secret(
    secret: &str,
    detector_name: &'static str,
    secret_type: &'static str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    visit(detector_name, secret_type, secret);
    if let Some(unescaped) = unescape_common_escapes(secret) {
        visit(detector_name, secret_type, &unescaped);
    }
}

fn is_quoted_keyword_secret(secret: &str) -> bool {
    let bytes = secret.as_bytes();
    bytes.first().is_some_and(|byte| is_secret_start(*byte))
        && bytes
            .iter()
            .all(|byte| !matches!(*byte, b'\'' | b'"' | b'`' | b',' | b'\r' | b'\n'))
}

fn skip_keyword_closing(bytes: &[u8], mut index: usize) -> usize {
    let mut skipped = 0;
    while skipped < 2 && index < bytes.len() && matches!(bytes[index], b']' | b'\'' | b'"') {
        index += 1;
        skipped += 1;
    }
    index
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn skip_ascii_whitespace_back(bytes: &[u8], mut end: usize) -> usize {
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

fn parse_assignment_operator(bytes: &[u8], index: usize) -> Option<usize> {
    let tail = bytes.get(index..)?;
    if tail.starts_with(b":=") || tail.starts_with(b"=>") {
        Some(index + 2)
    } else if tail.starts_with(b"!==") || tail.starts_with(b"===") {
        Some(index + 3)
    } else if tail.starts_with(b"!=") || tail.starts_with(b"==") {
        Some(index + 2)
    } else if tail.starts_with(b"=") || tail.starts_with(b":") {
        Some(index + 1)
    } else {
        None
    }
}

fn parse_comparison_operator_back(bytes: &[u8], end: usize) -> Option<usize> {
    if end >= 3 && matches!(&bytes[end - 3..end], b"!==" | b"===") {
        Some(end - 3)
    } else if end >= 2 && matches!(&bytes[end - 2..end], b"!=" | b"==") {
        Some(end - 2)
    } else {
        None
    }
}

fn is_keyword_word(word: &[u8]) -> bool {
    contains_ascii_case_insensitive(word, b"password")
        || contains_ascii_case_insensitive(word, b"passwd")
        || contains_ascii_case_insensitive(word, b"pwd")
        || contains_ascii_case_insensitive(word, b"secret")
        || contains_ascii_case_insensitive(word, b"token")
        || contains_ascii_case_insensitive(word, b"contrasena")
        || contains_keyword_pair(word, b"api", b"key")
        || contains_keyword_pair(word, b"auth", b"key")
        || contains_keyword_pair(word, b"service", b"key")
        || contains_keyword_pair(word, b"account", b"key")
        || contains_keyword_pair(word, b"db", b"key")
        || contains_keyword_pair(word, b"database", b"key")
        || contains_keyword_pair(word, b"priv", b"key")
        || contains_keyword_pair(word, b"private", b"key")
        || contains_keyword_pair(word, b"client", b"key")
        || contains_keyword_pair(word, b"db", b"pass")
        || contains_keyword_pair(word, b"database", b"pass")
        || contains_keyword_pair(word, b"key", b"pass")
        || contains_keyword_pair(word, b"access", b"key")
}

fn contains_keyword_pair(word: &[u8], prefix: &[u8], suffix: &[u8]) -> bool {
    for index in 0..word.len() {
        if !matches_ascii_case_insensitive_at(word, index, prefix) {
            continue;
        }

        let suffix_index = index + prefix.len();
        if matches_ascii_case_insensitive_at(word, suffix_index, suffix)
            || (word.get(suffix_index) == Some(&b'_')
                && matches_ascii_case_insensitive_at(word, suffix_index + 1, suffix))
        {
            return true;
        }
    }
    false
}

fn contains_ascii_case_insensitive(word: &[u8], needle: &[u8]) -> bool {
    word.len() >= needle.len()
        && (0..=word.len() - needle.len())
            .any(|index| matches_ascii_case_insensitive_at(word, index, needle))
}

fn matches_ascii_case_insensitive_at(word: &[u8], index: usize, needle: &[u8]) -> bool {
    let Some(candidate) = word.get(index..index + needle.len()) else {
        return false;
    };
    candidate
        .iter()
        .zip(needle)
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_secret_start(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

struct QuotedStrings<'a> {
    line: &'a str,
    offset: usize,
}

impl<'a> QuotedStrings<'a> {
    fn new(line: &'a str) -> Self {
        Self { line, offset: 0 }
    }
}

impl<'a> Iterator for QuotedStrings<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.line.as_bytes();

        while self.offset < bytes.len() {
            let start_quote = self.offset
                + bytes[self.offset..]
                    .iter()
                    .position(|byte| matches!(*byte, b'\'' | b'"'))?;
            let quote = bytes[start_quote];
            let content_start = start_quote + 1;
            self.offset = content_start;

            if let Some(relative_end) = bytes[content_start..]
                .iter()
                .position(|byte| *byte == quote)
            {
                let content_end = content_start + relative_end;
                return Some(&self.line[content_start..content_end]);
            }
        }

        None
    }
}

struct ScalarValues<'a> {
    line: Option<&'a str>,
}

impl<'a> ScalarValues<'a> {
    fn new(line: &'a str) -> Self {
        Self { line: Some(line) }
    }
}

impl<'a> Iterator for ScalarValues<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let line = self.line.take()?;
        let separator = line.find(':').or_else(|| line.find('='))?;
        let mut value = line[separator + 1..].trim();
        if value.starts_with(['"', '\'']) {
            return None;
        }
        if let Some((before_comment, _)) = value.split_once(" #") {
            value = before_comment.trim_end();
        }
        value = value.trim_end_matches(',');

        (!value.is_empty()).then_some(value)
    }
}

fn visit_entropy_candidate(
    detector_name: &'static str,
    secret_type: &'static str,
    charset: EntropyCharset,
    threshold: f64,
    min_len: usize,
    candidate: &str,
    visit: &mut impl FnMut(&'static str, &'static str, &str),
) {
    if candidate.len() < min_len {
        return;
    }

    match charset {
        EntropyCharset::Base64 => {
            if is_base64ish(candidate) && shannon_entropy(candidate) > threshold {
                visit(detector_name, secret_type, candidate);
            }
        }
        EntropyCharset::Hex => {
            if is_hex(candidate) && hex_entropy(candidate) > threshold {
                visit(detector_name, secret_type, candidate);
            }
        }
    }
}

fn is_base64ish(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
    })
}

fn is_hex(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn may_contain_keyword(line: &str) -> bool {
    static KEYWORD_PREFILTER: LazyLock<AhoCorasick> = LazyLock::new(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(["key", "pass", "pwd", "secret", "token", "auth", "client"])
            .expect("keyword prefilter patterns are valid")
    });

    KEYWORD_PREFILTER.is_match(line)
}

fn is_yaml_like(filename: &str) -> bool {
    let filename = filename.to_ascii_lowercase();
    filename.ends_with(".yml") || filename.ends_with(".yaml")
}

fn unescape_common_escapes(value: &str) -> Option<String> {
    if !value.as_bytes().contains(&b'\\') {
        return None;
    }

    let mut output = String::with_capacity(value.len());
    let mut changed = false;
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }

        match chars.next() {
            Some('n') => {
                output.push('\n');
                changed = true;
            }
            Some('r') => {
                output.push('\r');
                changed = true;
            }
            Some('t') => {
                output.push('\t');
                changed = true;
            }
            Some('"') => {
                output.push('"');
                changed = true;
            }
            Some('\\') => {
                output.push('\\');
                changed = true;
            }
            Some(other) => {
                output.push('\\');
                output.push(other);
            }
            None => output.push('\\'),
        }
    }

    changed.then_some(output)
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in value.bytes() {
        counts[byte as usize] += 1;
    }

    let len = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn hex_entropy(value: &str) -> f64 {
    let mut entropy = shannon_entropy(value);
    if value.len() > 1 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        entropy -= 1.2 / (value.len() as f64).log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aws_key_without_raw_output_contract() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line("key = AKIA1234567890ABCDEF");

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "AWSKeyDetector" && finding.secret == "AKIA1234567890ABCDEF"
        }));
    }

    #[test]
    fn github_detector_reports_full_runtime_token() {
        let detectors = DetectorSet::new(&[]).unwrap();
        let token = format!("{}{}", "ghp_", "0".repeat(36));

        let findings = detectors.detect_line(&format!("token = {token}"));

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "GitHubTokenDetector" && finding.secret == token
        }));
    }

    #[test]
    fn gitlab_detector_reports_full_runtime_token() {
        let detectors = DetectorSet::new(&[]).unwrap();
        let token = format!("{}{}", "glpat-", "A".repeat(20));

        let findings = detectors.detect_line(&format!("token = {token}"));

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "GitLabTokenDetector" && finding.secret == token
        }));
    }

    #[test]
    fn npm_detector_reports_full_runtime_token() {
        let detectors = DetectorSet::new(&[]).unwrap();
        let token = format!("{}{}", "npm_", "A".repeat(36));

        let findings = detectors.detect_line(&format!("//registry.npmjs.org/:_authToken={token}"));

        assert!(
            findings
                .iter()
                .any(|finding| finding.detector_name == "NpmDetector" && finding.secret == token)
        );
    }

    #[test]
    fn disabled_detector_is_not_used() {
        let detectors = DetectorSet::new(&["AWSKeyDetector".to_string()]).unwrap();

        let findings = detectors.detect_line("key = AKIA1234567890ABCDEF");

        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector_name == "AWSKeyDetector")
        );
    }

    #[test]
    fn entropy_is_high_for_random_like_values() {
        assert!(shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789") > 4.5);
    }

    #[test]
    fn finds_nested_quoted_hex_entropy() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#"etag = '"00112233445566778899aabbccddeeff"'"#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "HexHighEntropyString"
                && finding.secret == "00112233445566778899aabbccddeeff"
        }));
    }

    #[test]
    fn keyword_matches_unquoted_comparison_tail() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings =
            detectors.detect_line("if username != robot_user && password != robot_password && !ok");

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "robot_password && !ok"
        }));
    }

    #[test]
    fn keyword_emits_unescaped_variant() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#"password: "multi\nline""#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "multi\nline"
        }));
    }

    #[test]
    fn keyword_matches_quoted_json_key() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#""password": "hunter2","#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "hunter2"
        }));
    }

    #[test]
    fn keyword_matches_prefixed_key_name() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#"api_key = "hunter2""#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "hunter2"
        }));
    }

    #[test]
    fn keyword_matches_colon_equal_assignment() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#"password := "hunter2""#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "hunter2"
        }));
    }

    #[test]
    fn keyword_matches_arrow_assignment() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#"password => "hunter2""#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "hunter2"
        }));
    }

    #[test]
    fn keyword_matches_reverse_comparison() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#""hunter2" == user_password"#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "hunter2"
        }));
    }

    #[test]
    fn keyword_matches_assign_call() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#"password.assign("hunter2", 7)"#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "hunter2"
        }));
    }

    #[test]
    fn keyword_matches_quoted_statement() {
        let detectors = DetectorSet::new(&[]).unwrap();

        let findings = detectors.detect_line(r#"private_key "hunter2";"#);

        assert!(findings.iter().any(|finding| {
            finding.detector_name == "KeywordDetector" && finding.secret == "hunter2"
        }));
    }

    #[test]
    fn entropy_matches_yaml_scalar_hex() {
        let detectors = DetectorSet::new(&[]).unwrap();
        let mut found = false;

        detectors.visit_line(
            "openapi.yaml",
            "revision: 0a41f0000705c69ab8e0f9a723fc73e39ed62b07",
            |detector_name, _, secret| {
                if detector_name == "HexHighEntropyString"
                    && secret == "0a41f0000705c69ab8e0f9a723fc73e39ed62b07"
                {
                    found = true;
                }
            },
        );

        assert!(found);
    }
}
