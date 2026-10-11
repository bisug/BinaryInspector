//! Safe, zero-copy extraction and semantic classification of binary strings.
//!
//! Extracts contiguous printable ASCII/UTF-8 and UTF-16LE sequences from raw
//! binary slices without executing or loading the binary, mapping each string
//! to its originating section and classifying indicators of compromise (IOCs).

use crate::{
    model::{ExtractedString, Section, StringCategory, StringEncoding},
    text,
};

/// Maximum strings to collect to prevent unbounded memory growth.
pub const MAX_STRINGS_LIMIT: usize = 10_000;
/// Default minimum string length.
pub const DEFAULT_MIN_LENGTH: usize = 4;
/// Maximum length of one extracted string.
pub const MAX_STRING_LENGTH: usize = 4 * 1024;
const MAX_EXTRACTED_STRING_BYTES: usize = 4 * 1024 * 1024;

/// Extracts printable ASCII and UTF-16LE strings from a binary byte buffer.
pub fn extract(bytes: &[u8], sections: &[Section], min_len: usize) -> Vec<ExtractedString> {
    let min_len = min_len.max(3);
    let mut results = Vec::new();
    let mut extracted_bytes = 0;

    // 1. ASCII / UTF-8 extraction pass
    extract_ascii(bytes, sections, min_len, &mut results, &mut extracted_bytes);

    // 2. UTF-16LE extraction pass (if capacity permits)
    if results.len() < MAX_STRINGS_LIMIT {
        extract_utf16le(bytes, sections, min_len, &mut results, &mut extracted_bytes);
    }

    // Sort by file offset
    results.sort_by_key(|s| s.offset);
    if results.len() > MAX_STRINGS_LIMIT {
        results.truncate(MAX_STRINGS_LIMIT);
    }

    results
}

fn extract_ascii(
    bytes: &[u8],
    sections: &[Section],
    min_len: usize,
    results: &mut Vec<ExtractedString>,
    extracted_bytes: &mut usize,
) {
    let mut start = None;

    for (i, &b) in bytes.iter().enumerate() {
        if is_printable_ascii(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            let len = i - s;
            if len >= min_len {
                record_string(
                    bytes,
                    s,
                    len,
                    StringEncoding::Ascii,
                    sections,
                    results,
                    extracted_bytes,
                );
                if results.len() >= MAX_STRINGS_LIMIT {
                    return;
                }
            }
            start = None;
        }
    }

    if let Some(s) = start {
        let len = bytes.len() - s;
        if len >= min_len {
            record_string(
                bytes,
                s,
                len,
                StringEncoding::Ascii,
                sections,
                results,
                extracted_bytes,
            );
        }
    }
}

fn extract_utf16le(
    bytes: &[u8],
    sections: &[Section],
    min_len: usize,
    results: &mut Vec<ExtractedString>,
    extracted_bytes: &mut usize,
) {
    let mut start = None;
    let mut i = 0;

    while i + 1 < bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];

        // UTF-16LE ASCII subset: printable byte followed by 0x00
        if is_printable_ascii(b0) && b1 == 0 {
            if start.is_none() {
                start = Some(i);
            }
            i += 2;
        } else {
            if let Some(s) = start {
                if !record_utf16le(bytes, s, i, sections, min_len, results, extracted_bytes) {
                    return;
                }
                start = None;
            }
            i += 1;
        }
    }

    if let Some(s) = start {
        record_utf16le(bytes, s, i, sections, min_len, results, extracted_bytes);
    }
}

fn record_string(
    bytes: &[u8],
    start: usize,
    len: usize,
    encoding: StringEncoding,
    sections: &[Section],
    results: &mut Vec<ExtractedString>,
    extracted_bytes: &mut usize,
) {
    if len > MAX_STRING_LENGTH {
        return;
    }
    let slice = &bytes[start..start + len];
    let val_str = String::from_utf8_lossy(slice);
    let cat = classify_string(&val_str);
    let sec = find_section(start as u64, sections);
    let escaped = text::escape_bytes(slice);
    if extracted_bytes.saturating_add(escaped.len()) > MAX_EXTRACTED_STRING_BYTES {
        return;
    }
    *extracted_bytes += escaped.len();

    results.push(ExtractedString {
        offset: start as u64,
        length: len,
        encoding,
        category: cat,
        section: sec,
        value: escaped,
    });
}

fn record_utf16le(
    bytes: &[u8],
    start: usize,
    end: usize,
    sections: &[Section],
    min_len: usize,
    results: &mut Vec<ExtractedString>,
    extracted_bytes: &mut usize,
) -> bool {
    let char_len = (end - start) / 2;
    if char_len < min_len {
        return true;
    }
    if char_len > MAX_STRING_LENGTH {
        return true;
    }

    let mut decoded = String::with_capacity(char_len);
    for chunk in bytes[start..start + char_len * 2].as_chunks::<2>().0 {
        decoded.push(char::from(chunk[0]));
    }
    let cat = classify_string(&decoded);
    let sec = find_section(start as u64, sections);
    let escaped = text::escape_bytes(decoded.as_bytes());
    if extracted_bytes.saturating_add(escaped.len()) > MAX_EXTRACTED_STRING_BYTES {
        return true;
    }
    *extracted_bytes += escaped.len();

    results.push(ExtractedString {
        offset: start as u64,
        length: char_len,
        encoding: StringEncoding::Utf16Le,
        category: cat,
        section: sec,
        value: escaped,
    });
    results.len() < MAX_STRINGS_LIMIT
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

fn find_section(offset: u64, sections: &[Section]) -> Option<String> {
    for s in sections {
        if offset >= s.offset && offset < s.offset.saturating_add(s.size) {
            return Some(s.name.clone());
        }
    }
    None
}

/// Classifies a string into security and development categories.
pub fn classify_string(s: &str) -> StringCategory {
    let trimmed = s.trim();

    // URLs and web endpoints
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("ftp://")
        || trimmed.starts_with("ws://")
        || trimmed.starts_with("wss://")
        || trimmed.starts_with("git://")
        || trimmed.starts_with("ssh://")
    {
        return StringCategory::Url;
    }

    // Email addresses
    if is_email(trimmed) {
        return StringCategory::Email;
    }

    // IP addresses
    if is_ipv4(trimmed) || is_ipv6(trimmed) {
        return StringCategory::Ip;
    }

    // File paths
    if is_file_path(trimmed) {
        return StringCategory::FilePath;
    }

    // Cryptographic keys, tokens, UUIDs
    if is_crypto_or_secret(trimmed) {
        return StringCategory::Crypto;
    }

    StringCategory::General
}

fn is_email(s: &str) -> bool {
    if !s.contains('@') || s.contains(' ') || s.len() < 6 || s.len() > 254 {
        return false;
    }
    let Some((user, domain)) = s.split_once('@') else {
        return false;
    };
    if user.is_empty() || domain.is_empty() || !domain.contains('.') {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '+')
}

fn is_ipv4(s: &str) -> bool {
    let mut count = 0;
    for part in s.split('.') {
        if part.is_empty() || part.len() > 3 {
            return false;
        }
        if part.parse::<u8>().is_err() {
            return false;
        }
        if part.starts_with('0') && part.len() > 1 {
            return false; // Leading zero
        }
        count += 1;
    }
    count == 4
}

fn is_ipv6(s: &str) -> bool {
    if !s.contains(':') || s.len() < 3 || s.len() > 45 {
        return false;
    }
    let mut count = 0;
    for part in s.split(':') {
        if part.len() > 4 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        count += 1;
    }
    (3..=8).contains(&count)
}

fn is_file_path(s: &str) -> bool {
    // Unix paths
    if s.starts_with("/usr/")
        || s.starts_with("/etc/")
        || s.starts_with("/lib/")
        || s.starts_with("/bin/")
        || s.starts_with("/sbin/")
        || s.starts_with("/var/")
        || s.starts_with("/dev/")
        || s.starts_with("/proc/")
        || s.starts_with("/sys/")
        || s.starts_with("/tmp/")
        || s.starts_with("/opt/")
        || s.starts_with("/home/")
    {
        return true;
    }

    // Windows drive paths: C:\, D:\, etc.
    let bytes = s.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }

    // Windows UNC paths: \\server\share
    if s.starts_with("\\\\") && s.len() > 4 {
        return true;
    }

    false
}

fn is_crypto_or_secret(s: &str) -> bool {
    // PEM certificates & private keys
    if s.contains("-----BEGIN ") || s.contains("-----END ") {
        return true;
    }

    // UUID: 8-4-4-4-12 hex characters
    if s.len() == 36 {
        let b = s.as_bytes();
        if b[8] == b'-'
            && b[13] == b'-'
            && b[18] == b'-'
            && b[23] == b'-'
            && s.bytes().enumerate().all(|(index, byte)| {
                matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                    || !matches!(index, 8 | 13 | 18 | 23) && byte.is_ascii_hexdigit()
            })
        {
            return true;
        }
    }

    // AWS Access Key ID format (AKIA...)
    if s.starts_with("AKIA") && s.len() == 20 && s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return true;
    }

    // Bearer token prefix
    if s.starts_with("Bearer ") && s.len() > 16 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_and_classifies_urls() {
        let payload = b"leading noise\x00https://api.github.com/v1\x00trailing\x00";
        let strings = extract(payload, &[], 4);
        assert!(!strings.is_empty());

        let url_str = strings.iter().find(|s| s.category == StringCategory::Url);
        assert!(url_str.is_some());
        assert_eq!(url_str.unwrap().value, "https://api.github.com/v1");
    }

    #[test]
    fn extracts_utf16le_strings() {
        let mut payload = Vec::new();
        for c in "WindowsSystem32".encode_utf16() {
            payload.extend_from_slice(&c.to_le_bytes());
        }
        payload.push(0);
        payload.push(0);

        let strings = extract(&payload, &[], 4);
        let wide_str = strings
            .iter()
            .find(|s| s.encoding == StringEncoding::Utf16Le);
        assert!(wide_str.is_some());
        assert_eq!(wide_str.unwrap().value, "WindowsSystem32");
    }

    #[test]
    fn extracts_a_utf16le_string_at_end_of_input() {
        let mut payload = Vec::new();
        for c in "TrailingWide".encode_utf16() {
            payload.extend_from_slice(&c.to_le_bytes());
        }

        let strings = extract(&payload, &[], 4);
        assert_eq!(
            strings
                .iter()
                .find(|s| s.encoding == StringEncoding::Utf16Le)
                .map(|s| s.value.as_str()),
            Some("TrailingWide")
        );
    }

    #[test]
    fn bounds_extracted_string_memory() {
        let payload = vec![b'A'; MAX_STRING_LENGTH + 1];
        assert!(extract(&payload, &[], 3).is_empty());
    }

    #[test]
    fn classifies_ips_and_paths() {
        assert_eq!(classify_string("192.168.1.1"), StringCategory::Ip);
        assert_eq!(classify_string("10.0.0.254"), StringCategory::Ip);
        assert_eq!(classify_string("/etc/passwd"), StringCategory::FilePath);
        assert_eq!(
            classify_string("C:\\Windows\\System32\\cmd.exe"),
            StringCategory::FilePath
        );
        assert_eq!(classify_string("user@example.com"), StringCategory::Email);
        assert_eq!(
            classify_string("550e8400-e29b-41d4-a716-446655440000"),
            StringCategory::Crypto
        );
        assert_eq!(classify_string("Hello World"), StringCategory::General);
    }
}
