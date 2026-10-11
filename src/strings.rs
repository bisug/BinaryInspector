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

/// Extracts printable ASCII and UTF-16LE strings from a binary byte buffer.
pub fn extract(bytes: &[u8], sections: &[Section], min_len: usize) -> Vec<ExtractedString> {
    let min_len = min_len.max(3);
    let mut results = Vec::new();

    // 1. ASCII / UTF-8 extraction pass
    extract_ascii(bytes, sections, min_len, &mut results);

    // 2. UTF-16LE extraction pass (if capacity permits)
    if results.len() < MAX_STRINGS_LIMIT {
        extract_utf16le(bytes, sections, min_len, &mut results);
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
                record_string(bytes, s, len, StringEncoding::Ascii, sections, results);
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
            record_string(bytes, s, len, StringEncoding::Ascii, sections, results);
        }
    }
}

fn extract_utf16le(
    bytes: &[u8],
    sections: &[Section],
    min_len: usize,
    results: &mut Vec<ExtractedString>,
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
                let char_len = (i - s) / 2;
                if char_len >= min_len {
                    // Collect chars
                    let mut u16_chars = Vec::with_capacity(char_len);
                    for chunk in bytes[s..i].as_chunks::<2>().0 {
                        u16_chars.push(u16::from_le_bytes(*chunk));
                    }
                    if let Ok(decoded) = String::from_utf16(&u16_chars) {
                        let cat = classify_string(&decoded);
                        let sec = find_section(s as u64, sections);
                        let escaped = text::escape_bytes(decoded.as_bytes());

                        results.push(ExtractedString {
                            offset: s as u64,
                            length: char_len,
                            encoding: StringEncoding::Utf16Le,
                            category: cat,
                            section: sec,
                            value: escaped,
                        });
                        if results.len() >= MAX_STRINGS_LIMIT {
                            return;
                        }
                    }
                }
                start = None;
            }
            i += 1;
        }
    }
}

fn record_string(
    bytes: &[u8],
    start: usize,
    len: usize,
    encoding: StringEncoding,
    sections: &[Section],
    results: &mut Vec<ExtractedString>,
) {
    let slice = &bytes[start..start + len];
    let val_str = String::from_utf8_lossy(slice);
    let cat = classify_string(&val_str);
    let sec = find_section(start as u64, sections);
    let escaped = text::escape_bytes(slice);

    results.push(ExtractedString {
        offset: start as u64,
        length: len,
        encoding,
        category: cat,
        section: sec,
        value: escaped,
    });
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
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (user, domain) = (parts[0], parts[1]);
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
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        if part.is_empty() || part.len() > 3 {
            return false;
        }
        if let Ok(num) = part.parse::<u8>() {
            if part.starts_with('0') && part.len() > 1 {
                return false; // Leading zero
            }
            let _ = num;
        } else {
            return false;
        }
    }
    true
}

fn is_ipv6(s: &str) -> bool {
    if !s.contains(':') || s.len() < 3 || s.len() > 45 {
        return false;
    }
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 3 || parts.len() > 8 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() <= 4 && p.chars().all(|c| c.is_ascii_hexdigit()))
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
        if b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-' {
            let hex_only = s.replace('-', "");
            if hex_only.len() == 32 && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
                return true;
            }
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
