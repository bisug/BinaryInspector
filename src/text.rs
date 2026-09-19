//! Terminal-safe rendering of strings supplied by inspected binaries.

/// Escapes every non-printable or non-ASCII byte using a stable `\xNN` form.
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b' '..=b'~' if *byte != b'\\' => output.push(char::from(*byte)),
            _ => {
                use std::fmt::Write;
                let _ = write!(output, "\\x{byte:02X}");
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::escape_bytes;

    #[test]
    fn escapes_terminal_controls_and_invalid_utf8() {
        assert_eq!(escape_bytes(b"ok\x1b[31m\xff\\"), "ok\\x1B[31m\\xFF\\x5C");
    }
}
