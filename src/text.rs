//! Terminal-safe rendering of strings supplied by inspected binaries.

/// Escapes every non-printable or non-ASCII byte using a stable `\xNN` form.
pub fn escape_bytes(bytes: &[u8]) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b' '..=b'~' if *byte != b'\\' => output.push(char::from(*byte)),
            _ => {
                output.push('\\');
                output.push('x');
                output.push(HEX_UPPER[(byte >> 4) as usize] as char);
                output.push(HEX_UPPER[(byte & 0x0f) as usize] as char);
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
