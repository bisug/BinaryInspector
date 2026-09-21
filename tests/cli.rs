use std::{env, fs, process::Command};

#[test]
fn version_flag_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));
    let expected = format!("binary-inspector {}", env!("CARGO_PKG_VERSION"));
    assert!(String::from_utf8_lossy(&output.stdout).starts_with(&expected));
    assert!(output.status.success());
}

#[test]
fn usage_error_exits_with_code_1() {
    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg("--unknown-flag")
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn non_existent_file_exits_with_code_2() {
    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg("/tmp/non_existent_binary_inspector_path_12345")
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("I/O error"));
}

#[test]
fn directory_input_exits_with_code_2() {
    let temp_dir = env::temp_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg(&temp_dir)
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid file") || stderr.contains("I/O error"),
        "expected error message on directory input, got: {stderr}"
    );
}

#[test]
fn non_elf_file_exits_with_code_3() {
    let temp_file = env::temp_dir().join(format!("not_an_elf_{}.txt", std::process::id()));
    fs::write(
        &temp_file,
        b"Hello world! This is a plain text file, not an ELF binary.",
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg(&temp_file)
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));

    let _ = fs::remove_file(temp_file);
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("parse error: not an ELF file"));
}

#[test]
fn valid_minimal_elf_exits_with_code_0() {
    let mut bytes = [0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..9].copy_from_slice(&[2, 1, 1, 0, 0]);
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());

    let temp_file = env::temp_dir().join(format!("test_elf_{}.bin", std::process::id()));
    fs::write(&temp_file, bytes).unwrap_or_else(|error| panic!("{error}"));

    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg(&temp_file)
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));

    let _ = fs::remove_file(temp_file);
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("ELF64"));
}

#[test]
fn json_output_is_versioned_and_complete() {
    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg("/bin/ls")
        .arg("--json")
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with('{'));
    assert!(stdout.trim_end().ends_with('}'));
    assert!(stdout.contains("\"schema_version\": 1"));
    assert!(stdout.contains("\"sha256\""));
    assert!(stdout.contains("\"symbols\""));
    assert!(stdout.contains("\"mitigations\""));
}
