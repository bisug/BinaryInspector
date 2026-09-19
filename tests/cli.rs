use std::process::Command;

#[test]
fn version_flag_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_binary-inspector"))
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("could not run CLI: {error}"));
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("binary-inspector 0.1.0"));
}
