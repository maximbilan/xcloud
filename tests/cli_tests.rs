use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn prints_help() {
    let mut cmd = Command::cargo_bin("xcloud").unwrap();
    cmd.arg("--help");
    cmd.assert().success().stdout(predicate::str::contains("Xcode Cloud CLI in Rust"));
}
