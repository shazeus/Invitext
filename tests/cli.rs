use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn hide_list_reveal_and_strip() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("photo.jpg");
    let hidden = temp.path().join("photo.secret.jpg");
    let clean = temp.path().join("photo.clean.jpg");
    fs::write(&carrier, b"\xff\xd8\xff fake jpeg \xff\xd9").unwrap();

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "hide",
            carrier.to_str().unwrap(),
            "--message",
            "meet at 21:30",
            "--label",
            "plan",
            "--encrypt",
            "--password",
            "test-passphrase",
            "--kdf",
            "interactive",
            "--output",
            hidden.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Hidden note #1"));

    Command::cargo_bin("invitext")
        .unwrap()
        .args(["list", hidden.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypted"));

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "reveal",
            hidden.to_str().unwrap(),
            "--password",
            "test-passphrase",
        ])
        .assert()
        .success()
        .stdout("meet at 21:30\n");

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "strip",
            hidden.to_str().unwrap(),
            "--output",
            clean.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(clean).unwrap(), fs::read(carrier).unwrap());
}

#[test]
fn wrong_password_fails_without_leaking_text() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("archive.zip");
    let hidden = temp.path().join("archive.hidden.zip");
    fs::write(&carrier, b"PK fake zip").unwrap();

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "hide",
            carrier.to_str().unwrap(),
            "-m",
            "do not print me",
            "--password",
            "right",
            "--kdf",
            "interactive",
            "-o",
            hidden.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("itx")
        .unwrap()
        .args(["reveal", hidden.to_str().unwrap(), "--password", "wrong"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("incorrect")
                .and(predicate::str::contains("do not print me").not()),
        );
}

#[test]
fn json_output_is_parseable() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("data.bin");
    let hidden = temp.path().join("data.hidden.bin");
    fs::write(&carrier, b"carrier").unwrap();

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "--json",
            "hide",
            carrier.to_str().unwrap(),
            "-m",
            "json",
            "-o",
            hidden.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"hidden\""));

    let output = Command::cargo_bin("itx")
        .unwrap()
        .args(["--json", "list", hidden.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["notes"].as_array().unwrap().len(), 1);
}

#[test]
fn output_cannot_silently_replace_the_carrier() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("important.pdf");
    let original = b"%PDF-1.7 original";
    fs::write(&carrier, original).unwrap();

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "hide",
            carrier.to_str().unwrap(),
            "-m",
            "note",
            "--output",
            carrier.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("use --in-place explicitly"));

    assert_eq!(fs::read(carrier).unwrap(), original);
}

#[test]
fn tampering_blocks_verify_and_strip() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("carrier.bin");
    let hidden = temp.path().join("hidden.bin");
    fs::write(&carrier, b"trusted carrier").unwrap();

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "hide",
            carrier.to_str().unwrap(),
            "-m",
            "note",
            "-o",
            hidden.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut bytes = fs::read(&hidden).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&hidden, bytes).unwrap();

    Command::cargo_bin("itx")
        .unwrap()
        .args(["verify", hidden.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("carrier data was modified"));

    Command::cargo_bin("itx")
        .unwrap()
        .args(["strip", hidden.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("carrier data was modified"));
}
