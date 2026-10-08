use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

fn write_png(path: &std::path::Path, width: u32, height: u32) {
    let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
    for y in 0..height {
        for x in 0..width {
            pixels.extend_from_slice(&[
                ((x * 17 + y * 31) % 256) as u8,
                ((x * 47 + y * 13) % 256) as u8,
                ((x * 7 + y * 61) % 256) as u8,
                255,
            ]);
        }
    }
    let file = fs::File::create(path).unwrap();
    let mut encoder = png::Encoder::new(file, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&pixels)
        .unwrap();
}

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

#[test]
fn png_stealth_mode_round_trip_has_no_appended_signature() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("photo.png");
    let hidden = temp.path().join("photo.invitext.png");
    write_png(&carrier, 256, 256);

    Command::cargo_bin("itx")
        .unwrap()
        .args([
            "hide",
            carrier.to_str().unwrap(),
            "--mode",
            "stealth",
            "--message",
            "quietly embedded",
            "--label",
            "private",
            "--password",
            "test-passphrase",
            "--output",
            hidden.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Concealed one encrypted note"));

    let bytes = fs::read(&hidden).unwrap();
    assert!(!bytes.windows(8).any(|window| window == b"INVITEXT"));
    assert!(!bytes.windows(8).any(|window| window == b"ITXSTG01"));

    Command::cargo_bin("invitext")
        .unwrap()
        .args([
            "reveal",
            hidden.to_str().unwrap(),
            "--mode",
            "stealth",
            "--password",
            "test-passphrase",
        ])
        .assert()
        .success()
        .stdout("quietly embedded\n");

    Command::cargo_bin("itx")
        .unwrap()
        .args(["list", hidden.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no Invitext note was found"));
}

#[test]
fn inspect_reports_png_stealth_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("cover.png");
    write_png(&carrier, 256, 256);

    Command::cargo_bin("itx")
        .unwrap()
        .args(["inspect", carrier.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Stealth       supported")
                .and(predicate::str::contains("Change limit")),
        );
}

#[test]
fn encrypted_file_in_pdf_round_trip_and_safe_extraction() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("cover.pdf");
    let attachment = temp.path().join("archive.zip");
    let hidden = temp.path().join("hidden.pdf");
    let output = temp.path().join("restored.zip");
    let clean = temp.path().join("clean.pdf");
    let bytes: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let original = b"%PDF-1.7\noriginal document\n%%EOF\n";
    fs::write(&carrier, original).unwrap();
    fs::write(&attachment, &bytes).unwrap();

    Command::cargo_bin("itx")
        .unwrap()
        .arg("hide")
        .arg(&carrier)
        .arg("--file")
        .arg(&attachment)
        .args(["--password", "secret", "--kdf", "interactive"])
        .arg("-o")
        .arg(&hidden)
        .assert()
        .success();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("verify")
        .arg(&hidden)
        .args(["--deep", "--password", "secret"])
        .assert()
        .success();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("list")
        .arg(&hidden)
        .assert()
        .success()
        .stdout(predicate::str::contains("file"));
    Command::cargo_bin("itx")
        .unwrap()
        .arg("reveal")
        .arg(&hidden)
        .args(["--password", "secret"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("use itx extract"));

    fs::write(&output, b"keep this file").unwrap();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("extract")
        .arg(&hidden)
        .args(["--password", "wrong", "--force"])
        .arg("-o")
        .arg(&output)
        .assert()
        .failure();
    assert_eq!(fs::read(&output).unwrap(), b"keep this file");
    Command::cargo_bin("itx")
        .unwrap()
        .arg("extract")
        .arg(&hidden)
        .args(["--password", "secret"])
        .arg("-o")
        .arg(&output)
        .assert()
        .failure();
    assert_eq!(fs::read(&output).unwrap(), b"keep this file");
    Command::cargo_bin("invitext")
        .unwrap()
        .arg("--json")
        .arg("extract")
        .arg(&hidden)
        .args(["--password", "secret", "--force"])
        .arg("-o")
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"extracted\""));
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_eq!(fs::read(&attachment).unwrap(), bytes);
    let hidden_bytes = fs::read(&hidden).unwrap();
    let mut damaged = hidden_bytes.clone();
    damaged[original.len() + 76] ^= 0xff;
    let damaged_carrier = temp.path().join("damaged.pdf");
    fs::write(&damaged_carrier, damaged).unwrap();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("extract")
        .arg(&damaged_carrier)
        .args(["--password", "secret", "--force"])
        .arg("-o")
        .arg(&output)
        .assert()
        .failure();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    Command::cargo_bin("itx")
        .unwrap()
        .arg("extract")
        .arg(&hidden)
        .args(["--password", "secret", "--force"])
        .arg("-o")
        .arg(&hidden)
        .assert()
        .failure();
    assert_eq!(fs::read(&hidden).unwrap(), hidden_bytes);
    Command::cargo_bin("itx")
        .unwrap()
        .arg("strip")
        .arg(&hidden)
        .arg("-o")
        .arg(&clean)
        .assert()
        .success();
    assert_eq!(fs::read(&clean).unwrap(), original);
}

#[test]
fn binary_file_in_png_stealth_and_capacity_failure() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("cover.png");
    let attachment = temp.path().join("document.pdf");
    let hidden = temp.path().join("hidden.png");
    let output = temp.path().join("restored.pdf");
    write_png(&carrier, 256, 256);
    let bytes = b"%PDF-1.7\n\x00\xff binary document\n%%EOF";
    fs::write(&attachment, bytes).unwrap();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("hide")
        .arg(&carrier)
        .arg("--file")
        .arg(&attachment)
        .args(["--mode", "stealth", "--password", "secret"])
        .arg("-o")
        .arg(&hidden)
        .assert()
        .success();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("verify")
        .arg(&hidden)
        .args(["--mode", "stealth", "--password", "secret"])
        .assert()
        .success();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("extract")
        .arg(&hidden)
        .args(["--mode", "stealth", "--password", "secret"])
        .arg("-o")
        .arg(&output)
        .assert()
        .success();
    assert_eq!(fs::read(output).unwrap(), bytes);
    assert!(
        !fs::read(&hidden)
            .unwrap()
            .windows(8)
            .any(|bytes| bytes == b"INVITEXT")
    );

    let tiny = temp.path().join("tiny.png");
    let refused = temp.path().join("refused.png");
    write_png(&tiny, 16, 16);
    let original = fs::read(&tiny).unwrap();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("hide")
        .arg(&tiny)
        .arg("--file")
        .arg(&attachment)
        .args(["--mode", "stealth", "--password", "secret"])
        .arg("-o")
        .arg(&refused)
        .assert()
        .failure()
        .stderr(predicate::str::contains("capacity"));
    assert!(!refused.exists());
    assert_eq!(fs::read(&tiny).unwrap(), original);
}

#[test]
fn attachment_options_cannot_destroy_source_or_mix_with_text() {
    let temp = tempfile::tempdir().unwrap();
    let carrier = temp.path().join("cover.pdf");
    let attachment = temp.path().join("file.zip");
    fs::write(&carrier, b"%PDF-1.7").unwrap();
    fs::write(&attachment, b"source file").unwrap();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("hide")
        .arg(&carrier)
        .arg("--file")
        .arg(&attachment)
        .args(["--password", "secret", "--force"])
        .arg("-o")
        .arg(&attachment)
        .assert()
        .failure()
        .stderr(predicate::str::contains("attachment source"));
    assert_eq!(fs::read(&attachment).unwrap(), b"source file");
    Command::cargo_bin("itx")
        .unwrap()
        .arg("hide")
        .arg(&carrier)
        .arg("--file")
        .arg(&attachment)
        .args(["-m", "text"])
        .assert()
        .failure();
    Command::cargo_bin("itx")
        .unwrap()
        .arg("hide")
        .arg(&carrier)
        .arg("--file")
        .arg(&attachment)
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot prompt"));
    assert!(!temp.path().join("cover.invitext.pdf").exists());
}
