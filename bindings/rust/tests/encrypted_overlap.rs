//! Exercise the encrypted overlap role through the public Rust binding in two processes.

#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use turso::{Builder, Connection, EncryptionOpts, Error};

/// Use fixed synthetic credentials for local integration fixtures.
fn encrypted_builder(path: &Path, wrong_key: bool) -> Builder {
    Builder::new_local(path.to_str().expect("UTF-8 test path")).with_encryption(EncryptionOpts {
        cipher: "aes256gcm".into(),
        hexkey: if wrong_key { "ff" } else { "42" }.repeat(32),
    })
}

/// Return the first integer from a single-row query, including checkpoint status.
async fn integer(conn: &Connection, sql: &str) -> i64 {
    let mut rows = conn.query(sql, ()).await.expect("query");
    let value = rows
        .next()
        .await
        .expect("read row")
        .expect("one row")
        .get(0)
        .expect("integer column");
    assert!(rows.next().await.expect("finish statement").is_none());
    value
}

/// Wait for the other process to reach a test barrier with a bounded deadline.
fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "barrier {path:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Run the same test executable as a separate database process.
fn reader_process(directory: &Path, mode: &str) -> Command {
    let executable = std::env::var_os("TURSO_ENCRYPTED_OVERLAP_READER_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_exe().expect("test executable"));
    let mut command = Command::new(executable);
    command
        .args(["--exact", "encrypted_overlap_reader_process", "--ignored"])
        .env("TURSO_ENCRYPTED_OVERLAP_FIXTURE", directory)
        .env("TURSO_ENCRYPTED_OVERLAP_TEST_MODE", mode);
    command
}

/// Run the independently opened successor role until the owner verifies contention.
#[tokio::test]
#[ignore = "run by the overlap integration test in a separate process"]
async fn encrypted_overlap_reader_process() {
    if let Some(build) = option_env!("TURSO_ENCRYPTED_OVERLAP_BUILD_LABEL") {
        eprintln!("encrypted overlap reader fixture build {build}");
    }
    let dir = std::env::var_os("TURSO_ENCRYPTED_OVERLAP_FIXTURE").expect("fixture directory");
    let dir = Path::new(&dir);
    let mode = std::env::var("TURSO_ENCRYPTED_OVERLAP_TEST_MODE").expect("test mode");
    let result = encrypted_builder(&dir.join("overlap.db"), mode == "wrong-key")
        .build_encrypted_overlap_reader()
        .await;
    if mode != "reader" {
        assert!(result.is_err(), "role must refuse {mode}");
        return;
    }
    let db = result.expect("attach encrypted overlap reader");
    let conn = db.connect().expect("reader connection");
    assert!(encrypted_builder(&dir.join("overlap.db"), false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .is_err());
    conn.execute("BEGIN", ()).await.expect("start snapshot");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
    fs::write(dir.join("snapshot-pinned"), b"").expect("signal snapshot");
    wait_for(&dir.join("writer-committed"));
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
    conn.execute("COMMIT", ()).await.expect("end snapshot");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 32);
    assert_eq!(
        integer(&conn, "SELECT value FROM committed_schema").await,
        7
    );
    assert!(matches!(
        conn.execute("UPDATE parent SET value=33", ()).await,
        Err(Error::Readonly(_))
    ));
    let mut checkpoint = conn
        .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
        .await
        .expect("prepare checkpoint");
    assert!(matches!(checkpoint.next().await, Err(Error::Readonly(_))));
    assert!(matches!(
        conn.execute("VACUUM INTO 'read-only-must-not-create.db'", ())
            .await,
        Err(Error::Readonly(_))
    ));
}

/// Verify one writer, committed read snapshots, checkpoint contention and durable reopen.
#[tokio::test]
async fn encrypted_overlap_preserves_snapshot_and_writer() {
    verify_overlap(true).await;
    verify_overlap(false).await;
}

/// Exercise both a committed WAL tail and a reader pinned to the checkpointed database file.
async fn verify_overlap(with_wal_tail: bool) {
    let dir = tempfile::tempdir().expect("private fixture");
    let data = dir.path().join("overlap.db");
    let writer = encrypted_builder(&data, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("open writer");
    let conn = writer.connect().expect("writer connection");
    assert!(encrypted_builder(&data, false)
        .build_encrypted_overlap_reader()
        .await
        .is_err());
    conn.execute("PRAGMA synchronous=NORMAL", ())
        .await
        .expect("sync mode");
    conn.execute("PRAGMA foreign_keys=ON", ())
        .await
        .expect("foreign keys");
    conn.execute(
        "CREATE TABLE parent(id INTEGER PRIMARY KEY, value INTEGER)",
        (),
    )
    .await
    .expect("parent schema");
    conn.execute("CREATE TABLE child(id INTEGER REFERENCES parent(id))", ())
        .await
        .expect("child schema");
    conn.execute(
        "INSERT INTO parent VALUES(1, ?1)",
        [if with_wal_tail { 30 } else { 31 }],
    )
    .await
    .expect("seed data");
    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 0);
    let wal = dir.path().join("overlap.db-wal");
    assert_eq!(fs::metadata(&wal).expect("checkpointed WAL").len(), 0);
    if with_wal_tail {
        conn.execute("UPDATE parent SET value=31", ())
            .await
            .expect("commit to shared WAL");
        assert!(fs::metadata(&wal).expect("committed WAL").len() > 0);
    }

    let sidecars = ["overlap.db", "overlap.db-wal", "overlap.db-tshm"];
    let before = sidecars.map(|name| fs::read(dir.path().join(name)).expect("retained bytes"));
    assert!(reader_process(dir.path(), "wrong-key")
        .status()
        .expect("wrong-key process")
        .success());
    let after = sidecars.map(|name| fs::read(dir.path().join(name)).expect("retained bytes"));
    assert!(
        before == after,
        "refused credentials changed a retained file"
    );

    let mut child = reader_process(dir.path(), "reader")
        .spawn()
        .expect("reader process");
    wait_for(&dir.path().join("snapshot-pinned"));
    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .expect("begin write");
    conn.execute("UPDATE parent SET value=99", ())
        .await
        .expect("uncommitted write");
    conn.execute("ROLLBACK", ()).await.expect("roll back");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
    assert!(matches!(
        conn.execute("INSERT INTO child VALUES(2)", ()).await,
        Err(Error::Constraint(_))
    ));
    conn.execute("UPDATE parent SET value=32", ())
        .await
        .expect("next committed update");
    conn.execute("CREATE TABLE committed_schema(value INTEGER)", ())
        .await
        .expect("concurrent schema change");
    conn.execute("INSERT INTO committed_schema VALUES(7)", ())
        .await
        .expect("commit new schema data");
    let checkpoint_busy = integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await;
    let wal_retained = fs::metadata(&wal).expect("pinned WAL").len() > 0;
    fs::write(dir.path().join("writer-committed"), b"").expect("release reader");
    assert!(child.wait().expect("reap reader").success());
    assert_eq!(checkpoint_busy, 1);
    assert!(wal_retained);
    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 0);
    assert_eq!(fs::metadata(&wal).expect("settled WAL").len(), 0);

    drop(conn);
    drop(writer);
    let reopened = encrypted_builder(&data, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("reopen checkpoint");
    let conn = reopened.connect().expect("reopened connection");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 32);
    assert_eq!(integer(&conn, "SELECT count(*) FROM child").await, 0);
}

/// Refuse a different VFS or an initialized database without shared WAL coordination.
#[tokio::test]
async fn encrypted_overlap_refuses_fallback() {
    let dir = tempfile::tempdir().expect("private fixture");
    let data = dir.path().join("overlap.db");
    assert!(encrypted_builder(&data, false)
        .with_io("memory".into())
        .build_encrypted_overlap_reader()
        .await
        .is_err());
    assert!(!data.exists());

    let legacy = encrypted_builder(&data, false)
        .experimental_encryption(true)
        .build()
        .await
        .expect("initialize encrypted database in legacy custody");
    let conn = legacy.connect().expect("legacy connection");
    conn.execute("CREATE TABLE users(id INTEGER)", ())
        .await
        .expect("schema");
    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 0);
    assert!(!dir.path().join("overlap.db-tshm").exists());
    assert!(reader_process(dir.path(), "missing-coordinator")
        .status()
        .expect("reader process")
        .success());
    assert!(!dir.path().join("overlap.db-tshm").exists());
    let sidecar = dir.path().join("overlap.db-tshm");
    fs::write(&sidecar, b"incompatible fixture").expect("invalid coordinator fixture");
    assert!(reader_process(dir.path(), "incompatible-coordinator")
        .status()
        .expect("reader process")
        .success());
    assert_eq!(
        fs::read(sidecar).expect("retained coordinator"),
        b"incompatible fixture"
    );
}
