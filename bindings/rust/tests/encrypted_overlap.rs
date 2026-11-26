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

/// Verify the access mode of each retained file in the reader process.
fn assert_reader_descriptors(directory: &Path) {
    let expected = [
        ("overlap.db", 0),
        ("overlap.db-wal", 0),
        ("overlap.db-tshm", 2),
    ];
    let mut seen = [false; 3];
    for fd in fs::read_dir("/proc/self/fd").expect("reader descriptors") {
        let fd = fd.expect("descriptor entry");
        let Ok(target) = fs::read_link(fd.path()) else {
            continue;
        };
        for (index, (name, access)) in expected.iter().enumerate() {
            if target == directory.join(name) {
                let path = Path::new("/proc/self/fdinfo").join(fd.file_name());
                let info = fs::read_to_string(path).expect("descriptor flags");
                let flags = info
                    .lines()
                    .find_map(|line| line.strip_prefix("flags:"))
                    .expect("flags");
                let mode = u32::from_str_radix(flags.trim(), 8).expect("octal flags") & 3;
                assert_eq!(mode, *access, "{name}");
                seen[index] = true;
            }
        }
    }
    assert_eq!(seen, [true; 3]);
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
    if mode == "rolled-back-spill" {
        let result = encrypted_builder(&dir.join("overlap.db"), false)
            .build_encrypted_overlap_reader()
            .await;
        assert!(matches!(result, Err(Error::Busy(_))));
        return;
    }
    if mode == "ordinary-passive-backfill" {
        let db = encrypted_builder(&dir.join("overlap.db"), false)
            .experimental_encryption(true)
            .experimental_multiprocess_wal(true)
            .build()
            .await
            .expect("join encrypted WAL after passive checkpoint");
        let conn = db.connect().expect("joined connection");
        assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
        conn.execute("UPDATE parent SET value=32", ())
            .await
            .expect("commit from joined connection");
        return;
    }
    let result = encrypted_builder(&dir.join("overlap.db"), mode == "wrong-key")
        .build_encrypted_overlap_reader()
        .await;
    if mode != "reader" && mode != "passive-backfill" {
        assert!(result.is_err(), "role must refuse {mode}");
        return;
    }
    let db = result.expect("attach encrypted overlap reader");
    let conn = db.connect().expect("reader connection");
    assert_reader_descriptors(dir);
    if mode == "passive-backfill" {
        assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
        return;
    }
    assert!(encrypted_builder(&dir.join("overlap.db"), false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .is_err());
    conn.execute("BEGIN", ()).await.expect("start snapshot");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
    conn.execute("SAVEPOINT pinned_read", ())
        .await
        .expect("reader savepoint");
    fs::write(dir.join("snapshot-pinned"), b"").expect("signal snapshot");
    wait_for(&dir.join("writer-staged"));
    conn.execute("ROLLBACK TO pinned_read", ())
        .await
        .expect("roll back reader savepoint locally");
    conn.execute("RELEASE pinned_read", ())
        .await
        .expect("release reader savepoint");
    fs::write(dir.join("reader-rolled-back"), b"").expect("signal reader rollback");
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
    let output = dir.join("must-not-create.db");
    assert!(matches!(
        conn.execute(&format!("VACUUM INTO '{}'", output.display()), ())
            .await,
        Err(Error::Readonly(_))
    ));
    assert!(!output.exists());
}

#[tokio::test]
#[ignore = "run by the overlap integration test in a separate process"]
async fn encrypted_overlap_writer_contender_process() {
    let dir = std::env::var_os("TURSO_ENCRYPTED_OVERLAP_FIXTURE").expect("fixture directory");
    let dir = Path::new(&dir);
    let db = encrypted_builder(&dir.join("overlap.db"), false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("attach ordinary writer contender before the transaction");
    let conn = db.connect().expect("contender connection");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
    fs::write(dir.join("contender-attached"), b"").expect("signal contender attachment");

    wait_for(&dir.join("writer-staged"));
    assert!(matches!(
        conn.execute("BEGIN IMMEDIATE", ()).await,
        Err(Error::Busy(_))
    ));
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
    fs::write(dir.join("contender-busy"), b"").expect("signal writer contention");

    wait_for(&dir.join("writer-committed"));
    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .expect("acquire the released writer lock");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 32);
    conn.execute("ROLLBACK", ())
        .await
        .expect("release writer lock");
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

    let mut contender = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "encrypted_overlap_writer_contender_process",
            "--ignored",
        ])
        .env("TURSO_ENCRYPTED_OVERLAP_FIXTURE", dir.path())
        .spawn()
        .expect("ordinary writer contender process");
    wait_for(&dir.path().join("contender-attached"));
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
    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .expect("begin writer commit");
    let before_flush = fs::metadata(&wal).expect("writer WAL").len();
    conn.execute("UPDATE parent SET value=32", ())
        .await
        .expect("stage next update");
    conn.cacheflush().expect("flush uncommitted WAL frames");
    assert!(fs::metadata(&wal).expect("staged WAL").len() > before_flush);
    let coordinator = dir.path().join("overlap.db-tshm");
    let before_rollback = fs::read(&coordinator).expect("live coordinator");
    fs::write(dir.path().join("writer-staged"), b"").expect("allow reader rollback");
    wait_for(&dir.path().join("reader-rolled-back"));
    wait_for(&dir.path().join("contender-busy"));
    assert_eq!(
        fs::read(&coordinator).expect("live coordinator"),
        before_rollback
    );
    conn.execute("COMMIT", ())
        .await
        .expect("commit staged update");
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
    assert!(contender.wait().expect("reap writer contender").success());
    assert_eq!(checkpoint_busy, 1);
    assert!(wal_retained);
    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 0);
    assert_eq!(fs::metadata(&wal).expect("settled WAL").len(), 0);

    drop(conn);
    drop(writer);
    let retired = sidecars.map(|name| fs::read(dir.path().join(name)).expect("retired backing"));
    assert!(reader_process(dir.path(), "stale-coordinator")
        .status()
        .expect("stale coordinator process")
        .success());
    let after_refusal =
        sidecars.map(|name| fs::read(dir.path().join(name)).expect("retired backing"));
    assert!(
        retired == after_refusal,
        "refused attachment changed retired backing"
    );

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

/// Confirm the reader and checkpointer agree on the decoded encrypted page-1 identity.
#[tokio::test]
async fn encrypted_overlap_accepts_durable_passive_backfill() {
    let dir = tempfile::tempdir().expect("private fixture");
    let data = dir.path().join("overlap.db");
    let writer = encrypted_builder(&data, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("open writer");
    let conn = writer.connect().expect("writer connection");
    conn.execute("CREATE TABLE parent(value INTEGER)", ())
        .await
        .expect("schema");
    conn.execute("INSERT INTO parent VALUES(31)", ())
        .await
        .expect("seed encrypted data");
    let mut result = conn
        .query("PRAGMA wal_checkpoint(PASSIVE)", ())
        .await
        .expect("checkpoint");
    let row = result
        .next()
        .await
        .expect("checkpoint result")
        .expect("status");
    assert_eq!(row.get::<i64>(0).expect("busy status"), 0);
    let checkpointed_frames = row.get::<i64>(2).expect("backfilled frame count");
    assert!(checkpointed_frames > 0);
    assert!(result.next().await.expect("finish checkpoint").is_none());
    assert!(
        fs::metadata(dir.path().join("overlap.db-wal"))
            .expect("retained WAL")
            .len()
            > 0
    );
    assert!(reader_process(dir.path(), "passive-backfill")
        .status()
        .expect("reader")
        .success());
    assert!(reader_process(dir.path(), "ordinary-passive-backfill")
        .status()
        .expect("ordinary multiprocess participant")
        .success());
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 32);
}

/// Refuse a different VFS or an initialized database without shared WAL coordination.
#[tokio::test]
async fn encrypted_overlap_refuses_fallback() {
    let dir = tempfile::tempdir().expect("private fixture");
    let data = dir.path().join("overlap.db");
    assert!(encrypted_builder(&data, false)
        .with_io("memory")
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
}

/// Verify a fresh reader can retry after the writer checkpoints a rolled-back spill.
#[tokio::test]
async fn encrypted_overlap_retries_after_rolled_back_spill() {
    let dir = tempfile::tempdir().expect("private fixture");
    let data = dir.path().join("overlap.db");
    let wal = dir.path().join("overlap.db-wal");
    let writer = encrypted_builder(&data, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("open writer");
    let conn = writer.connect().expect("writer connection");
    conn.execute("CREATE TABLE parent(value INTEGER)", ())
        .await
        .expect("schema");
    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 0);
    conn.execute("INSERT INTO parent VALUES(31)", ())
        .await
        .expect("commit fixture row");
    let committed_len = fs::metadata(&wal).expect("committed WAL").len();
    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .expect("begin write");
    conn.execute("UPDATE parent SET value=99", ())
        .await
        .expect("stage update");
    conn.cacheflush().expect("flush uncommitted frames");
    let spilled_len = fs::metadata(&wal).expect("spilled WAL").len();
    assert!(spilled_len > committed_len);
    conn.execute("ROLLBACK", ())
        .await
        .expect("roll back spilled update");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
    assert_eq!(
        fs::metadata(&wal).expect("retained WAL extent").len(),
        spilled_len
    );

    let before = [&data, &wal].map(|p| fs::read(p).expect("retained bytes"));
    assert!(reader_process(dir.path(), "rolled-back-spill")
        .status()
        .expect("fresh reader process")
        .success());
    let after = [&data, &wal].map(|p| fs::read(p).expect("retained bytes"));
    assert_eq!(before, after, "retryable refusal changed the backing");

    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 0);
    assert_eq!(fs::metadata(&wal).expect("settled WAL").len(), 0);
    assert!(reader_process(dir.path(), "passive-backfill")
        .status()
        .expect("fresh reader after checkpoint")
        .success());
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
}
