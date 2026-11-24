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

/// Read the Linux access mode of an open backing descriptor.
fn descriptor_access_mode(fd: &fs::DirEntry) -> usize {
    let path = Path::new("/proc/self/fdinfo").join(fd.file_name());
    let info = fs::read_to_string(path).expect("descriptor flags");
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .expect("flags");
    usize::from_str_radix(flags.trim(), 8).expect("octal flags") & 3
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
                assert_eq!(descriptor_access_mode(&fd), *access, "{name}");
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
    let managed_activation =
        cfg!(all(feature = "encrypted-wal-handoff", not(miri))) && mode == "managed-activation";
    if !managed_activation
        && !matches!(
            mode.as_str(),
            "reader" | "passive-backfill" | "write-boundary" | "managed-receipt"
        )
    {
        assert!(result.is_err(), "role must refuse {mode}");
        return;
    }
    let db = result.expect("attach encrypted overlap reader");
    let conn = db.connect().expect("reader connection");
    assert_reader_descriptors(dir);
    #[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
    if managed_activation {
        run_managed_activation_successor(dir, &db, &conn).await;
        return;
    }
    if mode == "passive-backfill" {
        assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
        return;
    }
    if matches!(mode.as_str(), "write-boundary" | "managed-receipt") {
        conn.execute("BEGIN", ())
            .await
            .expect("pin read transaction");
        assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
        fs::write(dir.join("boundary-reader-pinned"), b"").expect("signal reader pin");
        wait_for(&dir.join("boundary-mutations-locked"));
        #[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
        if mode == "managed-receipt" {
            use std::num::{NonZeroU128, NonZeroU64};
            use turso::encrypted_wal_handoff as handoff;
            let previous = handoff::WriterClaim {
                owner: handoff::WriterId(NonZeroU128::MIN),
                epoch: NonZeroU64::MIN,
            };
            let request = handoff::WriterTransfer {
                id: handoff::TransferId(NonZeroU128::MIN),
                successor: handoff::WriterId(NonZeroU128::new(2).expect("successor ID")),
            };
            let other = handoff::WriterTransfer {
                successor: handoff::WriterId(NonZeroU128::new(3).expect("other ID")),
                ..request
            };
            assert!(handoff::verify_successor(&conn, previous, other).is_err());
            let report = handoff::verify_successor(&conn, previous, request)
                .expect("verify nominated boundary");
            fs::write(dir.join("boundary-receiver-position"), report.wal_position)
                .expect("record verified boundary");
            assert_reader_descriptors(dir);
        }
        assert_eq!(integer(&conn, "SELECT value FROM parent").await, 31);
        fs::write(dir.join("boundary-reader-checked"), b"").expect("signal pinned read");
        wait_for(&dir.join("boundary-mutations-unlocked"));
        conn.execute("COMMIT", ())
            .await
            .expect("end read transaction");
        assert_eq!(integer(&conn, "SELECT value FROM parent").await, 32);
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

/// Sync a committed writer boundary without losing the separate reader's snapshot.
#[tokio::test]
async fn encrypted_write_boundary_preserves_live_reader() {
    use std::os::unix::fs::MetadataExt;
    let directory = tempfile::tempdir().expect("fixture directory");
    let path = directory.path().join("overlap.db");
    let writer = encrypted_builder(&path, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("open writer");
    assert!(writer
        .with_encrypted_wal_write_boundary(|_| panic!("empty database admitted"))
        .is_err());
    let conn = writer.connect().expect("writer connection");
    conn.execute("CREATE TABLE parent(value INTEGER)", ())
        .await
        .expect("schema");
    conn.execute("INSERT INTO parent VALUES(31)", ())
        .await
        .expect("seed row");
    let mut reader = reader_process(directory.path(), "write-boundary")
        .spawn()
        .expect("start separate reader");
    wait_for(&directory.path().join("boundary-reader-pinned"));

    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .expect("take mutation lock");
    conn.execute("UPDATE parent SET value=99", ())
        .await
        .expect("uncommitted row");
    let refused = writer.with_encrypted_wal_write_boundary(|_| panic!("active writer admitted"));
    assert!(matches!(refused, Err(Error::Busy(_))));
    conn.execute("ROLLBACK", ())
        .await
        .expect("cancel active write");
    conn.execute("UPDATE parent SET value=32", ())
        .await
        .expect("commit final row");

    let started = Instant::now();
    let (boundary, preparation) = writer
        .with_encrypted_wal_write_boundary(|boundary| {
            let preparation = started.elapsed();
            fs::write(directory.path().join("boundary-mutations-locked"), b"")
                .expect("signal held mutation locks");
            wait_for(&directory.path().join("boundary-reader-checked"));
            (boundary, preparation)
        })
        .expect("sync committed backing while reader is pinned");
    eprintln!(
        "encrypted writer boundary prepared in {} microseconds",
        preparation.as_micros()
    );
    assert!(boundary.committed_frames > 0);
    for (name, opened) in [
        ("overlap.db", boundary.database),
        ("overlap.db-wal", boundary.wal),
        ("overlap.db-tshm", boundary.coordinator),
    ] {
        let current = fs::metadata(directory.path().join(name)).expect("retained backing");
        assert_eq!((current.dev(), current.ino()), (opened.dev, opened.ino));
    }
    fs::write(directory.path().join("boundary-mutations-unlocked"), b"")
        .expect("release separate reader");
    assert!(reader.wait().expect("reap reader").success());
    conn.execute("UPDATE parent SET value=33", ())
        .await
        .expect("mutation locks released");
    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 0);
    let checkpointed = writer
        .with_encrypted_wal_write_boundary(|boundary| boundary)
        .expect("initialized database may have an empty WAL");
    assert_eq!(checkpointed.committed_frames, 0);

    let retained = directory.path().join("retained.db");
    fs::rename(&path, &retained).expect("stage fixture replacement");
    fs::write(&path, b"").expect("create different fixture inode");
    let refused = writer.with_encrypted_wal_write_boundary(|_| panic!("replaced inode admitted"));
    fs::rename(&retained, &path).expect("restore opened fixture");
    assert!(refused.is_err());
    assert_eq!(
        writer
            .with_encrypted_wal_write_boundary(|boundary| boundary)
            .expect("locks released"),
        checkpointed
    );
}

/// Roll back a prepared successor while a separate reader keeps its snapshot.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
#[tokio::test]
async fn managed_encrypted_writer_rollback_preserves_separate_reader() {
    use std::num::NonZeroU128;
    use std::os::unix::fs::PermissionsExt;
    use turso::encrypted_wal_handoff as handoff;

    let directory = tempfile::tempdir().expect("fixture directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private service directory");
    let path = directory.path().join("overlap.db");
    let writer = encrypted_builder(&path, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .experimental_attach(false)
        .experimental_vacuum(false)
        .build()
        .await
        .expect("open encrypted writer");
    let conn = writer.connect().expect("writer connection");
    conn.execute("CREATE TABLE parent(value INTEGER)", ())
        .await
        .expect("schema");
    conn.execute("INSERT INTO parent VALUES(31)", ())
        .await
        .expect("commit initial value");
    let owner = handoff::WriterId(NonZeroU128::MIN);
    handoff::enroll(&writer, owner).expect("enroll the native writer");

    let mut reader = reader_process(directory.path(), "managed-receipt")
        .spawn()
        .expect("start separate reader");
    wait_for(&directory.path().join("boundary-reader-pinned"));
    conn.execute("UPDATE parent SET value=32", ())
        .await
        .expect("commit final value");
    let transfer = handoff::WriterTransfer {
        id: handoff::TransferId(NonZeroU128::MIN),
        successor: handoff::WriterId(NonZeroU128::new(2).expect("successor ID")),
    };
    let boundary = handoff::prepare(&writer, transfer).expect("prepare transfer");
    assert!(boundary.committed_frames > 0);
    fs::write(directory.path().join("boundary-mutations-locked"), b"").expect("signal prepared A");
    wait_for(&directory.path().join("boundary-reader-checked"));
    assert_eq!(
        fs::read(directory.path().join("boundary-receiver-position"))
            .expect("the original boundary verified by B"),
        boundary.wal_position
    );
    assert!(matches!(
        conn.execute("UPDATE parent SET value=99", ()).await,
        Err(Error::Busy(_))
    ));
    assert!(encrypted_builder(&path, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .is_err());
    handoff::rollback(&writer, transfer).expect("restore predecessor ownership");
    fs::write(directory.path().join("boundary-mutations-unlocked"), b"")
        .expect("allow the reader to observe the final value");
    assert!(reader.wait().expect("wait for reader").success());
    conn.execute("UPDATE parent SET value=33", ())
        .await
        .expect("resume predecessor writes");
    assert_eq!(integer(&conn, "SELECT value FROM parent").await, 33);
}

/// Use the same synthetic owner, epoch, and request in both activation processes.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
fn activation_request() -> (
    turso::encrypted_wal_handoff::WriterClaim,
    turso::encrypted_wal_handoff::WriterTransfer,
) {
    use std::num::{NonZeroU128, NonZeroU64};
    use turso::encrypted_wal_handoff::{TransferId, WriterClaim, WriterId, WriterTransfer};

    (
        WriterClaim {
            owner: WriterId(NonZeroU128::MIN),
            epoch: NonZeroU64::MIN,
        },
        WriterTransfer {
            id: TransferId(NonZeroU128::MIN),
            successor: WriterId(NonZeroU128::new(2).expect("successor ID")),
        },
    )
}

/// Observe the original read-only files and the successor's writable files by descriptor.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
fn assert_activated_descriptors(directory: &Path, boundary: turso::EncryptedWalWriteBoundary) {
    use std::os::unix::fs::MetadataExt;

    let expected = [
        ("overlap.db", boundary.database),
        ("overlap.db-wal", boundary.wal),
        ("overlap.db-tshm", boundary.coordinator),
    ];
    let mut access_modes = [[false; 3]; 3];
    for fd in fs::read_dir("/proc/self/fd").expect("successor descriptors") {
        let fd = fd.expect("descriptor entry");
        let Ok(target) = fs::read_link(fd.path()) else {
            continue;
        };
        for (index, (name, opened)) in expected.iter().enumerate() {
            if target != directory.join(name) {
                continue;
            }
            let metadata = fs::metadata(fd.path()).expect("stat the open backing descriptor");
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (opened.dev, opened.ino),
                "{name}"
            );
            access_modes[index][descriptor_access_mode(&fd)] = true;
        }
    }
    assert_eq!(
        access_modes,
        [
            [true, false, true],
            [true, false, true],
            [false, false, true]
        ]
    );
}

/// Activate from an existing reader and retain its original snapshot through the successor commit.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
async fn run_managed_activation_successor(dir: &Path, db: &turso::Database, reader: &Connection) {
    use turso::encrypted_wal_handoff as handoff;

    reader
        .execute("BEGIN", ())
        .await
        .expect("pin original reader");
    assert_eq!(integer(reader, "SELECT value FROM parent").await, 31);
    fs::write(dir.join("activation-reader-pinned"), b"").expect("signal pinned reader");
    wait_for(&dir.join("activation-prepared"));

    let (previous, request) = activation_request();
    let boundary = handoff::verify_successor(reader, previous, request).expect("verify prepare");
    assert_eq!(
        fs::read(dir.join("activation-prepared")).expect("read prepared position"),
        boundary.wal_position
    );
    let activation_started = Instant::now();
    let writer = handoff::activate(db, reader, previous, request).expect("activate successor");
    eprintln!(
        "encrypted WAL successor activation {} us",
        activation_started.elapsed().as_micros()
    );
    let writer_conn = writer.connect().expect("successor writer connection");
    assert_eq!(integer(&writer_conn, "SELECT value FROM parent").await, 32);
    assert_activated_descriptors(dir, boundary);
    let commit_started = Instant::now();
    writer_conn
        .execute("UPDATE parent SET value=33", ())
        .await
        .expect("commit successor write");
    eprintln!(
        "encrypted WAL successor first commit {} us",
        commit_started.elapsed().as_micros()
    );
    assert_eq!(integer(reader, "SELECT value FROM parent").await, 31);

    let retried = handoff::activate(db, reader, previous, request).expect("retry activation");
    let retried_conn = retried
        .connect()
        .expect("connection from retried activation");
    assert_eq!(integer(&retried_conn, "SELECT value FROM parent").await, 33);
    drop(retried_conn);
    drop(retried);
    drop(writer_conn);
    drop(writer);
    assert_reader_descriptors(dir);
    assert_eq!(integer(reader, "SELECT value FROM parent").await, 31);
    assert!(encrypted_builder(&dir.join("overlap.db"), false)
        .build_encrypted_overlap_reader()
        .await
        .is_err());

    let writer =
        handoff::activate(db, reader, previous, request).expect("reopen accepted successor");
    let writer_conn = writer
        .connect()
        .expect("connection from reopened activation");
    assert_eq!(integer(&writer_conn, "SELECT value FROM parent").await, 33);
    reader
        .execute("COMMIT", ())
        .await
        .expect("release original snapshot");
    assert_eq!(integer(reader, "SELECT value FROM parent").await, 33);
    assert!(matches!(
        reader.execute("UPDATE parent SET value=99", ()).await,
        Err(Error::Readonly(_))
    ));
    assert_eq!(
        integer(&writer_conn, "PRAGMA wal_checkpoint(TRUNCATE)").await,
        0
    );
    assert_eq!(
        fs::metadata(dir.join("overlap.db-wal"))
            .expect("retained WAL")
            .len(),
        0
    );
    assert_activated_descriptors(dir, boundary);
    fs::write(dir.join("activation-successor-committed"), b"").expect("signal successor commit");
    wait_for(&dir.join("activation-predecessor-checked"));
    assert_eq!(integer(&writer_conn, "SELECT value FROM parent").await, 33);
}

/// Transfer real writer custody between processes without replacing any backing file.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
#[tokio::test]
async fn managed_encrypted_writer_activates_separate_successor() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use turso::encrypted_wal_handoff as handoff;

    let directory = tempfile::tempdir().expect("fixture directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private service directory");
    let path = directory.path().join("overlap.db");
    let writer = encrypted_builder(&path, false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("open predecessor");
    let conn = writer.connect().expect("predecessor writer connection");
    conn.execute("CREATE TABLE parent(value INTEGER)", ())
        .await
        .expect("schema");
    conn.execute("INSERT INTO parent VALUES(31)", ())
        .await
        .expect("seed row");
    let (previous, request) = activation_request();
    assert_eq!(
        handoff::enroll(&writer, previous.owner).expect("enroll predecessor"),
        previous
    );

    let mut successor = reader_process(directory.path(), "managed-activation")
        .spawn()
        .expect("start separate successor");
    wait_for(&directory.path().join("activation-reader-pinned"));
    conn.execute("UPDATE parent SET value=32", ())
        .await
        .expect("final predecessor commit");
    let prepare_started = Instant::now();
    let boundary = handoff::prepare(&writer, request).expect("prepare successor");
    eprintln!(
        "encrypted WAL predecessor prepare {} us",
        prepare_started.elapsed().as_micros()
    );
    assert!(boundary.committed_frames > 0);
    let prepared = directory.path().join("activation-prepared");
    let staged = directory.path().join("activation-prepared-stage");
    fs::write(&staged, boundary.wal_position).expect("record prepared position");
    fs::rename(staged, prepared).expect("signal prepare with complete position");
    wait_for(&directory.path().join("activation-successor-committed"));

    assert!(matches!(
        conn.execute("UPDATE parent SET value=100", ()).await,
        Err(Error::Busy(_))
    ));
    assert_eq!(integer(&conn, "PRAGMA wal_checkpoint(TRUNCATE)").await, 1);
    assert!(handoff::rollback(&writer, request).is_err());
    for (name, opened) in [
        ("overlap.db", boundary.database),
        ("overlap.db-wal", boundary.wal),
        ("overlap.db-tshm", boundary.coordinator),
    ] {
        let current = fs::metadata(directory.path().join(name)).expect("retained backing");
        assert_eq!(
            (current.dev(), current.ino()),
            (opened.dev, opened.ino),
            "{name}"
        );
    }
    fs::write(directory.path().join("activation-predecessor-checked"), b"")
        .expect("release successor");
    assert!(successor.wait().expect("reap successor").success());
}

/// Own the crash fixture's predecessor even when an assertion fails before the planned kill.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
struct CrashPredecessor(std::process::Child);

#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
impl CrashPredecessor {
    /// Start the child test from this ELF or a separately compiled writer ELF.
    fn spawn(directory: &Path, prepare: bool) -> Self {
        let executable = std::env::var_os("TURSO_ENCRYPTED_OVERLAP_WRITER_BINARY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::current_exe().expect("test executable"));
        let child = Command::new(executable)
            .args([
                "--exact",
                "encrypted_overlap_predecessor_process",
                "--ignored",
                "--nocapture",
            ])
            .env("TURSO_ENCRYPTED_OVERLAP_FIXTURE", directory)
            .env(
                "TURSO_ENCRYPTED_OVERLAP_PREDECESSOR_OUTCOME",
                if prepare { "prepared" } else { "unprepared" },
            )
            .spawn()
            .expect("start predecessor process");
        Self(child)
    }

    /// Kill the live predecessor and confirm it exited by signal before continuing.
    fn kill_and_reap(&mut self) {
        use std::os::unix::process::ExitStatusExt;

        assert!(self.0.try_wait().expect("poll predecessor").is_none());
        self.0.kill().expect("kill live predecessor");
        assert_eq!(self.0.wait().expect("reap predecessor").signal(), Some(9));
    }
}

#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
impl Drop for CrashPredecessor {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Check both the non-idempotent effect and the unique receipt in the current SQL snapshot.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
async fn assert_crash_operation(conn: &Connection, visible: bool) {
    let expected_rows = if visible { 1 } else { 0 };
    assert_eq!(
        integer(conn, "SELECT total FROM counter WHERE id=1").await,
        7 * expected_rows
    );
    assert_eq!(
        integer(conn, "SELECT count(*) FROM operations").await,
        expected_rows
    );
    assert_eq!(
        integer(
            conn,
            "SELECT count(*) FROM operations WHERE operation_id='increment-0001' AND delta=7"
        )
        .await,
        expected_rows
    );
}

/// Run A in a separate process, with application acknowledgement held past the crash point.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
#[tokio::test]
#[ignore = "run by the predecessor-loss integration tests"]
async fn encrypted_overlap_predecessor_process() {
    use turso::encrypted_wal_handoff as handoff;

    if let Some(build) = option_env!("TURSO_ENCRYPTED_OVERLAP_BUILD_LABEL") {
        eprintln!("encrypted overlap predecessor fixture build {build}");
    }
    let directory = std::env::var_os("TURSO_ENCRYPTED_OVERLAP_FIXTURE").expect("fixture directory");
    let dir = Path::new(&directory);
    let prepare = match std::env::var("TURSO_ENCRYPTED_OVERLAP_PREDECESSOR_OUTCOME")
        .expect("predecessor outcome")
        .as_str()
    {
        "prepared" => true,
        "unprepared" => false,
        outcome => panic!("unknown predecessor outcome {outcome}"),
    };
    let writer = encrypted_builder(&dir.join("overlap.db"), false)
        .experimental_encryption(true)
        .experimental_multiprocess_wal(true)
        .build()
        .await
        .expect("open predecessor");
    let conn = writer.connect().expect("predecessor connection");
    conn.execute("PRAGMA synchronous=FULL", ())
        .await
        .expect("require durable commit");
    conn.execute(
        "CREATE TABLE counter(id INTEGER PRIMARY KEY, total INTEGER NOT NULL)",
        (),
    )
    .await
    .expect("create counter");
    conn.execute(
        "CREATE TABLE operations(operation_id TEXT PRIMARY KEY NOT NULL, delta INTEGER NOT NULL)",
        (),
    )
    .await
    .expect("create operation receipts");
    conn.execute("INSERT INTO counter VALUES(1, 0)", ())
        .await
        .expect("seed counter");
    let (previous, request) = activation_request();
    assert_eq!(
        handoff::enroll(&writer, previous.owner).expect("enroll A"),
        previous
    );
    fs::write(dir.join("crash-predecessor-ready"), b"").expect("signal active predecessor");
    wait_for(&dir.join("crash-reader-pinned"));

    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .expect("begin the operation");
    conn.execute("UPDATE counter SET total=total+7 WHERE id=1", ())
        .await
        .expect("apply the increment");
    conn.execute("INSERT INTO operations VALUES('increment-0001', 7)", ())
        .await
        .expect("record the operation ID");
    assert_crash_operation(&conn, true).await;
    if prepare {
        conn.execute("COMMIT", ())
            .await
            .expect("commit the increment and ID together");
        let boundary = handoff::prepare(&writer, request).expect("publish the prepared receipt");
        assert!(boundary.committed_frames > 0);
        let staged = dir.join("crash-position-stage");
        fs::write(&staged, boundary.wal_position).expect("stage A's prepared position");
        fs::rename(staged, dir.join("crash-predecessor-prepared"))
            .expect("signal prepared A with complete position");
    } else {
        fs::write(dir.join("crash-predecessor-uncommitted"), b"")
            .expect("signal A's open write transaction");
    }

    wait_for(&dir.join("crash-permit-acknowledgement"));
    if prepare {
        fs::write(
            dir.join("crash-application-acknowledgement"),
            b"increment-0001",
        )
        .expect("acknowledge the application operation");
    }
}

/// Reap A and verify B's snapshot and write authority against the original backing files.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
async fn verify_predecessor_loss(prepare: bool) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use turso::encrypted_wal_handoff as handoff;

    if let Some(build) = option_env!("TURSO_ENCRYPTED_OVERLAP_BUILD_LABEL") {
        eprintln!("encrypted overlap successor fixture build {build}");
    }
    let directory = tempfile::tempdir().expect("fixture directory");
    let dir = directory.path();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).expect("private service directory");
    let backing_ids = || {
        ["overlap.db", "overlap.db-wal", "overlap.db-tshm"].map(|name| {
            let metadata = fs::metadata(dir.join(name)).expect("original database backing");
            (metadata.dev(), metadata.ino())
        })
    };
    let mut predecessor = CrashPredecessor::spawn(dir, prepare);
    wait_for(&dir.join("crash-predecessor-ready"));
    let original_backing = backing_ids();
    let db = encrypted_builder(&dir.join("overlap.db"), false)
        .build_encrypted_overlap_reader()
        .await
        .expect("attach B while A is alive");
    let reader = db.connect().expect("original B reader");
    reader
        .execute("BEGIN", ())
        .await
        .expect("pin B before A applies the operation");
    assert_crash_operation(&reader, false).await;
    fs::write(dir.join("crash-reader-pinned"), b"").expect("signal B's read snapshot");
    let prepared = dir.join("crash-predecessor-prepared");
    let stopped = if prepare {
        prepared.clone()
    } else {
        dir.join("crash-predecessor-uncommitted")
    };
    wait_for(&stopped);
    if !prepare {
        let latest = db
            .connect()
            .expect("fresh observer of A's open transaction");
        assert_crash_operation(&latest, false).await;
    }
    predecessor.kill_and_reap();
    assert!(!dir.join("crash-application-acknowledgement").exists());
    assert_crash_operation(&reader, false).await;

    let (previous, request) = activation_request();
    if prepare {
        let boundary = handoff::verify_successor(&reader, previous, request)
            .expect("authenticate the prepared receipt after A exits");
        assert_eq!(
            fs::read(prepared).expect("A's prepared position"),
            boundary.wal_position
        );
        let writer =
            handoff::activate(&db, &reader, previous, request).expect("activate B after losing A");
        let recovery = writer.connect().expect("connect recovered writer");
        assert_crash_operation(&recovery, true).await;
        recovery
            .execute("PRAGMA synchronous=FULL", ())
            .await
            .expect("require durable successor commit");
        recovery
            .execute("BEGIN IMMEDIATE", ())
            .await
            .expect("begin the successor operation");
        recovery
            .execute("UPDATE counter SET total=total+11 WHERE id=1", ())
            .await
            .expect("apply the successor increment");
        recovery
            .execute("INSERT INTO operations VALUES('increment-0002', 11)", ())
            .await
            .expect("record the successor operation ID");
        recovery
            .execute("COMMIT", ())
            .await
            .expect("commit the successor operation after A exits");
        assert_crash_operation(&reader, false).await;
        reader
            .execute("COMMIT", ())
            .await
            .expect("release B's original snapshot");
        assert_eq!(
            integer(&recovery, "PRAGMA wal_checkpoint(TRUNCATE)").await,
            0
        );
        assert_eq!(
            fs::metadata(dir.join("overlap.db-wal"))
                .expect("retained WAL")
                .len(),
            0
        );
        assert_eq!(
            integer(&reader, "SELECT total FROM counter WHERE id=1").await,
            18
        );
        assert_eq!(integer(&reader, "SELECT count(*) FROM operations").await, 2);
        assert_eq!(
            integer(
                &reader,
                "SELECT count(*) FROM operations
                 WHERE (operation_id='increment-0001' AND delta=7)
                    OR (operation_id='increment-0002' AND delta=11)"
            )
            .await,
            2
        );
        assert_activated_descriptors(dir, boundary);
    } else {
        assert!(!prepared.exists());
        assert!(handoff::activate(&db, &reader, previous, request).is_err());
        assert_reader_descriptors(dir);
        reader
            .execute("COMMIT", ())
            .await
            .expect("release B's original snapshot");
        assert_crash_operation(&reader, false).await;
    }
    assert_eq!(backing_ids(), original_backing);
}

/// Recover A's unacknowledged increment and commit a new operation after A exits.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
#[tokio::test]
async fn managed_encrypted_writer_recovers_prepared_predecessor_loss() {
    verify_predecessor_loss(true).await;
}

/// An open transaction with no prepared receipt gives B no authority to write after A dies.
#[cfg(all(feature = "encrypted-wal-handoff", not(miri)))]
#[tokio::test]
async fn managed_encrypted_writer_refuses_unprepared_predecessor_loss() {
    verify_predecessor_loss(false).await;
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
