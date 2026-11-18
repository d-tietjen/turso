//! Regression contracts for stored encrypted-header WAL identities (EDEN-3420).

use super::database_identity_from_header_bytes;
use crate::storage::encryption::{validate_turso_header, CipherMode};
#[cfg(feature = "encryption")]
use crate::storage::encryption::{EncryptionContext, EncryptionKey};
#[cfg(all(host_shared_wal, feature = "fs"))]
use crate::storage::shared_wal_coordination::{
    MappedSharedWalCoordination, SharedWalCoordinationHeader,
};
use crate::LimboError;
#[cfg(all(host_shared_wal, feature = "fs"))]
use std::sync::Arc;

/// Build only synthetic header bytes, with an observable page count and raw CRC.
fn encrypted_header(cipher_id: u8) -> [u8; 100] {
    let mut header = [0; 100];
    header[..5].copy_from_slice(b"Turso");
    header[6] = cipher_id;
    header[28..32].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    header[99] = 0xA5;
    header
}

/// Each supported encrypted format retains its raw identity, including the cipher.
#[test]
fn encrypted_wal_identity_uses_raw_header_and_page_count() {
    for cipher_id in 1..=8 {
        let header = encrypted_header(cipher_id);
        let identity =
            database_identity_from_header_bytes(&header).expect("valid encrypted identity");
        assert_eq!(identity, (0x0102_0304, crc32c::crc32c(&header)));
        let mut sqlite = header;
        sqlite[..16].copy_from_slice(b"SQLite format 3\0");
        assert_eq!(
            database_identity_from_header_bytes(&sqlite).expect("unchanged SQLite identity"),
            (0x0102_0304, crc32c::crc32c(&sqlite))
        );
        assert_ne!(
            identity.1,
            crc32c::crc32c(&sqlite),
            "proofs must not normalize encrypted magic"
        );
        let mut changed = header;
        changed[99] ^= 1;
        assert_ne!(
            identity.1,
            database_identity_from_header_bytes(&changed)
                .expect("changed raw identity")
                .1,
            "reopen proof validation must observe changes outside the magic"
        );
    }
}

/// Unknown or malformed encrypted formats retain the existing WAL corruption class.
#[test]
fn malformed_encrypted_wal_headers_are_refused() {
    let valid = encrypted_header(2);
    for length in 0..100 {
        assert!(matches!(
            database_identity_from_header_bytes(&valid[..length]),
            Err(LimboError::Corrupt(_))
        ));
    }
    let mut malformed = Vec::new();
    for offset in 0..5 {
        let mut header = valid;
        header[offset] ^= 1;
        malformed.push(header);
    }
    for version in [1, 255] {
        let mut header = valid;
        header[5] = version;
        malformed.push(header);
    }
    for cipher_id in [0, 9, 255] {
        malformed.push(encrypted_header(cipher_id));
    }
    for offset in 7..16 {
        let mut header = valid;
        header[offset] = 1;
        malformed.push(header);
    }
    for header in malformed {
        assert!(matches!(
            database_identity_from_header_bytes(&header),
            Err(LimboError::Corrupt(message)) if message == "database header magic mismatch"
        ));
    }
}

/// A format acceptable to WAL identity still must match the decryption context.
#[test]
fn encrypted_header_validation_keeps_cipher_match_and_error_order() {
    let mut header = encrypted_header(2);
    assert!(validate_turso_header(&header, None).is_ok());
    assert!(validate_turso_header(&header, Some(CipherMode::Aes256Gcm)).is_ok());
    header[7] = 1;
    assert!(
        matches!(
            validate_turso_header(&header, Some(CipherMode::Aes128Gcm)),
            Err(LimboError::InternalError(message)) if message.starts_with("Cipher mode mismatch:")
        ),
        "cipher mismatch must still precede the reserved-byte check"
    );
    assert!(matches!(
        validate_turso_header(&header, None),
        Err(LimboError::InternalError(message)) if message == "Invalid Turso header: unused bytes must be zero"
    ));
    assert!(validate_turso_header(&header[..15], None).is_err());
}

/// Persisted proofs validate the same raw encrypted identity after mapping reopen.
#[cfg(all(host_shared_wal, feature = "fs"))]
#[test]
fn encrypted_backfill_proof_survives_reopen_and_refuses_changed_raw_header() {
    let directory = tempfile::tempdir().expect("isolated coordination fixture");
    let path = directory.path().join("encrypted-proof.tshm");
    #[cfg(not(all(target_os = "windows", feature = "experimental_win_iocp")))]
    let io: Arc<dyn crate::IO> = Arc::new(crate::PlatformIO::new().expect("native fixture IO"));
    #[cfg(all(target_os = "windows", feature = "experimental_win_iocp"))]
    let io: Arc<dyn crate::IO> = Arc::new(crate::WindowsIOCP::new().expect("native fixture IO"));
    let snapshot = SharedWalCoordinationHeader {
        max_frame: 14,
        nbackfills: 8,
        transaction_count: 9,
        visibility_generation: 1,
        checkpoint_seq: 5,
        checkpoint_epoch: 7,
        page_size: 4096,
        salt_1: 17,
        salt_2: 23,
        checksum_1: 31,
        checksum_2: 37,
        reader_slot_count: 64,
    };
    let header = encrypted_header(2);
    let (pages, checksum) =
        database_identity_from_header_bytes(&header).expect("encrypted stored identity");
    {
        let mapped = MappedSharedWalCoordination::create_or_open(&io, &path, 64)
            .expect("original proof mapping");
        mapped.install_snapshot(snapshot);
        mapped.install_backfill_proof(snapshot, pages, checksum);
        assert!(mapped.validate_backfill_proof(snapshot, pages, checksum));
    }
    let reopened = MappedSharedWalCoordination::create_or_open(&io, &path, 64)
        .expect("reopened proof mapping");
    let (pages, checksum) =
        database_identity_from_header_bytes(&header).expect("reopened encrypted identity");
    assert!(reopened.validate_backfill_proof(snapshot, pages, checksum));
    for offset in [6, 28, 99] {
        let mut changed = header;
        changed[offset] ^= 1;
        let (pages, checksum) = database_identity_from_header_bytes(&changed)
            .expect("still structurally valid identity");
        assert!(!reopened.validate_backfill_proof(snapshot, pages, checksum));
    }
}

/// Structural header acceptance does not bypass AEAD or allow a different key.
#[cfg(feature = "encryption")]
#[test]
fn encrypted_page_authentication_still_refuses_wrong_key_and_modified_header() {
    let context = EncryptionContext::new(
        CipherMode::Aes256Gcm,
        &EncryptionKey::new_256([0x12; 32]),
        4096,
    )
    .expect("synthetic encryption context");
    let wrong_key = EncryptionContext::new(
        CipherMode::Aes256Gcm,
        &EncryptionKey::new_256([0x34; 32]),
        4096,
    )
    .expect("different synthetic encryption key");
    let mut page = vec![0; 4096];
    page[..16].copy_from_slice(b"SQLite format 3\0");
    page[100..116].copy_from_slice(b"synthetic-value!");
    let encrypted = context
        .encrypt_page(&page, 1)
        .expect("authenticated encrypted page");
    assert_eq!(
        context.decrypt_page(&encrypted, 1).expect("correct key"),
        page
    );
    assert!(wrong_key.decrypt_page(&encrypted, 1).is_err());
    let mut changed = encrypted;
    changed[99] ^= 1;
    assert!(validate_turso_header(&changed, None).is_ok());
    assert!(
        context.decrypt_page(&changed, 1).is_err(),
        "plaintext header remains AEAD additional data"
    );
}
