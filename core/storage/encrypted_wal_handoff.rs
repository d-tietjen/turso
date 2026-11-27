//! Durable writer ownership for a native encrypted WAL handoff.
//!
//! The lifecycle caller verifies the open database, WAL, and coordinator under
//! the WAL mutation locks. This module serializes ownership changes through a
//! separate OFD byte and uses a receipt in the database's private directory.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Write};
use std::num::{NonZeroU128, NonZeroU64};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

use crate::io::{
    unix_shared_wal_lock_byte, unix_shared_wal_unlock_byte, FileId, SharedWalLockKind,
};
use crate::{io_error, EncryptedWalWriteBoundary, LimboError, Result};

use super::shared_wal_coordination::{
    SharedWalCoordinationHeader, CHECKPOINT_LOCK_OFFSET, WRITER_LOCK_OFFSET,
};

/// OFD byte reserved after the full range of `u32` reader-slot indices.
const WRITER_LEASE_BYTE: u64 = 3 + u32::MAX as u64 + 1;
/// Receipt format marker and version.
const RECEIPT_MAGIC: [u8; 8] = *b"TSOWN001";
/// Exact receipt size including the optional pending transfer slots.
const RECEIPT_BYTES: usize = 8 + 8 + 6 * 16 + 1 + 3 * 16 + SharedWalCoordinationHeader::BYTE_LEN;

/// Stable identity supplied by the controller for one writer incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterId(pub NonZeroU128);

/// Per-database transfer ID. Each new request must use a higher value, even
/// when the preceding request rolled back without advancing the writer epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransferId(pub NonZeroU128);

/// Owner and monotonically increasing epoch from the durable receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterClaim {
    /// Writer incarnation named by the controller.
    pub owner: WriterId,
    /// Ownership generation that advances only when a successor accepts.
    pub epoch: NonZeroU64,
}

/// Request to transfer one writer epoch to the named successor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterTransfer {
    /// Per-database sequence of this transfer request.
    pub id: TransferId,
    /// Only the nominated writer can accept the transfer.
    pub successor: WriterId,
}

/// Live predecessor handle. A prepared writer has no lease and stays fenced
/// until the exact pending request is rolled back.
pub(crate) struct ManagedWriter {
    pub(crate) claim: WriterClaim,
    pub(crate) lease: Option<WriterLease>,
    pub(crate) pending: Option<PendingWriterTransfer>,
    /// Latest confirmed rollback, for a retry at this open writer.
    pub(crate) last_rollback: Option<WriterTransfer>,
    /// The exact activation that created this live writable incarnation.
    pub(crate) activation: Option<WriterActivation>,
}

/// Identifies an activation retry within the lifetime of the accepted writer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WriterActivation {
    pub(crate) previous: WriterClaim,
    pub(crate) transfer: WriterTransfer,
}

/// No-create writable descriptors for the same files authenticated by the reader.
pub(crate) struct WritableWalBacking {
    pub(crate) database: File,
    pub(crate) wal: File,
}

/// Exact pending operation retained for retry and rollback in the predecessor.
pub(crate) struct PendingWriterTransfer {
    pub(crate) request: WriterTransfer,
    pub(crate) boundary: EncryptedWalWriteBoundary,
}

/// Database, WAL, and coordinator file identities in that order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BackingFiles([FileId; 3]);

impl From<EncryptedWalWriteBoundary> for BackingFiles {
    fn from(boundary: EncryptedWalWriteBoundary) -> Self {
        Self([boundary.database, boundary.wal, boundary.coordinator])
    }
}

/// Durable handoff waiting for successor acceptance or predecessor rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparedTransfer {
    request: WriterTransfer,
    /// Exact committed WAL snapshot encoded by the existing WAL coordinator.
    position: [u8; SharedWalCoordinationHeader::BYTE_LEN],
}

/// Terminal result retained for exact retries and to reject earlier requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedTransfer {
    request: WriterTransfer,
    predecessor: WriterId,
    outcome: TransferOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum TransferOutcome {
    Accepted = 1,
    RolledBack = 2,
}

/// Current epoch and optional prepared transfer stored in one atomic record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Receipt {
    backing: BackingFiles,
    claim: WriterClaim,
    resolved: Option<ResolvedTransfer>,
    prepared: Option<PreparedTransfer>,
}

/// Exclusive lease for receipt access and writer lifetime.
/// Dropping the lease unlocks its byte even if another reference to the file remains.
pub(crate) struct WriterLease {
    directory: File,
    coordinator: File,
    backing_names: [OsString; 3],
    receipt_name: OsString,
    staging_name: OsString,
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        release_handoff_byte(&self.coordinator, WRITER_LEASE_BYTE);
    }
}

/// Hold one mutation byte only for the scoped handoff operation.
struct MutationByte<'a> {
    file: &'a File,
    offset: u64,
}

impl<'a> MutationByte<'a> {
    /// Acquire the byte without waiting for another writer or checkpointer.
    fn acquire(file: &'a File, offset: u64) -> Result<Self> {
        if !unix_shared_wal_lock_byte(
            file.as_raw_fd(),
            offset,
            true,
            false,
            SharedWalLockKind::LinuxOfd,
        )? {
            return Err(LimboError::Busy);
        }
        Ok(Self { file, offset })
    }
}

impl Drop for MutationByte<'_> {
    fn drop(&mut self) {
        release_handoff_byte(self.file, self.offset);
    }
}

/// Release a handoff byte held by this exact open file description.
fn release_handoff_byte(file: &File, offset: u64) {
    if let Err(error) =
        unix_shared_wal_unlock_byte(file.as_raw_fd(), offset, SharedWalLockKind::LinuxOfd)
    {
        tracing::warn!(
            ?error,
            offset,
            "failed to unlock encrypted WAL handoff byte"
        );
    }
}

impl WriterLease {
    /// Open the existing coordinator without following a symlink or creating
    /// storage. A second open file description receives `Busy` while held.
    pub(crate) fn acquire(database: &Path) -> Result<Self> {
        let name = database.file_name().ok_or_else(|| {
            LimboError::InvalidArgument("managed WAL requires a database filename".into())
        })?;
        let path = database
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = File::from(
            fs::open(
                path,
                OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|err| os_error(err, "open WAL owner directory"))?,
        );
        let metadata = directory
            .metadata()
            .map_err(|err| io_error(err, "stat WAL owner directory"))?;
        if metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
            return Err(LimboError::InvalidArgument(
                "managed WAL requires a directory accessible only to the service user".into(),
            ));
        }
        let backing_names = [
            name.to_owned(),
            with_suffix(name, "-wal"),
            with_suffix(name, "-tshm"),
        ];
        let coordinator = open_file(&directory, &backing_names[2], OFlags::RDWR)
            .map_err(|err| io_error(err, "open managed WAL coordinator"))?;
        let initial = coordinator
            .metadata()
            .map_err(|err| io_error(err, "stat WAL coordinator"))?;
        if !initial.is_file() || initial.uid() != effective_uid() || initial.nlink() != 1 {
            return Err(invalid_backing());
        }
        if !unix_shared_wal_lock_byte(
            coordinator.as_raw_fd(),
            WRITER_LEASE_BYTE,
            true,
            false,
            SharedWalLockKind::LinuxOfd,
        )? {
            return Err(LimboError::Busy);
        }
        Ok(Self {
            directory,
            coordinator,
            backing_names,
            receipt_name: with_suffix(name, "-tshm.owner"),
            staging_name: with_suffix(name, "-tshm.owner.pending"),
        })
    }

    /// Exclude checkpoint and writer mutations on the reader's original coordinator.
    /// Both bytes are unlocked when this method returns, including on acquisition or action failure.
    pub(crate) fn with_mutation_locks<T>(
        &mut self,
        reader_coordinator: FileId,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let lock_file = open_file(&self.directory, &self.backing_names[2], OFlags::RDWR)
            .map_err(|err| io_error(err, "open managed WAL mutation locks"))?;
        let lock_metadata = lock_file
            .metadata()
            .map_err(|err| io_error(err, "stat WAL mutation locks"))?;
        let lease_metadata = self
            .coordinator
            .metadata()
            .map_err(|err| io_error(err, "stat WAL lease"))?;
        let lock_id = (lock_metadata.dev(), lock_metadata.ino());
        if !lock_metadata.is_file()
            || lock_metadata.uid() != effective_uid()
            || lock_metadata.nlink() != 1
            || lock_id != (reader_coordinator.dev, reader_coordinator.ino)
            || lock_id != (lease_metadata.dev(), lease_metadata.ino())
        {
            return Err(invalid_backing());
        }
        let _checkpoint = MutationByte::acquire(&lock_file, CHECKPOINT_LOCK_OFFSET)?;
        let _writer = MutationByte::acquire(&lock_file, WRITER_LOCK_OFFSET)?;
        action(self)
    }

    /// Explicitly initialize an existing authenticated database exactly once.
    /// Existing receipts, including unreadable receipts, cannot be replaced.
    pub(crate) fn initialize(
        &mut self,
        owner: WriterId,
        boundary: EncryptedWalWriteBoundary,
    ) -> Result<WriterClaim> {
        let backing = self.verify_backing(boundary)?;
        if let Some(existing) = self.load()? {
            let same_owner =
                existing.claim.owner == owner && existing.claim.epoch == NonZeroU64::MIN;
            if same_owner
                && existing.backing == backing
                && existing.prepared.is_none()
                && existing.resolved.is_none()
            {
                self.sync_directory()?;
                return Ok(existing.claim);
            }
            return Err(LimboError::Conflict(
                "WAL writer receipt already exists".into(),
            ));
        }
        let claim = WriterClaim {
            owner,
            epoch: NonZeroU64::MIN,
        };
        self.publish(Receipt {
            backing,
            claim,
            resolved: None,
            prepared: None,
        })?;
        Ok(claim)
    }

    /// Publish a drained owner's exact WAL boundary. While prepared, neither
    /// owner can recover an active writer without accepting or rolling back.
    pub(crate) fn prepare(
        &mut self,
        claim: WriterClaim,
        transfer: WriterTransfer,
        boundary: EncryptedWalWriteBoundary,
        before_publish: impl FnOnce(),
    ) -> Result<()> {
        let mut record = self.verified_receipt(boundary)?;
        if claim != record.claim
            || transfer.successor == claim.owner
            || record
                .resolved
                .is_some_and(|finished| finished.request.id >= transfer.id)
        {
            return Err(stale_writer());
        }
        let pending = PreparedTransfer {
            request: transfer,
            position: boundary.wal_position,
        };
        if let Some(existing) = record.prepared {
            if existing != pending {
                return Err(stale_writer());
            }
            before_publish();
            return self.sync_directory();
        }
        before_publish();
        record.prepared = Some(pending);
        self.publish(record)
    }

    /// Accept the nominated handoff after verifying the successor's own open
    /// boundary. Retrying an accepted operation returns the same writer epoch.
    pub(crate) fn accept(
        &mut self,
        previous: WriterClaim,
        transfer: WriterTransfer,
        boundary: EncryptedWalWriteBoundary,
    ) -> Result<WriterClaim> {
        let mut record = self.verified_receipt(boundary)?;
        let (claim, result) = record.require_activation(previous, transfer, boundary)?;
        if record.claim == claim && record.resolved == Some(result) && record.prepared.is_none() {
            self.sync_directory()?;
            return Ok(claim);
        }
        record.claim = claim;
        record.resolved = Some(result);
        record.prepared = None;
        self.publish(record)?;
        Ok(claim)
    }

    /// Cancel a transition started by the predecessor at the exact boundary.
    /// Cancellation is durable even if the preparation failed before publication.
    pub(crate) fn rollback(
        &mut self,
        claim: WriterClaim,
        transfer: WriterTransfer,
        boundary: EncryptedWalWriteBoundary,
    ) -> Result<()> {
        let mut record = self.verified_receipt(boundary)?;
        let result = ResolvedTransfer {
            request: transfer,
            predecessor: claim.owner,
            outcome: TransferOutcome::RolledBack,
        };
        if record.claim == claim && record.resolved == Some(result) && record.prepared.is_none() {
            return self.sync_directory();
        }
        if record.claim != claim || transfer.successor == claim.owner {
            return Err(stale_writer());
        }
        match record.prepared {
            Some(pending)
                if pending.request == transfer && pending.position == boundary.wal_position => {}
            None if record
                .resolved
                .is_none_or(|finished| finished.request.id < transfer.id) => {}
            _ => return Err(stale_writer()),
        }
        record.resolved = Some(result);
        record.prepared = None;
        self.publish(record)
    }

    /// Confirm an active claim after recovering and validating its actual WAL.
    /// Re-sync the directory before relying on a receipt left by a crash.
    pub(crate) fn verify_active(
        &self,
        claim: WriterClaim,
        boundary: EncryptedWalWriteBoundary,
    ) -> Result<()> {
        let record = self.verified_receipt(boundary)?;
        if record.claim != claim || record.prepared.is_some() {
            return Err(stale_writer());
        }
        self.sync_directory()
    }

    /// Match the still-prepared transfer and the successor's verified WAL boundary.
    /// The caller holds both mutation locks. This check only reads the receipt.
    pub(crate) fn verify_prepared(
        &self,
        previous: WriterClaim,
        request: WriterTransfer,
        boundary: EncryptedWalWriteBoundary,
    ) -> Result<()> {
        let record = self.verified_receipt(boundary)?;
        if !record.matches_prepared(previous, request, boundary.wal_position) {
            return Err(stale_writer());
        }
        Ok(())
    }

    /// Open the backing recorded for the exact active claim without creating files.
    pub(crate) fn open_current_backing(&self, claim: WriterClaim) -> Result<WritableWalBacking> {
        let receipt = self.load()?.ok_or_else(stale_writer)?;
        if receipt.claim != claim || receipt.prepared.is_some() {
            return Err(stale_writer());
        }
        let [database, wal, coordinator] = receipt.backing.0;
        let metadata = self
            .coordinator
            .metadata()
            .map_err(|err| io_error(err, "stat WAL lease"))?;
        if (metadata.dev(), metadata.ino()) != (coordinator.dev, coordinator.ino) {
            return Err(invalid_backing());
        }
        Ok(WritableWalBacking {
            database: self.open_matching_backing(&self.backing_names[0], database)?,
            wal: self.open_matching_backing(&self.backing_names[1], wal)?,
        })
    }

    /// Duplicate the original coordinator for its cold lifetime mapping.
    pub(crate) fn coordinator_file(&self) -> Result<File> {
        self.coordinator
            .try_clone()
            .map_err(|err| io_error(err, "duplicate WAL coordinator"))
    }

    /// Reopen the original backing writable once a prepared or exactly accepted
    /// receipt identifies the caller. Both mutation bytes must be held.
    pub(crate) fn open_for_activation(
        &self,
        activation: WriterActivation,
        boundary: EncryptedWalWriteBoundary,
    ) -> Result<WritableWalBacking> {
        let record = self.verified_receipt(boundary)?;
        record.require_activation(activation.previous, activation.transfer, boundary)?;
        Ok(WritableWalBacking {
            database: self.open_matching_backing(&self.backing_names[0], boundary.database)?,
            wal: self.open_matching_backing(&self.backing_names[1], boundary.wal)?,
        })
    }

    /// Check the descriptor returned by openat, independently of its pathname.
    fn open_matching_backing(&self, name: &OsString, identity: FileId) -> Result<File> {
        let file = open_file(&self.directory, name, OFlags::RDWR)
            .map_err(|err| io_error(err, "open writable WAL backing"))?;
        let stat = file
            .metadata()
            .map_err(|err| io_error(err, "stat writable WAL backing"))?;
        if !stat.is_file()
            || stat.uid() != effective_uid()
            || stat.nlink() != 1
            || stat.dev() != identity.dev
            || stat.ino() != identity.ino
        {
            return Err(invalid_backing());
        }
        Ok(file)
    }

    /// Bind the receipt to current path identities and the actual open handles
    /// returned by the WAL validation. Reject hard-linked and non-regular files.
    fn verify_backing(&self, boundary: EncryptedWalWriteBoundary) -> Result<BackingFiles> {
        let position = SharedWalCoordinationHeader::decode(&boundary.wal_position)?;
        if position.max_frame != boundary.committed_frames {
            return Err(invalid_backing());
        }
        let backing = BackingFiles::from(boundary);
        for (name, id) in self.backing_names.iter().zip(backing.0) {
            let stat = fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|err| os_error(err, "stat managed WAL backing"))?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != effective_uid()
                || stat.st_nlink != 1
                || stat.st_dev != id.dev
                || stat.st_ino != id.ino
            {
                return Err(invalid_backing());
            }
        }
        let stat = self
            .coordinator
            .metadata()
            .map_err(|err| io_error(err, "stat WAL lease"))?;
        if stat.dev() != boundary.coordinator.dev || stat.ino() != boundary.coordinator.ino {
            return Err(invalid_backing());
        }
        Ok(backing)
    }

    /// Load the existing receipt for the verified backing. Missing data never
    /// implicitly creates or authorizes a writer.
    fn verified_receipt(&self, boundary: EncryptedWalWriteBoundary) -> Result<Receipt> {
        let backing = self.verify_backing(boundary)?;
        let receipt = self.load()?.ok_or_else(stale_writer)?;
        if backing != receipt.backing {
            return Err(invalid_backing());
        }
        Ok(receipt)
    }

    /// Read one exact private record and refuse partial or malformed contents.
    fn load(&self) -> Result<Option<Receipt>> {
        let mut file = match open_file(&self.directory, &self.receipt_name, OFlags::RDONLY) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_error(err, "open WAL writer receipt")),
        };
        let stat = file
            .metadata()
            .map_err(|err| io_error(err, "stat WAL writer receipt"))?;
        if !stat.is_file()
            || stat.uid() != effective_uid()
            || stat.nlink() != 1
            || stat.mode() & 0o077 != 0
            || stat.len() != RECEIPT_BYTES as u64
        {
            return Err(invalid_receipt());
        }
        let mut bytes = [0; RECEIPT_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|err| io_error(err, "read WAL writer receipt"))?;
        Receipt::decode(&bytes).map(Some)
    }

    /// Replace the receipt by same-directory rename only after syncing the
    /// new record. Success requires the directory sync after rename.
    fn publish(&self, record: Receipt) -> Result<()> {
        match fs::unlinkat(&self.directory, &self.staging_name, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => (),
            Err(err) => return Err(os_error(err, "remove interrupted WAL receipt stage")),
        }
        let mut stage = open_file(
            &self.directory,
            &self.staging_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        )
        .map_err(|err| io_error(err, "stage WAL writer receipt"))?;
        stage
            .write_all(&record.encode())
            .map_err(|err| io_error(err, "write WAL writer receipt"))?;
        stage
            .sync_all()
            .map_err(|err| io_error(err, "sync WAL writer receipt"))?;
        fs::renameat(
            &self.directory,
            &self.staging_name,
            &self.directory,
            &self.receipt_name,
        )
        .map_err(|err| os_error(err, "publish WAL writer receipt"))?;
        self.sync_directory()
    }

    /// Synchronize publication of directory entries on the same open parent.
    fn sync_directory(&self) -> Result<()> {
        self.directory
            .sync_all()
            .map_err(|err| io_error(err, "sync WAL owner directory"))
    }
}

impl Receipt {
    /// Resolve an exact prepared request or its prior durable acceptance.
    fn require_activation(
        &self,
        previous: WriterClaim,
        transfer: WriterTransfer,
        boundary: EncryptedWalWriteBoundary,
    ) -> Result<(WriterClaim, ResolvedTransfer)> {
        let claim = WriterClaim {
            owner: transfer.successor,
            epoch: previous
                .epoch
                .checked_add(1)
                .ok_or(LimboError::IntegerOverflow)?,
        };
        let resolved = ResolvedTransfer {
            request: transfer,
            predecessor: previous.owner,
            outcome: TransferOutcome::Accepted,
        };
        let accepted =
            self.claim == claim && self.resolved == Some(resolved) && self.prepared.is_none();
        if !accepted && !self.matches_prepared(previous, transfer, boundary.wal_position) {
            return Err(stale_writer());
        }
        Ok((claim, resolved))
    }
    /// Match the exact predecessor, nominated successor, request ID, and WAL position.
    fn matches_prepared(
        &self,
        predecessor: WriterClaim,
        request: WriterTransfer,
        position: [u8; SharedWalCoordinationHeader::BYTE_LEN],
    ) -> bool {
        self.claim == predecessor && self.prepared == Some(PreparedTransfer { request, position })
    }

    /// Encode a versioned fixed-width record. Zero-valued IDs mark empty slots.
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_BYTES);
        bytes.extend(RECEIPT_MAGIC);
        bytes.extend(self.claim.epoch.get().to_le_bytes());
        bytes.extend(self.claim.owner.0.get().to_le_bytes());
        bytes.extend(
            self.resolved
                .map_or(0, |done| done.request.id.0.get())
                .to_le_bytes(),
        );
        bytes.extend(
            self.resolved
                .map_or(0, |done| done.predecessor.0.get())
                .to_le_bytes(),
        );
        bytes.extend(
            self.resolved
                .map_or(0, |done| done.request.successor.0.get())
                .to_le_bytes(),
        );
        bytes.push(self.resolved.map_or(0, |done| done.outcome as u8));
        bytes.extend(
            self.prepared
                .map_or(0, |pending| pending.request.id.0.get())
                .to_le_bytes(),
        );
        bytes.extend(
            self.prepared
                .map_or(0, |pending| pending.request.successor.0.get())
                .to_le_bytes(),
        );
        for identity in self.backing.0 {
            bytes.extend(identity.dev.to_le_bytes());
            bytes.extend(identity.ino.to_le_bytes());
        }
        bytes.extend(
            self.prepared
                .map_or([0; SharedWalCoordinationHeader::BYTE_LEN], |pending| {
                    pending.position
                }),
        );
        bytes
    }

    /// Decode only the supported version and reject inconsistent phase fields.
    fn decode(bytes: &[u8; RECEIPT_BYTES]) -> Result<Self> {
        let mut bytes = bytes.as_slice();
        if read_field(&mut bytes)? != RECEIPT_MAGIC {
            return Err(invalid_receipt());
        }
        let epoch = NonZeroU64::new(u64::from_le_bytes(read_field(&mut bytes)?))
            .ok_or_else(invalid_receipt)?;
        let owner = WriterId(
            NonZeroU128::new(u128::from_le_bytes(read_field(&mut bytes)?))
                .ok_or_else(invalid_receipt)?,
        );
        let resolved_id = read_id(&mut bytes)?.map(TransferId);
        let predecessor = read_id(&mut bytes)?.map(WriterId);
        let successor = read_id(&mut bytes)?.map(WriterId);
        let [outcome] = read_field(&mut bytes)?;
        let resolved = match (resolved_id, predecessor, successor, outcome) {
            (None, None, None, 0) if epoch == NonZeroU64::MIN => None,
            (Some(id), Some(predecessor), Some(successor), outcome) if predecessor != successor => {
                let outcome = match outcome {
                    1 if successor == owner && epoch > NonZeroU64::MIN => TransferOutcome::Accepted,
                    2 if predecessor == owner => TransferOutcome::RolledBack,
                    _ => return Err(invalid_receipt()),
                };
                Some(ResolvedTransfer {
                    request: WriterTransfer { id, successor },
                    predecessor,
                    outcome,
                })
            }
            _ => return Err(invalid_receipt()),
        };
        let pending_id = read_id(&mut bytes)?.map(TransferId);
        let pending_successor = read_id(&mut bytes)?.map(WriterId);
        let mut files = [FileId { dev: 0, ino: 0 }; 3];
        for file in &mut files {
            file.dev = u64::from_le_bytes(read_field(&mut bytes)?);
            file.ino = u64::from_le_bytes(read_field(&mut bytes)?);
        }
        let position = read_field(&mut bytes)?;
        let prepared = match (pending_id, pending_successor) {
            (None, None) if position == [0; SharedWalCoordinationHeader::BYTE_LEN] => None,
            (Some(id), Some(successor))
                if successor != owner && resolved.is_none_or(|done| done.request.id < id) =>
            {
                SharedWalCoordinationHeader::decode(&position)?;
                Some(PreparedTransfer {
                    request: WriterTransfer { id, successor },
                    position,
                })
            }
            _ => return Err(invalid_receipt()),
        };
        Ok(Self {
            backing: BackingFiles(files),
            claim: WriterClaim { owner, epoch },
            resolved,
            prepared,
        })
    }
}

/// Read a complete little-endian ID field with zero reserved for absence.
fn read_id(bytes: &mut &[u8]) -> Result<Option<NonZeroU128>> {
    Ok(NonZeroU128::new(u128::from_le_bytes(read_field(bytes)?)))
}

/// Read a field and advance the record slice only after it fits.
fn read_field<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
    let (field, remaining) = bytes.split_at_checked(N).ok_or_else(invalid_receipt)?;
    *bytes = remaining;
    field.try_into().map_err(|_| invalid_receipt())
}

/// Append a storage suffix without converting a native filename to UTF-8.
fn with_suffix(name: &std::ffi::OsStr, suffix: &str) -> OsString {
    let mut joined = name.to_owned();
    joined.push(suffix);
    joined
}

/// A normal writable open must refuse an existing managed database before
/// it can reuse a registered handle or repair the WAL and coordinator.
pub(crate) fn reject_unmanaged_open(path: &str) -> Result<()> {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| Path::new(path).to_owned());
    let receipt = with_suffix(path.as_os_str(), "-tshm.owner");
    match std::fs::symlink_metadata(receipt) {
        Ok(_) => Err(LimboError::Conflict(
            "managed WAL requires explicit writer admission".into(),
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_error(err, "inspect managed WAL receipt")),
    }
}

/// Open a receipt or coordinator under the trusted directory descriptor.
fn open_file(directory: &File, name: &OsString, flags: OFlags) -> std::io::Result<File> {
    fs::openat(
        directory,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(Error::from)
}

/// Effective service identity used for native file access checks.
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Preserve system I/O error classification when converting from `rustix`.
fn os_error(err: rustix::io::Errno, operation: &'static str) -> LimboError {
    io_error(Error::from(err), operation)
}

fn invalid_receipt() -> LimboError {
    LimboError::Corrupt("invalid managed WAL writer receipt".into())
}

fn invalid_backing() -> LimboError {
    LimboError::InvalidArgument("managed WAL does not name the original private backing".into())
}

fn stale_writer() -> LimboError {
    LimboError::Conflict("managed WAL writer claim or transfer is stale".into())
}

#[cfg(all(test, feature = "fs"))]
mod tests {
    use super::*;
    use crate::io::{OpenFlags, PlatformIO};
    use crate::sync::Arc;
    use crate::{Database, DatabaseOpts, EncryptionOpts, OpenOptions, SqliteDialect};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    const DB_NAME: &str = "handoff.db";
    const CHILD_DIRECTORY: &str = "TURSO_WAL_WRITER_LEASE_TEST_DIR";

    #[test]
    fn managed_predecessor_drains_and_rolls_back_or_stays_fenced() {
        let directory = private_directory();
        let path = directory.path().join(DB_NAME);
        let (db, _) = encrypted_boundary(&path);
        let a = db
            .enroll_encrypted_wal_writer(owner(1))
            .expect("enroll existing writer");
        let conn = db.connect().expect("writer connection");
        assert!(db
            .prepare_encrypted_wal_handoff(transfer(1, a.owner))
            .is_err());
        conn.execute("INSERT INTO records VALUES (40)")
            .expect("invalid request leaves writer active");

        let unpublished = transfer(1, owner(2));
        let staging = directory.path().join("handoff.db-tshm.owner.pending");
        std::fs::create_dir(&staging).expect("stage publication failure");
        assert!(db.prepare_encrypted_wal_handoff(unpublished).is_err());
        assert!(matches!(
            conn.execute("INSERT INTO records VALUES (41)"),
            Err(LimboError::Busy)
        ));
        std::fs::remove_dir(staging).expect("clear failed staging path");
        db.rollback_encrypted_wal_handoff(unpublished)
            .expect("cancel the unpublished request durably");
        assert!(db.rollback_encrypted_wal_handoff(unpublished).is_ok());
        assert!(db.prepare_encrypted_wal_handoff(unpublished).is_err());

        let first = transfer(2, owner(2));
        conn.execute("BEGIN IMMEDIATE").expect("begin transaction");
        conn.execute("INSERT INTO records VALUES (43)")
            .expect("write inside transaction");
        assert!(matches!(
            db.prepare_encrypted_wal_handoff(first),
            Err(LimboError::Busy)
        ));
        conn.execute("COMMIT")
            .expect("finish the eligible transaction");
        let initial = db
            .prepare_encrypted_wal_handoff(first)
            .expect("drained A prepares");
        assert_eq!(
            db.prepare_encrypted_wal_handoff(first)
                .expect("same prepared boundary"),
            initial
        );
        assert!(matches!(
            conn.execute("INSERT INTO records VALUES (44)"),
            Err(LimboError::Busy)
        ));
        assert!(matches!(
            conn.checkpoint(crate::CheckpointMode::Truncate {
                upper_bound_inclusive: None
            }),
            Err(LimboError::Busy)
        ));
        assert!(conn.cacheflush().is_err());
        assert!(db.with_encrypted_wal_write_boundary(|_| ()).is_err());
        assert!(Database::check_handoff_open(path.to_str().expect("fixture path"), false).is_err());
        assert!(Database::check_handoff_open(path.to_str().expect("fixture path"), true).is_ok());
        db.rollback_encrypted_wal_handoff(first)
            .expect("restore A before acceptance");
        assert!(db.rollback_encrypted_wal_handoff(first).is_ok());
        conn.execute("INSERT INTO records VALUES (45)")
            .expect("A writes after rollback");
        assert!(
            conn.checkpoint(crate::CheckpointMode::Passive {
                upper_bound_inclusive: None
            })
            .expect("active writer can checkpoint pending frames")
            .wal_checkpoint_backfilled
                > 0
        );

        let second = transfer(3, owner(2));
        let boundary = db
            .prepare_encrypted_wal_handoff(second)
            .expect("prepare another request");
        let mut b = WriterLease::acquire(&path).expect("take released lease");
        assert_eq!(
            b.accept(a, second, boundary).expect("accept as B").owner,
            owner(2)
        );
        drop(b);
        assert!(db.rollback_encrypted_wal_handoff(second).is_err());
        assert!(matches!(
            conn.execute("INSERT INTO records VALUES (46)"),
            Err(LimboError::Busy)
        ));
        let wal_path = directory.path().join("handoff.db-wal");
        let wal_length = std::fs::metadata(&wal_path)
            .expect("wal before close")
            .len();
        assert!(wal_length > 0);
        let new_conn = db
            .connect()
            .expect("A can still read with a new connection");
        assert!(new_conn.query("SELECT i FROM records").is_ok());
        new_conn.close().expect("close new reader");
        conn.close()
            .expect("fenced last close releases local resources");
        assert_eq!(
            std::fs::metadata(wal_path)
                .expect("retained WAL after close")
                .len(),
            wal_length
        );
    }

    #[test]
    fn prepared_receipt_survives_lease_process_exit_and_accepts_once() {
        let directory = private_directory();
        let path = directory.path().join(DB_NAME);
        let (_db, boundary) = encrypted_boundary(&path);
        let mut lease = WriterLease::acquire(&path).expect("acquire predecessor lease");
        let a = lease.initialize(owner(1), boundary).expect("initialize A");
        let transfer = transfer(3, owner(2));
        lease
            .prepare(a, transfer, boundary, || {})
            .expect("prepare A to B");
        assert!(lease.prepare(a, transfer, boundary, || {}).is_ok());
        assert!(lease.verify_active(a, boundary).is_err());
        assert!(matches!(WriterLease::acquire(&path), Err(LimboError::Busy)));
        drop(lease);

        let mut child = LeaseChild(
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "storage::encrypted_wal_handoff::tests::lease_process",
                    "--ignored",
                ])
                .env(CHILD_DIRECTORY, directory.path())
                .spawn()
                .expect("start independent lease holder"),
        );
        let started = Instant::now();
        while !directory.path().join("lease-ready").exists() {
            assert!(started.elapsed() < Duration::from_secs(10));
            assert!(child.0.try_wait().expect("poll lease holder").is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(WriterLease::acquire(&path), Err(LimboError::Busy)));
        child.0.kill().expect("lose lease process");
        assert!(!child.0.wait().expect("collect lease process").success());

        let mut successor = WriterLease::acquire(&path).expect("take released lease");
        let wrong = WriterTransfer {
            successor: owner(4),
            ..transfer
        };
        assert!(successor.accept(a, wrong, boundary).is_err());
        let mut drifted = boundary;
        let mut position =
            SharedWalCoordinationHeader::decode(&boundary.wal_position).expect("current position");
        position.checkpoint_epoch += 1;
        drifted.wal_position = position.encode();
        assert!(successor.accept(a, transfer, drifted).is_err());
        let b = successor
            .with_mutation_locks(boundary.coordinator, |lease| {
                assert!(lease.verify_prepared(a, wrong, boundary).is_err());
                assert!(lease.verify_prepared(a, transfer, drifted).is_err());
                lease.verify_prepared(a, transfer, boundary)?;
                let accepted = lease.accept(a, transfer, boundary)?;
                assert!(lease.verify_prepared(a, transfer, boundary).is_err());
                Ok(accepted)
            })
            .expect("accept durable receipt");
        assert_eq!(b.owner, owner(2));
        assert_eq!(b.epoch.get(), 2);
        drop(successor);

        let mut retry = WriterLease::acquire(&path).expect("retry after losing acknowledgement");
        assert_eq!(
            retry
                .accept(a, transfer, boundary)
                .expect("same accepted result"),
            b
        );
        assert!(retry.verify_active(b, boundary).is_ok());
        assert!(retry
            .accept(
                WriterClaim {
                    owner: owner(4),
                    ..a
                },
                transfer,
                boundary
            )
            .is_err());
        assert!(retry.verify_active(a, boundary).is_err());
        assert!(retry.rollback(a, transfer, boundary).is_err());
        assert!(retry.prepare(a, transfer, boundary, || {}).is_err());
    }

    #[test]
    fn handoff_bytes_unlock_while_a_descriptor_copy_is_open() {
        let directory = private_directory();
        let path = directory.path().join(DB_NAME);
        let (_db, _) = encrypted_boundary(&path);
        let lease = WriterLease::acquire(&path).expect("acquire writer lease");
        let copy = lease
            .coordinator
            .try_clone()
            .expect("retain same description");
        assert!(matches!(WriterLease::acquire(&path), Err(LimboError::Busy)));
        drop(lease);
        let successor = WriterLease::acquire(&path).expect("reacquire after logical release");

        let checkpoint = MutationByte::acquire(&copy, CHECKPOINT_LOCK_OFFSET).expect("lock byte");
        assert!(matches!(
            MutationByte::acquire(&successor.coordinator, CHECKPOINT_LOCK_OFFSET),
            Err(LimboError::Busy)
        ));
        drop(checkpoint);
        let _checkpoint = MutationByte::acquire(&successor.coordinator, CHECKPOINT_LOCK_OFFSET)
            .expect("reacquire with original description still open");
    }

    #[test]
    fn mutation_locks_release_on_contention_and_callback_error() {
        let directory = private_directory();
        let path = directory.path().join(DB_NAME);
        let (_db, boundary) = encrypted_boundary(&path);
        let mut lease = WriterLease::acquire(&path).expect("acquire writer lease");
        let coordinator = directory.path().join(&lease.backing_names[2]);
        let before = std::fs::read(&coordinator).expect("read coordinator");
        let open_contender = || File::options().read(true).write(true).open(&coordinator);
        let try_lock = |file: &File, offset| {
            unix_shared_wal_lock_byte(
                file.as_raw_fd(),
                offset,
                true,
                false,
                SharedWalLockKind::LinuxOfd,
            )
            .expect("try mutation lock")
        };

        let contender = open_contender().expect("open competing description");
        assert!(try_lock(&contender, WRITER_LOCK_OFFSET));
        let result: Result<()> = lease.with_mutation_locks(boundary.coordinator, |_| {
            panic!("entered with a competing writer")
        });
        assert!(matches!(result, Err(LimboError::Busy)));
        assert!(try_lock(&contender, CHECKPOINT_LOCK_OFFSET));
        drop(contender);

        let wrong_id = FileId {
            ino: boundary.coordinator.ino ^ 1,
            ..boundary.coordinator
        };
        let result: Result<()> =
            lease.with_mutation_locks(wrong_id, |_| panic!("entered with a different coordinator"));
        assert!(matches!(result, Err(LimboError::InvalidArgument(_))));

        let contender = open_contender().expect("open competing description");
        let result: Result<()> = lease.with_mutation_locks(boundary.coordinator, |_| {
            assert!(!try_lock(&contender, CHECKPOINT_LOCK_OFFSET));
            assert!(!try_lock(&contender, WRITER_LOCK_OFFSET));
            Err(LimboError::ReadOnly)
        });
        assert!(matches!(result, Err(LimboError::ReadOnly)));
        assert!(try_lock(&contender, CHECKPOINT_LOCK_OFFSET));
        assert!(try_lock(&contender, WRITER_LOCK_OFFSET));
        assert_eq!(
            before,
            std::fs::read(&coordinator).expect("unchanged coordinator")
        );
    }

    #[test]
    fn rollback_preserves_the_current_epoch_and_ignores_partial_publication() {
        let directory = private_directory();
        let path = directory.path().join(DB_NAME);
        let (_db, boundary) = encrypted_boundary(&path);
        let mut lease = WriterLease::acquire(&path).expect("acquire lease");
        let a = lease.initialize(owner(1), boundary).expect("initialize A");
        let request = transfer(3, owner(2));
        let staging = directory.path().join(&lease.staging_name);
        std::fs::write(&staging, b"incomplete record").expect("stage interrupted write");
        assert!(lease.verify_active(a, boundary).is_ok());
        assert!(lease.accept(a, request, boundary).is_err());
        lease
            .prepare(a, request, boundary, || {})
            .expect("publish over abandoned stage");
        assert!(!staging.exists());
        lease
            .rollback(a, request, boundary)
            .expect("roll back before acceptance");
        assert!(lease.rollback(a, request, boundary).is_ok());
        assert!(lease.verify_active(a, boundary).is_ok());
        assert!(lease.accept(a, request, boundary).is_err());
        assert!(lease.prepare(a, request, boundary, || {}).is_err());
        let next = transfer(4, owner(2));
        lease
            .prepare(a, next, boundary, || {})
            .expect("prepare a new transfer");
        lease
            .rollback(a, next, boundary)
            .expect("roll back a new transfer");
        assert!(lease.prepare(a, request, boundary, || {}).is_err());

        let receipt = directory.path().join(&lease.receipt_name);
        std::fs::write(&receipt, b"malformed record").expect("damage fixture receipt");
        assert!(lease.verify_active(a, boundary).is_err());
        assert!(lease.initialize(owner(1), boundary).is_err());
        assert_eq!(
            std::fs::read(receipt).expect("unchanged damaged receipt"),
            b"malformed record"
        );
    }

    #[test]
    fn receipt_refuses_nonprivate_directory_and_replaced_backing() {
        let directory = private_directory();
        let path = directory.path().join(DB_NAME);
        let (_db, boundary) = encrypted_boundary(&path);
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750))
            .expect("relax fixture permissions");
        assert!(matches!(
            WriterLease::acquire(&path),
            Err(LimboError::InvalidArgument(_))
        ));
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore fixture permissions");
        let mut lease = WriterLease::acquire(&path).expect("acquire private lease");
        let a = lease.initialize(owner(1), boundary).expect("initialize A");
        let copy = directory.path().join("original.db");
        std::fs::rename(&path, &copy).expect("move fixture database");
        std::os::unix::fs::symlink(&copy, &path).expect("replace path with symlink");
        assert!(lease.verify_active(a, boundary).is_err());
        std::fs::remove_file(&path).expect("remove fixture link");
        std::fs::rename(&copy, &path).expect("restore original backing");
        assert!(lease.verify_active(a, boundary).is_ok());
    }

    #[test]
    #[ignore = "launched by the cross-process lease test"]
    fn lease_process() {
        let dir = std::env::var_os(CHILD_DIRECTORY).expect("lease fixture directory");
        let dir = Path::new(&dir);
        let _lease = WriterLease::acquire(&dir.join(DB_NAME)).expect("acquire child lease");
        std::fs::write(dir.join("lease-ready"), b"").expect("signal lease acquisition");
        std::thread::park_timeout(Duration::from_secs(15));
    }

    struct LeaseChild(Child);

    impl Drop for LeaseChild {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    fn private_directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("private receipt fixture");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict fixture directory");
        dir
    }

    fn encrypted_boundary(path: &Path) -> (Arc<Database>, EncryptedWalWriteBoundary) {
        let encryption = EncryptionOpts {
            cipher: "aes256gcm".into(),
            hexkey: "42".repeat(32),
        };
        let db = Database::open(
            Arc::new(PlatformIO::new().expect("native IO")),
            path.to_str().expect("UTF-8 test path"),
            OpenOptions::new(Arc::new(SqliteDialect))
                .flags(OpenFlags::Create)
                .db_opts(
                    DatabaseOpts::new()
                        .with_encryption(true)
                        .with_multiprocess_wal(true),
                )
                .encryption(encryption),
        )
        .expect("open encrypted fixture");
        let conn = db.connect().expect("open test writer");
        conn.execute("CREATE TABLE records(i INTEGER)")
            .expect("write schema");
        conn.execute("INSERT INTO records VALUES (42)")
            .expect("commit fixture");
        let boundary = db
            .with_encrypted_wal_write_boundary(|boundary| boundary)
            .expect("sync committed boundary");
        (db, boundary)
    }

    fn owner(id: u128) -> WriterId {
        WriterId(NonZeroU128::new(id).expect("nonzero writer identity"))
    }

    fn transfer(id: u128, successor: WriterId) -> WriterTransfer {
        WriterTransfer {
            id: TransferId(NonZeroU128::new(id).expect("nonzero transfer identity")),
            successor,
        }
    }
}
