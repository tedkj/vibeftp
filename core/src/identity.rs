//! Which local file a name stands for. A question the user answered is about the item they saw:
//! before a delete or a replace acts on its name, the item there must still be that one, not
//! another program's file that took the name while the question was open (VIBEWARE.md
//! "Identity, not names"; review SOL-FTP-2).

use std::io;
use std::path::Path;

/// A local file or folder as it was when the user was asked about it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LocalId {
    /// (volume serial, 128-bit file id) from `FILE_ID_INFO`. `None` where the file system gives
    /// none: a zero id or serial is unknown, never "the same".
    pub id: Option<(u64, u128)>,
    pub is_dir: bool,
    /// A link itself (a symlink, junction or mount point: a name-surrogate reparse point), never
    /// what it points at. Other reparse points (OneDrive and other cloud placeholders,
    /// deduplicated files) are the files and folders they look like (review R-SOL-3).
    pub reparse: bool,
    pub size: u64,
    /// Last write time, Unix ms.
    pub modified: u64,
}

impl LocalId {
    /// Whether `now` is the item this one describes. Without ids (FAT, some network file
    /// systems): the same kind, size and modified time, which another file can match.
    pub fn same(&self, now: &LocalId) -> bool {
        if self.is_dir != now.is_dir || self.reparse != now.reparse {
            return false;
        }
        match (self.id, now.id) {
            (Some(a), Some(b)) => a == b,
            _ => self.size == now.size && self.modified == now.modified,
        }
    }

    /// `same` for a folder this delete has just emptied: its modified time is ours now, so
    /// without ids only its kind is left to compare (while it was being emptied it was held
    /// open so that it could not be renamed away and replaced).
    fn same_emptied(&self, now: &LocalId) -> bool {
        match (self.id, now.id) {
            (Some(_), Some(_)) => self.same(now),
            _ => self.is_dir == now.is_dir && self.reparse == now.reparse,
        }
    }
}

/// Said when the item at the name is not the one the user was asked about.
pub const CHANGED: &str = "it changed since you confirmed (another item has that name now)";

/// The identity of what `path` names now (a link itself, not its target).
pub fn of(path: &Path) -> io::Result<LocalId> {
    imp::of(path, false)
}

/// The identity of the file a write to `path` lands in (through a link, its target).
pub fn of_target(path: &Path) -> io::Result<LocalId> {
    imp::of(path, true)
}

/// The identity of an open file: the very file a write through this handle lands in.
#[cfg(windows)]
pub fn of_file(f: &impl std::os::windows::io::AsRawHandle) -> io::Result<LocalId> {
    imp::of_handle(f.as_raw_handle())
}
#[cfg(not(windows))]
pub fn of_file(f: &std::fs::File) -> io::Result<LocalId> {
    imp::of_meta(&f.metadata()?)
}

/// Delete the file, link or empty folder at `path` if it is still `seen`. The identity is read
/// from the handle the delete goes through, so what is checked is what goes. `Ok(Some(why))`:
/// left alone. A read-only file is refused, as `remove_file` refuses it.
pub fn remove_one(path: &Path, seen: &LocalId) -> io::Result<Option<&'static str>> {
    imp::remove_if(path, false, |now| seen.same(now))
}

/// Delete the folder at `path` and everything in it if it is still `seen`. The folder is held
/// open without delete sharing while its contents go, so nobody can rename it away and put
/// another one in its place meanwhile; a link or junction inside is removed, never followed.
pub fn remove_tree(path: &Path, seen: &LocalId) -> io::Result<Option<&'static str>> {
    {
        let Some(pin) = imp::pin(path, seen)? else { return Ok(Some(CHANGED)) };
        for child in std::fs::read_dir(path)? {
            let child = child?.path();
            let m = std::fs::symlink_metadata(&child)?;
            if m.is_dir() && !m.file_type().is_symlink() {
                std::fs::remove_dir_all(&child)?;
            } else {
                // As `remove_dir_all` takes them: read-only files inside go too.
                imp::remove_if(&child, true, |_| true)?;
            }
        }
        drop(pin);
    }
    // A read-only folder goes too, as it did through `remove_dir_all`.
    imp::remove_if(path, true, |now| seen.same_emptied(now))
}

#[cfg(windows)]
mod imp {
    use super::LocalId;
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::Path;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    /// BY_HANDLE_FILE_INFORMATION
    #[repr(C)]
    struct ByHandle {
        attributes: u32,
        created: FileTime,
        accessed: FileTime,
        written: FileTime,
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    /// FILE_ID_INFO
    #[repr(C)]
    struct FileIdInfo {
        volume: u64,
        id: [u8; 16],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(name: *const u16, access: u32, share: u32, security: *const c_void, disposition: u32, flags: u32, template: *mut c_void) -> *mut c_void;
        fn GetFileInformationByHandle(h: *mut c_void, info: *mut ByHandle) -> i32;
        fn GetFileInformationByHandleEx(h: *mut c_void, class: i32, info: *mut c_void, size: u32) -> i32;
        fn SetFileInformationByHandle(h: *mut c_void, class: i32, info: *const c_void, size: u32) -> i32;
    }

    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const DELETE: u32 = 0x0001_0000;
    const SHARE_READ: u32 = 0x1;
    const SHARE_WRITE: u32 = 0x2;
    const SHARE_DELETE: u32 = 0x4;
    const OPEN_EXISTING: u32 = 3;
    // Folders open only with backup semantics; a link opens as itself, never its target.
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
    const FILE_ID_INFO_CLASS: i32 = 18;
    const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
    const FILE_DISPOSITION_INFO_EX_CLASS: i32 = 21;
    // DELETE | POSIX_SEMANTICS: the name goes at once, as DeleteFileW does on current Windows.
    const DISPOSE: u32 = 0x1 | 0x2;
    const IGNORE_READONLY: u32 = 0x10;

    fn open(path: &Path, access: u32, share: u32) -> io::Result<OwnedHandle> {
        open_as(path, access, share, false)
    }

    fn open_as(path: &Path, access: u32, share: u32, follow: bool) -> io::Result<OwnedHandle> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let flags = BACKUP_SEMANTICS | if follow { 0 } else { OPEN_REPARSE_POINT };
        // SAFETY: a NUL-terminated path; no security attributes or template.
        let h = unsafe { CreateFileW(wide.as_ptr(), access, share, std::ptr::null(), OPEN_EXISTING, flags, std::ptr::null_mut()) };
        if h as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a handle CreateFileW just opened, owned from here on.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    /// FILE_ATTRIBUTE_TAG_INFO
    #[repr(C)]
    struct TagInfo {
        attributes: u32,
        tag: u32,
    }

    /// Whether a reparse tag makes the item a link (`IsReparseTagNameSurrogate`, as std's
    /// `is_symlink`): symlinks, junctions, mount points, WSL links. Cloud placeholders and the
    /// like are not.
    pub fn is_link_tag(tag: u32) -> bool {
        tag & 0x2000_0000 != 0
    }

    pub fn of_handle(h: RawHandle) -> io::Result<LocalId> {
        // SAFETY: the structs are plain data of the sizes passed, written by the calls.
        let mut info: ByHandle = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let reparse = info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && {
            let mut t: TagInfo = unsafe { std::mem::zeroed() };
            if unsafe { GetFileInformationByHandleEx(h, FILE_ATTRIBUTE_TAG_INFO_CLASS, &mut t as *mut _ as *mut c_void, size_of::<TagInfo>() as u32) } == 0 {
                return Err(io::Error::last_os_error());
            }
            is_link_tag(t.tag)
        };
        let mut fid: FileIdInfo = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandleEx(h, FILE_ID_INFO_CLASS, &mut fid as *mut _ as *mut c_void, size_of::<FileIdInfo>() as u32) };
        let file = u128::from_le_bytes(fid.id);
        let id = (ok != 0 && fid.volume != 0 && file != 0).then_some((fid.volume, file));
        let written = ((info.written.high as u64) << 32) | info.written.low as u64;
        Ok(LocalId {
            id,
            is_dir: info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            reparse,
            size: ((info.size_high as u64) << 32) | info.size_low as u64,
            // FILETIME counts 100 ns from 1601.
            modified: written.saturating_sub(116_444_736_000_000_000) / 10_000,
        })
    }

    pub fn of(path: &Path, follow: bool) -> io::Result<LocalId> {
        let h = open_as(path, FILE_READ_ATTRIBUTES, SHARE_READ | SHARE_WRITE | SHARE_DELETE, follow)?;
        of_handle(h.as_raw_handle())
    }

    /// The folder held open without delete sharing (it cannot be renamed or deleted while the
    /// handle lives), or `None` when it is not `seen` any more.
    pub fn pin(path: &Path, seen: &LocalId) -> io::Result<Option<OwnedHandle>> {
        let h = open(path, FILE_READ_ATTRIBUTES, SHARE_READ | SHARE_WRITE)?;
        Ok(seen.same(&of_handle(h.as_raw_handle())?).then_some(h))
    }

    pub fn remove_if(path: &Path, readonly_too: bool, keep: impl Fn(&LocalId) -> bool) -> io::Result<Option<&'static str>> {
        let h = open(path, DELETE | FILE_READ_ATTRIBUTES, SHARE_READ | SHARE_WRITE | SHARE_DELETE)?;
        let raw = h.as_raw_handle();
        if !keep(&of_handle(raw)?) {
            return Ok(Some(super::CHANGED));
        }
        let flags: u32 = DISPOSE | if readonly_too { IGNORE_READONLY } else { 0 };
        // SAFETY: a live handle opened with DELETE access; the infos are of the sizes passed.
        if unsafe { SetFileInformationByHandle(raw, FILE_DISPOSITION_INFO_EX_CLASS, &flags as *const u32 as *const c_void, 4) } == 0 {
            // FAT and Windows before 10 1709 only know the classic flag.
            let classic: u8 = 1;
            if unsafe { SetFileInformationByHandle(raw, FILE_DISPOSITION_INFO_CLASS, &classic as *const u8 as *const c_void, 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(None)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::LocalId;
    use crate::types::millis;
    use std::io;
    use std::path::Path;

    pub fn of_meta(m: &std::fs::Metadata) -> io::Result<LocalId> {
        use std::os::unix::fs::MetadataExt;
        Ok(LocalId {
            id: Some((m.dev(), m.ino() as u128)),
            is_dir: m.is_dir(),
            reparse: m.file_type().is_symlink(),
            size: m.len(),
            modified: m.modified().map(millis).unwrap_or(0),
        })
    }

    pub fn of(path: &Path, follow: bool) -> io::Result<LocalId> {
        of_meta(&if follow { std::fs::metadata(path)? } else { std::fs::symlink_metadata(path)? })
    }

    pub fn pin(path: &Path, seen: &LocalId) -> io::Result<Option<()>> {
        Ok(seen.same(&of(path, false)?).then_some(()))
    }

    pub fn remove_if(path: &Path, _readonly_too: bool, keep: impl Fn(&LocalId) -> bool) -> io::Result<Option<&'static str>> {
        let now = of(path, false)?;
        if !keep(&now) {
            return Ok(Some(super::CHANGED));
        }
        if now.is_dir && !now.reparse { std::fs::remove_dir(path)? } else { std::fs::remove_file(path)? }
        Ok(None)
    }
}
