//! Minisign signing for releases with the VibeWare release key
//! (`%USERPROFILE%\.vibeware\release.key`, made by `keygen`: a minisign secret key,
//! scrypt-encrypted), checked by `minisign-verify` in the app's updater.
//!
//! The trusted comment is signed together with the file and carries what the updater insists
//! on: `timestamp:<unix>\tfile:<file name>\tversion:<version>`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use blake2::{Blake2b256, Blake2b512, Digest};
use ed25519_dalek::{Signer, SigningKey};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct SecretKey {
    keynum: [u8; 8],
    key: SigningKey,
}

fn err(m: &str) -> String {
    m.to_string()
}

/// The scrypt cost written into a new secret key file, as minisign's opslimit and memlimit.
#[derive(Clone, Copy, Debug)]
pub struct Kdf {
    pub ops: u64,
    pub mem: u64,
}

/// minisign's own choice for a new key (libsodium's "sensitive" limits: scrypt N = 2^20, r = 8,
/// p = 1, 1 GiB for a moment at every signing). A release key is worth the wait.
pub const KDF: Kdf = Kdf { ops: 33_554_432, mem: 1_073_741_824 };

/// The key files `keygen` writes into its folder.
pub const KEY_FILE: &str = "release.key";
pub const PUB_FILE: &str = "release.key.pub";

/// The key id as minisign prints it: the key number, read as a little-endian u64, in hex.
pub fn key_id(keynum: &[u8; 8]) -> String {
    format!("{:016X}", u64::from_le_bytes(*keynum))
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| format!("the system's random source failed: {e}"))?;
    Ok(b)
}

/// The scrypt stream that encrypts a secret key's 104-byte box.
fn kdf_stream(password: &str, salt: &[u8], ops: u64, mem: u64) -> Result<[u8; 104], String> {
    let (log_n, r, p) = pick_params(ops, mem);
    let params = scrypt::Params::new(log_n, r, p).map_err(|_| err("bad scrypt parameters"))?;
    let mut stream = [0u8; 104];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut stream).map_err(|_| err("scrypt failed"))?;
    Ok(stream)
}

/// BLAKE2b-256 over the algorithm, key number and secret key: minisign's check that the password
/// was right.
fn checksum(keynum: &[u8], sk: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(b"Ed");
    h.update(keynum);
    h.update(sk);
    h.finalize().into()
}

impl SecretKey {
    /// A deterministic key for tests (never for releases).
    pub fn from_seed(seed: [u8; 32], keynum: [u8; 8]) -> SecretKey {
        SecretKey { keynum, key: SigningKey::from_bytes(&seed) }
    }

    /// A new key from the system's random source.
    pub fn generate() -> Result<SecretKey, String> {
        Ok(SecretKey::from_seed(random()?, random()?))
    }

    /// The key id minisign prints for this key.
    pub fn key_id(&self) -> String {
        key_id(&self.keynum)
    }

    /// The secret key file: minisign's text, the key encrypted under `password` with a fresh salt.
    pub fn encode(&self, password: &str, kdf: Kdf) -> Result<String, String> {
        let salt: [u8; 32] = random()?;
        let sk = self.key.to_keypair_bytes();
        let mut box_ = Vec::with_capacity(104);
        box_.extend_from_slice(&self.keynum);
        box_.extend_from_slice(&sk);
        box_.extend_from_slice(&checksum(&self.keynum, &sk));
        for (x, s) in box_.iter_mut().zip(kdf_stream(password, &salt, kdf.ops, kdf.mem)?) {
            *x ^= s;
        }
        let mut b = Vec::with_capacity(158);
        b.extend_from_slice(b"EdScB2");
        b.extend_from_slice(&salt);
        b.extend_from_slice(&kdf.ops.to_le_bytes());
        b.extend_from_slice(&kdf.mem.to_le_bytes());
        b.extend_from_slice(&box_);
        Ok(format!("untrusted comment: minisign encrypted secret key\n{}\n", B64.encode(b)))
    }

    /// The public key file, as minisign writes it.
    pub fn public_key_file(&self) -> String {
        format!("untrusted comment: minisign public key {}\n{}\n", self.key_id(), self.public_key())
    }

    /// Read a minisign secret key file.
    pub fn decode(text: &str, password: &str) -> Result<SecretKey, String> {
        if !text.trim_start().starts_with("untrusted comment:") {
            return Err(err("not a minisign secret key file"));
        }
        let line = text.trim_start().lines().nth(1).ok_or_else(|| err("the key file has no key line"))?;
        let b = B64.decode(line.trim()).map_err(|_| err("the key line is not base64"))?;
        if b.len() != 158 || &b[0..2] != b"Ed" || &b[4..6] != b"B2" {
            return Err(err("not an Ed25519 minisign secret key"));
        }
        let mut box_ = [0u8; 104];
        box_.copy_from_slice(&b[54..158]);
        match &b[2..4] {
            b"Sc" => {
                let ops = u64::from_le_bytes(b[38..46].try_into().unwrap());
                let mem = u64::from_le_bytes(b[46..54].try_into().unwrap());
                for (x, s) in box_.iter_mut().zip(kdf_stream(password, &b[6..38], ops, mem)?) {
                    *x ^= s;
                }
            }
            [0, 0] => {}
            _ => return Err(err("unknown key encryption")),
        }
        let (keynum, rest) = box_.split_at(8);
        let (sk, chk) = rest.split_at(64);
        if checksum(keynum, sk) != chk {
            return Err(err("wrong password for the signing key"));
        }
        let key = SigningKey::from_keypair_bytes(sk.try_into().unwrap()).map_err(|_| err("the secret and public halves disagree"))?;
        Ok(SecretKey { keynum: keynum.try_into().unwrap(), key })
    }

    /// The public key line (`RW...`), as minisign prints it and the app compiles in.
    pub fn public_key(&self) -> String {
        let mut b = Vec::with_capacity(42);
        b.extend_from_slice(b"Ed");
        b.extend_from_slice(&self.keynum);
        b.extend_from_slice(self.key.verifying_key().as_bytes());
        B64.encode(b)
    }

    /// A prehashed ("ED") minisign signature of `data` with this trusted comment, as the text of
    /// a .sig file.
    pub fn sign(&self, data: &[u8], trusted_comment: &str) -> String {
        assert!(!trusted_comment.contains('\n'), "a trusted comment is one line");
        let hash = Blake2b512::digest(data);
        let sig = self.key.sign(&hash).to_bytes();
        let mut line = Vec::with_capacity(74);
        line.extend_from_slice(b"ED");
        line.extend_from_slice(&self.keynum);
        line.extend_from_slice(&sig);
        let mut global = sig.to_vec();
        global.extend_from_slice(trusted_comment.as_bytes());
        let global = self.key.sign(&global).to_bytes();
        format!(
            "untrusted comment: signature from VibeFTP's release key\n{}\ntrusted comment: {}\n{}\n",
            B64.encode(line),
            trusted_comment,
            B64.encode(global)
        )
    }
}

/// Make a new key pair and write `release.key` (encrypted under `password`, which may not be
/// empty) and `release.key.pub` into `dir`. Refuses when either file is already there: a key is
/// never overwritten.
pub fn keygen(dir: &Path, password: &str, kdf: Kdf) -> Result<SecretKey, String> {
    if password.is_empty() {
        return Err(err("refusing an empty password: the key file would be readable by anyone who gets it"));
    }
    let (key_path, pub_path) = (dir.join(KEY_FILE), dir.join(PUB_FILE));
    for p in [&key_path, &pub_path] {
        if p.symlink_metadata().is_ok() {
            return Err(format!("{} already exists; a key is never overwritten", p.display()));
        }
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let key = SecretKey::generate()?;
    let write_new = |p: &Path, text: &str| -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(p).map_err(|e| format!("{}: {e}", p.display()))?;
        f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", p.display()))
    };
    write_new(&key_path, &key.encode(password, kdf)?)?;
    if let Err(e) = write_new(&pub_path, &key.public_key_file()) {
        // Ours, just made: a secret key without its public half is not left behind.
        let _ = std::fs::remove_file(&key_path);
        return Err(e);
    }
    Ok(key)
}

/// What the updater requires of a release's trusted comment.
pub fn trusted_comment(timestamp: u64, file: &str, version: &str) -> String {
    format!("timestamp:{timestamp}\tfile:{file}\tversion:{version}")
}

/// The hosts the updater fetches releases from, over https on port 443 only, and the largest
/// latest.json it reads (`Policy::release` in app/src/updater.rs; app/tests/updater.rs holds
/// the two copies to the same values).
pub const RELEASE_HOSTS: [&str; 3] = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
pub const MAX_MANIFEST: usize = 64 * 1024;

/// `Policy::allowed` for a release URL: https, no user or password, the default port (or 443
/// spelled out), one of the release hosts.
fn url_ok(url: &str) -> bool {
    let Some(rest) = url.get(..8).filter(|s| s.eq_ignore_ascii_case("https://")).map(|_| &url[8..]) else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = authority.rsplit_once(':').map_or((authority, None), |(h, p)| (h, Some(p)));
    !authority.contains('@') && port.is_none_or(|p| p == "443") && RELEASE_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(host))
}

/// What the updater will accept, checked before anything is signed: a version it can read (as
/// written, no leading `v`: the updater strips one from the manifest but not from the signed
/// comment), an installer name it would save, and a URL it would fetch that ends in that name.
pub fn check_release(version: &str, file: &str, url: &str) -> Result<(), String> {
    if version.starts_with('v') {
        return Err(format!("--version {version}: without the leading v (the updater compares it with the signed version)"));
    }
    if !version_ok(version) {
        return Err(format!("--version {version}: not a version the updater reads (x.y.z, optional -pre and +build)"));
    }
    if !file.ends_with("-setup.exe") || !file.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        return Err(format!("{file}: the updater only saves *-setup.exe names of letters, digits, '.', '_' and '-'"));
    }
    if !url.ends_with(&format!("/{file}")) {
        return Err(format!("the URL must end in /{file}: the updater checks the signed file name against it"));
    }
    if !url_ok(url) {
        return Err(format!("{url}: the updater only downloads over https (port 443) from {}", RELEASE_HOSTS.join(", ")));
    }
    Ok(())
}

/// The updater's version rules (app/src/updater.rs: the shape check in `check` and `newer`'s
/// parse); app/tests/updater.rs holds the two to the same answers.
fn version_ok(v: &str) -> bool {
    if v.len() > 64 || !v.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c)) {
        return false;
    }
    let v = v.split('+').next().unwrap_or("");
    let (core, pre) = v.split_once('-').map_or((v, None), |(c, p)| (c, Some(p)));
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) && p.parse::<u64>().is_ok())
        && pre.is_none_or(|p| p.split('.').all(|x| !x.is_empty()))
}

/// Sign `installer` and write `<installer>.sig` and latest.json beside it. Returns both paths.
pub fn publish(key: &SecretKey, installer: &Path, version: &str, url: &str, notes: &str, now: u64, date: &str) -> Result<(PathBuf, PathBuf), String> {
    let name = installer.file_name().and_then(|n| n.to_str()).ok_or("the installer needs a file name")?;
    check_release(version, name, url)?;
    let data = std::fs::read(installer).map_err(|e| format!("{}: {e}", installer.display()))?;
    let sig = key.sign(&data, &trusted_comment(now, name, version));
    let sig_path = PathBuf::from(format!("{}.sig", installer.display()));
    std::fs::write(&sig_path, B64.encode(&sig)).map_err(|e| e.to_string())?;
    let manifest_path = installer.parent().unwrap_or(Path::new(".")).join("latest.json");
    std::fs::write(&manifest_path, manifest(version, notes, date, url, &sig)).map_err(|e| e.to_string())?;
    Ok((sig_path, manifest_path))
}

/// Check a release the way a client will: latest.json beside `installer` fits the updater's
/// size cap, names it, passes `check_release`, and its signature (the same as the .sig file) verifies the installer's bytes
/// under `public_key`, with this file and version in the trusted comment. A stale signature, the
/// wrong key or a mismatched manifest is an error, so it is caught before upload.
pub fn verify(installer: &Path, public_key: &str) -> Result<(), String> {
    use minisign_verify::{PublicKey, Signature};
    let name = installer.file_name().and_then(|n| n.to_str()).ok_or("the installer needs a file name")?;
    let manifest_path = installer.parent().unwrap_or(Path::new(".")).join("latest.json");
    let text = std::fs::read(&manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    if text.len() > MAX_MANIFEST {
        return Err(format!("latest.json is {} bytes; the updater reads at most {MAX_MANIFEST} (shorter notes)", text.len()));
    }
    let m: serde_json::Value = serde_json::from_slice(&text).map_err(|e| format!("latest.json: {e}"))?;
    let p = &m["platforms"]["windows-x86_64"];
    let (Some(version), Some(url), Some(sig_b64)) = (m["version"].as_str(), p["url"].as_str(), p["signature"].as_str()) else {
        return Err("latest.json lacks the version, the windows-x86_64 URL or its signature".into());
    };
    check_release(version, name, url)?;
    let sig_path = format!("{}.sig", installer.display());
    let sig_file = std::fs::read_to_string(&sig_path).map_err(|e| format!("{sig_path}: {e}"))?;
    if sig_file.trim() != sig_b64.trim() {
        return Err(format!("{sig_path} and latest.json carry different signatures"));
    }
    let sig_text = B64.decode(sig_b64.trim()).ok().and_then(|b| String::from_utf8(b).ok()).ok_or("latest.json's signature is not base64 text")?;
    let key = PublicKey::from_base64(public_key).map_err(|_| err("the public key is not valid"))?;
    let sig = Signature::decode(&sig_text).map_err(|_| err("latest.json's signature is not readable"))?;
    let data = std::fs::read(installer).map_err(|e| format!("{}: {e}", installer.display()))?;
    key.verify(&data, &sig, false)
        .map_err(|e| format!("the signature does not verify {name} with {public_key} ({e}): a stale signature or another key"))?;
    let fields: Vec<(&str, &str)> = sig.trusted_comment().split('\t').filter_map(|f| f.split_once(':')).collect();
    let field = |k: &str| fields.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
    if field("file") != Some(name) || field("version") != Some(version) {
        return Err(format!("the signed comment ({}) is not for {name} at {version}", sig.trusted_comment()));
    }
    Ok(())
}

/// libsodium's crypto_pwhash_scryptsalsa208sha256 parameter choice (what minisign uses to turn
/// opslimit/memlimit into scrypt's N, r, p).
fn pick_params(ops: u64, mem: u64) -> (u8, u32, u32) {
    let ops = ops.max(32768);
    let r: u64 = 8;
    let (log_n, p);
    if ops < mem / 32 {
        p = 1;
        let max_n = ops / (r * 4);
        log_n = (1..63).find(|&n| (1u64 << n) > max_n / 2).unwrap_or(63);
    } else {
        let max_n = mem / (r * 128);
        log_n = (1..63).find(|&n| (1u64 << n) > max_n / 2).unwrap_or(63);
        let max_rp = ((ops / 4) / (1u64 << log_n)).min(0x3fff_ffff);
        p = max_rp / r;
    }
    (log_n as u8, r as u32, p.max(1) as u32)
}

/// VibeFTP's update manifest (latest.json): version, notes, date, and per platform the installer's
/// URL and its signature (base64 of the minisign text, the same as the .sig file).
pub fn manifest(version: &str, notes: &str, pub_date: &str, url: &str, signature_file: &str) -> String {
    let v = serde_json::json!({
        "version": version,
        "notes": notes,
        "pub_date": pub_date,
        "platforms": { "windows-x86_64": { "signature": B64.encode(signature_file), "url": url } }
    });
    serde_json::to_string_pretty(&v).unwrap()
}
