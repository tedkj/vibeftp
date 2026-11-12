//! A session is one site plus a small pool of connections to it.
//! Slot 0 is the "browse" connection used for listings and file ops;
//! transfers prefer the other slots and open new ones up to the site's limit.
//! Dead connections are re-dialed transparently and the operation retried once.

use crate::error::{AppError, Result};
use crate::protocol::{Remote, Shared};
use crate::types::{SessionState, Site};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::host::{Event, Host};

/// A connection idle this long gets a quick ping before use: NATs drop silent
/// TCP sessions, and FTP has no keepalive of its own.
const IDLE_PROBE: Duration = Duration::from_secs(60);

/// How long a refused extra connection lowers the cap: the usual cause (an old session's
/// links still counted by the server, a moment at the server's limit) passes.
const CAP_COOLDOWN: Duration = Duration::from_secs(60);

struct Slot {
    remote: Arc<Remote>,
    busy: bool,
    /// Probably dead (a sibling link dropped); redialed in place on next use.
    stale: bool,
    last_used: Instant,
}

/// Drop a replaced connection politely, unless something is still using it.
fn retire(r: Arc<Remote>) {
    if Arc::strong_count(&r) == 1 {
        tokio::spawn(async move { r.disconnect().await });
    }
}

pub struct Session {
    pub id: String,
    pub site: Site,
    password: String,
    known: Option<String>,
    pub max: usize,
    /// Effective connection cap: lowered when the server refuses another connection, back to
    /// `max` once `CAP_COOLDOWN` has passed since (`capped_at`).
    cap: AtomicUsize,
    capped_at: Mutex<Option<Instant>>,
    /// An extra dial's login was turned down (a password changed while the links stayed
    /// logged in): the cap stays down for the session, each new try would be a failed login.
    login_refused: AtomicBool,
    slots: Mutex<Vec<Slot>>,
    /// Connections currently being dialed (counted against `max`).
    opening: AtomicUsize,
    closed: AtomicBool,
    host: Arc<dyn Host>,
    /// What its links learn together (protocol::Shared).
    shared: Shared,
}

/// A leased connection. Dropping it frees the slot.
pub struct Lease {
    session: Arc<Session>,
    pub idx: usize,
    pub remote: Arc<Remote>,
    owned: bool,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(s) = self.session.slots.lock().unwrap().get_mut(self.idx) {
            if self.owned {
                s.busy = false;
            }
            s.last_used = Instant::now(); // a link that just carried a transfer is not idle
        }
        if self.owned {
            self.session.emit_state("");
        }
    }
}

impl Lease {
    /// The link was torn down on purpose (an FTP cancel closes it without a goodbye): the next
    /// user redials the slot in place, without taking its siblings for dead.
    pub fn mark_stale(&self) {
        if let Some(s) = self.session.slots.lock().unwrap().get_mut(self.idx)
            && Arc::ptr_eq(&s.remote, &self.remote)
        {
            s.stale = true;
        }
    }
}

impl Session {
    pub async fn open(
        host: Arc<dyn Host>,
        id: String,
        site: Site,
        password: String,
        known: Option<String>,
    ) -> Result<(Arc<Session>, String, Option<String>)> {
        let (mut remote, cwd, fp) = Remote::connect(&site, &password, known.clone()).await?;
        let shared = Shared::default();
        remote.share(&shared);
        let max = site.max_connections();
        // Pool dials must verify against the key we just trusted; a legacy SSH pin is used in
        // its fuller form (with the key type), so pool dials ask for that type first too.
        let known = match (&known, &fp) {
            (Some(k), Some(f))
                if site.protocol == crate::types::Protocol::Sftp && crate::protocol::sftp::pin_needs_upgrade(k, f) =>
            {
                fp.clone()
            }
            _ => known.or(fp.clone()),
        };
        let s = Arc::new(Session {
            id,
            site,
            password,
            known,
            max,
            cap: AtomicUsize::new(max),
            capped_at: Mutex::new(None),
            login_refused: AtomicBool::new(false),
            slots: Mutex::new(vec![Slot {
                remote: Arc::new(remote),
                busy: false,
                stale: false,
                last_used: Instant::now(),
            }]),
            opening: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            host,
            shared,
        });
        s.emit_state("");
        Ok((s, cwd, fp))
    }

    fn check_open(&self) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            Err(AppError::NotConnected)
        } else {
            Ok(())
        }
    }

    async fn dial(&self) -> Result<Arc<Remote>> {
        self.check_open()?;
        let (mut remote, _, _) =
            Remote::connect(&self.site.for_pool(), &self.password, self.known.clone()).await?;
        remote.share(&self.shared);
        if self.closed.load(Ordering::Relaxed) {
            // Closed while dialing: don't leave the fresh connection dangling.
            tokio::spawn(async move { remote.disconnect().await });
            return Err(AppError::NotConnected);
        }
        Ok(Arc::new(remote))
    }

    /// Mark a slot as just used (for the idle probe).
    fn touch(&self, idx: usize) {
        if let Some(s) = self.slots.lock().unwrap().get_mut(idx) {
            s.last_used = Instant::now();
        }
    }

    /// Idle too long? Ping it; a failure marks the slot stale so the caller redials.
    /// A link that is busy (or shared by a transfer) is not idle, whatever the clock says:
    /// its NOOP would queue behind the transfer and time out falsely.
    async fn probe_if_idle(&self, idx: usize, remote: &Arc<Remote>) -> bool {
        let idle = self
            .slots
            .lock()
            .unwrap()
            .get(idx)
            .map(|s| !s.busy && Arc::strong_count(&s.remote) <= 2 && s.last_used.elapsed() > IDLE_PROBE)
            .unwrap_or(false);
        if !idle {
            return true;
        }
        self.probe(idx, remote).await
    }

    /// Ping a link; a failure marks its slot stale so the caller redials.
    async fn probe(&self, idx: usize, remote: &Arc<Remote>) -> bool {
        let ok = tokio::time::timeout(Duration::from_secs(5), remote.ping()).await.is_ok_and(|r| r.is_ok());
        if !ok
            && let Some(s) = self.slots.lock().unwrap().get_mut(idx)
        {
            s.stale = true;
        }
        ok
    }

    pub fn state(&self) -> SessionState {
        let slots = self.slots.lock().unwrap();
        SessionState {
            session: self.id.clone(),
            connections: slots.iter().filter(|s| !s.stale).count(),
            busy: slots.iter().filter(|s| s.busy).count(),
            note: String::new(),
        }
    }

    pub fn emit_state(&self, note: &str) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let mut st = self.state();
        st.note = note.to_string();
        self.host.emit(Event::SessionState(st));
    }

    /// Replace the connection in `idx` with a fresh one, unless someone already
    /// did (then hand back theirs). Idle siblings are marked stale: if one link
    /// died the server most likely dropped them all.
    pub async fn redial(&self, idx: usize, failed: &Arc<Remote>) -> Result<Arc<Remote>> {
        self.check_open()?;
        if let Some(s) = self.slots.lock().unwrap().get(idx)
            && !Arc::ptr_eq(&s.remote, failed) && !s.stale
        {
            return Ok(s.remote.clone());
        }
        self.emit_state("Reconnecting…");
        log::warn!(target: "vibeftp", "Connection {} dropped, reconnecting", idx);
        let fresh = match self.redial_once(failed).await {
            Ok(f) => f,
            Err(e) => {
                // The link stays dead: the slot says so (it is redialed on next use and no
                // longer counted), and "Reconnecting…" must not outlive the attempt.
                if let Some(s) = self.slots.lock().unwrap().get_mut(idx)
                    && Arc::ptr_eq(&s.remote, failed)
                {
                    s.stale = true;
                }
                self.emit_state("");
                return Err(e);
            }
        };
        let old: Option<Arc<Remote>> = {
            let mut slots = self.slots.lock().unwrap();
            if self.closed.load(Ordering::Relaxed) {
                drop(slots);
                tokio::spawn(async move { fresh.disconnect().await });
                return Err(AppError::NotConnected);
            }
            let was_stale;
            let old = match slots.get_mut(idx) {
                Some(s) if Arc::ptr_eq(&s.remote, failed) || s.stale => {
                    was_stale = s.stale;
                    s.stale = false;
                    s.last_used = Instant::now();
                    Some(std::mem::replace(&mut s.remote, fresh.clone()))
                }
                Some(s) => {
                    // Lost the race: a sibling already replaced it. Use theirs.
                    let theirs = s.remote.clone();
                    drop(slots);
                    tokio::spawn(async move { fresh.disconnect().await });
                    return Ok(theirs);
                }
                None => {
                    slots.push(Slot {
                        remote: fresh.clone(),
                        busy: true,
                        stale: false,
                        last_used: Instant::now(),
                    });
                    was_stale = true;
                    None
                }
            };
            // Only a link that actually died implicates its siblings; replacing a slot
            // that was merely flagged must not cascade. Flag, never disconnect: a browse
            // or shared lease may still be using one.
            if !was_stale {
                for (i, s) in slots.iter_mut().enumerate() {
                    if i != idx && !s.busy && !s.stale {
                        s.stale = true;
                    }
                }
            }
            old
        };
        if let Some(r) = old {
            // The caller still holds `failed` (its lease or browse clone) and we hold the
            // slot's reference: two means nobody else is on the dead link. A merely stale
            // sibling has no caller reference, so one.
            let limit = if Arc::ptr_eq(&r, failed) { 2 } else { 1 };
            if Arc::strong_count(&r) <= limit {
                tokio::spawn(async move { r.disconnect().await });
            }
        }
        // A reconnect may be to another server behind the same name (a failover): what the
        // links learnt about refused exclusive creates is learnt again (review R2-7).
        self.shared.reconnected();
        self.emit_state("Reconnected");
        Ok(fresh)
    }

    /// One dial for `redial`, plus one more after releasing the old link when the server
    /// refused it for being at its limit.
    async fn redial_once(&self, failed: &Arc<Remote>) -> Result<Arc<Remote>> {
        match self.dial().await {
            Ok(f) => Ok(f),
            Err(e) => {
                if self.closed.load(Ordering::Relaxed) {
                    return Err(e);
                }
                // A refused login stays refused: a second try is one more failed login
                // for fail2ban to count, not a fix.
                if e.is_auth_failure() {
                    return Err(e);
                }
                // The server may still count the failed link (a data-socket timeout leaves
                // the control session logged in): say goodbye on it, then try once more.
                // Only when nobody else is on it: under a one-connection cap a transfer may
                // share this very link and still be moving bytes. Slot + caller = 2 references.
                if Arc::strong_count(failed) > 2 {
                    return Err(e);
                }
                log::warn!(target: "vibeftp", "Reconnect refused ({e}); releasing the old link first");
                let _ = tokio::time::timeout(Duration::from_secs(3), failed.disconnect()).await;
                self.dial().await
            }
        }
    }

    /// Run a browse operation on slot 0, reconnecting and retrying once if the link is dead.
    /// The closure's second argument says it is that retry: the first attempt may have taken
    /// effect with only its reply lost, so a non-idempotent operation must look before acting.
    pub async fn browse<T, F, Fut>(&self, f: F) -> Result<T>
    where
        F: Fn(Arc<Remote>, bool) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.check_open()?;
        let (remote, stale) = {
            let slots = self.slots.lock().unwrap();
            let s = slots.first().ok_or(AppError::NotConnected)?;
            (s.remote.clone(), s.stale)
        };
        let stale = stale || !self.probe_if_idle(0, &remote).await;
        let remote = if stale { self.redial(0, &remote).await? } else { remote };
        self.touch(0);
        match f(remote.clone(), false).await {
            Err(e) if e.is_connection_error() => {
                let fresh = self.redial(0, &remote).await?;
                self.touch(0);
                f(fresh, true).await
            }
            other => other,
        }
    }

    /// A lease on the browse link, for a transfer whose own link cannot be replaced right now.
    pub fn share(self: &Arc<Self>) -> Option<Lease> {
        let remote = self.slots.lock().unwrap().first().map(|s| s.remote.clone())?;
        Some(Lease { session: self.clone(), idx: 0, remote, owned: false })
    }

    /// Lease a connection for a transfer: a free slot other than the browse
    /// slot (redialed in place if stale), a new one if under the limit, then
    /// slot 0 if it is free, otherwise share slot 0.
    pub async fn lease(self: &Arc<Self>) -> Result<Lease> {
        self.check_open()?;
        enum Pick {
            /// (slot, link, sat idle long enough to deserve a probe)
            Reuse(usize, Arc<Remote>, bool),
            Stale(usize),
            New,
            Share(Arc<Remote>),
        }
        {
            // A refusal is a moment, not a property of the server: try the full pool again.
            let mut at = self.capped_at.lock().unwrap();
            if at.is_some_and(|t| t.elapsed() > CAP_COOLDOWN) && !self.login_refused.load(Ordering::Relaxed) {
                *at = None;
                self.cap.store(self.max, Ordering::Relaxed);
            }
        }
        let pick = {
            let mut slots = self.slots.lock().unwrap();
            let opening = self.opening.load(Ordering::Relaxed);
            let cap = self.cap.load(Ordering::Relaxed);
            // Slot 0 is the browse connection: with more than one slot allowed it
            // never carries a transfer, so listings stay snappy.
            let free = slots
                .iter_mut()
                .enumerate()
                .skip(1)
                .find(|(_, s)| !s.busy)
                .map(|(i, _)| i)
                .or_else(|| {
                    if self.max == 1 && slots.first().is_some_and(|s| !s.busy) {
                        Some(0)
                    } else {
                        None
                    }
                });
            if let Some(i) = free {
                let s = &mut slots[i];
                // Decide "idle" before the slot is taken: a busy slot never counts as idle.
                let idle = Arc::strong_count(&s.remote) <= 1 && s.last_used.elapsed() > IDLE_PROBE;
                s.busy = true;
                if s.stale {
                    Pick::Stale(i)
                } else {
                    Pick::Reuse(i, s.remote.clone(), idle)
                }
            } else if slots.len() + opening < cap {
                self.opening.fetch_add(1, Ordering::Relaxed);
                Pick::New
            } else {
                Pick::Share(slots.first().ok_or(AppError::NotConnected)?.remote.clone())
            }
        };
        // A reused slot that sat idle gets probed; a dead one is redialed in place.
        let pick = match pick {
            Pick::Reuse(idx, remote, true) if !self.probe(idx, &remote).await => Pick::Stale(idx),
            other => other,
        };
        let lease = match pick {
            Pick::Reuse(idx, remote, _) => {
                self.touch(idx);
                Lease { session: self.clone(), idx, remote, owned: true }
            }
            Pick::Share(remote) => Lease { session: self.clone(), idx: 0, remote, owned: false },
            Pick::Stale(idx) => match self.redial_stale(idx).await {
                Ok(fresh) => {
                    let old = {
                        let mut slots = self.slots.lock().unwrap();
                        if self.closed.load(Ordering::Relaxed) {
                            drop(slots);
                            tokio::spawn(async move { fresh.disconnect().await });
                            return Err(AppError::NotConnected);
                        }
                        slots.get_mut(idx).map(|s| {
                            s.stale = false;
                            s.last_used = Instant::now();
                            std::mem::replace(&mut s.remote, fresh.clone())
                        })
                    };
                    if let Some(r) = old {
                        retire(r);
                    }
                    Lease { session: self.clone(), idx, remote: fresh, owned: true }
                }
                Err(e) => {
                    // The server may still count the dead link against the user's limit
                    // (NAT drops): share the browse link rather than fail the transfer.
                    if let Some(s) = self.slots.lock().unwrap().get_mut(idx) {
                        s.busy = false;
                    }
                    if self.closed.load(Ordering::Relaxed) || e.is_connection_error() && idx == 0 {
                        return Err(e);
                    }
                    log::warn!(target: "vibeftp", "Redial refused ({e}); sharing the browse connection");
                    let shared = self.slots.lock().unwrap().first().map(|s| s.remote.clone());
                    match shared {
                        Some(remote) => Lease { session: self.clone(), idx: 0, remote, owned: false },
                        None => return Err(e),
                    }
                }
            },
            Pick::New => {
                let dialed = self.dial().await;
                let fresh = match dialed {
                    Ok(r) => r,
                    Err(e) => {
                        self.opening.fetch_sub(1, Ordering::Relaxed);
                        // Servers cap connections per client: fall back to sharing the
                        // browse connection instead of failing the transfer outright.
                        if self.closed.load(Ordering::Relaxed) {
                            return Err(e);
                        }
                        log::warn!(target: "vibeftp", "Extra connection refused ({e}); sharing the browse connection");
                        // Remember a refusal for a while: later leases must not each pay for
                        // another failed login. A transport failure (a blip) is not one.
                        if e.is_refusal() || e.is_auth_failure() {
                            let have = self.slots.lock().unwrap().len().max(1);
                            self.cap.fetch_min(have, Ordering::Relaxed);
                            *self.capped_at.lock().unwrap() = Some(Instant::now());
                            if e.is_auth_failure() {
                                self.login_refused.store(true, Ordering::Relaxed);
                            }
                        }
                        self.emit_state("");
                        return self.share().ok_or(e);
                    }
                };
                // Decrement and push under the same lock, so `len + opening` never dips below truth.
                let idx = {
                    let mut slots = self.slots.lock().unwrap();
                    self.opening.fetch_sub(1, Ordering::Relaxed);
                    if self.closed.load(Ordering::Relaxed) {
                        drop(slots);
                        tokio::spawn(async move { fresh.disconnect().await });
                        return Err(AppError::NotConnected);
                    }
                    slots.push(Slot {
                        remote: fresh.clone(),
                        busy: true,
                        stale: false,
                        last_used: Instant::now(),
                    });
                    slots.len() - 1
                };
                Lease { session: self.clone(), idx, remote: fresh, owned: true }
            }
        };
        self.emit_state("");
        Ok(lease)
    }

    /// Dial a replacement for a stale slot, after saying goodbye on the old link when
    /// nothing else holds it: the server may still count it against the user's limit.
    async fn redial_stale(&self, idx: usize) -> Result<Arc<Remote>> {
        let old = self.slots.lock().unwrap().get(idx).map(|s| s.remote.clone());
        if let Some(r) = old
            && Arc::strong_count(&r) <= 2
        {
            let _ = tokio::time::timeout(Duration::from_secs(3), r.disconnect()).await;
        }
        self.dial().await
    }

    /// Mark the session closed (no more dials or retries) and drop every connection.
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let slots: Vec<Arc<Remote>> = self
            .slots
            .lock()
            .unwrap()
            .drain(..)
            .map(|s| s.remote)
            .collect();
        // All links say goodbye at once; a stuck one gets two seconds, not two each.
        let handles: Vec<_> = slots
            .into_iter()
            .map(|r| tokio::spawn(async move { r.disconnect().await }))
            .collect();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            for h in handles {
                let _ = h.await;
            }
        })
        .await;
    }
}
