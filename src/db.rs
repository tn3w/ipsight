//! Hot-swapping, self-updating database registry.
//!
//! Each [`Database`] declares a name + URL. [`spawn`] loads it from the on-disk
//! cache (or downloads if absent), then runs a background task that refreshes
//! every 24h via conditional GET. Updates atomically replace the in-memory
//! instance; readers see the old version until the swap completes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use reqwest::header::IF_MODIFIED_SINCE;
use tokio::{fs, time::sleep};

const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 3600);

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// A binary database loadable from raw bytes and fetched from a stable URL.
pub trait Database: Sized + Send + Sync + 'static {
    /// Stable identifier used as the cache filename.
    const NAME: &'static str;
    /// HTTPS URL serving the latest binary.
    const URL: &'static str;

    /// Parse a downloaded or cached blob.
    fn parse(bytes: Box<[u8]>) -> Result<Self>;
}

/// Atomic shared handle to a [`Database`] whose contents may be swapped out
/// from under you. Cheap to clone; readers are wait-free.
pub struct Handle<T>(Arc<ArcSwap<T>>);

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Handle<T> {
    /// Snapshot the current database. Hold the returned [`Arc`] for as long as
    /// you need stable access; the next update creates a new [`Arc`] without
    /// invalidating yours.
    pub fn load(&self) -> Arc<T> {
        self.0.load_full()
    }
}

/// Load `T` from cache (or download) and spawn a 24h background updater.
pub async fn spawn<T: Database>() -> Result<Handle<T>> {
    let path = cache_path(T::NAME)?;
    let initial = match fs::read(&path).await {
        Ok(bytes) => T::parse(bytes.into_boxed_slice())?,
        Err(_) => {
            let bytes = fetch::<T>(&path, None).await?.context("initial download empty")?;
            T::parse(bytes)?
        }
    };

    let swap = Arc::new(ArcSwap::from_pointee(initial));
    let task_swap = swap.clone();
    let task_path = path.clone();

    tokio::spawn(async move {
        sleep(initial_delay(&task_path).await).await;
        loop {
            if let Err(error) = refresh::<T>(&task_path, &task_swap).await {
                tracing::warn!(db = T::NAME, %error, "update failed");
            }
            sleep(UPDATE_INTERVAL).await;
        }
    });

    Ok(Handle(swap))
}

async fn refresh<T: Database>(path: &Path, swap: &ArcSwap<T>) -> Result<()> {
    let mtime = fs::metadata(path).await.ok().and_then(|m| m.modified().ok());
    let Some(bytes) = fetch::<T>(path, mtime).await? else {
        return Ok(());
    };
    let parsed = T::parse(bytes)?;
    swap.store(Arc::new(parsed));
    tracing::info!(db = T::NAME, "updated");
    Ok(())
}

async fn fetch<T: Database>(
    path: &Path,
    if_modified_since: Option<SystemTime>,
) -> Result<Option<Box<[u8]>>> {
    let mut request = http_client().get(T::URL);
    if let Some(time) = if_modified_since {
        request = request.header(IF_MODIFIED_SINCE, httpdate::fmt_http_date(time));
    }
    let response = request.send().await?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    let bytes = response.error_for_status()?.bytes().await?;
    let tmp = path.with_extension("bin.tmp");
    fs::write(&tmp, &bytes).await?;
    fs::rename(&tmp, path).await?;
    Ok(Some(bytes.to_vec().into_boxed_slice()))
}

async fn initial_delay(path: &Path) -> Duration {
    let Ok(meta) = fs::metadata(path).await else {
        return Duration::ZERO;
    };
    let Ok(mtime) = meta.modified() else {
        return Duration::ZERO;
    };
    let age = SystemTime::now().duration_since(mtime).unwrap_or_default();
    UPDATE_INTERVAL.saturating_sub(age)
}

fn cache_path(name: &str) -> Result<PathBuf> {
    let dir = dirs::cache_dir().context("no cache dir")?.join("ipsight");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{name}.bin")))
}
