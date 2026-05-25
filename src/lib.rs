//! IP → geographic + threat + ASN enrichment with hot-swapping, self-updating databases.
//!
//! Pipeline: IP → `(lat, lon)` via [`IpGeo`] → [`Place`] via [`Geocoder`];
//! IP → [`IntelReport`] via [`Intel`]; IP → [`AsnInfo`] via [`Asndb`]. Each
//! database refreshes every 24h in the background; lookups never block.

#![warn(missing_docs)]

mod asndb;
mod db;
mod geocoder;
mod intel;
mod ip_geo;

pub use asndb::{Asndb, AsnInfo};
pub use db::{Database, Handle, spawn};
pub use geocoder::{Geocoder, Place};
pub use intel::{Intel, IntelMatch, IntelReport};
pub use ip_geo::IpGeo;

use std::net::IpAddr;

use anyhow::Result;

/// Combined geo + threat + ASN report for a single IP.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Reverse-geocoded place. `None` if the IP is not in the geo database.
    pub place: Option<Place>,
    /// Threat-intelligence verdict. `None` if no range matched.
    pub intel: Option<IntelReport>,
    /// Owning ASN + brand info. `None` if the IP is in an unassigned segment.
    pub asn: Option<AsnInfo>,
}

/// Bundled IP → [`Report`] lookup over the four default databases.
pub struct Ipsight {
    /// IP → `(lat, lon)` database (IP2X).
    pub ip_geo: Handle<IpGeo>,
    /// `(lat, lon)` → [`Place`] database (genom).
    pub geocoder: Handle<Geocoder>,
    /// IP → [`IntelReport`] database (IPBlocklist).
    pub intel: Handle<Intel>,
    /// IP → [`AsnInfo`] database (ASNDB tiny).
    pub asn: Handle<Asndb>,
}

impl Ipsight {
    /// Load every database from cache (or download) and start background updaters.
    pub async fn new() -> Result<Self> {
        let (ip_geo, geocoder, intel, asn) = tokio::try_join!(
            spawn::<IpGeo>(),
            spawn::<Geocoder>(),
            spawn::<Intel>(),
            spawn::<Asndb>(),
        )?;
        Ok(Self { ip_geo, geocoder, intel, asn })
    }

    /// Build a full [`Report`] for an IP across all loaded databases.
    pub fn lookup(&self, ip: IpAddr) -> Report {
        let place = self
            .ip_geo
            .load()
            .lookup(ip)
            .and_then(|(lat, lon)| self.geocoder.load().lookup(lat, lon));
        let intel = self.intel.load().lookup(ip);
        let asn = self.asn.load().lookup(ip);
        Report { place, intel, asn }
    }
}
