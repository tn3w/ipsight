//! IP → `(latitude, longitude)` lookup over the IP2X `geo.bin` format.
//!
//! Layout — header (24 B), point table, per-base v4 deltas + packed indices,
//! v6 /64 keys + packed indices. Native arrays for `bases4`, `off4`, `v6_k` are
//! materialized at parse time so lookups touch only contiguous memory.

use std::net::IpAddr;

use anyhow::{Result, bail};

use crate::db::Database;

const MAGIC: &[u8] = b"GEO1";
const COORD_SCALE: f64 = 1000.0;

/// IP → `(lat, lon)` reverse-lookup over a loaded `geo.bin`.
pub struct IpGeo {
    bytes: Box<[u8]>,
    idx_bits: u32,
    idx_mask: u64,
    pts_off: usize,
    bases4: Box<[u32]>,
    off4: Box<[u32]>,
    deltas4_off: usize,
    v4_idx_off: usize,
    v6_keys: Box<[u64]>,
    v6_idx_off: usize,
}

impl Database for IpGeo {
    const NAME: &'static str = "ip2x";
    const URL: &'static str = "https://github.com/tn3w/IP2X/releases/latest/download/geo.bin";

    fn parse(bytes: Box<[u8]>) -> Result<Self> {
        Self::parse(bytes)
    }
}

impl IpGeo {
    /// Parse a `geo.bin` blob into a queryable database.
    pub fn parse(bytes: Box<[u8]>) -> Result<Self> {
        if bytes.len() < 24 || &bytes[..4] != MAGIC {
            bail!("bad IP2X geo.bin");
        }
        let idx_bits = bytes[6] as u32;
        let idx_mask = (1u64 << idx_bits) - 1;
        let n_pts = u32le(&bytes, 8) as usize;
        let n4 = u32le(&bytes, 12) as usize;
        let n6 = u32le(&bytes, 16) as usize;
        let nb4 = u32le(&bytes, 20) as usize;

        let mut offset = 24;
        let pts_off = offset;
        offset += n_pts * 6;

        let bases4 = read_u32_array(&bytes, offset, nb4);
        offset += nb4 * 4;

        let off4 = read_u32_array(&bytes, offset, nb4 + 1);
        offset += (nb4 + 1) * 4;

        let deltas_len = off4[nb4] as usize;
        let deltas4_off = offset;
        offset += deltas_len;

        let v4_idx_off = offset;
        offset += (n4 * idx_bits as usize).div_ceil(8) + 4;

        let v6_keys = read_u64_array(&bytes, offset, n6);
        offset += n6 * 8;

        let v6_idx_off = offset;

        Ok(Self {
            bytes,
            idx_bits,
            idx_mask,
            pts_off,
            bases4,
            off4,
            deltas4_off,
            v4_idx_off,
            v6_keys,
            v6_idx_off,
        })
    }

    /// Look up `(lat, lon)` for an IPv4 or IPv6 address.
    pub fn lookup(&self, ip: IpAddr) -> Option<(f64, f64)> {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(u32::from(v4)),
            IpAddr::V6(v6) => self.lookup_v6(u128::from(v6)),
        }
    }

    fn lookup_v4(&self, ip: u32) -> Option<(f64, f64)> {
        let group = self.bases4.partition_point(|&base| base <= ip).checked_sub(1)?;
        let base = self.bases4[group];
        let begin = self.off4[group] as usize;
        let end = self.off4[group + 1] as usize;
        let target = ip - base;

        let deltas = &self.bytes[self.deltas4_off + begin..self.deltas4_off + end];
        let count = deltas.len() / 3;
        let mut lo = 0;
        let mut hi = count;
        while lo < hi {
            let mid = (lo + hi) >> 1;
            if u24le(deltas, mid * 3) <= target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let local = lo.checked_sub(1)?;
        let row = begin / 3 + local;
        self.point(self.packed(self.v4_idx_off, row))
    }

    fn lookup_v6(&self, ip: u128) -> Option<(f64, f64)> {
        let key = (ip >> 64) as u64;
        let row = self.v6_keys.partition_point(|&k| k <= key).checked_sub(1)?;
        self.point(self.packed(self.v6_idx_off, row))
    }

    fn packed(&self, base: usize, row: usize) -> u64 {
        let bit = row * self.idx_bits as usize;
        let byte = base + (bit >> 3);
        let shift = bit & 7;
        let word = u32::from_le_bytes(self.bytes[byte..byte + 4].try_into().unwrap()) as u64;
        (word >> shift) & self.idx_mask
    }

    fn point(&self, index: u64) -> Option<(f64, f64)> {
        if index == 0 {
            return None;
        }
        let offset = self.pts_off + index as usize * 6;
        let lat = i24le(&self.bytes, offset);
        let lon = i24le(&self.bytes, offset + 3);
        Some((lat as f64 / COORD_SCALE, lon as f64 / COORD_SCALE))
    }
}

fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u24le(bytes: &[u8], offset: usize) -> u32 {
    bytes[offset] as u32
        | ((bytes[offset + 1] as u32) << 8)
        | ((bytes[offset + 2] as u32) << 16)
}

fn i24le(bytes: &[u8], offset: usize) -> i32 {
    let value = u24le(bytes, offset);
    if value & 0x80_0000 != 0 {
        (value | 0xFF00_0000) as i32
    } else {
        value as i32
    }
}

fn read_u32_array(bytes: &[u8], offset: usize, count: usize) -> Box<[u32]> {
    (0..count).map(|i| u32le(bytes, offset + i * 4)).collect()
}

fn read_u64_array(bytes: &[u8], offset: usize, count: usize) -> Box<[u64]> {
    (0..count)
        .map(|i| u64::from_le_bytes(bytes[offset + i * 8..offset + i * 8 + 8].try_into().unwrap()))
        .collect()
}
