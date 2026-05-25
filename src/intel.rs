//! IP → threat intelligence over the IPBlocklist `intel.bin` format.
//!
//! Layout — 4-byte version (=6), 19× u64 offsets, then sections:
//! bucketed 16-bit CIDR table, long-range table, sorted v6 table, value table
//! (flag bits + provider/source ids), string blob. Lookup is upper-bound +
//! reverse scan bounded by a max-end prefix array.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

use crate::db::Database;

const FLAG_NAMES: [&str; 20] = [
    "vpn", "proxy", "tor", "malware", "c2", "scanner", "brute_force", "spammer",
    "compromised", "datacenter", "cdn", "anycast", "crawler", "bot", "cloud",
    "private_relay", "anonymizer", "mobile", "isp", "government",
];
const FLAG_BASE_WEIGHTS: [f64; 20] = [
    30.0, 25.0, 45.0, 95.0, 95.0, 55.0, 70.0, 65.0, 75.0, 15.0,
    5.0, 0.0, 10.0, 40.0, 10.0, 15.0, 35.0, 0.0, 0.0, 0.0,
];
const VERDICT_LEVELS: [(f64, &str); 4] = [
    (80.0, "critical"),
    (60.0, "high"),
    (35.0, "medium"),
    (15.0, "low"),
];

/// Aggregated threat report for a single IP.
#[derive(Debug, Clone)]
pub struct IntelReport {
    /// `critical` | `high` | `medium` | `low` | `minimal` | `clean`.
    pub verdict: &'static str,
    /// 0–100 composite risk score.
    pub score: f64,
    /// Total matching ranges across all sources.
    pub detections: usize,
    /// Distinct `(provider, source)` pairs.
    pub sources: usize,
    /// First non-empty provider (Tor pinned first if present).
    pub top_provider: String,
    /// Unique providers in detection order.
    pub providers: Vec<String>,
    /// All flags seen, in first-seen order.
    pub flags: Vec<&'static str>,
    /// Top 5 flags ranked by calibrated weight.
    pub reasons: Vec<&'static str>,
    /// Underlying per-range matches, heaviest first.
    pub matches: Vec<IntelMatch>,
}

/// A single matching range from one source.
#[derive(Debug, Clone)]
pub struct IntelMatch {
    /// Source feed identifier.
    pub source: String,
    /// Provider name.
    pub provider: String,
    /// Human-readable `start-end` range.
    pub range: String,
    /// Flags set on this range.
    pub flags: Vec<&'static str>,
    /// Heaviest calibrated flag weight.
    pub weight: f64,
}

/// IPBlocklist intel database.
pub struct Intel {
    v4_starts: Box<[u32]>,
    v4_ends: Box<[u32]>,
    v4_max_end: Box<[u32]>,
    v4_vals: Box<[u16]>,
    v6_starts: Box<[u128]>,
    v6_ends: Box<[u128]>,
    v6_max_end: Box<[u128]>,
    v6_vals: Box<[u16]>,
    value_table: Box<[[u32; 4]]>,
    strings: Box<[String]>,
    flag_weights: [f64; 20],
}

impl Database for Intel {
    const NAME: &'static str = "ipblocklist";
    const URL: &'static str =
        "https://github.com/tn3w/IPBlocklist/releases/latest/download/intel.bin";

    fn parse(bytes: Box<[u8]>) -> Result<Self> {
        Self::parse(bytes)
    }
}

impl Intel {
    /// Parse an `intel.bin` blob.
    pub fn parse(bytes: Box<[u8]>) -> Result<Self> {
        if bytes.len() < 8 + 19 * 8 || u32le(&bytes, 0) != 6 {
            bail!("bad intel.bin");
        }
        let header: Vec<usize> =
            (0..19).map(|i| u64le(&bytes, 8 + i * 8) as usize).collect();
        let (cidr_n, long_n, v6_n, val_n, str_n) =
            (header[0], header[1], header[2], header[3], header[4]);
        let section = &header[5..];

        let bucket_index: Vec<u32> =
            (0..=65536).map(|i| u32le(&bytes, section[0] + i * 4)).collect();

        let total = cidr_n + long_n;
        let mut starts = vec![0u32; total];
        let mut ends = vec![0u32; total];
        let mut vals = vec![0u16; total];
        for bucket in 0..65536 {
            for j in bucket_index[bucket]..bucket_index[bucket + 1] {
                let i = j as usize;
                let lo = u16le(&bytes, section[1] + i * 2) as u32;
                starts[i] = ((bucket as u32) << 16) | lo;
                ends[i] = starts[i] + u16le(&bytes, section[2] + i * 2) as u32;
                vals[i] = u16le(&bytes, section[3] + i * 2);
            }
        }
        for i in 0..long_n {
            starts[cidr_n + i] = u32le(&bytes, section[4] + i * 4);
            ends[cidr_n + i] = u32le(&bytes, section[5] + i * 4);
            vals[cidr_n + i] = u16le(&bytes, section[6] + i * 2);
        }
        let mut order: Vec<usize> = (0..total).collect();
        order.sort_unstable_by_key(|&i| starts[i]);
        let v4_starts: Box<[u32]> = order.iter().map(|&i| starts[i]).collect();
        let v4_ends: Box<[u32]> = order.iter().map(|&i| ends[i]).collect();
        let v4_vals: Box<[u16]> = order.iter().map(|&i| vals[i]).collect();
        let v4_max_end = max_prefix(&v4_ends);

        let v6_starts: Box<[u128]> =
            (0..v6_n).map(|i| u128_le(&bytes, section[7] + i * 16)).collect();
        let v6_ends: Box<[u128]> =
            (0..v6_n).map(|i| u128_le(&bytes, section[8] + i * 16)).collect();
        let v6_vals: Box<[u16]> =
            (0..v6_n).map(|i| u16le(&bytes, section[9] + i * 2)).collect();
        let v6_max_end = max_prefix(&v6_ends);

        let value_table: Box<[[u32; 4]]> = (0..val_n)
            .map(|i| {
                let o = section[10] + i * 16;
                [u32le(&bytes, o), u32le(&bytes, o + 4), u32le(&bytes, o + 8), u32le(&bytes, o + 12)]
            })
            .collect();

        let string_body = section[12];
        let strings: Box<[String]> = (0..str_n)
            .map(|i| {
                let o = u32le(&bytes, section[11] + i * 8) as usize;
                let l = u32le(&bytes, section[11] + i * 8 + 4) as usize;
                String::from_utf8_lossy(&bytes[string_body + o..string_body + o + l]).into_owned()
            })
            .collect();

        let flag_weights = calibrate_weights(&v4_vals, &value_table);

        Ok(Self {
            v4_starts, v4_ends, v4_max_end, v4_vals,
            v6_starts, v6_ends, v6_max_end, v6_vals,
            value_table, strings, flag_weights,
        })
    }

    /// Reverse-lookup an IP. Returns `None` if no range matched.
    pub fn lookup(&self, ip: IpAddr) -> Option<IntelReport> {
        let matches = match ip {
            IpAddr::V4(v4) => self.collect_v4(u32::from(v4)),
            IpAddr::V6(v6) => self.collect_v6(u128::from(v6)),
        };
        if matches.is_empty() {
            return None;
        }
        Some(self.build_report(matches))
    }

    fn collect_v4(&self, ip: u32) -> Vec<IntelMatch> {
        let mut out = Vec::new();
        let mut i = self.v4_starts.partition_point(|&s| s <= ip);
        while i > 0 {
            i -= 1;
            if self.v4_max_end[i] < ip {
                break;
            }
            if self.v4_ends[i] >= ip {
                let range = format!(
                    "{}-{}",
                    Ipv4Addr::from(self.v4_starts[i]),
                    Ipv4Addr::from(self.v4_ends[i])
                );
                out.push(self.make_match(self.v4_vals[i], range));
            }
        }
        out
    }

    fn collect_v6(&self, ip: u128) -> Vec<IntelMatch> {
        let mut out = Vec::new();
        let mut i = self.v6_starts.partition_point(|&s| s <= ip);
        while i > 0 {
            i -= 1;
            if self.v6_max_end[i] < ip {
                break;
            }
            if self.v6_ends[i] >= ip {
                let range = format!(
                    "{}-{}",
                    Ipv6Addr::from(self.v6_starts[i]),
                    Ipv6Addr::from(self.v6_ends[i])
                );
                out.push(self.make_match(self.v6_vals[i], range));
            }
        }
        out
    }

    fn make_match(&self, value_id: u16, range: String) -> IntelMatch {
        let entry = self.value_table[value_id as usize];
        let bits = entry[0];
        let mut flags = Vec::new();
        let mut max_weight = 0.0f64;
        #[allow(clippy::needless_range_loop)]
        for i in 0..20 {
            if bits & (1 << i) != 0 {
                flags.push(FLAG_NAMES[i]);
                if self.flag_weights[i] > max_weight {
                    max_weight = self.flag_weights[i];
                }
            }
        }
        IntelMatch {
            source: self.strings[entry[2] as usize].clone(),
            provider: self.strings[entry[1] as usize].clone(),
            range,
            flags,
            weight: round1(max_weight),
        }
    }

    fn build_report(&self, mut matches: Vec<IntelMatch>) -> IntelReport {
        matches.sort_by(|a, b| b.weight.partial_cmp(&a.weight).unwrap());

        let mut all_flags: Vec<&'static str> = Vec::new();
        for m in &matches {
            for flag in &m.flags {
                if !all_flags.contains(flag) {
                    all_flags.push(*flag);
                }
            }
        }
        let weight_of = |flag: &str| {
            FLAG_NAMES.iter().position(|x| *x == flag).map(|i| self.flag_weights[i]).unwrap_or(0.0)
        };
        let mut ranked = all_flags.clone();
        ranked.sort_by(|a, b| weight_of(b).partial_cmp(&weight_of(a)).unwrap());

        let mut source_set: HashSet<(String, String)> = HashSet::new();
        for m in &matches {
            source_set.insert((m.provider.clone(), m.source.clone()));
        }

        let score = if ranked.is_empty() {
            0.0
        } else {
            let top = weight_of(ranked[0]);
            let extras: f64 = ranked[1..].iter().map(|f| weight_of(f)).sum();
            round1(
                100f64.min(
                    (top + extras * 0.15)
                        * (1.0 + 0.08 * ((source_set.len() + 1) as f64).log2()),
                ),
            )
        };
        let verdict = VERDICT_LEVELS
            .iter()
            .find(|(threshold, _)| score >= *threshold)
            .map(|(_, name)| *name)
            .unwrap_or("minimal");

        let mut providers: Vec<String> = Vec::new();
        for m in &matches {
            if !m.provider.is_empty() && !providers.contains(&m.provider) {
                providers.push(m.provider.clone());
            }
        }
        if let Some(i) = providers.iter().position(|p| p.eq_ignore_ascii_case("tor")) {
            let tor = providers.remove(i);
            providers.insert(0, tor);
        }
        let reasons: Vec<&'static str> = ranked.iter().take(5).copied().collect();
        let top_provider = providers.first().cloned().unwrap_or_default();

        IntelReport {
            verdict,
            score,
            detections: matches.len(),
            sources: source_set.len(),
            top_provider,
            providers,
            flags: all_flags,
            reasons,
            matches,
        }
    }
}

fn max_prefix<T: Ord + Copy + Default>(values: &[T]) -> Box<[T]> {
    let mut out = vec![T::default(); values.len()].into_boxed_slice();
    let mut max = T::default();
    for (i, &value) in values.iter().enumerate() {
        if value > max {
            max = value;
        }
        out[i] = max;
    }
    out
}

fn calibrate_weights(v4_vals: &[u16], value_table: &[[u32; 4]]) -> [f64; 20] {
    if v4_vals.is_empty() {
        return FLAG_BASE_WEIGHTS;
    }
    let mut counts = [0usize; 20];
    for &vid in v4_vals {
        let bits = value_table[vid as usize][0];
        #[allow(clippy::needless_range_loop)]
        for i in 0..20 {
            if bits & (1 << i) != 0 {
                counts[i] += 1;
            }
        }
    }
    let total = v4_vals.len() as f64;
    let mut weights = [0f64; 20];
    #[allow(clippy::needless_range_loop)]
    for i in 0..20 {
        let rarity = (total / counts[i].max(1) as f64).log2();
        weights[i] = FLAG_BASE_WEIGHTS[i] * (1.0 + rarity / 24.0);
    }
    weights
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn u16le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn u128_le(bytes: &[u8], offset: usize) -> u128 {
    let lo = u64le(bytes, offset) as u128;
    let hi = u64le(bytes, offset + 8) as u128;
    (hi << 64) | lo
}
