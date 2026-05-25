//! IP → ASN over the ASNDB `asndb-tiny.bin` (flavor 4) format.
//!
//! Layout — 104B header, sorted `TinyRec[24]` table (by ASN, for binary search),
//! sorted `Seg4[8]` + `Seg6[20]` segments (by start, for partition-point lookup),
//! deduped UTF-8 string pool (`u32 len + bytes`, offset 0 = empty).
//!
//! Provider brand cleanup is bundled at the bottom of this file (port of
//! <https://github.com/tn3w/ASNDB/blob/master/src/provider.rs>).

use std::net::IpAddr;

use anyhow::{Result, bail};

use crate::db::Database;

const MAGIC: u64 = 0x0004_4244_4E53_4144;
const FLAVOR_TINY: u8 = 4;
const TINY_REC_SIZE: usize = 24;
const HEADER_SIZE: usize = 104;
const NO_ASN: u32 = u32::MAX;

/// Per-ASN metadata returned for an IP lookup.
#[derive(Debug, Clone)]
pub struct AsnInfo {
    /// Autonomous System Number.
    pub asn: u32,
    /// RPSL handle (e.g. `CLOUDFLARENET - Cloudflare, Inc.`).
    pub name: String,
    /// CAIDA org name (e.g. `Cloudflare, Inc.`).
    pub company: String,
    /// Website URL if known.
    pub website: String,
    /// Cleaned brand derived from `name` + `company` (e.g. `Cloudflare`).
    pub provider: String,
    /// ISO 3166-1 alpha-2 country code for the ASN.
    pub country_code: String,
    /// CAIDA-derived AS kind (Tier-1, Transit, Content, ISP, ...).
    pub kind: &'static str,
    /// PeeringDB declared info type (NSP, Cable/DSL/ISP, Content, ...).
    pub info_type: &'static str,
    /// RIR that allocated the ASN.
    pub rir: &'static str,
}

/// IP → ASN database backed by `asndb-tiny.bin`.
pub struct Asndb {
    bytes: Box<[u8]>,
    tiny_off: usize,
    tiny_count: usize,
    seg4: Box<[(u32, u32)]>,
    seg6: Box<[(u128, u32)]>,
    str_off: usize,
}

impl Database for Asndb {
    const NAME: &'static str = "asndb-tiny";
    const URL: &'static str =
        "https://github.com/tn3w/ASNDB/releases/latest/download/asndb-tiny.bin";

    fn parse(bytes: Box<[u8]>) -> Result<Self> {
        Self::parse(bytes)
    }
}

impl Asndb {
    /// Parse an `asndb-tiny.bin` blob.
    pub fn parse(bytes: Box<[u8]>) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            bail!("asndb-tiny.bin too small");
        }
        if u64le(&bytes, 0) != MAGIC {
            bail!("bad asndb magic");
        }
        if bytes[8] != FLAVOR_TINY {
            bail!("expected asndb-tiny (flavor {FLAVOR_TINY}), got {}", bytes[8]);
        }
        let tiny_count = u32le(&bytes, 16) as usize;
        let seg4_count = u32le(&bytes, 20) as usize;
        let seg6_count = u32le(&bytes, 24) as usize;
        let tiny_off = u64le(&bytes, 40) as usize;
        let seg4_off = u64le(&bytes, 48) as usize;
        let seg6_off = u64le(&bytes, 56) as usize;
        let str_off = u64le(&bytes, 88) as usize;

        let seg4: Box<[(u32, u32)]> = (0..seg4_count)
            .map(|i| {
                let o = seg4_off + i * 8;
                (u32le(&bytes, o), u32le(&bytes, o + 4))
            })
            .collect();
        let seg6: Box<[(u128, u32)]> = (0..seg6_count)
            .map(|i| {
                let o = seg6_off + i * 20;
                let start = u128::from_be_bytes(bytes[o..o + 16].try_into().unwrap());
                let asn_idx = u32le(&bytes, o + 16);
                (start, asn_idx)
            })
            .collect();

        Ok(Self { bytes, tiny_off, tiny_count, seg4, seg6, str_off })
    }

    /// Reverse-lookup an IP. Returns `None` if the IP is in an unassigned
    /// segment or outside the known address space.
    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        let idx = match ip {
            IpAddr::V4(v4) => self.lookup_v4(u32::from(v4))?,
            IpAddr::V6(v6) => self.lookup_v6(u128::from(v6))?,
        };
        self.info_at(idx)
    }

    fn lookup_v4(&self, ip: u32) -> Option<u32> {
        let pos = self.seg4.partition_point(|&(start, _)| start <= ip);
        let idx = self.seg4.get(pos.checked_sub(1)?)?.1;
        (idx != NO_ASN).then_some(idx)
    }

    fn lookup_v6(&self, ip: u128) -> Option<u32> {
        let pos = self.seg6.partition_point(|&(start, _)| start <= ip);
        let idx = self.seg6.get(pos.checked_sub(1)?)?.1;
        (idx != NO_ASN).then_some(idx)
    }

    fn info_at(&self, idx: u32) -> Option<AsnInfo> {
        if idx as usize >= self.tiny_count {
            return None;
        }
        let off = self.tiny_off + idx as usize * TINY_REC_SIZE;
        let rec = &self.bytes[off..off + TINY_REC_SIZE];
        let asn = u32le(rec, 0);
        let raw_name = self.string_at(u32le(rec, 4));
        let company = self.string_at(u32le(rec, 8)).to_string();
        let website = self.string_at(u32le(rec, 12)).to_string();
        let provider = provider(raw_name, &company);
        let name = split_first_token(raw_name);
        let country_code = std::str::from_utf8(&rec[16..18])
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        Some(AsnInfo {
            asn,
            name,
            company,
            website,
            provider,
            country_code,
            kind: kind_name(rec[18]),
            info_type: info_type_name(rec[19]),
            rir: rir_name(rec[20]),
        })
    }

    fn string_at(&self, offset: u32) -> &str {
        if offset == 0 {
            return "";
        }
        let o = self.str_off + offset as usize;
        if o + 4 > self.bytes.len() {
            return "";
        }
        let len = u32le(&self.bytes, o) as usize;
        let start = o + 4;
        if start + len > self.bytes.len() {
            return "";
        }
        std::str::from_utf8(&self.bytes[start..start + len]).unwrap_or("")
    }
}

fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn kind_name(value: u8) -> &'static str {
    match value {
        1 => "Tier-1",
        2 => "Transit",
        3 => "Content",
        4 => "ISP",
        5 => "Enterprise",
        6 => "Education",
        7 => "Non-Profit",
        8 => "Government",
        9 => "Personal",
        10 => "Stub",
        _ => "",
    }
}

fn info_type_name(value: u8) -> &'static str {
    match value {
        1 => "NSP",
        2 => "Cable/DSL/ISP",
        3 => "Content",
        4 => "Enterprise",
        5 => "Educational/Research",
        6 => "Non-Profit",
        7 => "Route Server",
        8 => "Network Services",
        9 => "Route Collector",
        10 => "Government",
        11 => "Personal",
        _ => "",
    }
}

fn rir_name(value: u8) -> &'static str {
    match value {
        1 => "ARIN",
        2 => "RIPE",
        3 => "APNIC",
        4 => "AFRINIC",
        5 => "LACNIC",
        _ => "",
    }
}

const PROVIDER_DROP: &[&str] = &[
    "inc", "llc", "ltd", "limited", "gmbh", "ag", "corp", "corporation",
    "co", "company", "sa", "sl", "bv", "srl", "pty", "plc", "kg", "ohg", "se",
    "ug", "spa", "ab", "as", "oy", "oyj", "kft", "doo", "sas", "eurl", "ltda",
    "online", "networks", "network", "telecom", "telecommunications",
    "communications", "comunicaciones", "hosting", "solutions", "services",
    "technologies", "technology", "tech", "group", "holdings", "holding",
    "international", "global", "internet", "systems", "system", "data",
    "datacenter", "cloud", "isp", "of", "and", "parent", "enterprises",
    "enterprise", "backbone",
];
const PROVIDER_LEAD_DROP: &[&str] = &["the", "pt", "pp", "ps", "ip", "uab"];
const PROVIDER_RIR_SUFFIX: &[&str] = &[
    "AS", "AP", "US", "UK", "DE", "FR", "IN", "CN", "JP", "EU",
    "NET", "COM", "ORG",
];
const PROVIDER_NET_TAIL: &[&str] = &["net", "com", "tel", "web", "line"];
const PROVIDER_URL_SUFFIX: &[&str] = &[".com", ".net", ".org", ".io"];

fn in_set(set: &[&str], s: &str) -> bool {
    let lower = s.trim_matches(|c: char| ".,;:'\"".contains(c)).to_ascii_lowercase();
    set.iter().any(|x| *x == lower)
}

fn smart_tok(token: &str) -> String {
    let is_upper_alpha = !token.is_empty()
        && token.chars().all(|c| c.is_ascii_alphabetic())
        && token.chars().all(|c| c.is_ascii_uppercase());
    if is_upper_alpha && token.len() >= 5 { title(token) } else { token.to_string() }
}

fn title(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        if i == 0 { out.extend(c.to_uppercase()); }
        else { out.extend(c.to_lowercase()); }
    }
    out
}

fn smart_case(s: &str) -> String {
    s.split(' ').map(smart_tok).collect::<Vec<_>>().join(" ")
}

fn split_punct(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for c in s.chars() {
        if c.is_whitespace() || c == ',' || c == '(' || c == ')' {
            if !current.is_empty() { tokens.push(std::mem::take(&mut current)); }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() { tokens.push(current); }
    for token in tokens.iter_mut() {
        while token.ends_with('.') { token.pop(); }
    }
    tokens.into_iter().filter(|t| !t.is_empty()).collect()
}

fn from_company(company: &str) -> String {
    let mut tokens = split_punct(company.trim());
    while tokens.last().map(|t| in_set(PROVIDER_DROP, t)).unwrap_or(false) {
        tokens.pop();
    }
    while tokens.first().map(|t| in_set(PROVIDER_LEAD_DROP, t)).unwrap_or(false) {
        tokens.remove(0);
    }
    let mut out = tokens.join(" ");
    for suffix in PROVIDER_URL_SUFFIX {
        if out.to_ascii_lowercase().ends_with(suffix) {
            out.truncate(out.len() - suffix.len());
        }
    }
    smart_case(&out)
}

fn split_first_token(name: &str) -> String {
    if let Some(idx) = name.find(" - ") { return name[..idx].to_string(); }
    name.split_whitespace().next().unwrap_or("").to_string()
}

fn strip_rir_suffix(handle: &str) -> String {
    for suffix in PROVIDER_RIR_SUFFIX {
        if handle.len() > suffix.len() + 1
            && handle.as_bytes()[handle.len() - suffix.len() - 1] == b'-'
            && handle[handle.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            return handle[..handle.len() - suffix.len() - 1].to_string();
        }
    }
    handle.to_string()
}

fn strip_net_tail(handle: &str) -> String {
    let is_upper = handle.chars().all(|c| !c.is_ascii_lowercase());
    if handle.len() <= 4 || !is_upper { return handle.to_string(); }
    for suffix in PROVIDER_NET_TAIL {
        if handle.len() > suffix.len()
            && handle[handle.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            return handle[..handle.len() - suffix.len()].to_string();
        }
    }
    handle.to_string()
}

fn from_name(name: &str) -> String {
    let handle = split_first_token(name.trim());
    let handle = strip_rir_suffix(&handle);
    let handle = strip_net_tail(&handle);
    smart_case(&handle)
}

fn provider(name: &str, company: &str) -> String {
    let company_clean = if company.is_empty() { String::new() } else { from_company(company) };
    let handle = if name.is_empty() { String::new() } else { from_name(name) };
    if !company_clean.is_empty() && !handle.is_empty() {
        let cl = company_clean.to_ascii_lowercase();
        let hl = handle.to_ascii_lowercase();
        if cl == hl || cl.starts_with(&format!("{hl} ")) { return handle; }
        if hl.starts_with(&format!("{cl} ")) { return company_clean; }
    }
    if !company_clean.is_empty() { company_clean } else { handle }
}

#[cfg(test)]
mod tests {
    use super::provider;

    fn case(name: &str, org: &str, expected: &str) {
        let got = provider(name, org);
        assert_eq!(got, expected, "name={name:?} org={org:?}");
    }

    #[test]
    fn brands() {
        case("CLOUDFLARENET - Cloudflare, Inc.", "Cloudflare, Inc.", "Cloudflare");
        case("HETZNER-AS Hetzner Online GmbH", "Hetzner Online GmbH", "Hetzner");
        case("GOOGLE - Google LLC", "Google LLC", "Google");
        case("AMAZON-02 - Amazon.com, Inc.", "Amazon.com, Inc.", "Amazon");
        case("DTAG Deutsche Telekom AG", "Deutsche Telekom AG", "Deutsche Telekom");
        case("SOFTLAYER - IBM Cloud", "IBM Cloud", "IBM");
        case("OVH OVH SAS", "OVH SAS", "OVH");
        case("ATT-INTERNET4 - AT&T Enterprises, LLC", "AT&T Enterprises, LLC", "AT&T");
        case("TELUS Communications", "TELUS Communications Inc.", "Telus");
        case("M247 M247 Europe SRL", "M247 Europe SRL", "M247");
        case("netcup-AS netcup GmbH", "netcup GmbH", "netcup");
        case("APPLE-ENGINEERING - Apple Inc.", "Apple Inc.", "Apple");
        case("FACEBOOK - Facebook, Inc.", "Facebook, Inc.", "Facebook");
    }
}
