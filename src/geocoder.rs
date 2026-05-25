//! `(lat, lon)` → [`Place`] over the genom `geo.bin` format.
//!
//! Owns the file as `Box<[u8]>` (no leak, no mmap). Sorted `Box<[(u32, u32)]>`
//! grid indexes + binary search. Varint/zigzag decode on demand; strings and
//! postal-offset tables are read on demand.

use std::str::FromStr;

use anyhow::{Result, bail};
use chrono::{Offset, TimeZone, Utc};
use chrono_tz::Tz;

use crate::db::Database;

/// Enriched reverse-geocoding result.
#[derive(Debug, Clone)]
pub struct Place {
    /// City or locality name.
    pub city: String,
    /// Region / state / province full name.
    pub region: String,
    /// ISO 3166-2 region code.
    pub region_code: String,
    /// District / county.
    pub district: String,
    /// ISO 3166-1 alpha-2 country code.
    pub country_code: String,
    /// Full country name.
    pub country_name: String,
    /// Postal / ZIP code.
    pub postal_code: String,
    /// IANA timezone id.
    pub timezone: String,
    /// Current timezone abbreviation.
    pub timezone_abbr: String,
    /// Current UTC offset in seconds.
    pub utc_offset: i32,
    /// Formatted UTC offset (e.g. `UTC+1`).
    pub utc_offset_str: String,
    /// Latitude in decimal degrees.
    pub latitude: f64,
    /// Longitude in decimal degrees.
    pub longitude: f64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Two-letter continent code.
    pub continent_code: String,
    /// Full continent name.
    pub continent_name: String,
    /// EU member state.
    pub is_eu: bool,
    /// DST currently active.
    pub dst_active: bool,
}

const GRID_LON: i32 = 3600;
const GRID_LAT: i32 = 1800;
const GRID_SCALE: f64 = 10.0;
const PGRID_LON: i32 = 36000;
const PGRID_LAT: i32 = 18000;
const PGRID_SCALE: f64 = 100.0;

/// Reverse-geocoder backed by a genom `geo.bin`.
pub struct Geocoder {
    bytes: Box<[u8]>,
    str_offsets_off: usize,
    str_count: usize,
    str_body_off: usize,
    cc_off: usize,
    grid: Box<[(u32, u32)]>,
    cities_range: (usize, usize),
    postal: Box<[PostalCountry]>,
}

struct PostalCountry {
    cc: u16,
    ps_offsets_off: usize,
    ps_body_off: usize,
    cell_dir: Box<[(u32, u32)]>,
    body_off: usize,
}

struct CityHit {
    lat: i64,
    lon: i64,
    name_i: u32,
    a1_i: u32,
    a2_i: u32,
    a1c_i: u32,
    tz_i: u32,
    cc: u16,
}

impl Database for Geocoder {
    const NAME: &'static str = "genom";
    const URL: &'static str = "https://github.com/tn3w/genom/releases/latest/download/geo.bin";

    fn parse(bytes: Box<[u8]>) -> Result<Self> {
        Self::parse(bytes)
    }
}

impl Geocoder {
    /// Parse a `geo.bin` blob into a queryable database.
    pub fn parse(bytes: Box<[u8]>) -> Result<Self> {
        if bytes.len() < 64 || &bytes[..4] != b"GEO1" {
            bail!("bad genom geo.bin");
        }
        let data = &bytes[..];
        let off_str = u32le(data, 8) as usize;
        let off_cc = u32le(data, 16) as usize;
        let off_grid = u32le(data, 24) as usize;
        let off_cities = u32le(data, 32) as usize;
        let len_cities = u32le(data, 36) as usize;
        let off_pdir = u32le(data, 40) as usize;
        let off_postal = u32le(data, 48) as usize;

        let str_count = u32le(data, off_str) as usize;
        let str_offsets_off = off_str + 4;
        let str_body_off = str_offsets_off + 4 * (str_count + 1);
        let cc_off = off_cc + 4;

        let grid = decode_grid(data, off_grid);

        let pdir_count = u32le(data, off_pdir) as usize;
        let mut postal: Vec<PostalCountry> = Vec::with_capacity(pdir_count);
        let mut cursor = off_pdir + 4;
        for _ in 0..pdir_count {
            let cc = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
            let start = u32le(data, cursor + 4) as usize;
            let end = u32le(data, cursor + 8) as usize;
            cursor += 12;
            postal.push(parse_pcountry(data, cc, off_postal + start, off_postal + end));
        }
        postal.sort_unstable_by_key(|c| c.cc);

        Ok(Self {
            bytes,
            str_offsets_off,
            str_count,
            str_body_off,
            cc_off,
            grid,
            cities_range: (off_cities, off_cities + len_cities),
            postal: postal.into_boxed_slice(),
        })
    }

    /// Reverse-geocode `(latitude, longitude)`.
    pub fn lookup(&self, latitude: f64, longitude: f64) -> Option<Place> {
        let city = self.nearest_city(latitude, longitude)?;
        let postal = self.nearest_postal(city.cc, latitude, longitude).unwrap_or("");
        Some(enrich(
            self.str_at(city.name_i),
            self.str_at(city.a1_i),
            self.str_at(city.a1c_i),
            self.str_at(city.a2_i),
            self.cc_iso(city.cc),
            postal,
            self.str_at(city.tz_i),
            city.lat as f64 / 1e6,
            city.lon as f64 / 1e6,
        ))
    }

    fn str_at(&self, i: u32) -> &str {
        let i = i as usize;
        if i + 1 > self.str_count {
            return "";
        }
        let s = u32le(&self.bytes, self.str_offsets_off + 4 * i) as usize;
        let e = u32le(&self.bytes, self.str_offsets_off + 4 * (i + 1)) as usize;
        std::str::from_utf8(&self.bytes[self.str_body_off + s..self.str_body_off + e]).unwrap_or("")
    }

    fn cc_iso(&self, i: u16) -> &str {
        let p = self.cc_off + (i as usize) * 2;
        std::str::from_utf8(self.bytes.get(p..p + 2).unwrap_or(&[])).unwrap_or("")
    }

    fn nearest_city(&self, lat: f64, lon: f64) -> Option<CityHit> {
        let cities = &self.bytes[self.cities_range.0..self.cities_range.1];
        if cities.is_empty() {
            return None;
        }
        let lat_q = (lat * 1e6) as i64;
        let lon_q = (lon * 1e6) as i64;
        let cell = cell_of(lat, lon, GRID_SCALE, GRID_LAT, GRID_LON);
        let base_la = (cell / GRID_LON as u32) as i32;
        let base_lo = (cell % GRID_LON as u32) as i32;
        let mut best: Option<(i64, CityHit)> = None;
        let mut r = 1i32;
        loop {
            for dla in -r..=r {
                for dlo in -r..=r {
                    let la = base_la + dla;
                    let lo = base_lo + dlo;
                    if !(0..GRID_LAT).contains(&la) || !(0..GRID_LON).contains(&lo) {
                        continue;
                    }
                    let c = (la * GRID_LON + lo) as u32;
                    if let Some(off) = bsearch(&self.grid, c) {
                        scan_city_cell(cities, off as usize, lat_q, lon_q, &mut best);
                    }
                }
            }
            if best.is_some() || r > 200 {
                break;
            }
            r = (r * 2).max(r + 1);
        }
        best.map(|(_, c)| c)
    }

    fn nearest_postal(&self, cc: u16, lat: f64, lon: f64) -> Option<&str> {
        let i = self.postal.binary_search_by_key(&cc, |c| c.cc).ok()?;
        let pc = &self.postal[i];
        let lat_q = (lat * 1e6) as i64;
        let lon_q = (lon * 1e6) as i64;
        let cell = cell_of(lat, lon, PGRID_SCALE, PGRID_LAT, PGRID_LON);
        let base_la = (cell / PGRID_LON as u32) as i32;
        let base_lo = (cell % PGRID_LON as u32) as i32;
        let mut best: Option<(i64, u32)> = None;
        let mut r = 1i32;
        loop {
            for dla in -r..=r {
                for dlo in -r..=r {
                    let la = base_la + dla;
                    let lo = base_lo + dlo;
                    if !(0..PGRID_LAT).contains(&la) || !(0..PGRID_LON).contains(&lo) {
                        continue;
                    }
                    let c = (la * PGRID_LON + lo) as u32;
                    if let Some(off) = bsearch(&pc.cell_dir, c) {
                        scan_postal_cell(
                            &self.bytes[pc.body_off + off as usize..],
                            lat_q,
                            lon_q,
                            &mut best,
                        );
                    }
                }
            }
            if best.is_some() || r > 1000 {
                break;
            }
            r = (r * 2).max(r + 1);
        }
        let (_, ps_i) = best?;
        let s = u32le(&self.bytes, pc.ps_offsets_off + 4 * ps_i as usize) as usize;
        let e = u32le(&self.bytes, pc.ps_offsets_off + 4 * (ps_i as usize + 1)) as usize;
        std::str::from_utf8(&self.bytes[pc.ps_body_off + s..pc.ps_body_off + e]).ok()
    }
}

fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

fn varint(d: &[u8]) -> (u64, usize) {
    let mut value = 0u64;
    let mut shift = 0;
    let mut i = 0;
    loop {
        let byte = d[i];
        i += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return (value, i);
        }
        shift += 7;
    }
}

fn zigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

fn cell_of(lat: f64, lon: f64, scale: f64, max_la: i32, max_lo: i32) -> u32 {
    let la = (((lat + 90.0) * scale).floor() as i32).clamp(0, max_la - 1);
    let lo = (((lon + 180.0) * scale).floor() as i32).clamp(0, max_lo - 1);
    (la * max_lo + lo) as u32
}

fn bsearch(v: &[(u32, u32)], key: u32) -> Option<u32> {
    v.binary_search_by_key(&key, |&(k, _)| k).ok().map(|i| v[i].1)
}

fn decode_grid(d: &[u8], off: usize) -> Box<[(u32, u32)]> {
    let n = u32le(d, off) as usize;
    let mut out = Vec::with_capacity(n);
    let mut p = off + 4;
    let mut cell = 0u32;
    let mut byte_off = 0u32;
    for _ in 0..n {
        let (dc, k) = varint(&d[p..]);
        p += k;
        let (deo, k) = varint(&d[p..]);
        p += k;
        cell += dc as u32;
        byte_off += deo as u32;
        out.push((cell, byte_off));
    }
    out.into_boxed_slice()
}

fn parse_pcountry(d: &[u8], cc: u16, start: usize, end: usize) -> PostalCountry {
    let sec = &d[start..end];
    let mut p = 0;
    let tuple_count = u32le(sec, p) as usize;
    p += 4;
    p += tuple_count * 12;
    let ps_count = u32le(sec, p) as usize;
    p += 4;
    let ps_offsets_off = start + p;
    p += 4 * (ps_count + 1);
    let body_len = u32le(sec, ps_offsets_off - start + 4 * ps_count) as usize;
    let ps_body_off = start + p;
    p += body_len;
    let (cell_count, k) = varint(&sec[p..]);
    p += k;
    let mut cd = Vec::with_capacity(cell_count as usize);
    let mut cell = 0u32;
    let mut byte_off = 0u32;
    for _ in 0..cell_count {
        let (dc, k) = varint(&sec[p..]);
        p += k;
        let (deo, k) = varint(&sec[p..]);
        p += k;
        cell += dc as u32;
        byte_off += deo as u32;
        cd.push((cell, byte_off));
    }
    PostalCountry {
        cc,
        ps_offsets_off,
        ps_body_off,
        cell_dir: cd.into_boxed_slice(),
        body_off: start + p,
    }
}

fn scan_city_cell(
    buf: &[u8],
    off: usize,
    lat_q: i64,
    lon_q: i64,
    best: &mut Option<(i64, CityHit)>,
) {
    let mut i = off;
    let (n, k) = varint(&buf[i..]);
    i += k;
    let mut lat = 0i64;
    let mut lon = 0i64;
    for _ in 0..n {
        let (dl, k) = varint(&buf[i..]);
        i += k;
        let (do_, k) = varint(&buf[i..]);
        i += k;
        lat += zigzag(dl);
        lon += zigzag(do_);
        let (name_i, k) = varint(&buf[i..]);
        i += k;
        let (a1_i, k) = varint(&buf[i..]);
        i += k;
        let (a2_i, k) = varint(&buf[i..]);
        i += k;
        let (a1c_i, k) = varint(&buf[i..]);
        i += k;
        let (tz_i, k) = varint(&buf[i..]);
        i += k;
        let (cc, k) = varint(&buf[i..]);
        i += k;
        let dx = lat - lat_q;
        let dy = lon - lon_q;
        let d2 = dx * dx + dy * dy;
        if best.as_ref().is_none_or(|(c, _)| d2 < *c) {
            *best = Some((
                d2,
                CityHit {
                    lat,
                    lon,
                    name_i: name_i as u32,
                    a1_i: a1_i as u32,
                    a2_i: a2_i as u32,
                    a1c_i: a1c_i as u32,
                    tz_i: tz_i as u32,
                    cc: cc as u16,
                },
            ));
        }
    }
}

fn scan_postal_cell(buf: &[u8], lat_q: i64, lon_q: i64, best: &mut Option<(i64, u32)>) {
    let mut i = 0;
    let (n, k) = varint(&buf[i..]);
    i += k;
    let mut lat = 0i64;
    let mut lon = 0i64;
    for _ in 0..n {
        let (dl, k) = varint(&buf[i..]);
        i += k;
        let (do_, k) = varint(&buf[i..]);
        i += k;
        lat += zigzag(dl);
        lon += zigzag(do_);
        let (ps_i, k) = varint(&buf[i..]);
        i += k;
        let (_tuple_i, k) = varint(&buf[i..]);
        i += k;
        let dx = lat - lat_q;
        let dy = lon - lon_q;
        let d2 = dx * dx + dy * dy;
        if best.is_none_or(|(c, _)| d2 < c) {
            *best = Some((d2, ps_i as u32));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn enrich(
    city: &str,
    region: &str,
    region_code: &str,
    district: &str,
    cc: &str,
    postal: &str,
    timezone: &str,
    latitude: f64,
    longitude: f64,
) -> Place {
    let (tz_abbr, off_sec, off_str, dst) = Tz::from_str(timezone)
        .ok()
        .map(|tz| {
            let local = Utc::now().with_timezone(&tz);
            let secs = local.offset().fix().local_minus_utc();
            (format!("{}", local.format("%Z")), secs, fmt_offset(secs), is_dst(&tz, secs))
        })
        .unwrap_or_else(|| (String::new(), 0, "UTC+0".into(), false));
    let info = country_info(cc);
    Place {
        city: city.into(),
        region: region.into(),
        region_code: region_code.into(),
        district: district.into(),
        country_code: cc.into(),
        country_name: info.map(|i| i.name).unwrap_or("Unknown").into(),
        postal_code: postal.into(),
        timezone: timezone.into(),
        timezone_abbr: tz_abbr,
        utc_offset: off_sec,
        utc_offset_str: off_str,
        latitude,
        longitude,
        currency: info.map(|i| i.currency).unwrap_or("").into(),
        continent_code: info.map(|i| cont_code(i.cont)).unwrap_or("").into(),
        continent_name: info.and_then(|i| cont_name(i.cont)).unwrap_or("Unknown").into(),
        is_eu: info.is_some_and(|i| i.eu),
        dst_active: dst,
    }
}

fn fmt_offset(s: i32) -> String {
    let h = s / 3600;
    let m = (s.abs() % 3600) / 60;
    if m == 0 {
        format!("UTC{:+}", h)
    } else {
        format!("UTC{:+}:{:02}", h, m)
    }
}

fn is_dst(tz: &Tz, secs: i32) -> bool {
    let j = tz.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap().offset().fix().local_minus_utc();
    let l = tz.with_ymd_and_hms(2024, 7, 15, 12, 0, 0).unwrap().offset().fix().local_minus_utc();
    secs != j.min(l)
}

#[derive(Copy, Clone)]
struct CInfo {
    name: &'static str,
    currency: &'static str,
    cont: u16,
    eu: bool,
}

const fn cc(s: &[u8; 2]) -> u16 {
    u16::from_be_bytes([s[0], s[1]])
}

fn country_info(s: &str) -> Option<CInfo> {
    let b = s.as_bytes();
    if b.len() != 2 {
        return None;
    }
    let key = u16::from_be_bytes([b[0], b[1]]);
    COUNTRIES.binary_search_by_key(&key, |e| e.0).ok().map(|i| COUNTRIES[i].1)
}

fn cont_code(c: u16) -> &'static str {
    CONTINENTS.iter().find(|e| e.0 == c).map(|e| e.1).unwrap_or("")
}

fn cont_name(c: u16) -> Option<&'static str> {
    CONTINENTS.iter().find(|e| e.0 == c).map(|e| e.2)
}

const CONTINENTS: &[(u16, &str, &str)] = &[
    (cc(b"AF"), "AF", "Africa"),
    (cc(b"AN"), "AN", "Antarctica"),
    (cc(b"AS"), "AS", "Asia"),
    (cc(b"EU"), "EU", "Europe"),
    (cc(b"NA"), "NA", "North America"),
    (cc(b"OC"), "OC", "Oceania"),
    (cc(b"SA"), "SA", "South America"),
];

const fn c(name: &'static str, currency: &'static str, cont: &[u8; 2], eu: bool) -> CInfo {
    CInfo { name, currency, cont: cc(cont), eu }
}

const COUNTRIES: &[(u16, CInfo)] = &[
    (cc(b"AD"), c("Andorra", "EUR", b"EU", false)),
    (cc(b"AE"), c("United Arab Emirates", "AED", b"AS", false)),
    (cc(b"AF"), c("Afghanistan", "AFN", b"AS", false)),
    (cc(b"AG"), c("Antigua and Barbuda", "XCD", b"NA", false)),
    (cc(b"AI"), c("Anguilla", "XCD", b"NA", false)),
    (cc(b"AL"), c("Albania", "ALL", b"EU", false)),
    (cc(b"AM"), c("Armenia", "AMD", b"AS", false)),
    (cc(b"AN"), c("Netherlands Antilles", "ANG", b"NA", false)),
    (cc(b"AO"), c("Angola", "AOA", b"AF", false)),
    (cc(b"AQ"), c("Antarctica", "USD", b"AN", false)),
    (cc(b"AR"), c("Argentina", "ARS", b"SA", false)),
    (cc(b"AS"), c("American Samoa", "USD", b"OC", false)),
    (cc(b"AT"), c("Austria", "EUR", b"EU", true)),
    (cc(b"AU"), c("Australia", "AUD", b"OC", false)),
    (cc(b"AW"), c("Aruba", "AWG", b"\0\0", false)),
    (cc(b"AZ"), c("Azerbaijan", "AZN", b"AS", false)),
    (cc(b"BA"), c("Bosnia and Herzegovina", "BAM", b"EU", false)),
    (cc(b"BB"), c("Barbados", "BBD", b"NA", false)),
    (cc(b"BD"), c("Bangladesh", "BDT", b"AS", false)),
    (cc(b"BE"), c("Belgium", "EUR", b"EU", true)),
    (cc(b"BF"), c("Burkina Faso", "XOF", b"AF", false)),
    (cc(b"BG"), c("Bulgaria", "BGN", b"EU", true)),
    (cc(b"BH"), c("Bahrain", "BHD", b"AS", false)),
    (cc(b"BI"), c("Burundi", "BIF", b"AF", false)),
    (cc(b"BJ"), c("Benin", "XOF", b"AF", false)),
    (cc(b"BM"), c("Bermuda", "BMD", b"NA", false)),
    (cc(b"BN"), c("Brunei", "BND", b"AS", false)),
    (cc(b"BO"), c("Bolivia", "BOB", b"SA", false)),
    (cc(b"BR"), c("Brazil", "BRL", b"SA", false)),
    (cc(b"BS"), c("Bahamas", "BSD", b"NA", false)),
    (cc(b"BT"), c("Bhutan", "BTN", b"AS", false)),
    (cc(b"BV"), c("Bouvet Island", "NOK", b"AN", false)),
    (cc(b"BW"), c("Botswana", "BWP", b"AF", false)),
    (cc(b"BY"), c("Belarus", "BYR", b"EU", false)),
    (cc(b"BZ"), c("Belize", "BZD", b"NA", false)),
    (cc(b"CA"), c("Canada", "CAD", b"NA", false)),
    (cc(b"CC"), c("Cocos (Keeling) Islands", "AUD", b"AS", false)),
    (cc(b"CD"), c("Democratic Republic of the Congo", "CDF", b"AF", false)),
    (cc(b"CF"), c("Central African Republic", "XAF", b"AF", false)),
    (cc(b"CG"), c("Republic of the Congo", "XAF", b"AF", false)),
    (cc(b"CH"), c("Switzerland", "CHF", b"EU", false)),
    (cc(b"CI"), c("Ivory Coast", "XOF", b"AF", false)),
    (cc(b"CK"), c("Cook Islands", "NZD", b"OC", false)),
    (cc(b"CL"), c("Chile", "CLP", b"SA", false)),
    (cc(b"CM"), c("Cameroon", "XAF", b"AF", false)),
    (cc(b"CN"), c("China", "CNY", b"AS", false)),
    (cc(b"CO"), c("Colombia", "COP", b"SA", false)),
    (cc(b"CR"), c("Costa Rica", "CRC", b"NA", false)),
    (cc(b"CS"), c("Serbia and Montenegro", "RSD", b"EU", false)),
    (cc(b"CU"), c("Cuba", "CUP", b"NA", false)),
    (cc(b"CV"), c("Cape Verde", "CVE", b"AF", false)),
    (cc(b"CX"), c("Christmas Island", "AUD", b"AS", false)),
    (cc(b"CY"), c("Cyprus", "EUR", b"EU", true)),
    (cc(b"CZ"), c("Czech Republic", "CZK", b"EU", true)),
    (cc(b"DE"), c("Germany", "EUR", b"EU", true)),
    (cc(b"DJ"), c("Djibouti", "DJF", b"AF", false)),
    (cc(b"DK"), c("Denmark", "DKK", b"EU", true)),
    (cc(b"DM"), c("Dominica", "XCD", b"NA", false)),
    (cc(b"DO"), c("Dominican Republic", "DOP", b"NA", false)),
    (cc(b"DZ"), c("Algeria", "DZD", b"AF", false)),
    (cc(b"EC"), c("Ecuador", "USD", b"SA", false)),
    (cc(b"EE"), c("Estonia", "EUR", b"EU", true)),
    (cc(b"EG"), c("Egypt", "EGP", b"AF", false)),
    (cc(b"EH"), c("Western Sahara", "MAD", b"AF", false)),
    (cc(b"ER"), c("Eritrea", "ERN", b"AF", false)),
    (cc(b"ES"), c("Spain", "EUR", b"EU", true)),
    (cc(b"ET"), c("Ethiopia", "ETB", b"AF", false)),
    (cc(b"FI"), c("Finland", "EUR", b"EU", true)),
    (cc(b"FJ"), c("Fiji", "FJD", b"OC", false)),
    (cc(b"FK"), c("Falkland Islands", "FKP", b"SA", false)),
    (cc(b"FM"), c("Micronesia", "USD", b"OC", false)),
    (cc(b"FO"), c("Faroe Islands", "DKK", b"\0\0", false)),
    (cc(b"FR"), c("France", "EUR", b"EU", true)),
    (cc(b"GA"), c("Gabon", "XAF", b"AF", false)),
    (cc(b"GB"), c("United Kingdom", "GBP", b"EU", false)),
    (cc(b"GD"), c("Grenada", "XCD", b"NA", false)),
    (cc(b"GE"), c("Georgia", "GEL", b"AS", false)),
    (cc(b"GF"), c("French Guiana", "EUR", b"SA", false)),
    (cc(b"GH"), c("Ghana", "GHS", b"AF", false)),
    (cc(b"GI"), c("Gibraltar", "GIP", b"EU", false)),
    (cc(b"GL"), c("Greenland", "DKK", b"NA", false)),
    (cc(b"GM"), c("Gambia", "GMD", b"AF", false)),
    (cc(b"GN"), c("Guinea", "GNF", b"AF", false)),
    (cc(b"GP"), c("Guadeloupe", "EUR", b"NA", false)),
    (cc(b"GQ"), c("Equatorial Guinea", "XAF", b"AF", false)),
    (cc(b"GR"), c("Greece", "EUR", b"EU", true)),
    (cc(b"GS"), c("South Georgia and the South Sandwich Islands", "GBP", b"AN", false)),
    (cc(b"GT"), c("Guatemala", "GTQ", b"NA", false)),
    (cc(b"GU"), c("Guam", "USD", b"OC", false)),
    (cc(b"GW"), c("Guinea-Bissau", "XOF", b"AF", false)),
    (cc(b"GY"), c("Guyana", "GYD", b"SA", false)),
    (cc(b"HK"), c("Hong Kong", "HKD", b"AS", false)),
    (cc(b"HM"), c("Heard Island and McDonald Islands", "AUD", b"AN", false)),
    (cc(b"HN"), c("Honduras", "HNL", b"NA", false)),
    (cc(b"HR"), c("Croatia", "HRK", b"EU", true)),
    (cc(b"HT"), c("Haiti", "HTG", b"NA", false)),
    (cc(b"HU"), c("Hungary", "HUF", b"EU", true)),
    (cc(b"ID"), c("Indonesia", "IDR", b"AS", false)),
    (cc(b"IE"), c("Ireland", "EUR", b"EU", true)),
    (cc(b"IL"), c("Israel", "ILS", b"AS", false)),
    (cc(b"IN"), c("India", "INR", b"AS", false)),
    (cc(b"IO"), c("British Indian Ocean Territory", "USD", b"AS", false)),
    (cc(b"IQ"), c("Iraq", "IQD", b"AS", false)),
    (cc(b"IR"), c("Iran", "IRR", b"AS", false)),
    (cc(b"IS"), c("Iceland", "ISK", b"EU", false)),
    (cc(b"IT"), c("Italy", "EUR", b"EU", true)),
    (cc(b"JM"), c("Jamaica", "JMD", b"NA", false)),
    (cc(b"JO"), c("Jordan", "JOD", b"AS", false)),
    (cc(b"JP"), c("Japan", "JPY", b"AS", false)),
    (cc(b"KE"), c("Kenya", "KES", b"AF", false)),
    (cc(b"KG"), c("Kyrgyzstan", "KGS", b"AS", false)),
    (cc(b"KH"), c("Cambodia", "KHR", b"AS", false)),
    (cc(b"KI"), c("Kiribati", "AUD", b"OC", false)),
    (cc(b"KM"), c("Comoros", "KMF", b"AF", false)),
    (cc(b"KN"), c("Saint Kitts and Nevis", "XCD", b"NA", false)),
    (cc(b"KP"), c("North Korea", "KPW", b"AS", false)),
    (cc(b"KR"), c("South Korea", "KRW", b"AS", false)),
    (cc(b"KW"), c("Kuwait", "KWD", b"AS", false)),
    (cc(b"KY"), c("Cayman Islands", "KYD", b"NA", false)),
    (cc(b"KZ"), c("Kazakhstan", "KZT", b"AS", false)),
    (cc(b"LA"), c("Laos", "LAK", b"AS", false)),
    (cc(b"LB"), c("Lebanon", "LBP", b"AS", false)),
    (cc(b"LC"), c("Saint Lucia", "XCD", b"NA", false)),
    (cc(b"LI"), c("Liechtenstein", "CHF", b"EU", false)),
    (cc(b"LK"), c("Sri Lanka", "LKR", b"AS", false)),
    (cc(b"LR"), c("Liberia", "LRD", b"AF", false)),
    (cc(b"LS"), c("Lesotho", "LSL", b"AF", false)),
    (cc(b"LT"), c("Lithuania", "EUR", b"EU", true)),
    (cc(b"LU"), c("Luxembourg", "EUR", b"EU", true)),
    (cc(b"LV"), c("Latvia", "EUR", b"EU", true)),
    (cc(b"LY"), c("Libya", "LYD", b"AF", false)),
    (cc(b"MA"), c("Morocco", "MAD", b"AF", false)),
    (cc(b"MC"), c("Monaco", "EUR", b"EU", false)),
    (cc(b"MD"), c("Moldova", "MDL", b"EU", false)),
    (cc(b"ME"), c("Montenegro", "", b"EU", false)),
    (cc(b"MG"), c("Madagascar", "MGA", b"AF", false)),
    (cc(b"MH"), c("Marshall Islands", "USD", b"OC", false)),
    (cc(b"MK"), c("Macedonia", "MKD", b"EU", false)),
    (cc(b"ML"), c("Mali", "XOF", b"AF", false)),
    (cc(b"MM"), c("Myanmar", "MMK", b"AS", false)),
    (cc(b"MN"), c("Mongolia", "MNT", b"AS", false)),
    (cc(b"MO"), c("Macau", "MOP", b"AS", false)),
    (cc(b"MP"), c("Northern Mariana Islands", "USD", b"OC", false)),
    (cc(b"MQ"), c("Martinique", "EUR", b"NA", false)),
    (cc(b"MR"), c("Mauritania", "MRU", b"AF", false)),
    (cc(b"MS"), c("Montserrat", "XCD", b"NA", false)),
    (cc(b"MT"), c("Malta", "EUR", b"EU", true)),
    (cc(b"MU"), c("Mauritius", "MUR", b"AF", false)),
    (cc(b"MV"), c("Maldives", "MVR", b"AS", false)),
    (cc(b"MW"), c("Malawi", "MWK", b"AF", false)),
    (cc(b"MX"), c("Mexico", "MXN", b"NA", false)),
    (cc(b"MY"), c("Malaysia", "MYR", b"AS", false)),
    (cc(b"MZ"), c("Mozambique", "MZN", b"AF", false)),
    (cc(b"NA"), c("Namibia", "NAD", b"AF", false)),
    (cc(b"NC"), c("New Caledonia", "XPF", b"OC", false)),
    (cc(b"NE"), c("Niger", "XOF", b"AF", false)),
    (cc(b"NF"), c("Norfolk Island", "AUD", b"OC", false)),
    (cc(b"NG"), c("Nigeria", "NGN", b"AF", false)),
    (cc(b"NI"), c("Nicaragua", "NIO", b"NA", false)),
    (cc(b"NL"), c("Netherlands", "EUR", b"EU", true)),
    (cc(b"NO"), c("Norway", "NOK", b"EU", false)),
    (cc(b"NP"), c("Nepal", "NPR", b"AS", false)),
    (cc(b"NR"), c("Nauru", "AUD", b"OC", false)),
    (cc(b"NU"), c("Niue", "NZD", b"OC", false)),
    (cc(b"NZ"), c("New Zealand", "NZD", b"OC", false)),
    (cc(b"OM"), c("Oman", "OMR", b"AS", false)),
    (cc(b"PA"), c("Panama", "PAB", b"NA", false)),
    (cc(b"PE"), c("Peru", "PEN", b"SA", false)),
    (cc(b"PF"), c("French Polynesia", "XPF", b"OC", false)),
    (cc(b"PG"), c("Papua New Guinea", "PGK", b"OC", false)),
    (cc(b"PH"), c("Philippines", "PHP", b"AS", false)),
    (cc(b"PK"), c("Pakistan", "PKR", b"AS", false)),
    (cc(b"PL"), c("Poland", "PLN", b"EU", true)),
    (cc(b"PM"), c("Saint Pierre and Miquelon", "EUR", b"NA", false)),
    (cc(b"PN"), c("Pitcairn", "NZD", b"OC", false)),
    (cc(b"PR"), c("Puerto Rico", "USD", b"NA", false)),
    (cc(b"PS"), c("Palestinian Territory", "ILS", b"AS", false)),
    (cc(b"PT"), c("Portugal", "EUR", b"EU", true)),
    (cc(b"PW"), c("Palau", "USD", b"OC", false)),
    (cc(b"PY"), c("Paraguay", "PYG", b"SA", false)),
    (cc(b"QA"), c("Qatar", "QAR", b"AS", false)),
    (cc(b"RE"), c("Reunion", "EUR", b"\0\0", false)),
    (cc(b"RO"), c("Romania", "RON", b"EU", true)),
    (cc(b"RS"), c("Serbia", "", b"EU", false)),
    (cc(b"RU"), c("Russia", "RUB", b"EU", false)),
    (cc(b"RW"), c("Rwanda", "RWF", b"AF", false)),
    (cc(b"SA"), c("Saudi Arabia", "SAR", b"AS", false)),
    (cc(b"SB"), c("Solomon Islands", "SBD", b"OC", false)),
    (cc(b"SC"), c("Seychelles", "SCR", b"AF", false)),
    (cc(b"SD"), c("Sudan", "SDG", b"AF", false)),
    (cc(b"SE"), c("Sweden", "SEK", b"EU", true)),
    (cc(b"SG"), c("Singapore", "SGD", b"AS", false)),
    (cc(b"SH"), c("Saint Helena", "SHP", b"\0\0", false)),
    (cc(b"SI"), c("Slovenia", "EUR", b"EU", true)),
    (cc(b"SJ"), c("Svalbard and Jan Mayen", "NOK", b"EU", false)),
    (cc(b"SK"), c("Slovakia", "EUR", b"EU", true)),
    (cc(b"SL"), c("Sierra Leone", "SLL", b"AF", false)),
    (cc(b"SM"), c("San Marino", "EUR", b"EU", false)),
    (cc(b"SN"), c("Senegal", "XOF", b"AF", false)),
    (cc(b"SO"), c("Somalia", "SOS", b"AF", false)),
    (cc(b"SR"), c("Suriname", "SRD", b"SA", false)),
    (cc(b"ST"), c("São Tomé and Príncipe", "STN", b"AF", false)),
    (cc(b"SV"), c("El Salvador", "SVC", b"NA", false)),
    (cc(b"SY"), c("Syria", "SYP", b"AS", false)),
    (cc(b"SZ"), c("Swaziland", "SZL", b"AF", false)),
    (cc(b"TC"), c("Turks and Caicos Islands", "USD", b"NA", false)),
    (cc(b"TD"), c("Chad", "XAF", b"AF", false)),
    (cc(b"TF"), c("French Southern Territories", "EUR", b"AN", false)),
    (cc(b"TG"), c("Togo", "XOF", b"AF", false)),
    (cc(b"TH"), c("Thailand", "THB", b"AS", false)),
    (cc(b"TJ"), c("Tajikistan", "TJS", b"AS", false)),
    (cc(b"TK"), c("Tokelau", "NZD", b"OC", false)),
    (cc(b"TL"), c("East Timor", "USD", b"AS", false)),
    (cc(b"TM"), c("Turkmenistan", "TMT", b"AS", false)),
    (cc(b"TN"), c("Tunisia", "TND", b"AF", false)),
    (cc(b"TO"), c("Tonga", "TOP", b"OC", false)),
    (cc(b"TR"), c("Turkey", "TRY", b"AS", false)),
    (cc(b"TT"), c("Trinidad and Tobago", "TTD", b"\0\0", false)),
    (cc(b"TV"), c("Tuvalu", "AUD", b"OC", false)),
    (cc(b"TW"), c("Taiwan", "TWD", b"AS", false)),
    (cc(b"TZ"), c("Tanzania", "TZS", b"AF", false)),
    (cc(b"UA"), c("Ukraine", "UAH", b"EU", false)),
    (cc(b"UG"), c("Uganda", "UGX", b"AF", false)),
    (cc(b"UM"), c("United States Minor Outlying Islands", "USD", b"NA", false)),
    (cc(b"US"), c("United States", "USD", b"NA", false)),
    (cc(b"UY"), c("Uruguay", "UYU", b"SA", false)),
    (cc(b"UZ"), c("Uzbekistan", "UZS", b"AS", false)),
    (cc(b"VA"), c("Vatican City", "EUR", b"EU", false)),
    (cc(b"VC"), c("Saint Vincent and the Grenadines", "XCD", b"NA", false)),
    (cc(b"VE"), c("Venezuela", "VES", b"SA", false)),
    (cc(b"VG"), c("British Virgin Islands", "USD", b"\0\0", false)),
    (cc(b"VI"), c("U.S. Virgin Islands", "USD", b"NA", false)),
    (cc(b"VN"), c("Vietnam", "VND", b"AS", false)),
    (cc(b"VU"), c("Vanuatu", "VUV", b"OC", false)),
    (cc(b"WF"), c("Wallis and Futuna", "XPF", b"OC", false)),
    (cc(b"WS"), c("Samoa", "WST", b"OC", false)),
    (cc(b"YE"), c("Yemen", "YER", b"AS", false)),
    (cc(b"YT"), c("Mayotte", "EUR", b"\0\0", false)),
    (cc(b"ZA"), c("South Africa", "ZAR", b"AF", false)),
    (cc(b"ZM"), c("Zambia", "ZMW", b"AF", false)),
    (cc(b"ZW"), c("Zimbabwe", "ZWL", b"AF", false)),
];
