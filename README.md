# ipsight

IP enrichment with geo, threat, ASN data. Hot-swapping, self-updating DBs. Wait-free lookups.

## Pipeline

- IP → `(lat, lon)` — `IpGeo` (IP2X)
- `(lat, lon)` → `Place` — `Geocoder` (genom)
- IP → `IntelReport` — `Intel` (IPBlocklist)
- IP → `AsnInfo` — `Asndb` (ASNDB tiny)

Each DB loads from `~/.cache/ipsight/`, falls back to download, then refreshes every 24h in the background via `If-Modified-Since`. Atomic `ArcSwap` → readers never block.

## Use

```rust
use ipsight::Ipsight;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ipsight = Ipsight::new().await?;
    let report = ipsight.lookup("8.8.8.8".parse()?);
    println!("{:#?}", report);
    Ok(())
}
```

`Report { place, intel, asn }` — each field `Option`, `None` when no match.

## Example

```sh
$ cargo run --example lookup --release -- 1.1.1.1

loaded in 108.79ms

=== 1.1.1.1 (48.84µs) ===
[asn]
  asn             = AS13335
  name            = CLOUDFLARENET
  provider        = Cloudflare
  company         = Cloudflare, Inc.
  website         = https://www.cloudflare.com
  country_code    = US
  kind            = Content
  info_type       = Content
  rir             = ARIN
[place]
  city            = Brisbane
  region          = Queensland (04)
  district        = Brisbane
  country         = Australia (AU)
  postal_code     = 4000
  latitude        = -27.467940
  longitude       = 153.028090
  timezone        = Australia/Brisbane [AEST]
  utc_offset      = UTC+10 (36000s)
  dst_active      = false
  currency        = AUD
  continent       = Oceania (OC)
  is_eu           = false
[intel]
  verdict         = medium
  score           = 55.2
  detections      = 6
  sources         = 6
  top_provider    = Cloudflare
  providers       = Cloudflare
  flags           = vpn, anonymizer, datacenter, cdn, anycast
  reasons         = vpn, anonymizer, datacenter, cdn, anycast
  match           = 1.1.1.0-1.1.1.255 via Cloudflare [bgptools_vpn_asns] weight=36.3 flags=vpn,anonymizer
  match           = 1.1.1.0-1.1.1.255 via Cloudflare [riskdb_asn_hosting] weight=17.2 flags=datacenter
  match           = 1.1.1.0-1.1.1.255 via  [riskdb_hosting] weight=17.2 flags=datacenter
  match           = 1.1.1.0-1.1.1.255 via Cloudflare [bgptools_ddos_asns] weight=6.0 flags=cdn
  match           = 1.1.1.0-1.1.1.255 via Cloudflare [bgptools_cdn_asns] weight=6.0 flags=cdn
  match           = 1.1.1.0-1.1.1.255 via Cloudflare [bgptools_anycast_asns] weight=0.0 flags=anycast
```

## Sources

- `ip2x` — github.com/tn3w/IP2X
- `genom` — github.com/tn3w/genom
- `ipblocklist` — github.com/tn3w/IPBlocklist
- `asndb-tiny` — github.com/tn3w/ASNDB

## Custom DB

Implement `Database` (`NAME`, `URL`, `parse`), then `spawn::<MyDb>().await?` returns a `Handle<MyDb>`. `handle.load()` snapshots the current instance as `Arc<MyDb>`.

## License

Apache-2.0
