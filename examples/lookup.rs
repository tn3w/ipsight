//! `cargo run --example lookup --release -- 8.8.8.8 1.1.1.1 2606:4700::1111`

use std::env;
use std::net::IpAddr;
use std::time::Instant;

use ipsight::{AsnInfo, IntelReport, Ipsight, Place, Report};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ips: Vec<IpAddr> = env::args().skip(1).map(|a| a.parse()).collect::<Result<_, _>>()?;
    if ips.is_empty() {
        eprintln!("usage: lookup <ip>...");
        std::process::exit(2);
    }

    let load_start = Instant::now();
    let ipsight = Ipsight::new().await?;
    let load_elapsed = load_start.elapsed();
    println!("loaded in {:.2?}", load_elapsed);

    for ip in ips {
        let lookup_start = Instant::now();
        let report = ipsight.lookup(ip);
        let lookup_elapsed = lookup_start.elapsed();
        print_report(ip, &report, lookup_elapsed);
    }
    Ok(())
}

fn print_report(ip: IpAddr, report: &Report, elapsed: std::time::Duration) {
    println!("\n=== {ip} ({:.2?}) ===", elapsed);
    match &report.asn {
        Some(asn) => print_asn(asn),
        None => println!("[asn] not found"),
    }
    match &report.place {
        Some(place) => print_place(place),
        None => println!("[place] not found"),
    }
    match &report.intel {
        Some(intel) => print_intel(intel),
        None => println!("[intel] clean"),
    }
}

fn print_asn(a: &AsnInfo) {
    println!("[asn]");
    println!("  asn             = AS{}", a.asn);
    println!("  name            = {}", a.name);
    println!("  provider        = {}", a.provider);
    println!("  company         = {}", a.company);
    if !a.website.is_empty() {
        println!("  website         = {}", a.website);
    }
    println!("  country_code    = {}", a.country_code);
    println!("  kind            = {}", a.kind);
    println!("  info_type       = {}", a.info_type);
    println!("  rir             = {}", a.rir);
}

fn print_place(p: &Place) {
    println!("[place]");
    println!("  city            = {}", p.city);
    println!("  region          = {} ({})", p.region, p.region_code);
    println!("  district        = {}", p.district);
    println!("  country         = {} ({})", p.country_name, p.country_code);
    println!("  postal_code     = {}", p.postal_code);
    println!("  latitude        = {:.6}", p.latitude);
    println!("  longitude       = {:.6}", p.longitude);
    println!("  timezone        = {} [{}]", p.timezone, p.timezone_abbr);
    println!("  utc_offset      = {} ({}s)", p.utc_offset_str, p.utc_offset);
    println!("  dst_active      = {}", p.dst_active);
    println!("  currency        = {}", p.currency);
    println!("  continent       = {} ({})", p.continent_name, p.continent_code);
    println!("  is_eu           = {}", p.is_eu);
}

fn print_intel(i: &IntelReport) {
    println!("[intel]");
    println!("  verdict         = {}", i.verdict);
    println!("  score           = {:.1}", i.score);
    println!("  detections      = {}", i.detections);
    println!("  sources         = {}", i.sources);
    println!("  top_provider    = {}", i.top_provider);
    println!("  providers       = {}", i.providers.join(", "));
    println!("  flags           = {}", i.flags.join(", "));
    println!("  reasons         = {}", i.reasons.join(", "));
    for m in &i.matches {
        println!(
            "  match           = {} via {} [{}] weight={:.1} flags={}",
            m.range,
            m.provider,
            m.source,
            m.weight,
            m.flags.join(",")
        );
    }
}
