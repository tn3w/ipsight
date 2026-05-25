import {
  parseIpGeo, parseAsndb, parseIntel, parseGeocoder,
  parseTarget, ipv4ToInt, ipv6ToBig, bigToIpv6, intToIpv4
} from "./parsers.js";

const DBS = {
  asndb: "data/asndb.bin",
  ip2x: "data/ip2x.bin",
  genom: "data/genom.bin",
  intel: "data/intel.bin"
};

const COUNTRY = {
  AD:["Andorra","EUR","EU",0], AE:["United Arab Emirates","AED","AS",0],
  AF:["Afghanistan","AFN","AS",0], AL:["Albania","ALL","EU",0],
  AM:["Armenia","AMD","AS",0], AO:["Angola","AOA","AF",0],
  AR:["Argentina","ARS","SA",0], AT:["Austria","EUR","EU",1],
  AU:["Australia","AUD","OC",0], AZ:["Azerbaijan","AZN","AS",0],
  BA:["Bosnia and Herzegovina","BAM","EU",0], BD:["Bangladesh","BDT","AS",0],
  BE:["Belgium","EUR","EU",1], BG:["Bulgaria","BGN","EU",1],
  BO:["Bolivia","BOB","SA",0], BR:["Brazil","BRL","SA",0],
  BY:["Belarus","BYN","EU",0], CA:["Canada","CAD","NA",0],
  CH:["Switzerland","CHF","EU",0], CL:["Chile","CLP","SA",0],
  CN:["China","CNY","AS",0], CO:["Colombia","COP","SA",0],
  CR:["Costa Rica","CRC","NA",0], CU:["Cuba","CUP","NA",0],
  CY:["Cyprus","EUR","EU",1], CZ:["Czech Republic","CZK","EU",1],
  DE:["Germany","EUR","EU",1], DK:["Denmark","DKK","EU",1],
  DO:["Dominican Republic","DOP","NA",0], DZ:["Algeria","DZD","AF",0],
  EC:["Ecuador","USD","SA",0], EE:["Estonia","EUR","EU",1],
  EG:["Egypt","EGP","AF",0], ES:["Spain","EUR","EU",1],
  ET:["Ethiopia","ETB","AF",0], FI:["Finland","EUR","EU",1],
  FR:["France","EUR","EU",1], GB:["United Kingdom","GBP","EU",0],
  GE:["Georgia","GEL","AS",0], GH:["Ghana","GHS","AF",0],
  GR:["Greece","EUR","EU",1], HK:["Hong Kong","HKD","AS",0],
  HR:["Croatia","EUR","EU",1], HU:["Hungary","HUF","EU",1],
  ID:["Indonesia","IDR","AS",0], IE:["Ireland","EUR","EU",1],
  IL:["Israel","ILS","AS",0], IN:["India","INR","AS",0],
  IQ:["Iraq","IQD","AS",0], IR:["Iran","IRR","AS",0],
  IS:["Iceland","ISK","EU",0], IT:["Italy","EUR","EU",1],
  JP:["Japan","JPY","AS",0], KE:["Kenya","KES","AF",0],
  KR:["South Korea","KRW","AS",0], KW:["Kuwait","KWD","AS",0],
  KZ:["Kazakhstan","KZT","AS",0], LB:["Lebanon","LBP","AS",0],
  LK:["Sri Lanka","LKR","AS",0], LT:["Lithuania","EUR","EU",1],
  LU:["Luxembourg","EUR","EU",1], LV:["Latvia","EUR","EU",1],
  MA:["Morocco","MAD","AF",0], MD:["Moldova","MDL","EU",0],
  MX:["Mexico","MXN","NA",0], MY:["Malaysia","MYR","AS",0],
  NG:["Nigeria","NGN","AF",0], NL:["Netherlands","EUR","EU",1],
  NO:["Norway","NOK","EU",0], NP:["Nepal","NPR","AS",0],
  NZ:["New Zealand","NZD","OC",0], PE:["Peru","PEN","SA",0],
  PH:["Philippines","PHP","AS",0], PK:["Pakistan","PKR","AS",0],
  PL:["Poland","PLN","EU",1], PT:["Portugal","EUR","EU",1],
  RO:["Romania","RON","EU",1], RS:["Serbia","RSD","EU",0],
  RU:["Russia","RUB","EU",0], SA:["Saudi Arabia","SAR","AS",0],
  SE:["Sweden","SEK","EU",1], SG:["Singapore","SGD","AS",0],
  SI:["Slovenia","EUR","EU",1], SK:["Slovakia","EUR","EU",1],
  TH:["Thailand","THB","AS",0], TR:["Turkey","TRY","AS",0],
  TW:["Taiwan","TWD","AS",0], UA:["Ukraine","UAH","EU",0],
  US:["United States","USD","NA",0], UY:["Uruguay","UYU","SA",0],
  VE:["Venezuela","VES","SA",0], VN:["Vietnam","VND","AS",0],
  ZA:["South Africa","ZAR","AF",0]
};
const CONTINENT = { AF:"Africa", AS:"Asia", EU:"Europe",
  NA:"North America", OC:"Oceania", SA:"South America", AN:"Antarctica" };

const $ = (s) => document.querySelector(s);
const bootRow = (k) => document.querySelector(`.boot-row[data-key="${k}"]`);
function setBoot(k, state, label) {
  const row = bootRow(k);
  if (!row) return;
  row.dataset.state = state;
  row.querySelector("b").textContent = label;
}

const CACHE_NAME = "ipsight-db-v1";
const STALE_MS = 24 * 3600 * 1000;

async function streamToBuffer(response, key, fromCache) {
  const total = +response.headers.get("content-length") || 0;
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  const label = fromCache ? "cache" : "load";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    if (total)
      setBoot(key, "loading", `${label} ${Math.round(received / total * 100)}%`);
    else
      setBoot(key, "loading", `${label} ${(received / 1048576).toFixed(1)}M`);
  }
  const buf = new Uint8Array(received);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  return buf.buffer;
}

async function fetchDb(key) {
  setBoot(key, "loading", "…");
  const url = DBS[key];
  const cache = "caches" in window ? await caches.open(CACHE_NAME) : null;

  if (cache) {
    const cached = await cache.match(url);
    if (cached) {
      const cachedAt = +cached.headers.get("x-cached-at") || 0;
      const age = Date.now() - cachedAt;
      const buf = await streamToBuffer(cached, key, true);
      if (age < STALE_MS) return buf;
      revalidate(cache, url, key, cached.headers.get("last-modified"));
      return buf;
    }
  }

  const r = await fetch(url);
  if (!r.ok) throw new Error(`${key}: ${r.status}`);
  const teed = r.clone();
  const buf = await streamToBuffer(r, key, false);
  if (cache) await storeInCache(cache, url, teed);
  return buf;
}

async function storeInCache(cache, url, response) {
  const body = await response.arrayBuffer();
  const headers = new Headers(response.headers);
  headers.set("x-cached-at", String(Date.now()));
  await cache.put(url, new Response(body, { headers }));
}

async function revalidate(cache, url, key, lastModified) {
  try {
    const head = lastModified
      ? await fetch(url, { headers: { "If-Modified-Since": lastModified } })
      : await fetch(url);
    if (head.status === 304) {
      const existing = await cache.match(url);
      if (existing) {
        const headers = new Headers(existing.headers);
        headers.set("x-cached-at", String(Date.now()));
        const body = await existing.arrayBuffer();
        await cache.put(url, new Response(body, { headers }));
      }
      return;
    }
    if (!head.ok) return;
    await storeInCache(cache, url, head);
    setBoot(key, "ready", "updated");
  } catch {}
}

const DB = {};
async function loadAll() {
  const tasks = [
    ["asndb", parseAsndb],
    ["ip2x", parseIpGeo],
    ["intel", parseIntel],
    ["genom", parseGeocoder]
  ];
  await Promise.all(tasks.map(async ([k, parser]) => {
    try {
      const buf = await fetchDb(k);
      DB[k] = parser(buf);
      setBoot(k, "ready", "ready");
    } catch (e) {
      console.error(k, e);
      setBoot(k, "error", "error");
    }
  }));
  $("#go").disabled = false;
}

let map = null;
let lastCoord = null;
function ensureMap() {
  if (map) return;
  map = L.map("map", {
    zoomControl: false,
    attributionControl: true,
    worldCopyJump: true
  }).setView([20, 0], 2);
  L.tileLayer("https://cartodb-basemaps-{s}.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png", {
    subdomains: "abcd",
    maxZoom: 19,
    attribution: '© <a href="https://carto.com/attributions">CARTO</a>'
  }).addTo(map);
}
function showLocation(lat, lon) {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
  ensureMap();
  lastCoord = [lat, lon];
  setTimeout(() => {
    map.invalidateSize();
    map.flyTo([lat, lon], 9, { duration: 0.8 });
  }, 50);
}

function kv(target, pairs) {
  target.innerHTML = "";
  for (const [k, v] of pairs) {
    if (v === null || v === undefined || v === "") continue;
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v;
    target.append(dt, dd);
  }
}

function fmtOffset(tz) {
  if (!tz) return "";
  try {
    const fmt = new Intl.DateTimeFormat("en-US",
      { timeZone: tz, timeZoneName: "shortOffset" });
    return fmt.formatToParts(new Date())
      .find(p => p.type === "timeZoneName")?.value || "";
  } catch { return ""; }
}

function enrichPlace(p) {
  const c = COUNTRY[p.country_code];
  return {
    ...p,
    country_name: c ? c[0] : p.country_code,
    currency: c ? c[1] : "",
    continent_code: c ? c[2] : "",
    continent_name: c ? CONTINENT[c[2]] : "",
    is_eu: !!(c && c[3]),
    utc_offset_str: fmtOffset(p.timezone)
  };
}

function renderPlace(place) {
  const p = enrichPlace(place);
  $("#place").innerHTML = "";
  kv($("#place"), [
    ["City", p.city],
    ["Region", p.region_code ? `${p.region} (${p.region_code})` : p.region],
    ["District", p.district],
    ["Country", `${p.country_name} (${p.country_code})`],
    ["Postal", p.postal_code],
    ["Coords", `${p.latitude.toFixed(4)}, ${p.longitude.toFixed(4)}`],
    ["Timezone", p.timezone + (p.utc_offset_str ? ` · ${p.utc_offset_str}` : "")],
    ["Currency", p.currency],
    ["Continent", p.continent_name ? `${p.continent_name} (${p.continent_code})` : ""],
    ["EU member", p.is_eu ? "yes" : "no"]
  ]);
  showLocation(p.latitude, p.longitude, p.city || `${p.latitude}, ${p.longitude}`);
}

function renderAsn(a) {
  $("#asn").innerHTML = "";
  if (!a) { $("#asn").innerHTML = '<dd style="color:var(--fg-mute)">no ASN match</dd>'; return; }
  kv($("#asn"), [
    ["ASN", `AS${a.asn}`],
    ["Provider", a.provider],
    ["Name", a.name],
    ["Company", a.company],
    ["Website", a.website],
    ["Country", a.country_code],
    ["Kind", a.kind],
    ["Type", a.info_type],
    ["RIR", a.rir]
  ]);
}

function renderIntel(report) {
  const v = $("#verdict");
  const flags = $("#intel-flags");
  const matches = $("#intel-matches");
  flags.innerHTML = "";
  matches.innerHTML = "";
  if (!report) {
    v.textContent = "clean";
    v.dataset.level = "clean";
    $("#intel-summary").innerHTML = '<dd style="color:var(--fg-mute)">no threat signals</dd>';
    return;
  }
  v.textContent = report.verdict;
  v.dataset.level = report.verdict;
  kv($("#intel-summary"), [
    ["Score", report.score.toFixed(1)],
    ["Detections", report.detections],
    ["Sources", report.sources],
    ["Top provider", report.top_provider],
    ["Providers", report.providers.join(", ")],
    ["Reasons", report.reasons.join(", ")]
  ]);
  for (const f of report.flags) {
    const s = document.createElement("span");
    s.className = "flag"; s.textContent = f;
    flags.append(s);
  }
  for (const m of report.matches) {
    const el = document.createElement("div");
    el.className = "match";
    el.innerHTML = `<b>${m.range}</b> · ${m.provider || "?"} [${m.source}] · ${m.flags.join(", ") || "—"} · w=${m.weight}`;
    matches.append(el);
  }
}

function setToolLinks(text, asn) {
  $("#link-bgp").href = asn
    ? `https://bgp.tools/as/${asn}`
    : `https://bgp.tools/prefix/${text}`;
  $("#link-shodan").href = `https://www.shodan.io/host/${text}`;
  $("#link-abuse").href = `https://www.abuseipdb.com/check/${text}`;
  $("#link-rdap").href = `https://rdap.org/ip/${text}`;
  $("#link-osm").href = lastCoord
    ? `https://www.openstreetmap.org/?mlat=${lastCoord[0]}&mlon=${lastCoord[1]}#map=10/${lastCoord[0]}/${lastCoord[1]}`
    : "#";
}

function reveal(sectionId) {
  const el = document.getElementById(sectionId);
  el.hidden = false;
  el.scrollIntoView({ behavior: "smooth", block: "start" });
}

function lookupIp(text, value, kind) {
  const t0 = performance.now();
  const coord = kind === "v4" ? DB.ip2x.lookupV4(value) : DB.ip2x.lookupV6(value);
  const place = coord ? DB.genom.lookup(coord[0], coord[1]) : null;
  const asn = kind === "v4" ? DB.asndb.lookupV4(value) : DB.asndb.lookupV6(value);
  const intel = kind === "v4" ? DB.intel.lookupV4(value) : DB.intel.lookupV6(value);
  const elapsed = performance.now() - t0;

  $("#lookup-time").textContent = `${text} · ${elapsed.toFixed(2)} ms`;
  if (place) renderPlace(place);
  else {
    $("#place").innerHTML = '<dd style="color:var(--fg-mute)">no location data</dd>';
    if (map) map.setView([20, 0], 2);
  }
  renderAsn(asn);
  renderIntel(intel);
  setToolLinks(text, asn?.asn);
  $("#search").hidden = true;
  reveal("lookup");
}

function lookupAsn(asn) {
  const info = DB.asndb.findByAsn(asn);
  $("#asn-query").textContent = `AS${asn}`;
  if (!info) {
    $("#asn-result").innerHTML = `<dd style="color:var(--fg-mute)">no record for AS${asn}</dd>`;
  } else {
    kv($("#asn-result"), [
      ["ASN", `AS${info.asn}`],
      ["Provider", info.provider],
      ["Name", info.name],
      ["Company", info.company],
      ["Website", info.website],
      ["Country", info.country_code],
      ["Kind", info.kind],
      ["Type", info.info_type],
      ["RIR", info.rir]
    ]);
  }
  $("#lookup").hidden = true;
  reveal("search");
}

const MY_IP_SOURCES = [
  "https://ipinfo.io/ip",
  "https://ipapi.co/ip",
  "https://api.bigdatacloud.net/data/client-ip"
];
async function resolveMyIp() {
  $("#ip-input").value = "resolving…";
  for (const url of MY_IP_SOURCES) {
    try {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) continue;
      const text = await r.text();
      const ip = text.trim().match(/(\d{1,3}\.){3}\d{1,3}|[0-9a-f:]+:[0-9a-f:]+/i)?.[0];
      if (ip) { $("#ip-input").value = ip; submit(); return; }
    } catch {}
  }
  $("#ip-input").value = "";
  $("#ip-input").placeholder = "browser blocked all my-IP services";
}

function submit() {
  const raw = $("#ip-input").value.trim();
  if (!raw) return;
  if (raw.toLowerCase() === "my") { resolveMyIp(); return; }
  const t = parseTarget(raw);
  if (!t) { $("#ip-input").focus(); $("#ip-input").style.color = "var(--bad)"; return; }
  $("#ip-input").style.color = "";
  if (t.kind === "asn") lookupAsn(t.asn);
  else lookupIp(t.text, t.value, t.kind);
}

$("#ip-form").addEventListener("submit", (e) => { e.preventDefault(); submit(); });
document.querySelectorAll(".chip").forEach(b => {
  b.addEventListener("click", () => {
    $("#ip-input").value = b.dataset.suggest;
    submit();
  });
});
document.querySelectorAll(".tile").forEach(b => {
  b.addEventListener("click", () => {
    $("#ip-input").value = b.dataset.q;
    submit();
  });
});

$("#go").disabled = true;
loadAll().catch(e => console.error(e));
