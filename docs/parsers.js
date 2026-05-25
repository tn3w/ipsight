// Ports of ipsight Rust parsers to ES modules.
// IP2X, genom, IPBlocklist, ASNDB tiny.

const u8 = (d, o) => d.getUint8(o);
const u16 = (d, o) => d.getUint16(o, true);
const u32 = (d, o) => d.getUint32(o, true);
const u64 = (d, o) => d.getBigUint64(o, true);
const u128be = (d, o) =>
  (d.getBigUint64(o, false) << 64n) | d.getBigUint64(o + 8, false);
const u24 = (d, o) => u8(d, o) | (u8(d, o + 1) << 8) | (u8(d, o + 2) << 16);
const i24 = (d, o) => {
  const v = u24(d, o);
  return v & 0x800000 ? v | 0xff000000 : v;
};

function partitionPoint(arr, pred) {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (pred(arr[mid])) lo = mid + 1; else hi = mid;
  }
  return lo;
}

function partitionPointBig(arr, target) {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (arr[mid] <= target) lo = mid + 1; else hi = mid;
  }
  return lo;
}

export function ipv4ToInt(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let v = 0;
  for (const p of parts) {
    const n = +p;
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}

export function ipv6ToBig(s) {
  let head = s, tail = "";
  if (s.includes("::")) {
    const [a, b] = s.split("::");
    head = a; tail = b;
  }
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const fill = 8 - h.length - t.length;
  if (fill < 0) return null;
  const parts = [...h, ...Array(fill).fill("0"), ...t];
  let v = 0n;
  for (const p of parts) {
    const n = parseInt(p || "0", 16);
    if (isNaN(n) || n < 0 || n > 0xffff) return null;
    v = (v << 16n) | BigInt(n);
  }
  return v;
}

export function bigToIpv6(v) {
  const parts = [];
  for (let i = 7; i >= 0; i--) {
    parts.push(Number((v >> BigInt(i * 16)) & 0xffffn).toString(16));
  }
  return parts.join(":").replace(/(^|:)(0:){2,}/, "::").replace(/^::0$/, "::");
}

export function intToIpv4(v) {
  return [v >>> 24, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff].join(".");
}

export function parseTarget(raw) {
  const s = raw.trim();
  if (/^as\s*\d+$/i.test(s)) return { kind: "asn", asn: +s.replace(/\D/g, "") };
  if (/^\d+$/.test(s) && +s < 4_300_000_000) return { kind: "asn", asn: +s };
  if (s.includes(":")) {
    const v = ipv6ToBig(s);
    if (v !== null) return { kind: "v6", value: v, text: s };
  }
  const v = ipv4ToInt(s);
  if (v !== null) return { kind: "v4", value: v, text: s };
  return null;
}

// ----- IP2X: IP → (lat, lon) -----

export function parseIpGeo(buf) {
  const d = new DataView(buf);
  const bytes = new Uint8Array(buf);
  if (bytes[0] !== 0x47 || bytes[1] !== 0x45 || bytes[2] !== 0x4f || bytes[3] !== 0x31)
    throw new Error("bad IP2X");
  const idxBits = u8(d, 6);
  const idxMask = (1n << BigInt(idxBits)) - 1n;
  const nPts = u32(d, 8);
  const n4 = u32(d, 12);
  const nb4 = u32(d, 20);
  let off = 24;
  const ptsOff = off;
  off += nPts * 6;
  const bases4 = new Uint32Array(nb4);
  for (let i = 0; i < nb4; i++) bases4[i] = u32(d, off + i * 4);
  off += nb4 * 4;
  const off4 = new Uint32Array(nb4 + 1);
  for (let i = 0; i <= nb4; i++) off4[i] = u32(d, off + i * 4);
  off += (nb4 + 1) * 4;
  const deltasLen = off4[nb4];
  const deltas4Off = off;
  off += deltasLen;
  const v4IdxOff = off;
  off += Math.ceil((n4 * idxBits) / 8) + 4;
  const v6Keys = new BigUint64Array(u32(d, 16));
  for (let i = 0; i < v6Keys.length; i++) v6Keys[i] = u64(d, off + i * 8);
  off += v6Keys.length * 8;
  const v6IdxOff = off;

  function packed(base, row) {
    const bit = row * idxBits;
    const byte = base + (bit >>> 3);
    const shift = bit & 7;
    const word = BigInt(u32(d, byte));
    return (word >> BigInt(shift)) & idxMask;
  }
  function point(idx) {
    if (idx === 0n) return null;
    const o = ptsOff + Number(idx) * 6;
    return [i24(d, o) / 1000, i24(d, o + 3) / 1000];
  }
  function lookupV4(ip) {
    const group = partitionPoint(bases4, (b) => b <= ip) - 1;
    if (group < 0) return null;
    const base = bases4[group];
    const begin = off4[group];
    const end = off4[group + 1];
    const target = ip - base;
    const count = (end - begin) / 3;
    let lo = 0, hi = count;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (u24(d, deltas4Off + (begin + mid * 3)) <= target) lo = mid + 1;
      else hi = mid;
    }
    if (lo === 0) return null;
    const row = (begin / 3 | 0) + (lo - 1);
    return point(packed(v4IdxOff, row));
  }
  function lookupV6(ip) {
    const key = ip >> 64n;
    const row = partitionPointBig(v6Keys, key) - 1;
    if (row < 0) return null;
    return point(packed(v6IdxOff, row));
  }
  return { lookupV4, lookupV6 };
}

// ----- ASNDB tiny: IP → AsnInfo -----

const MAGIC_ASN = 0x00044244_4e534144n;
const KIND = ["", "Tier-1", "Transit", "Content", "ISP", "Enterprise",
  "Education", "Non-Profit", "Government", "Personal", "Stub"];
const INFO = ["", "NSP", "Cable/DSL/ISP", "Content", "Enterprise",
  "Educational/Research", "Non-Profit", "Route Server", "Network Services",
  "Route Collector", "Government", "Personal"];
const RIR = ["", "ARIN", "RIPE", "APNIC", "AFRINIC", "LACNIC"];

export function parseAsndb(buf) {
  const d = new DataView(buf);
  const bytes = new Uint8Array(buf);
  if (u64(d, 0) !== MAGIC_ASN) throw new Error("bad asndb");
  if (bytes[8] !== 4) throw new Error("not tiny");
  const tinyCount = u32(d, 16);
  const seg4Count = u32(d, 20);
  const seg6Count = u32(d, 24);
  const tinyOff = Number(u64(d, 40));
  const seg4Off = Number(u64(d, 48));
  const seg6Off = Number(u64(d, 56));
  const strOff = Number(u64(d, 88));

  const seg4Start = new Uint32Array(seg4Count);
  const seg4Idx = new Uint32Array(seg4Count);
  for (let i = 0; i < seg4Count; i++) {
    seg4Start[i] = u32(d, seg4Off + i * 8);
    seg4Idx[i] = u32(d, seg4Off + i * 8 + 4);
  }
  const seg6Start = new BigUint64Array(seg6Count * 2);
  const seg6Idx = new Uint32Array(seg6Count);
  for (let i = 0; i < seg6Count; i++) {
    const o = seg6Off + i * 20;
    seg6Start[i * 2 + 1] = (BigInt(d.getUint32(o, false)) << 32n) |
      BigInt(d.getUint32(o + 4, false));
    seg6Start[i * 2] = (BigInt(d.getUint32(o + 8, false)) << 32n) |
      BigInt(d.getUint32(o + 12, false));
    seg6Idx[i] = u32(d, o + 16);
  }
  function seg6At(i) {
    return (seg6Start[i * 2 + 1] << 64n) | seg6Start[i * 2];
  }
  const dec = new TextDecoder();
  function stringAt(o) {
    if (o === 0) return "";
    const p = strOff + o;
    const len = u32(d, p);
    return dec.decode(bytes.subarray(p + 4, p + 4 + len));
  }
  function info(idx) {
    if (idx >= tinyCount) return null;
    const o = tinyOff + idx * 24;
    const rawName = stringAt(u32(d, o + 4));
    const company = stringAt(u32(d, o + 8));
    return {
      asn: u32(d, o),
      name: splitFirst(rawName),
      raw_name: rawName,
      company,
      website: stringAt(u32(d, o + 12)),
      provider: providerBrand(rawName, company),
      country_code: dec.decode(bytes.subarray(o + 16, o + 18)).replace(/\0+/g, ""),
      kind: KIND[bytes[o + 18]] || "",
      info_type: INFO[bytes[o + 19]] || "",
      rir: RIR[bytes[o + 20]] || ""
    };
  }
  function lookupV4(ip) {
    const pos = partitionPoint(seg4Start, (s) => s <= ip) - 1;
    if (pos < 0) return null;
    const idx = seg4Idx[pos];
    return idx === 0xffffffff ? null : info(idx);
  }
  function lookupV6(ip) {
    let lo = 0, hi = seg6Count;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (seg6At(mid) <= ip) lo = mid + 1; else hi = mid;
    }
    if (lo === 0) return null;
    const idx = seg6Idx[lo - 1];
    return idx === 0xffffffff ? null : info(idx);
  }
  function findByAsn(asn) {
    for (let i = 0; i < tinyCount; i++) {
      const o = tinyOff + i * 24;
      if (u32(d, o) === asn) return info(i);
    }
    return null;
  }
  return { lookupV4, lookupV6, findByAsn, tinyCount };
}

const DROP = new Set(["inc","llc","ltd","limited","gmbh","ag","corp","corporation",
  "co","company","sa","sl","bv","srl","pty","plc","kg","ohg","se","ug","spa","ab",
  "as","oy","oyj","kft","doo","sas","eurl","ltda","online","networks","network",
  "telecom","telecommunications","communications","comunicaciones","hosting",
  "solutions","services","technologies","technology","tech","group","holdings",
  "holding","international","global","internet","systems","system","data",
  "datacenter","cloud","isp","of","and","parent","enterprises","enterprise",
  "backbone"]);
const LEAD = new Set(["the","pt","pp","ps","ip","uab"]);
const RIR_SUFFIX = ["AS","AP","US","UK","DE","FR","IN","CN","JP","EU","NET","COM","ORG"];

function splitFirst(name) {
  const i = name.indexOf(" - ");
  if (i >= 0) return name.slice(0, i);
  return name.split(/\s+/)[0] || "";
}
function title(s) {
  return s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : s;
}
function smartTok(t) {
  if (t.length >= 5 && /^[A-Z]+$/.test(t)) return title(t);
  return t;
}
function smartCase(s) {
  return s.split(" ").map(smartTok).join(" ");
}
function providerBrand(name, company) {
  const fromCo = (company || "").replace(/[(),]/g, " ")
    .split(/\s+/).filter(Boolean).map(t => t.replace(/\.+$/, ""));
  while (fromCo.length && DROP.has(fromCo[fromCo.length - 1].toLowerCase().replace(/[.,;:'"]/g,"")))
    fromCo.pop();
  while (fromCo.length && LEAD.has(fromCo[0].toLowerCase().replace(/[.,;:'"]/g,"")))
    fromCo.shift();
  let co = fromCo.join(" ");
  for (const suf of [".com",".net",".org",".io"])
    if (co.toLowerCase().endsWith(suf)) co = co.slice(0, -suf.length);
  co = smartCase(co);
  let handle = splitFirst(name);
  for (const suf of RIR_SUFFIX) {
    if (handle.length > suf.length + 1 &&
        handle[handle.length - suf.length - 1] === "-" &&
        handle.slice(-suf.length).toUpperCase() === suf) {
      handle = handle.slice(0, -suf.length - 1);
      break;
    }
  }
  if (handle.length > 4 && handle === handle.toUpperCase()) {
    for (const tail of ["net","com","tel","web","line"]) {
      if (handle.slice(-tail.length).toLowerCase() === tail) {
        handle = handle.slice(0, -tail.length);
        break;
      }
    }
  }
  handle = smartCase(handle);
  if (co && handle) {
    const cl = co.toLowerCase(), hl = handle.toLowerCase();
    if (cl === hl || cl.startsWith(hl + " ")) return handle;
    if (hl.startsWith(cl + " ")) return co;
  }
  return co || handle;
}

// ----- IPBlocklist intel -----

const FLAG_NAMES = ["vpn","proxy","tor","malware","c2","scanner","brute_force",
  "spammer","compromised","datacenter","cdn","anycast","crawler","bot","cloud",
  "private_relay","anonymizer","mobile","isp","government"];
const FLAG_BASE = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0];
const VERDICT = [[80,"critical"],[60,"high"],[35,"medium"],[15,"low"]];

export function parseIntel(buf) {
  const d = new DataView(buf);
  const bytes = new Uint8Array(buf);
  if (u32(d, 0) !== 6) throw new Error("bad intel");
  const header = [];
  for (let i = 0; i < 19; i++) header.push(Number(u64(d, 8 + i * 8)));
  const [cidrN, longN, v6N, valN, strN] = header;
  const sec = header.slice(5);

  const bucket = new Uint32Array(65537);
  for (let i = 0; i <= 65536; i++) bucket[i] = u32(d, sec[0] + i * 4);

  const total = cidrN + longN;
  const starts = new Uint32Array(total);
  const ends = new Uint32Array(total);
  const vals = new Uint16Array(total);
  for (let b = 0; b < 65536; b++) {
    for (let j = bucket[b]; j < bucket[b + 1]; j++) {
      const lo = u16(d, sec[1] + j * 2);
      starts[j] = ((b << 16) | lo) >>> 0;
      ends[j] = (starts[j] + u16(d, sec[2] + j * 2)) >>> 0;
      vals[j] = u16(d, sec[3] + j * 2);
    }
  }
  for (let i = 0; i < longN; i++) {
    starts[cidrN + i] = u32(d, sec[4] + i * 4);
    ends[cidrN + i] = u32(d, sec[5] + i * 4);
    vals[cidrN + i] = u16(d, sec[6] + i * 2);
  }
  const order = Array.from({ length: total }, (_, i) => i);
  order.sort((a, b) => starts[a] - starts[b]);
  const v4Starts = new Uint32Array(total);
  const v4Ends = new Uint32Array(total);
  const v4Vals = new Uint16Array(total);
  for (let i = 0; i < total; i++) {
    v4Starts[i] = starts[order[i]];
    v4Ends[i] = ends[order[i]];
    v4Vals[i] = vals[order[i]];
  }
  const v4MaxEnd = new Uint32Array(total);
  let m = 0;
  for (let i = 0; i < total; i++) { if (v4Ends[i] > m) m = v4Ends[i]; v4MaxEnd[i] = m; }

  const v6Starts = new BigUint64Array(v6N * 2);
  const v6Ends = new BigUint64Array(v6N * 2);
  const v6Vals = new Uint16Array(v6N);
  for (let i = 0; i < v6N; i++) {
    const oS = sec[7] + i * 16, oE = sec[8] + i * 16;
    v6Starts[i * 2] = u64(d, oS);
    v6Starts[i * 2 + 1] = u64(d, oS + 8);
    v6Ends[i * 2] = u64(d, oE);
    v6Ends[i * 2 + 1] = u64(d, oE + 8);
    v6Vals[i] = u16(d, sec[9] + i * 2);
  }
  const v6S = (i) => (v6Starts[i * 2 + 1] << 64n) | v6Starts[i * 2];
  const v6E = (i) => (v6Ends[i * 2 + 1] << 64n) | v6Ends[i * 2];
  const v6Max = new BigUint64Array(v6N * 2);
  let mb = 0n;
  for (let i = 0; i < v6N; i++) {
    const e = v6E(i);
    if (e > mb) mb = e;
    v6Max[i * 2] = mb & 0xffffffffffffffffn;
    v6Max[i * 2 + 1] = mb >> 64n;
  }
  const v6MaxAt = (i) => (v6Max[i * 2 + 1] << 64n) | v6Max[i * 2];

  const valTable = new Uint32Array(valN * 4);
  for (let i = 0; i < valN; i++) {
    const o = sec[10] + i * 16;
    valTable[i * 4] = u32(d, o);
    valTable[i * 4 + 1] = u32(d, o + 4);
    valTable[i * 4 + 2] = u32(d, o + 8);
    valTable[i * 4 + 3] = u32(d, o + 12);
  }
  const dec = new TextDecoder();
  const strings = new Array(strN);
  const strBody = sec[12];
  for (let i = 0; i < strN; i++) {
    const o = u32(d, sec[11] + i * 8);
    const l = u32(d, sec[11] + i * 8 + 4);
    strings[i] = dec.decode(bytes.subarray(strBody + o, strBody + o + l));
  }
  const weights = calibrate(v4Vals, valTable);

  function makeMatch(vid, range) {
    const off = vid * 4;
    const bits = valTable[off];
    const flags = [];
    let mx = 0;
    for (let i = 0; i < 20; i++) {
      if (bits & (1 << i)) {
        flags.push(FLAG_NAMES[i]);
        if (weights[i] > mx) mx = weights[i];
      }
    }
    return {
      source: strings[valTable[off + 2]],
      provider: strings[valTable[off + 1]],
      range, flags, weight: Math.round(mx * 10) / 10
    };
  }
  function collectV4(ip) {
    const out = [];
    let i = partitionPoint(v4Starts, (s) => s <= ip);
    while (i > 0) {
      i--;
      if (v4MaxEnd[i] < ip) break;
      if (v4Ends[i] >= ip) {
        out.push(makeMatch(v4Vals[i], `${intToIpv4(v4Starts[i])}-${intToIpv4(v4Ends[i])}`));
      }
    }
    return out;
  }
  function collectV6(ip) {
    const out = [];
    let lo = 0, hi = v6N;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (v6S(mid) <= ip) lo = mid + 1; else hi = mid;
    }
    let i = lo;
    while (i > 0) {
      i--;
      if (v6MaxAt(i) < ip) break;
      if (v6E(i) >= ip) {
        out.push(makeMatch(v6Vals[i], `${bigToIpv6(v6S(i))}-${bigToIpv6(v6E(i))}`));
      }
    }
    return out;
  }
  function buildReport(matches) {
    if (!matches.length) return null;
    matches.sort((a, b) => b.weight - a.weight);
    const all = [];
    for (const m of matches) for (const f of m.flags) if (!all.includes(f)) all.push(f);
    const wOf = (f) => weights[FLAG_NAMES.indexOf(f)] || 0;
    const ranked = [...all].sort((a, b) => wOf(b) - wOf(a));
    const sources = new Set(matches.map(m => `${m.provider}|${m.source}`));
    let score = 0;
    if (ranked.length) {
      const top = wOf(ranked[0]);
      const extras = ranked.slice(1).reduce((s, f) => s + wOf(f), 0);
      score = Math.min(100, (top + extras * 0.15) *
        (1 + 0.08 * Math.log2(sources.size + 1)));
      score = Math.round(score * 10) / 10;
    }
    const verdict = (VERDICT.find(([t]) => score >= t) || [, "minimal"])[1];
    const providers = [];
    for (const m of matches)
      if (m.provider && !providers.includes(m.provider)) providers.push(m.provider);
    const ti = providers.findIndex(p => p.toLowerCase() === "tor");
    if (ti > 0) providers.unshift(providers.splice(ti, 1)[0]);
    return {
      verdict, score,
      detections: matches.length,
      sources: sources.size,
      top_provider: providers[0] || "",
      providers,
      flags: all,
      reasons: ranked.slice(0, 5),
      matches
    };
  }
  return {
    lookupV4: (ip) => buildReport(collectV4(ip)),
    lookupV6: (ip) => buildReport(collectV6(ip))
  };
}

function calibrate(v4Vals, valTable) {
  if (!v4Vals.length) return FLAG_BASE;
  const counts = new Array(20).fill(0);
  for (let i = 0; i < v4Vals.length; i++) {
    const bits = valTable[v4Vals[i] * 4];
    for (let j = 0; j < 20; j++) if (bits & (1 << j)) counts[j]++;
  }
  const total = v4Vals.length;
  return FLAG_BASE.map((w, i) => {
    const rarity = Math.log2(total / Math.max(1, counts[i]));
    return w * (1 + rarity / 24);
  });
}

// ----- Genom: (lat, lon) → Place -----

const GRID_LON = 3600, GRID_LAT = 1800, GRID_SCALE = 10;
const PGRID_LON = 36000, PGRID_LAT = 1800 * 10, PGRID_SCALE = 100;

function varint(bytes, p) {
  let v = 0n, shift = 0n, i = 0;
  while (true) {
    const b = bytes[p + i]; i++;
    v |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [Number(v), i];
    shift += 7n;
  }
}
function zigzag(v) { return (v >>> 1) ^ -(v & 1); }
function cellOf(lat, lon, scale, mLa, mLo) {
  const la = Math.max(0, Math.min(mLa - 1, Math.floor((lat + 90) * scale)));
  const lo = Math.max(0, Math.min(mLo - 1, Math.floor((lon + 180) * scale)));
  return la * mLo + lo;
}
function bsearchGrid(grid, key) {
  let lo = 0, hi = grid.length / 2;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    const k = grid[mid * 2];
    if (k === key) return grid[mid * 2 + 1];
    if (k < key) lo = mid + 1; else hi = mid;
  }
  return null;
}

export function parseGeocoder(buf) {
  const d = new DataView(buf);
  const bytes = new Uint8Array(buf);
  if (bytes[0] !== 0x47 || bytes[1] !== 0x45 || bytes[2] !== 0x4f || bytes[3] !== 0x31)
    throw new Error("bad genom");
  const offStr = u32(d, 8);
  const offCc = u32(d, 16);
  const offGrid = u32(d, 24);
  const offCities = u32(d, 32);
  const lenCities = u32(d, 36);
  const offPdir = u32(d, 40);
  const offPostal = u32(d, 48);

  const strCount = u32(d, offStr);
  const strOffsetsOff = offStr + 4;
  const strBodyOff = strOffsetsOff + 4 * (strCount + 1);
  const ccOff = offCc + 4;

  const grid = decodeGrid(bytes, offGrid);

  const pdirCount = u32(d, offPdir);
  const postal = [];
  let cursor = offPdir + 4;
  for (let i = 0; i < pdirCount; i++) {
    const cc = u16(d, cursor);
    const start = u32(d, cursor + 4);
    const end = u32(d, cursor + 8);
    cursor += 12;
    postal.push(parsePCountry(bytes, d, cc, offPostal + start, offPostal + end));
  }
  postal.sort((a, b) => a.cc - b.cc);

  const dec = new TextDecoder();
  function strAt(i) {
    if (i >= strCount) return "";
    const s = u32(d, strOffsetsOff + 4 * i);
    const e = u32(d, strOffsetsOff + 4 * (i + 1));
    return dec.decode(bytes.subarray(strBodyOff + s, strBodyOff + e));
  }
  function ccIso(i) {
    return dec.decode(bytes.subarray(ccOff + i * 2, ccOff + i * 2 + 2));
  }
  function nearestCity(lat, lon) {
    const latQ = Math.round(lat * 1e6);
    const lonQ = Math.round(lon * 1e6);
    const cell = cellOf(lat, lon, GRID_SCALE, GRID_LAT, GRID_LON);
    const baseLa = (cell / GRID_LON) | 0;
    const baseLo = cell % GRID_LON;
    let best = null, r = 1;
    while (true) {
      for (let dla = -r; dla <= r; dla++) {
        for (let dlo = -r; dlo <= r; dlo++) {
          const la = baseLa + dla, lo = baseLo + dlo;
          if (la < 0 || la >= GRID_LAT || lo < 0 || lo >= GRID_LON) continue;
          const c = la * GRID_LON + lo;
          const off = bsearchGrid(grid, c);
          if (off !== null)
            best = scanCity(bytes, offCities + off, latQ, lonQ, best);
        }
      }
      if (best || r > 200) break;
      r = Math.max(r + 1, r * 2);
    }
    return best ? best[1] : null;
  }
  function nearestPostal(cc, lat, lon) {
    let idx = postal.findIndex(p => p.cc === cc);
    if (idx < 0) return "";
    const pc = postal[idx];
    const latQ = Math.round(lat * 1e6);
    const lonQ = Math.round(lon * 1e6);
    const cell = cellOf(lat, lon, PGRID_SCALE, PGRID_LAT, PGRID_LON);
    const baseLa = (cell / PGRID_LON) | 0;
    const baseLo = cell % PGRID_LON;
    let best = null, r = 1;
    while (true) {
      for (let dla = -r; dla <= r; dla++) {
        for (let dlo = -r; dlo <= r; dlo++) {
          const la = baseLa + dla, lo = baseLo + dlo;
          if (la < 0 || la >= PGRID_LAT || lo < 0 || lo >= PGRID_LON) continue;
          const c = la * PGRID_LON + lo;
          const off = bsearchGrid(pc.cellDir, c);
          if (off !== null)
            best = scanPostal(bytes, pc.bodyOff + off, latQ, lonQ, best);
        }
      }
      if (best || r > 1000) break;
      r = Math.max(r + 1, r * 2);
    }
    if (!best) return "";
    const psI = best[1];
    const s = u32(d, pc.psOffsetsOff + 4 * psI);
    const e = u32(d, pc.psOffsetsOff + 4 * (psI + 1));
    return dec.decode(bytes.subarray(pc.psBodyOff + s, pc.psBodyOff + e));
  }
  function lookup(lat, lon) {
    const city = nearestCity(lat, lon);
    if (!city) return null;
    const cc = ccIso(city.cc);
    const ps = nearestPostal(city.cc, lat, lon) || "";
    return {
      city: strAt(city.name_i),
      region: strAt(city.a1_i),
      region_code: strAt(city.a1c_i),
      district: strAt(city.a2_i),
      country_code: cc,
      postal_code: ps,
      timezone: strAt(city.tz_i),
      latitude: city.lat / 1e6,
      longitude: city.lon / 1e6
    };
  }
  return { lookup };
}

function decodeGrid(bytes, off) {
  const n = bytes[off] | (bytes[off + 1] << 8) |
    (bytes[off + 2] << 16) | (bytes[off + 3] << 24);
  const out = new Uint32Array(n * 2);
  let p = off + 4, cell = 0, byteOff = 0;
  for (let i = 0; i < n; i++) {
    const [dc, k1] = varint(bytes, p); p += k1;
    const [deo, k2] = varint(bytes, p); p += k2;
    cell += dc; byteOff += deo;
    out[i * 2] = cell;
    out[i * 2 + 1] = byteOff;
  }
  return out;
}

function parsePCountry(bytes, d, cc, start, end) {
  let p = start;
  const tupleCount = u32(d, p); p += 4;
  p += tupleCount * 12;
  const psCount = u32(d, p); p += 4;
  const psOffsetsOff = p;
  p += 4 * (psCount + 1);
  const bodyLen = u32(d, psOffsetsOff + 4 * psCount);
  const psBodyOff = p;
  p += bodyLen;
  const [cellCount, k] = varint(bytes, p); p += k;
  const cellDir = new Uint32Array(cellCount * 2);
  let cell = 0, byteOff = 0;
  for (let i = 0; i < cellCount; i++) {
    const [dc, k1] = varint(bytes, p); p += k1;
    const [deo, k2] = varint(bytes, p); p += k2;
    cell += dc; byteOff += deo;
    cellDir[i * 2] = cell;
    cellDir[i * 2 + 1] = byteOff;
  }
  return { cc, psOffsetsOff, psBodyOff, cellDir, bodyOff: p };
}

function scanCity(bytes, off, latQ, lonQ, best) {
  let i = off;
  const [n, k] = varint(bytes, i); i += k;
  let lat = 0, lon = 0;
  for (let j = 0; j < n; j++) {
    const [dl, k1] = varint(bytes, i); i += k1;
    const [dlo, k2] = varint(bytes, i); i += k2;
    lat += zigzag(dl); lon += zigzag(dlo);
    const [name_i, k3] = varint(bytes, i); i += k3;
    const [a1_i, k4] = varint(bytes, i); i += k4;
    const [a2_i, k5] = varint(bytes, i); i += k5;
    const [a1c_i, k6] = varint(bytes, i); i += k6;
    const [tz_i, k7] = varint(bytes, i); i += k7;
    const [cc, k8] = varint(bytes, i); i += k8;
    const dx = lat - latQ, dy = lon - lonQ;
    const d2 = dx * dx + dy * dy;
    if (!best || d2 < best[0])
      best = [d2, { lat, lon, name_i, a1_i, a2_i, a1c_i, tz_i, cc }];
  }
  return best;
}

function scanPostal(bytes, off, latQ, lonQ, best) {
  let i = off;
  const [n, k] = varint(bytes, i); i += k;
  let lat = 0, lon = 0;
  for (let j = 0; j < n; j++) {
    const [dl, k1] = varint(bytes, i); i += k1;
    const [dlo, k2] = varint(bytes, i); i += k2;
    lat += zigzag(dl); lon += zigzag(dlo);
    const [ps_i, k3] = varint(bytes, i); i += k3;
    const [, k4] = varint(bytes, i); i += k4;
    const dx = lat - latQ, dy = lon - lonQ;
    const d2 = dx * dx + dy * dy;
    if (!best || d2 < best[0]) best = [d2, ps_i];
  }
  return best;
}
