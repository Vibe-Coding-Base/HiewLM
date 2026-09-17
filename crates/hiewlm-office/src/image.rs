//! Image metadata: what an image file remembers about where it came from.
//!
//! Images are read the same passive way as every other format here — bytes in,
//! description out, nothing executed and nothing fetched. The point is not to
//! decode the picture but to read the metadata an analyst or a privacy-minded
//! author cares about: who and what device made it, when, where (GPS), what
//! tool last touched it, and whether an embedded thumbnail still carries a
//! pre-crop version of the image.
//!
//! Three containers arrive here: JPEG (EXIF/XMP in APP segments), PNG (an `eXIf`
//! chunk and textual chunks), and TIFF (EXIF is its native structure). All three
//! reduce to the same TIFF/IFD walk plus a little XMP and PNG-text reading.

/// What the file actually is, whatever the extension says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageKind {
    Jpeg,
    Png,
    Tiff,
    Gif,
    Bmp,
    Webp,
}

impl ImageKind {
    pub fn label(self) -> &'static str {
        match self {
            ImageKind::Jpeg => "JPEG image",
            ImageKind::Png => "PNG image",
            ImageKind::Tiff => "TIFF image",
            ImageKind::Gif => "GIF image",
            ImageKind::Bmp => "BMP image",
            ImageKind::Webp => "WebP image",
        }
    }
}

/// One segment/chunk of the container, for the structure tree.
#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub file_off: u64,
    pub size: u64,
    pub detail: String,
}

/// A metadata field worth showing, classified by what it leaks.
#[derive(Clone, Debug)]
pub struct Field {
    pub key: String,
    pub value: String,
    /// Identity fields (author, GPS, owner) are what a privacy scrub targets;
    /// the rest is attribution context (device, software, timestamps).
    pub identity: bool,
}

/// The parsed image.
#[derive(Clone, Debug)]
pub struct Image {
    pub kind: ImageKind,
    pub segments: Vec<Segment>,
    pub fields: Vec<Field>,
    /// Decimal (lat, lon) if the file carries GPS coordinates.
    pub gps: Option<(f64, f64)>,
    /// An embedded thumbnail can retain the picture before a crop or redaction.
    pub has_thumbnail: bool,
}

/// Recognise an image container by its magic bytes.
pub fn detect(b: &[u8]) -> Option<ImageKind> {
    if b.len() < 12 {
        return None;
    }
    if b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF {
        return Some(ImageKind::Jpeg);
    }
    if b[0..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(ImageKind::Png);
    }
    if &b[0..4] == b"II\x2a\x00" || &b[0..4] == b"MM\x00\x2a" {
        return Some(ImageKind::Tiff);
    }
    if &b[0..6] == b"GIF87a" || &b[0..6] == b"GIF89a" {
        return Some(ImageKind::Gif);
    }
    if &b[0..2] == b"BM" {
        return Some(ImageKind::Bmp);
    }
    if &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return Some(ImageKind::Webp);
    }
    None
}

/// Parse an image's metadata, or `None` if `bytes` is not a supported image.
pub fn parse(bytes: &[u8]) -> Option<Image> {
    let kind = detect(bytes)?;
    let mut img = Image {
        kind,
        segments: Vec::new(),
        fields: Vec::new(),
        gps: None,
        has_thumbnail: false,
    };
    match kind {
        ImageKind::Jpeg => parse_jpeg(bytes, &mut img),
        ImageKind::Png => parse_png(bytes, &mut img),
        ImageKind::Tiff => {
            img.segments.push(Segment {
                name: "TIFF header".into(),
                file_off: 0,
                size: bytes.len() as u64,
                detail: String::new(),
            });
            read_exif(bytes, &mut img);
        }
        // GIF, BMP and WebP carry little standard metadata; they are recognised
        // so the view opens, but there is nothing sensitive to pull.
        _ => {}
    }
    img.fields
        .dedup_by(|a, b| a.key == b.key && a.value == b.value);
    Some(img)
}

// ── JPEG ─────────────────────────────────────────────────────────────────────

const EXIF_PREFIX: &[u8] = b"Exif\x00\x00";
const XMP_PREFIX: &[u8] = b"http://ns.adobe.com/xap/1.0/\x00";

fn parse_jpeg(b: &[u8], img: &mut Image) {
    let mut i = 2; // past SOI
    let mut guard = 0;
    while i + 4 <= b.len() && guard < 512 {
        guard += 1;
        if b[i] != 0xFF {
            break;
        }
        let marker = b[i + 1];
        // Standalone markers (RSTn, SOI, EOI, TEM) have no length.
        if marker == 0xD9 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            i += 2;
            continue;
        }
        let len = u16be(b, i + 2) as usize;
        if len < 2 || i + 2 + len > b.len() {
            break;
        }
        let seg = &b[i + 4..i + 2 + len];
        let name = jpeg_marker_name(marker);
        let mut detail = String::new();
        if marker == 0xE1 {
            if seg.starts_with(EXIF_PREFIX) {
                detail = "EXIF".into();
                read_exif(&seg[EXIF_PREFIX.len()..], img);
            } else if seg.starts_with(XMP_PREFIX) {
                detail = "XMP".into();
                read_xmp(&seg[XMP_PREFIX.len()..], img);
            }
        }
        img.segments.push(Segment {
            name: name.into(),
            file_off: i as u64,
            size: (len + 2) as u64,
            detail,
        });
        // Start of scan: the rest is entropy-coded pixel data, no more segments.
        if marker == 0xDA {
            break;
        }
        i += 2 + len;
    }
}

fn jpeg_marker_name(m: u8) -> &'static str {
    match m {
        0xE0 => "APP0 (JFIF)",
        0xE1 => "APP1",
        0xE2 => "APP2",
        0xED => "APP13 (IPTC)",
        0xEE => "APP14 (Adobe)",
        0xC0..=0xC2 => "SOF (frame)",
        0xC4 => "DHT",
        0xDB => "DQT",
        0xDA => "SOS (scan)",
        0xFE => "COM (comment)",
        _ => "segment",
    }
}

// ── PNG ──────────────────────────────────────────────────────────────────────

fn parse_png(b: &[u8], img: &mut Image) {
    let mut i = 8; // past signature
    let mut guard = 0;
    while i + 8 <= b.len() && guard < 4096 {
        guard += 1;
        let len = u32be(b, i) as usize;
        let typ = &b[i + 4..i + 8];
        let data_start = i + 8;
        if data_start + len + 4 > b.len() {
            break;
        }
        let data = &b[data_start..data_start + len];
        let tname = String::from_utf8_lossy(typ).to_string();
        let mut detail = String::new();
        match typ {
            b"eXIf" => {
                detail = "EXIF".into();
                read_exif(data, img);
            }
            b"tEXt" => detail = read_png_text(data, img),
            b"zTXt" => detail = read_png_ztext(data, img),
            b"iTXt" => detail = read_png_itext(data, img),
            _ => {}
        }
        img.segments.push(Segment {
            name: format!("{tname} chunk"),
            file_off: i as u64,
            size: (len + 12) as u64,
            detail,
        });
        if typ == b"IEND" {
            break;
        }
        i = data_start + len + 4; // skip data + CRC
    }
}

/// PNG textual keywords that carry identity, mapped to display names. The bool
/// is whether the field leaks identity (targeted by a privacy scrub).
fn png_keyword(k: &str) -> Option<(&'static str, bool)> {
    Some(match k {
        "Author" => ("Author", true),
        "Artist" => ("Artist", true),
        "Copyright" => ("Copyright", true),
        "Owner" => ("Owner", true),
        "Software" => ("Software", false),
        "Source" => ("Source", false),
        "Comment" => ("Comment", false),
        "Description" => ("Description", false),
        "Creation Time" => ("Creation Time", false),
        _ => return None,
    })
}

fn push_png_kv(key: &str, value: &str, img: &mut Image) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }
    if let Some((name, identity)) = png_keyword(key) {
        img.fields.push(Field {
            key: name.into(),
            value: truncate(value),
            identity,
        });
        format!("{name}: {}", truncate(value))
    } else {
        String::new()
    }
}

fn read_png_text(data: &[u8], img: &mut Image) -> String {
    let nul = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    let key = String::from_utf8_lossy(&data[..nul]).to_string();
    let value = String::from_utf8_lossy(data.get(nul + 1..).unwrap_or(&[])).to_string();
    push_png_kv(&key, &value, img)
}

fn read_png_ztext(data: &[u8], img: &mut Image) -> String {
    let nul = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    let key = String::from_utf8_lossy(&data[..nul]).to_string();
    // byte after NUL is the compression method; the rest is zlib-deflated.
    let comp = data.get(nul + 2..).unwrap_or(&[]);
    let Some(value) = inflate_zlib(comp, 256 * 1024) else {
        return String::new();
    };
    push_png_kv(&key, &String::from_utf8_lossy(&value), img)
}

fn read_png_itext(data: &[u8], img: &mut Image) -> String {
    // keyword\0 compflag comp\0 lang\0 transkey\0 text
    let mut parts = data.splitn(2, |&c| c == 0);
    let key = String::from_utf8_lossy(parts.next().unwrap_or(&[])).to_string();
    let rest = parts.next().unwrap_or(&[]);
    if rest.len() < 2 {
        return String::new();
    }
    let compressed = rest[0] == 1;
    // skip compflag, compmethod, then lang\0 transkey\0
    let after = &rest[2..];
    let mut it = after.splitn(3, |&c| c == 0);
    it.next(); // language
    it.next(); // translated keyword
    let text = it.next().unwrap_or(&[]);
    let value = if compressed {
        match inflate_zlib(text, 256 * 1024) {
            Some(v) => String::from_utf8_lossy(&v).to_string(),
            None => return String::new(),
        }
    } else {
        String::from_utf8_lossy(text).to_string()
    };
    if key.eq_ignore_ascii_case("XML:com.adobe.xmp") {
        read_xmp(value.as_bytes(), img);
        return "XMP".into();
    }
    push_png_kv(&key, &value, img)
}

fn inflate_zlib(data: &[u8], limit: u64) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut out = Vec::new();
    let mut dec = ZlibDecoder::new(data).take(limit);
    dec.read_to_end(&mut out).ok()?;
    (!out.is_empty()).then_some(out)
}

// ── EXIF / TIFF IFD walk ─────────────────────────────────────────────────────

struct Tiff<'a> {
    d: &'a [u8],
    le: bool,
}

impl Tiff<'_> {
    fn u16(&self, off: usize) -> Option<u16> {
        let s = self.d.get(off..off + 2)?;
        Some(if self.le {
            u16::from_le_bytes([s[0], s[1]])
        } else {
            u16::from_be_bytes([s[0], s[1]])
        })
    }
    fn u32(&self, off: usize) -> Option<u32> {
        let s = self.d.get(off..off + 4)?;
        Some(if self.le {
            u32::from_le_bytes([s[0], s[1], s[2], s[3]])
        } else {
            u32::from_be_bytes([s[0], s[1], s[2], s[3]])
        })
    }
}

fn read_exif(d: &[u8], img: &mut Image) {
    if d.len() < 8 {
        return;
    }
    let le = match &d[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return,
    };
    let t = Tiff { d, le };
    let Some(ifd0) = t.u32(4) else { return };

    // IFD0: image-level identity and attribution, plus pointers to sub-IFDs.
    let mut exif_ptr = None;
    let mut gps_ptr = None;
    walk_ifd(&t, ifd0 as usize, 0, img, &mut |tag, val| match tag {
        0x010E => Some(("Image description", val, false)),
        0x010F => Some(("Camera make", val, false)),
        0x0110 => Some(("Camera model", val, false)),
        0x0131 => Some(("Software", val, false)),
        0x0132 => Some(("Modify date", val, false)),
        0x013B => Some(("Artist", val, true)),
        0x013C => Some(("Host computer", val, true)),
        0x8298 => Some(("Copyright", val, true)),
        _ => None,
    });
    // Re-walk raw to pick up sub-IFD pointers (walk_ifd hides them from the map).
    for e in ifd_entries(&t, ifd0 as usize) {
        match e.tag {
            0x8769 => exif_ptr = t.u32(e.value_off),
            0x8825 => gps_ptr = t.u32(e.value_off),
            _ => {}
        }
    }

    if let Some(p) = exif_ptr {
        walk_ifd(&t, p as usize, 0, img, &mut |tag, val| match tag {
            0x9003 => Some(("Date taken", val, false)),
            0x9004 => Some(("Create date", val, false)),
            0xA430 => Some(("Camera owner", val, true)),
            0xA433 => Some(("Lens make", val, false)),
            0xA434 => Some(("Lens model", val, false)),
            0xA420 => Some(("Image unique ID", val, true)),
            _ => None,
        });
    }

    if let Some(p) = gps_ptr {
        if let Some((lat, lon)) = read_gps(&t, p as usize) {
            img.gps = Some((lat, lon));
            img.fields.push(Field {
                key: "GPS position".into(),
                value: format!("{lat:.6}, {lon:.6}"),
                identity: true,
            });
        }
    }

    // A second IFD (IFD1) is the embedded thumbnail.
    if let Some(next) = t.u32(ifd0 as usize + 2 + entry_count(&t, ifd0 as usize) * 12) {
        if next != 0 && (next as usize) < d.len() {
            img.has_thumbnail = true;
        }
    }
}

struct Entry {
    tag: u16,
    typ: u16,
    count: u32,
    value_off: usize,
}

fn entry_count(t: &Tiff, ifd: usize) -> usize {
    t.u16(ifd).unwrap_or(0).min(4096) as usize
}

fn ifd_entries(t: &Tiff, ifd: usize) -> Vec<Entry> {
    let n = entry_count(t, ifd);
    let mut out = Vec::new();
    for k in 0..n {
        let e = ifd + 2 + k * 12;
        let (Some(tag), Some(typ), Some(count)) = (t.u16(e), t.u16(e + 2), t.u32(e + 4)) else {
            break;
        };
        out.push(Entry {
            tag,
            typ,
            count,
            value_off: e + 8,
        });
    }
    out
}

/// Walk one IFD, handing each mapped tag's string value to `map`.
fn walk_ifd(
    t: &Tiff,
    ifd: usize,
    depth: usize,
    img: &mut Image,
    map: &mut dyn FnMut(u16, String) -> Option<(&'static str, String, bool)>,
) {
    if depth > 4 || ifd + 2 > t.d.len() {
        return;
    }
    for e in ifd_entries(t, ifd) {
        let Some(val) = entry_string(t, &e) else {
            continue;
        };
        if val.trim().is_empty() {
            continue;
        }
        if let Some((name, value, identity)) = map(e.tag, val) {
            img.fields.push(Field {
                key: name.into(),
                value: truncate(value.trim()),
                identity,
            });
        }
    }
}

/// The value of an entry rendered as a string, following the offset for values
/// that do not fit in the inline four bytes.
fn entry_string(t: &Tiff, e: &Entry) -> Option<String> {
    let size = type_size(e.typ)?;
    let total = size.checked_mul(e.count as usize)?;
    let start = if total <= 4 {
        e.value_off
    } else {
        t.u32(e.value_off)? as usize
    };
    match e.typ {
        2 => {
            // ASCII, NUL-terminated.
            let end = (start + e.count as usize).min(t.d.len());
            let raw = t.d.get(start..end)?;
            let s: Vec<u8> = raw.iter().take_while(|&&c| c != 0).copied().collect();
            Some(String::from_utf8_lossy(&s).to_string())
        }
        3 => Some(t.u16(start)?.to_string()),
        4 => Some(t.u32(start)?.to_string()),
        _ => None,
    }
}

fn type_size(typ: u16) -> Option<usize> {
    Some(match typ {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => return None,
    })
}

/// GPS coordinates as signed decimal degrees, or `None` if absent/malformed.
fn read_gps(t: &Tiff, ifd: usize) -> Option<(f64, f64)> {
    let mut lat = None;
    let mut lon = None;
    let mut lat_ref = 1.0;
    let mut lon_ref = 1.0;
    for e in ifd_entries(t, ifd) {
        match e.tag {
            0x0001 => {
                if entry_string(t, &e).as_deref() == Some("S") {
                    lat_ref = -1.0;
                }
            }
            0x0003 => {
                if entry_string(t, &e).as_deref() == Some("W") {
                    lon_ref = -1.0;
                }
            }
            0x0002 => lat = dms(t, &e),
            0x0004 => lon = dms(t, &e),
            _ => {}
        }
    }
    Some((lat? * lat_ref, lon? * lon_ref))
}

/// Three RATIONALs (degrees, minutes, seconds) as decimal degrees.
fn dms(t: &Tiff, e: &Entry) -> Option<f64> {
    if e.typ != 5 || e.count < 3 {
        return None;
    }
    let base = t.u32(e.value_off)? as usize;
    let mut parts = [0f64; 3];
    for (k, p) in parts.iter_mut().enumerate() {
        let num = t.u32(base + k * 8)?;
        let den = t.u32(base + k * 8 + 4)?;
        if den == 0 {
            return None;
        }
        *p = num as f64 / den as f64;
    }
    Some(parts[0] + parts[1] / 60.0 + parts[2] / 3600.0)
}

// ── XMP ──────────────────────────────────────────────────────────────────────

/// A handful of identity fields from an XMP packet, read as plain text rather
/// than parsed as XML — the packet is untrusted and we only want a few values.
fn read_xmp(bytes: &[u8], img: &mut Image) {
    let xml = String::from_utf8_lossy(bytes);
    const WANTED: &[(&str, &str, bool)] = &[
        ("dc:creator", "Creator (XMP)", true),
        ("dc:rights", "Rights (XMP)", true),
        ("xmp:CreatorTool", "Creator tool", false),
        ("photoshop:AuthorsPosition", "Author position", true),
        ("Iptc4xmpCore:CreatorContactInfo", "Creator contact", true),
        ("photoshop:City", "City", true),
        ("photoshop:Country", "Country", true),
    ];
    for (tag, name, identity) in WANTED {
        if let Some(v) = xmp_value(&xml, tag) {
            let v = v.trim();
            if !v.is_empty() {
                img.fields.push(Field {
                    key: (*name).into(),
                    value: truncate(v),
                    identity: *identity,
                });
            }
        }
    }
}

/// The text of `<tag>...</tag>` or the attribute `tag="..."`, whichever appears
/// — XMP writes the same field either way. `rdf:li` inside is unwrapped.
fn xmp_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    if let Some(i) = xml.find(&open) {
        if let Some(gt) = xml[i..].find('>') {
            let start = i + gt + 1;
            let close = format!("</{tag}>");
            if let Some(j) = xml[start..].find(&close) {
                let inner = &xml[start..start + j];
                if let Some(li) = inner.find("<rdf:li") {
                    if let Some(g) = inner[li..].find('>') {
                        let s = li + g + 1;
                        if let Some(e) = inner[s..].find("</rdf:li>") {
                            return Some(inner[s..s + e].to_string());
                        }
                    }
                }
                return Some(inner.trim().to_string());
            }
        }
    }
    // Attribute form: tag="value"
    let attr = format!("{tag}=\"");
    let i = xml.find(&attr)? + attr.len();
    let j = xml[i..].find('"')?;
    Some(xml[i..i + j].to_string())
}

// ── shared ───────────────────────────────────────────────────────────────────

fn truncate(s: &str) -> String {
    const MAX: usize = 512;
    if s.len() <= MAX {
        s.to_string()
    } else {
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

fn u16be(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .unwrap_or(0)
}

fn u32be(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian TIFF/EXIF block with IFD0 holding the given ASCII tags.
    fn exif(tags: &[(u16, &str)]) -> Vec<u8> {
        let mut out = b"II\x2a\x00".to_vec();
        out.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at offset 8
        out.extend_from_slice(&(tags.len() as u16).to_le_bytes());
        // Values that do not fit inline go into a heap after the IFD.
        let ifd_end = 8 + 2 + tags.len() * 12 + 4;
        let mut heap = Vec::new();
        for (tag, val) in tags {
            let bytes = format!("{val}\0");
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&2u16.to_le_bytes()); // ASCII
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            if bytes.len() <= 4 {
                let mut v = bytes.clone().into_bytes();
                v.resize(4, 0);
                out.extend_from_slice(&v);
            } else {
                let off = ifd_end + heap.len();
                out.extend_from_slice(&(off as u32).to_le_bytes());
                heap.extend_from_slice(bytes.as_bytes());
            }
        }
        out.extend_from_slice(&0u32.to_le_bytes()); // no IFD1
        out.extend_from_slice(&heap);
        out
    }

    fn jpeg_with_exif(exif: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8]; // SOI
        let mut app1 = EXIF_PREFIX.to_vec();
        app1.extend_from_slice(exif);
        out.extend_from_slice(&[0xFF, 0xE1]);
        out.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&app1);
        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    #[test]
    fn detects_the_common_containers() {
        assert_eq!(
            detect(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Some(ImageKind::Jpeg)
        );
        assert_eq!(
            detect(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0]),
            Some(ImageKind::Png)
        );
        assert_eq!(detect(b"II\x2a\x00abcdefgh"), Some(ImageKind::Tiff));
        assert!(detect(b"not an image").is_none());
    }

    #[test]
    fn reads_identity_tags_from_a_jpeg() {
        let e = exif(&[
            (0x013B, "Jane Photographer"),
            (0x010F, "NIKON"),
            (0x0131, "Adobe Photoshop 25.0"),
        ]);
        let img = parse(&jpeg_with_exif(&e)).expect("jpeg parses");
        assert_eq!(img.kind, ImageKind::Jpeg);
        let artist = img
            .fields
            .iter()
            .find(|f| f.key == "Artist")
            .expect("artist");
        assert_eq!(artist.value, "Jane Photographer");
        assert!(artist.identity, "an author name is identity");
        let sw = img
            .fields
            .iter()
            .find(|f| f.key == "Software")
            .expect("software");
        assert!(!sw.identity, "software is attribution, not identity");
    }

    #[test]
    fn decodes_gps_to_signed_decimal() {
        // 40°44'54.36\"N, 73°59'8.36\"W  (roughly Manhattan)
        let mut d = b"II\x2a\x00".to_vec();
        d.extend_from_slice(&8u32.to_le_bytes());
        // one IFD0 entry: GPS IFD pointer (0x8825) -> offset
        d.extend_from_slice(&1u16.to_le_bytes());
        let gps_ifd_off = 8 + 2 + 12 + 4;
        d.extend_from_slice(&0x8825u16.to_le_bytes());
        d.extend_from_slice(&4u16.to_le_bytes()); // LONG
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&(gps_ifd_off as u32).to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes()); // no IFD1
                                                  // GPS IFD: refs + lat + lon, rationals in a heap after it.
        let entries: u16 = 4;
        let gps_end = gps_ifd_off + 2 + entries as usize * 12 + 4;
        d.extend_from_slice(&entries.to_le_bytes());
        let lat_off = gps_end;
        let lon_off = gps_end + 24;
        // 0x0001 lat ref N
        d.extend_from_slice(&0x0001u16.to_le_bytes());
        d.extend_from_slice(&2u16.to_le_bytes());
        d.extend_from_slice(&2u32.to_le_bytes());
        d.extend_from_slice(b"N\0\0\0");
        // 0x0002 lat (deg,min,sec rationals)
        d.extend_from_slice(&0x0002u16.to_le_bytes());
        d.extend_from_slice(&5u16.to_le_bytes());
        d.extend_from_slice(&3u32.to_le_bytes());
        d.extend_from_slice(&(lat_off as u32).to_le_bytes());
        // 0x0003 lon ref W
        d.extend_from_slice(&0x0003u16.to_le_bytes());
        d.extend_from_slice(&2u16.to_le_bytes());
        d.extend_from_slice(&2u32.to_le_bytes());
        d.extend_from_slice(b"W\0\0\0");
        // 0x0004 lon
        d.extend_from_slice(&0x0004u16.to_le_bytes());
        d.extend_from_slice(&5u16.to_le_bytes());
        d.extend_from_slice(&3u32.to_le_bytes());
        d.extend_from_slice(&(lon_off as u32).to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes()); // next IFD
        for (deg, min, sec) in [(40u32, 44u32, 5436u32), (73, 59, 836)] {
            d.extend_from_slice(&deg.to_le_bytes());
            d.extend_from_slice(&1u32.to_le_bytes());
            d.extend_from_slice(&min.to_le_bytes());
            d.extend_from_slice(&1u32.to_le_bytes());
            d.extend_from_slice(&sec.to_le_bytes());
            d.extend_from_slice(&100u32.to_le_bytes());
        }
        let img = parse(&jpeg_with_exif(&d)).expect("jpeg parses");
        let (lat, lon) = img.gps.expect("gps present");
        assert!((lat - 40.7484).abs() < 0.001, "lat={lat}");
        assert!(
            (lon + 73.9856).abs() < 0.001,
            "lon={lon} (should be negative/West)"
        );
        assert!(img
            .fields
            .iter()
            .any(|f| f.key == "GPS position" && f.identity));
    }

    #[test]
    fn reads_png_text_chunks() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let chunk = |typ: &[u8], data: &[u8]| {
            let mut c = Vec::new();
            c.extend_from_slice(&(data.len() as u32).to_be_bytes());
            c.extend_from_slice(typ);
            c.extend_from_slice(data);
            c.extend_from_slice(&0u32.to_be_bytes()); // CRC placeholder
            c
        };
        png.extend(chunk(b"tEXt", b"Author\0Alice Doe"));
        png.extend(chunk(b"tEXt", b"Software\0GIMP 2.10"));
        png.extend(chunk(b"IEND", b""));
        let img = parse(&png).expect("png parses");
        let author = img
            .fields
            .iter()
            .find(|f| f.key == "Author")
            .expect("author");
        assert_eq!(author.value, "Alice Doe");
        assert!(author.identity);
    }

    #[test]
    fn a_bare_image_with_no_metadata_still_parses() {
        let img = parse(&[0xFF, 0xD8, 0xFF, 0xD9, 0, 0, 0, 0, 0, 0, 0, 0]).expect("parses");
        assert!(img.fields.is_empty());
        assert!(img.gps.is_none());
    }
}
