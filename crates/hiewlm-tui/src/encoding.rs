//! Text-mode byte→glyph encodings. All are 1 byte = 1 glyph so the cursor stays
//! byte-aligned (multi-byte UTF-8 text rendering is a separate future mode).

/// CP437 (the classic IBM PC / DOS code page) — every byte has a glyph.
const CP437: [char; 256] = [
    '\u{00}', '☺', '☻', '♥', '♦', '♣', '♠', '•', '◘', '○', '◙', '♂', '♀', '♪', '♫', '☼',
    '►', '◄', '↕', '‼', '¶', '§', '▬', '↨', '↑', '↓', '→', '←', '∟', '↔', '▲', '▼',
    ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '⌂',
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
    'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
    'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
    '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
    '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
    '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
    'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
    '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{00}',
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    Ascii,
    Cp437,
    Latin1,
    /// UTF-16 little-endian: one glyph per 2 bytes (rendered at even offsets).
    Utf16Le,
}

impl Encoding {
    pub fn next(self) -> Self {
        match self {
            Encoding::Ascii => Encoding::Cp437,
            Encoding::Cp437 => Encoding::Latin1,
            Encoding::Latin1 => Encoding::Utf16Le,
            Encoding::Utf16Le => Encoding::Ascii,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Encoding::Ascii => "ascii",
            Encoding::Cp437 => "cp437",
            Encoding::Latin1 => "latin1",
            Encoding::Utf16Le => "utf16le",
        }
    }

    pub fn is_wide(self) -> bool {
        matches!(self, Encoding::Utf16Le)
    }

    /// Glyph for the UTF-16LE code unit `hi<<8 | lo`.
    pub fn wide_glyph(lo: u8, hi: u8) -> char {
        let c = u16::from_le_bytes([lo, hi]);
        char::from_u32(c as u32).filter(|c| !c.is_control()).unwrap_or('.')
    }

    /// Guess an encoding from a byte sample: lots of zero high-bytes at odd
    /// positions ⇒ UTF-16LE ASCII text; otherwise ASCII.
    pub fn detect(sample: &[u8]) -> Encoding {
        if sample.len() < 16 {
            return Encoding::Ascii;
        }
        let pairs = sample.len() / 2;
        let mut ascii_lo_zero_hi = 0;
        for i in (0..pairs * 2).step_by(2) {
            if (0x20..0x7f).contains(&sample[i]) && sample[i + 1] == 0 {
                ascii_lo_zero_hi += 1;
            }
        }
        if ascii_lo_zero_hi * 100 / pairs.max(1) > 60 {
            Encoding::Utf16Le
        } else {
            Encoding::Ascii
        }
    }

    /// Render one byte as a glyph. Non-printable bytes become '.' (except CP437,
    /// which has a glyph for every byte but null/blank).
    pub fn decode(self, b: u8) -> char {
        match self {
            Encoding::Ascii => {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            }
            Encoding::Cp437 => {
                let c = CP437[b as usize];
                if c == '\u{00}' {
                    ' '
                } else {
                    c
                }
            }
            Encoding::Latin1 => {
                if (0x20..0x7f).contains(&b) || b >= 0xa0 {
                    char::from_u32(b as u32).unwrap_or('.')
                } else {
                    '.'
                }
            }
            // Wide encoding is rendered pairwise in the view; per-byte falls back
            // to ASCII.
            Encoding::Utf16Le => {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            }
        }
    }
}
