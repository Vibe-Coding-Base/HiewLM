//! 64-bit expression calculator (HIEW `Alt+=`). Recursive-descent, C operator
//! precedence, wrapping arithmetic. Supports operands read from the file at the
//! cursor. Pure and side-effect free.
//!
//! Numbers: bare = decimal; `0x`/`h` = hex; `0b`/`i` = binary; `0o`/`o` = octal;
//! `t` suffix forces decimal.  Operators (low→high precedence):
//! `|`  `^`  `&`  `<< >>`  `+ -`  `* / %`  unary `~ - +`.
//! Operands: `@o` cursor offset, `@O` global offset (== `@o` here),
//! `@b/@w/@d/@q` = u8/u16/u32/u64 read little-endian at the cursor.

/// Values the calculator can read from the current file position.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ctx {
    pub offset: u64,
    pub b: u64,
    pub w: u64,
    pub d: u64,
    pub q: u64,
}

pub fn eval(expr: &str, ctx: &Ctx) -> Result<u64, String> {
    let tokens = tokenize(expr)?;
    let mut p = Parser {
        tokens: &tokens,
        pos: 0,
        ctx,
    };
    let v = p.parse_or()?;
    if p.pos != p.tokens.len() {
        return Err(format!("unexpected token near position {}", p.pos));
    }
    Ok(v)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Num(u64),
    Op(char),
    Shl,
    Shr,
    LParen,
    RParen,
    Operand(char), // b w d q o O
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '+' | '-' | '*' | '/' | '%' | '&' | '|' | '^' | '~' => {
                out.push(Tok::Op(c));
                i += 1;
            }
            '<' if i + 1 < chars.len() && chars[i + 1] == '<' => {
                out.push(Tok::Shl);
                i += 2;
            }
            '>' if i + 1 < chars.len() && chars[i + 1] == '>' => {
                out.push(Tok::Shr);
                i += 2;
            }
            '@' if i + 1 < chars.len() => {
                let o = chars[i + 1];
                if !matches!(o, 'b' | 'w' | 'd' | 'q' | 'o' | 'O') {
                    return Err(format!("unknown operand @{o}"));
                }
                out.push(Tok::Operand(o));
                i += 2;
            }
            c if c.is_ascii_alphanumeric() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_alphanumeric() {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                out.push(Tok::Num(parse_number(&word)?));
            }
            _ => return Err(format!("bad character '{c}'")),
        }
    }
    Ok(out)
}

fn parse_number(w: &str) -> Result<u64, String> {
    let err = || format!("bad number '{w}'");
    if let Some(r) = w.strip_prefix("0x").or_else(|| w.strip_prefix("0X")) {
        return u64::from_str_radix(r, 16).map_err(|_| err());
    }
    if let Some(r) = w.strip_prefix("0b").or_else(|| w.strip_prefix("0B")) {
        return u64::from_str_radix(r, 2).map_err(|_| err());
    }
    if let Some(r) = w.strip_prefix("0o").or_else(|| w.strip_prefix("0O")) {
        return u64::from_str_radix(r, 8).map_err(|_| err());
    }
    if let Some(r) = w.strip_suffix(['t', 'T']) {
        return r.parse().map_err(|_| err());
    }
    if let Some(r) = w.strip_suffix(['h', 'H']) {
        return u64::from_str_radix(r, 16).map_err(|_| err());
    }
    if let Some(r) = w.strip_suffix(['i', 'I']) {
        return u64::from_str_radix(r, 2).map_err(|_| err());
    }
    if let Some(r) = w.strip_suffix(['o', 'O']) {
        return u64::from_str_radix(r, 8).map_err(|_| err());
    }
    w.parse().map_err(|_| err())
}

struct Parser<'a> {
    tokens: &'a [Tok],
    pos: usize,
    ctx: &'a Ctx,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn eat(&mut self) -> Option<&Tok> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Result<u64, String> {
        let mut v = self.parse_xor()?;
        while matches!(self.peek(), Some(Tok::Op('|'))) {
            self.pos += 1;
            v |= self.parse_xor()?;
        }
        Ok(v)
    }

    fn parse_xor(&mut self) -> Result<u64, String> {
        let mut v = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Op('^'))) {
            self.pos += 1;
            v ^= self.parse_and()?;
        }
        Ok(v)
    }

    fn parse_and(&mut self) -> Result<u64, String> {
        let mut v = self.parse_shift()?;
        while matches!(self.peek(), Some(Tok::Op('&'))) {
            self.pos += 1;
            v &= self.parse_shift()?;
        }
        Ok(v)
    }

    fn parse_shift(&mut self) -> Result<u64, String> {
        let mut v = self.parse_add()?;
        loop {
            match self.peek() {
                Some(Tok::Shl) => {
                    self.pos += 1;
                    v = v.wrapping_shl(self.parse_add()? as u32);
                }
                Some(Tok::Shr) => {
                    self.pos += 1;
                    v = v.wrapping_shr(self.parse_add()? as u32);
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn parse_add(&mut self) -> Result<u64, String> {
        let mut v = self.parse_mul()?;
        loop {
            match self.peek() {
                Some(Tok::Op('+')) => {
                    self.pos += 1;
                    v = v.wrapping_add(self.parse_mul()?);
                }
                Some(Tok::Op('-')) => {
                    self.pos += 1;
                    v = v.wrapping_sub(self.parse_mul()?);
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn parse_mul(&mut self) -> Result<u64, String> {
        let mut v = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Tok::Op('*')) => {
                    self.pos += 1;
                    v = v.wrapping_mul(self.parse_unary()?);
                }
                Some(Tok::Op('/')) => {
                    self.pos += 1;
                    let d = self.parse_unary()?;
                    if d == 0 {
                        return Err("division by zero".into());
                    }
                    v /= d;
                }
                Some(Tok::Op('%')) => {
                    self.pos += 1;
                    let d = self.parse_unary()?;
                    if d == 0 {
                        return Err("modulo by zero".into());
                    }
                    v %= d;
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn parse_unary(&mut self) -> Result<u64, String> {
        match self.peek() {
            Some(Tok::Op('~')) => {
                self.pos += 1;
                Ok(!self.parse_unary()?)
            }
            Some(Tok::Op('-')) => {
                self.pos += 1;
                Ok(0u64.wrapping_sub(self.parse_unary()?))
            }
            Some(Tok::Op('+')) => {
                self.pos += 1;
                self.parse_unary()
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<u64, String> {
        match self.eat() {
            Some(Tok::Num(n)) => Ok(*n),
            Some(Tok::Operand(o)) => Ok(match o {
                'o' | 'O' => self.ctx.offset,
                'b' => self.ctx.b,
                'w' => self.ctx.w,
                'd' => self.ctx.d,
                'q' => self.ctx.q,
                _ => 0,
            }),
            Some(Tok::LParen) => {
                let v = self.parse_or()?;
                match self.eat() {
                    Some(Tok::RParen) => Ok(v),
                    _ => Err("expected ')'".into()),
                }
            }
            _ => Err("expected a value".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(s: &str) -> u64 {
        eval(s, &Ctx::default()).unwrap()
    }

    #[test]
    fn arithmetic_and_precedence() {
        assert_eq!(e("2 + 3 * 4"), 14);
        assert_eq!(e("(2 + 3) * 4"), 20);
        assert_eq!(e("0x10 + 0x20"), 0x30);
        assert_eq!(e("1 << 4"), 16);
        assert_eq!(e("0xff & 0x0f"), 0x0f);
        assert_eq!(e("0b1010 | 0b0101"), 0b1111);
        assert_eq!(e("~0"), u64::MAX);
        assert_eq!(e("-1"), u64::MAX);
        assert_eq!(e("100t"), 100);
        assert_eq!(e("10 % 3"), 1);
    }

    #[test]
    fn operands_and_errors() {
        let ctx = Ctx {
            offset: 0x1000,
            b: 0xAB,
            w: 0x1234,
            d: 0xdead,
            q: 0xbeef,
        };
        assert_eq!(eval("@o + 4", &ctx).unwrap(), 0x1004);
        assert_eq!(eval("@w", &ctx).unwrap(), 0x1234);
        assert_eq!(eval("@d ^ @d", &ctx).unwrap(), 0);
        assert!(eval("1 / 0", &Ctx::default()).is_err());
        assert!(eval("1 +", &Ctx::default()).is_err());
        assert!(eval("@z", &Ctx::default()).is_err());
    }
}
