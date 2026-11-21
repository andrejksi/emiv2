use std::collections::BTreeMap;

const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            map.insert(k.to_owned(), v);
        }
        Value::Object(map)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }


    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(i) if *i >= 0 => Some(*i as u64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn canonical(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    pub fn pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Float(f) => {
                if f.is_finite() {
                    out.push_str(&format!("{f}"));
                } else {
                    out.push_str("null");
                }
            }
            Value::Str(s) => write_escaped(s, out),
            Value::Array(items) => {
                out.push('[');
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (idx, (k, v)) in map.iter().enumerate() {
                    if idx > 0 {
                        out.push(',');
                    }
                    write_escaped(k, out);
                    out.push(':');
                    v.write_canonical(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        match self {
            Value::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (idx, item) in items.iter().enumerate() {
                    for _ in 0..indent + 2 {
                        out.push(' ');
                    }
                    item.write_pretty(out, indent + 2);
                    if idx + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                for _ in 0..indent {
                    out.push(' ');
                }
                out.push(']');
            }
            Value::Object(map) if !map.is_empty() => {
                out.push_str("{\n");
                for (idx, (k, v)) in map.iter().enumerate() {
                    for _ in 0..indent + 2 {
                        out.push(' ');
                    }
                    write_escaped(k, out);
                    out.push_str(": ");
                    v.write_pretty(out, indent + 2);
                    if idx + 1 < map.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                for _ in 0..indent {
                    out.push(' ');
                }
                out.push('}');
            }
            _ => self.write_canonical(out),
        }
    }
}

fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return Err("json nesting depth exceeded".to_owned());
        }
        self.skip_ws();
        let b = self.peek().ok_or_else(|| "unexpected end of json".to_owned())?;
        match b {
            b'n' => self.parse_literal(b"null", Value::Null),
            b't' => self.parse_literal(b"true", Value::Bool(true)),
            b'f' => self.parse_literal(b"false", Value::Bool(false)),
            b'"' => self.parse_string().map(Value::Str),
            b'[' => self.parse_array(depth + 1),
            b'{' => self.parse_object(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(format!("unexpected byte {} at {}", other as char, self.pos)),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], val: Value) -> Result<Value, String> {
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(format!("invalid literal at {}", self.pos))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        assert!(self.peek() == Some(b'"'));
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.peek().ok_or_else(|| "unterminated escape".to_owned())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\x08'),
                        b'f' => out.push('\x0c'),
                        b'u' => {
                            if self.pos + 4 > self.bytes.len() {
                                return Err("short unicode escape".to_owned());
                            }
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|_| "invalid unicode escape".to_owned())?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|_| "invalid unicode hex".to_owned())?;
                            self.pos += 4;
                            let ch = char::from_u32(code).unwrap_or('\u{FFFD}');
                            out.push(ch);
                        }
                        _ => return Err(format!("invalid escape at {}", self.pos)),
                    }
                }
                c if c < 0x80 => out.push(c as char),
                _ => {
                    self.pos -= 1;
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| "invalid utf8 in json string".to_owned())?;
                    let ch = rest.chars().next().ok_or_else(|| "eof".to_owned())?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
        Err("unterminated json string".to_owned())
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let mut is_float = false;
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' => self.pos += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' if self.pos > start => {
                    is_float = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number utf8".to_owned())?;
        if is_float {
            let f = raw.parse::<f64>().map_err(|_| format!("invalid float: {raw}"))?;
            Ok(Value::Float(f))
        } else {
            let i = raw.parse::<i64>().map_err(|_| format!("invalid int: {raw}"))?;
            Ok(Value::Int(i))
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, String> {
        assert!(self.peek() == Some(b'['));
        self.pos += 1;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, String> {
        assert!(self.peek() == Some(b'{'));
        self.pos += 1;
        self.skip_ws();
        let mut map = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected string key at {}", self.pos));
            }
            let key = self.parse_string()?;
            if map.contains_key(&key) {
                return Err(format!("duplicate json key: {key}"));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
            }
        }
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing bytes at {}", parser.pos));
    }
    Ok(val)
}
