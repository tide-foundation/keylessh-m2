// Minimal ASN.1 DER encoder/decoder — port of the TypeScript original.

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_SEQUENCE: u8 = 0x30;

/// Returns the context-specific constructed tag for EXPLICIT [n].
pub fn context_tag(n: u8) -> u8 {
    0xa0 | n
}

/// Encode a DER length field.
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

/// Encode a TLV (tag-length-value).
pub fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode a DER INTEGER from an i64 value.
/// Prepends 0x00 if the high bit of the most-significant byte is set (signed encoding).
pub fn encode_integer(value: i64) -> Vec<u8> {
    if value == 0 {
        return encode_tlv(TAG_INTEGER, &[0x00]);
    }

    // Collect significant bytes, big-endian
    let all_bytes = (value as u64).to_be_bytes();
    let first_nonzero = all_bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let mut content: Vec<u8> = all_bytes[first_nonzero..].to_vec();

    // Prepend 0x00 if the high bit is set (DER signed integer)
    if content[0] & 0x80 != 0 {
        content.insert(0, 0x00);
    }

    encode_tlv(TAG_INTEGER, &content)
}

/// Encode a DER OCTET STRING.
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, data)
}

/// Encode a DER UTF8String.
pub fn encode_utf8_string(s: &str) -> Vec<u8> {
    encode_tlv(TAG_UTF8_STRING, s.as_bytes())
}

/// Encode a DER SEQUENCE from pre-encoded element slices.
pub fn encode_sequence(elements: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for el in elements {
        content.extend_from_slice(el);
    }
    encode_tlv(TAG_SEQUENCE, &content)
}

/// Encode a DER SEQUENCE from pre-encoded Vec elements.
pub fn encode_sequence_from_vecs(elements: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = elements.iter().map(|v| v.as_slice()).collect();
    encode_sequence(&refs)
}

/// Encode a context-specific EXPLICIT [tag_num] wrapping inner bytes.
pub fn encode_explicit(tag_num: u8, inner: &[u8]) -> Vec<u8> {
    encode_tlv(context_tag(tag_num), inner)
}

// ---------------------------------------------------------------------------
// DER Reader
// ---------------------------------------------------------------------------

pub struct DerReader {
    buf: Vec<u8>,
    pos: usize,
    end: usize,
}

impl DerReader {
    pub fn new(buf: &[u8]) -> Self {
        let end = buf.len();
        Self { buf: buf.to_vec(), pos: 0, end }
    }

    pub fn new_slice(buf: &[u8], offset: usize, length: usize) -> Self {
        Self {
            buf: buf.to_vec(),
            pos: offset,
            end: offset + length,
        }
    }

    pub fn has_more(&self) -> bool {
        self.pos < self.end
    }

    pub fn peek_tag(&self) -> Option<u8> {
        if self.pos < self.end {
            Some(self.buf[self.pos])
        } else {
            None
        }
    }

    pub fn read_tag(&mut self) -> Result<u8, String> {
        if self.pos >= self.end {
            return Err("DER: unexpected end of data reading tag".into());
        }
        let tag = self.buf[self.pos];
        self.pos += 1;
        Ok(tag)
    }

    pub fn read_length(&mut self) -> Result<usize, String> {
        if self.pos >= self.end {
            return Err("DER: unexpected end of data reading length".into());
        }
        let first = self.buf[self.pos] as usize;
        self.pos += 1;

        if first < 0x80 {
            return Ok(first);
        }

        let num_bytes = first & 0x7f;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(format!("DER: unsupported length encoding: {num_bytes} bytes"));
        }
        if self.pos + num_bytes > self.end {
            return Err("DER: unexpected end of data reading multi-byte length".into());
        }

        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (self.buf[self.pos + i] as usize);
        }
        self.pos += num_bytes;
        Ok(len)
    }

    /// Read one TLV, returning (tag, value_bytes).
    pub fn read_tlv(&mut self) -> Result<(u8, Vec<u8>), String> {
        let tag = self.read_tag()?;
        let len = self.read_length()?;
        if self.pos + len > self.end {
            return Err(format!(
                "DER: TLV value overflows buffer (need {len}, have {})",
                self.end - self.pos
            ));
        }
        let value = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok((tag, value))
    }

    /// Read a SEQUENCE and return a sub-reader over its contents.
    pub fn read_sequence(&mut self) -> Result<DerReader, String> {
        let tag = self.read_tag()?;
        if tag != TAG_SEQUENCE {
            return Err(format!("DER: expected SEQUENCE (0x30), got 0x{tag:02x}"));
        }
        let len = self.read_length()?;
        if self.pos + len > self.end {
            return Err("DER: SEQUENCE overflows buffer".into());
        }
        let reader = DerReader::new_slice(&self.buf, self.pos, len);
        self.pos += len;
        Ok(reader)
    }

    /// If the next tag is EXPLICIT [tag_num], consume it and return a sub-reader
    /// over its contents. Otherwise return None without consuming anything.
    pub fn read_explicit(&mut self, tag_num: u8) -> Result<Option<DerReader>, String> {
        let expected = context_tag(tag_num);
        if self.peek_tag() != Some(expected) {
            return Ok(None);
        }
        // Consume the tag
        self.read_tag()?;
        let len = self.read_length()?;
        if self.pos + len > self.end {
            return Err("DER: EXPLICIT context overflows buffer".into());
        }
        let reader = DerReader::new_slice(&self.buf, self.pos, len);
        self.pos += len;
        Ok(Some(reader))
    }

    pub fn read_integer(&mut self) -> Result<i64, String> {
        let (tag, value) = self.read_tlv()?;
        if tag != TAG_INTEGER {
            return Err(format!("DER: expected INTEGER (0x02), got 0x{tag:02x}"));
        }
        if value.is_empty() {
            return Err("DER: empty INTEGER".into());
        }
        // Sign-extend from first byte
        let mut result: i64 = if value[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in &value {
            result = (result << 8) | (b as i64);
        }
        Ok(result)
    }

    pub fn read_octet_string(&mut self) -> Result<Vec<u8>, String> {
        let (tag, value) = self.read_tlv()?;
        if tag != TAG_OCTET_STRING {
            return Err(format!(
                "DER: expected OCTET STRING (0x04), got 0x{tag:02x}"
            ));
        }
        Ok(value)
    }

    pub fn read_utf8_string(&mut self) -> Result<String, String> {
        let (tag, value) = self.read_tlv()?;
        if tag != TAG_UTF8_STRING {
            return Err(format!(
                "DER: expected UTF8String (0x0c), got 0x{tag:02x}"
            ));
        }
        String::from_utf8(value).map_err(|e| format!("DER: invalid UTF-8: {e}"))
    }

    /// Skip one TLV without returning its contents.
    #[allow(dead_code)]
    pub fn skip(&mut self) -> Result<(), String> {
        let _tag = self.read_tag()?;
        let len = self.read_length()?;
        if self.pos + len > self.end {
            return Err("DER: skip overflows buffer".into());
        }
        self.pos += len;
        Ok(())
    }

    /// Read a SEQUENCE whose elements are all OCTET STRINGs.
    #[allow(dead_code)]
    pub fn read_sequence_of_octet_strings(&mut self) -> Result<Vec<Vec<u8>>, String> {
        let mut seq = self.read_sequence()?;
        let mut result = Vec::new();
        while seq.has_more() {
            result.push(seq.read_octet_string()?);
        }
        Ok(result)
    }

    /// Read a SEQUENCE and return a sub-reader (alias for convenience).
    pub fn read_sequence_inner(&mut self) -> Result<DerReader, String> {
        self.read_sequence()
    }

    /// Read an INTEGER and return its value as i64.
    pub fn read_integer_value(&mut self) -> Option<i64> {
        let (tag, value) = self.read_tlv().ok()?;
        if tag != TAG_INTEGER || value.is_empty() {
            return None;
        }
        let mut result: i64 = if value[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in &value {
            result = (result << 8) | (b as i64);
        }
        Some(result)
    }
}

impl DerReader {
    /// Convenience: read EXPLICIT [n] and return sub-reader, or None.
    #[allow(dead_code)]
    pub fn try_read_explicit(&mut self, tag_num: u8) -> Option<DerReader> {
        self.read_explicit(tag_num).ok().flatten()
    }
}

// ---------------------------------------------------------------------------
// Tests — ported from tests/gateway/der-codec.test.ts (Node RDCleanPath codec)
// to preserve coverage after the Node gateway was removed.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_constants() {
        assert_eq!(TAG_INTEGER, 0x02);
        assert_eq!(TAG_OCTET_STRING, 0x04);
        assert_eq!(TAG_UTF8_STRING, 0x0c);
        assert_eq!(TAG_SEQUENCE, 0x30);
    }

    #[test]
    fn context_tag_produces_constructed_tags() {
        assert_eq!(context_tag(0), 0xa0);
        assert_eq!(context_tag(1), 0xa1);
        assert_eq!(context_tag(7), 0xa7);
        assert_eq!(context_tag(9), 0xa9);
    }

    #[test]
    fn encode_integer_cases() {
        assert_eq!(encode_integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(encode_integer(42), vec![0x02, 0x01, 0x2a]);
        assert_eq!(encode_integer(127), vec![0x02, 0x01, 0x7f]);
        // high bit set -> 0x00 prefix
        assert_eq!(encode_integer(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_integer(256), vec![0x02, 0x02, 0x01, 0x00]);
        // RDCLEANPATH_VERSION 3390 = 0x0D3E
        assert_eq!(encode_integer(3390), vec![0x02, 0x02, 0x0d, 0x3e]);
    }

    #[test]
    fn encode_octet_string_cases() {
        assert_eq!(encode_octet_string(&[]), vec![0x04, 0x00]);
        assert_eq!(
            encode_octet_string(&[0xDE, 0xAD, 0xBE, 0xEF]),
            vec![0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn encode_utf8_string_cases() {
        assert_eq!(encode_utf8_string(""), vec![0x0c, 0x00]);
        let hello = encode_utf8_string("hello");
        assert_eq!(hello[0], 0x0c);
        assert_eq!(hello[1], 5);
        assert_eq!(&hello[2..], b"hello");
        // multibyte
        let accented = encode_utf8_string("héllo");
        assert_eq!(accented[0], 0x0c);
        assert_eq!(std::str::from_utf8(&accented[2..]).unwrap(), "héllo");
    }

    #[test]
    fn encode_sequence_cases() {
        assert_eq!(encode_sequence(&[]), vec![0x30, 0x00]);
        let inner = encode_integer(42);
        let seq = encode_sequence(&[&inner]);
        assert_eq!(seq[0], 0x30);
        assert_eq!(seq[1] as usize, inner.len());
        assert_eq!(&seq[2..], inner.as_slice());
    }

    #[test]
    fn encode_explicit_cases() {
        let inner = encode_integer(3390);
        let buf = encode_explicit(0, &inner);
        assert_eq!(buf[0], 0xa0);
        assert_eq!(buf[1] as usize, inner.len());
        assert_eq!(&buf[2..], inner.as_slice());

        let inner7 = encode_octet_string(&[0x01]);
        let buf7 = encode_explicit(7, &inner7);
        assert_eq!(buf7[0], 0xa7);
    }

    #[test]
    fn long_form_length_encoding() {
        // length 200 -> 0x81 0xC8
        let data200 = vec![0x42u8; 200];
        let buf = encode_octet_string(&data200);
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf[1], 0x81);
        assert_eq!(buf[2], 200);
        assert_eq!(buf.len(), 1 + 2 + 200);

        // length 300 -> 0x82 0x01 0x2C
        let data300 = vec![0x42u8; 300];
        let buf2 = encode_octet_string(&data300);
        assert_eq!(buf2[0], 0x04);
        assert_eq!(buf2[1], 0x82);
        assert_eq!(((buf2[2] as usize) << 8) | (buf2[3] as usize), 300);
        assert_eq!(buf2.len(), 1 + 3 + 300);
    }

    #[test]
    fn reader_read_integer() {
        let buf = encode_integer(3390);
        assert_eq!(DerReader::new(&buf).read_integer().unwrap(), 3390);
        let zero = encode_integer(0);
        assert_eq!(DerReader::new(&zero).read_integer().unwrap(), 0);
        // wrong tag
        let s = encode_utf8_string("hello");
        assert!(DerReader::new(&s).read_integer().is_err());
    }

    #[test]
    fn reader_read_octet_and_utf8() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let buf = encode_octet_string(&data);
        assert_eq!(DerReader::new(&buf).read_octet_string().unwrap(), data.to_vec());
        let empty = encode_octet_string(&[]);
        assert_eq!(DerReader::new(&empty).read_octet_string().unwrap(), Vec::<u8>::new());
        let s = encode_utf8_string("hello world");
        assert_eq!(DerReader::new(&s).read_utf8_string().unwrap(), "hello world");
    }

    #[test]
    fn reader_read_sequence_multiple() {
        let buf = encode_sequence(&[&encode_integer(1), &encode_integer(2), &encode_integer(3)]);
        let mut reader = DerReader::new(&buf);
        let mut seq = reader.read_sequence().unwrap();
        assert_eq!(seq.read_integer().unwrap(), 1);
        assert_eq!(seq.read_integer().unwrap(), 2);
        assert_eq!(seq.read_integer().unwrap(), 3);
        assert!(!seq.has_more());
    }

    #[test]
    fn reader_read_explicit_match_and_none() {
        let inner = encode_integer(42);
        let buf = encode_explicit(0, &inner);
        let mut reader = DerReader::new(&buf);
        let mut ctx = reader.read_explicit(0).unwrap().expect("should match [0]");
        assert_eq!(ctx.read_integer().unwrap(), 42);

        // non-matching tag returns None without consuming
        let buf2 = encode_explicit(0, &encode_integer(42));
        let mut reader2 = DerReader::new(&buf2);
        assert!(reader2.read_explicit(1).unwrap().is_none());
    }

    #[test]
    fn reader_read_sequence_of_octet_strings() {
        let cert1 = [0x01u8, 0x02];
        let cert2 = [0x03u8, 0x04];
        let buf = encode_sequence(&[&encode_octet_string(&cert1), &encode_octet_string(&cert2)]);
        let result = DerReader::new(&buf).read_sequence_of_octet_strings().unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], cert1.to_vec());
        assert_eq!(result[1], cert2.to_vec());
    }

    #[test]
    fn reader_has_more_peek_skip() {
        assert!(!DerReader::new(&[]).has_more());
        let buf = encode_integer(42);
        let mut reader = DerReader::new(&buf);
        assert_eq!(reader.peek_tag(), Some(TAG_INTEGER));
        assert_eq!(reader.read_integer().unwrap(), 42);
        assert!(!reader.has_more());
        assert_eq!(DerReader::new(&[]).peek_tag(), None);

        // skip a TLV
        let mut concat = encode_integer(1);
        concat.extend_from_slice(&encode_integer(2));
        let mut r = DerReader::new(&concat);
        r.skip().unwrap();
        assert_eq!(r.read_integer().unwrap(), 2);
    }

    #[test]
    fn reader_error_handling() {
        // unexpected end for read_tag
        assert!(DerReader::new(&[]).read_tag().is_err());
        // value overflows buffer: OCTET STRING claims len 100 but only 1 byte
        let bad = [0x04u8, 0x64, 0x00];
        assert!(DerReader::new(&bad).read_octet_string().is_err());
    }

    #[test]
    fn roundtrip_nested_structure() {
        // SEQUENCE { [0] INTEGER(3390), [2] UTF8("hello"), [6] OCTET(deadbeef) }
        let original = encode_sequence(&[
            &encode_explicit(0, &encode_integer(3390)),
            &encode_explicit(2, &encode_utf8_string("hello")),
            &encode_explicit(6, &encode_octet_string(&[0xDE, 0xAD, 0xBE, 0xEF])),
        ]);
        let mut outer = DerReader::new(&original);
        let mut seq = outer.read_sequence().unwrap();
        assert_eq!(seq.read_explicit(0).unwrap().unwrap().read_integer().unwrap(), 3390);
        assert_eq!(seq.read_explicit(2).unwrap().unwrap().read_utf8_string().unwrap(), "hello");
        assert_eq!(
            seq.read_explicit(6).unwrap().unwrap().read_octet_string().unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(!seq.has_more());
    }
}
