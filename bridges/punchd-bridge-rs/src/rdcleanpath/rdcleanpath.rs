// RDCleanPath PDU types — port of the TypeScript original.

use super::der_codec::*;

pub const RDCLEANPATH_VERSION: i64 = 3390;
pub const RDCLEANPATH_ERROR_GENERAL: i64 = 1;
#[allow(dead_code)]
pub const RDCLEANPATH_ERROR_NEGOTIATION: i64 = 2;

#[allow(dead_code)]
pub struct RDCleanPathRequest {
    pub version: i64,
    pub destination: String,
    pub proxy_auth: String,
    pub preconnection_blob: Option<String>,
    pub x224_connection_pdu: Vec<u8>,
}

pub struct RDCleanPathResponse {
    pub x224_connection_pdu: Vec<u8>,
    pub server_cert_chain: Vec<Vec<u8>>,
    pub server_addr: String,
}

pub struct RDCleanPathError {
    pub error_code: i64,
    pub http_status_code: Option<i64>,
    pub wsa_last_error: Option<i64>,
    pub tls_alert_code: Option<i64>,
}

/// Parse an RDCleanPath Request PDU from raw DER bytes.
///
/// Layout (SEQUENCE):
///   [0] version  INTEGER   — must be 3390
///   [1] error    (skip)
///   [2] destination  UTF8String
///   [3] proxyAuth    UTF8String
///   [4] serverAuth   (skip)
///   [5] preconnectionBlob  UTF8String  (optional)
///   [6] x224ConnectionPdu  OCTET STRING
pub fn parse_request(data: &[u8]) -> Result<RDCleanPathRequest, String> {
    let mut outer = DerReader::new(data);
    let mut seq = outer.read_sequence()?;

    // [0] version
    let mut version_reader = seq
        .read_explicit(0)?
        .ok_or("RDCleanPath: missing [0] version")?;
    let version = version_reader.read_integer()?;
    if version != RDCLEANPATH_VERSION {
        return Err(format!(
            "RDCleanPath: unsupported version {version}, expected {RDCLEANPATH_VERSION}"
        ));
    }

    // [1] error — skip if present
    if let Some(mut _err_reader) = seq.read_explicit(1)? {
        // consume / ignore
    }

    // [2] destination
    let mut dest_reader = seq
        .read_explicit(2)?
        .ok_or("RDCleanPath: missing [2] destination")?;
    let destination = dest_reader.read_utf8_string()?;

    // [3] proxyAuth
    let mut auth_reader = seq
        .read_explicit(3)?
        .ok_or("RDCleanPath: missing [3] proxyAuth")?;
    let proxy_auth = auth_reader.read_utf8_string()?;

    // [4] serverAuth — skip if present
    if let Some(mut _sa_reader) = seq.read_explicit(4)? {
        // consume / ignore
    }

    // [5] preconnectionBlob (optional)
    let preconnection_blob = if let Some(mut pcb_reader) = seq.read_explicit(5)? {
        Some(pcb_reader.read_utf8_string()?)
    } else {
        None
    };

    // [6] x224ConnectionPdu
    let mut x224_reader = seq
        .read_explicit(6)?
        .ok_or("RDCleanPath: missing [6] x224ConnectionPdu")?;
    let x224_connection_pdu = x224_reader.read_octet_string()?;

    Ok(RDCleanPathRequest {
        version,
        destination,
        proxy_auth,
        preconnection_blob,
        x224_connection_pdu,
    })
}

/// Build an RDCleanPath Response PDU.
///
/// Layout (SEQUENCE):
///   [0] version  INTEGER
///   [6] x224ConnectionPdu  OCTET STRING
///   [7] serverCertChain  SEQUENCE OF OCTET STRING
///   [9] serverAddr  UTF8String
pub fn build_response(resp: &RDCleanPathResponse) -> Vec<u8> {
    let version_el = encode_explicit(0, &encode_integer(RDCLEANPATH_VERSION));

    let x224_el = encode_explicit(6, &encode_octet_string(&resp.x224_connection_pdu));

    // SEQUENCE OF OCTET STRING for cert chain
    let cert_elements: Vec<Vec<u8>> = resp
        .server_cert_chain
        .iter()
        .map(|c| encode_octet_string(c))
        .collect();
    let cert_seq = encode_sequence_from_vecs(&cert_elements);
    let cert_el = encode_explicit(7, &cert_seq);

    let addr_el = encode_explicit(9, &encode_utf8_string(&resp.server_addr));

    encode_sequence(&[&version_el, &x224_el, &cert_el, &addr_el])
}

/// Build an RDCleanPath Error PDU.
///
/// Layout (SEQUENCE):
///   [0] version  INTEGER
///   [1] error  SEQUENCE {
///     [0] errorCode  INTEGER
///     [1] httpStatusCode  INTEGER  (optional)
///     [2] wsaLastError  INTEGER  (optional)
///     [3] tlsAlertCode  INTEGER  (optional)
///   }
pub fn build_error(err: &RDCleanPathError) -> Vec<u8> {
    let version_el = encode_explicit(0, &encode_integer(RDCLEANPATH_VERSION));

    let mut error_fields = vec![encode_explicit(0, &encode_integer(err.error_code))];

    if let Some(http_status) = err.http_status_code {
        error_fields.push(encode_explicit(1, &encode_integer(http_status)));
    }
    if let Some(wsa_error) = err.wsa_last_error {
        error_fields.push(encode_explicit(2, &encode_integer(wsa_error)));
    }
    if let Some(tls_alert) = err.tls_alert_code {
        error_fields.push(encode_explicit(3, &encode_integer(tls_alert)));
    }

    let error_seq = encode_sequence_from_vecs(&error_fields);
    let error_el = encode_explicit(1, &error_seq);

    encode_sequence(&[&version_el, &error_el])
}

// ---------------------------------------------------------------------------
// Tests — ported from tests/gateway/rdcleanpath.test.ts (Node gateway) to
// preserve coverage after the Node gateway was removed.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    struct ReqOpts {
        version: i64,
        destination: String,
        proxy_auth: String,
        preconnection_blob: Option<String>,
        x224: Vec<u8>,
    }

    impl Default for ReqOpts {
        fn default() -> Self {
            Self {
                version: RDCLEANPATH_VERSION,
                destination: "My PC".to_string(),
                proxy_auth: "jwt-token-here".to_string(),
                preconnection_blob: None,
                x224: vec![0x03, 0x00],
            }
        }
    }

    fn build_request(opts: ReqOpts) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = Vec::new();
        // [0] version
        fields.push(encode_explicit(0, &encode_integer(opts.version)));
        // [1] error (empty explicit, matching the TS fixture)
        fields.push(encode_explicit(1, &encode_sequence(&[])));
        // [2] destination
        fields.push(encode_explicit(2, &encode_utf8_string(&opts.destination)));
        // [3] proxy_auth
        fields.push(encode_explicit(3, &encode_utf8_string(&opts.proxy_auth)));
        // [4] server_auth (unused)
        fields.push(encode_explicit(4, &encode_utf8_string("")));
        // [5] preconnection_blob (optional)
        if let Some(ref pcb) = opts.preconnection_blob {
            fields.push(encode_explicit(5, &encode_utf8_string(pcb)));
        }
        // [6] x224_connection_pdu
        fields.push(encode_explicit(6, &encode_octet_string(&opts.x224)));
        encode_sequence_from_vecs(&fields)
    }

    #[test]
    fn version_constant() {
        assert_eq!(RDCLEANPATH_VERSION, 3390);
    }

    #[test]
    fn error_constants() {
        assert_eq!(RDCLEANPATH_ERROR_GENERAL, 1);
        assert_eq!(RDCLEANPATH_ERROR_NEGOTIATION, 2);
    }

    #[test]
    fn parse_valid_request() {
        let x224 = vec![0x03, 0x00, 0x00, 0x13];
        let buf = build_request(ReqOpts {
            destination: "My PC".to_string(),
            proxy_auth: "my-jwt-token".to_string(),
            x224: x224.clone(),
            ..Default::default()
        });
        let req = parse_request(&buf).unwrap();
        assert_eq!(req.version, RDCLEANPATH_VERSION);
        assert_eq!(req.destination, "My PC");
        assert_eq!(req.proxy_auth, "my-jwt-token");
        assert_eq!(req.x224_connection_pdu, x224);
        assert!(req.preconnection_blob.is_none());
    }

    #[test]
    fn parse_request_with_preconnection_blob() {
        let buf = build_request(ReqOpts {
            preconnection_blob: Some("vm-guid-123".to_string()),
            ..Default::default()
        });
        let req = parse_request(&buf).unwrap();
        assert_eq!(req.preconnection_blob.as_deref(), Some("vm-guid-123"));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let buf = build_request(ReqOpts { version: 9999, ..Default::default() });
        match parse_request(&buf) {
            Ok(_) => panic!("expected wrong-version request to be rejected"),
            Err(err) => assert!(err.contains("9999"), "error should mention bad version: {err}"),
        }
    }

    #[test]
    fn build_valid_response() {
        let x224_confirm = vec![0x03, 0x00, 0x00, 0x0B];
        let cert1 = vec![0x30, 0x82, 0x01, 0x00];
        let cert2 = vec![0x30, 0x82, 0x02, 0x00];
        let buf = build_response(&RDCleanPathResponse {
            x224_connection_pdu: x224_confirm.clone(),
            server_cert_chain: vec![cert1.clone(), cert2.clone()],
            server_addr: "192.168.1.100:3389".to_string(),
        });

        let mut outer = DerReader::new(&buf);
        let mut seq = outer.read_sequence().unwrap();
        // [0] version
        assert_eq!(seq.read_explicit(0).unwrap().unwrap().read_integer().unwrap(), RDCLEANPATH_VERSION);
        // [6] x224
        assert_eq!(seq.read_explicit(6).unwrap().unwrap().read_octet_string().unwrap(), x224_confirm);
        // [7] cert chain
        let certs = seq.read_explicit(7).unwrap().unwrap().read_sequence_of_octet_strings().unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], cert1);
        assert_eq!(certs[1], cert2);
        // [9] server_addr
        assert_eq!(seq.read_explicit(9).unwrap().unwrap().read_utf8_string().unwrap(), "192.168.1.100:3389");
    }

    #[test]
    fn build_response_single_cert() {
        let cert = vec![0x30, 0x00];
        let buf = build_response(&RDCleanPathResponse {
            x224_connection_pdu: vec![0x03],
            server_cert_chain: vec![cert],
            server_addr: "10.0.0.1:3389".to_string(),
        });
        let mut outer = DerReader::new(&buf);
        let mut seq = outer.read_sequence().unwrap();
        seq.read_explicit(0).unwrap();
        seq.read_explicit(6).unwrap();
        let certs = seq.read_explicit(7).unwrap().unwrap().read_sequence_of_octet_strings().unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn build_error_code_only() {
        let buf = build_error(&RDCleanPathError {
            error_code: RDCLEANPATH_ERROR_GENERAL,
            http_status_code: None,
            wsa_last_error: None,
            tls_alert_code: None,
        });
        let mut outer = DerReader::new(&buf);
        let mut seq = outer.read_sequence().unwrap();
        assert_eq!(seq.read_explicit(0).unwrap().unwrap().read_integer().unwrap(), RDCLEANPATH_VERSION);
        let mut err_seq = seq.read_explicit(1).unwrap().unwrap().read_sequence().unwrap();
        assert_eq!(err_seq.read_explicit(0).unwrap().unwrap().read_integer().unwrap(), RDCLEANPATH_ERROR_GENERAL);
    }

    #[test]
    fn build_error_with_http_status() {
        let buf = build_error(&RDCleanPathError {
            error_code: RDCLEANPATH_ERROR_GENERAL,
            http_status_code: Some(401),
            wsa_last_error: None,
            tls_alert_code: None,
        });
        let mut outer = DerReader::new(&buf);
        let mut seq = outer.read_sequence().unwrap();
        seq.read_explicit(0).unwrap();
        let mut err_seq = seq.read_explicit(1).unwrap().unwrap().read_sequence().unwrap();
        err_seq.read_explicit(0).unwrap();
        assert_eq!(err_seq.read_explicit(1).unwrap().unwrap().read_integer().unwrap(), 401);
    }

    #[test]
    fn build_error_all_fields() {
        let buf = build_error(&RDCleanPathError {
            error_code: RDCLEANPATH_ERROR_NEGOTIATION,
            http_status_code: Some(403),
            wsa_last_error: Some(10061),
            tls_alert_code: Some(48),
        });
        let mut outer = DerReader::new(&buf);
        let mut seq = outer.read_sequence().unwrap();
        seq.read_explicit(0).unwrap();
        let mut err_seq = seq.read_explicit(1).unwrap().unwrap().read_sequence().unwrap();
        assert_eq!(err_seq.read_explicit(0).unwrap().unwrap().read_integer().unwrap(), RDCLEANPATH_ERROR_NEGOTIATION);
        assert_eq!(err_seq.read_explicit(1).unwrap().unwrap().read_integer().unwrap(), 403);
        assert_eq!(err_seq.read_explicit(2).unwrap().unwrap().read_integer().unwrap(), 10061);
        assert_eq!(err_seq.read_explicit(3).unwrap().unwrap().read_integer().unwrap(), 48);
    }
}
