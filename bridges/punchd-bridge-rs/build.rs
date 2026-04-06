fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("favicon.ico");

        // Set product info based on which binary is being built
        let bin = std::env::var("CARGO_BIN_NAME").unwrap_or_default();
        if bin == "punchd-vpn" {
            res.set("ProductName", "Punchd VPN");
            res.set("FileDescription", "Punchd VPN Client");
        } else {
            res.set("ProductName", "Punchd Gateway");
            res.set("FileDescription", "Punchd Gateway");
        }

        // Require administrator privileges (UAC prompt)
        res.set_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#);

        res.compile().expect("Failed to compile Windows resources");
    }
}
