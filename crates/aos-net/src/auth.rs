/// Authentication options collected from CLI flags.
///
/// Unified across all transports: HTTP tokens/basic auth, S3 credentials,
/// SSH keys, and FTP credentials.
#[derive(Debug, Clone, Default)]
pub struct AuthOptions {
    // HTTP
    pub token: Option<String>,
    pub view: String,
    pub http_user: Option<String>,
    pub http_password: Option<String>,
    pub headers: Vec<String>,

    // S3
    pub s3_region: Option<String>,
    pub s3_profile: Option<String>,
    pub s3_endpoint: Option<String>,

    // SFTP
    pub ssh_key: Option<String>,
    pub ssh_password: Option<String>,
    pub ssh_ask_pass: bool,

    // FTP
    pub ftp_user: Option<String>,
    pub ftp_password: Option<String>,
}
