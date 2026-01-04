/// https://www.erlang.org/doc/apps/public_key/public_key#t:combined_cert/0
pub type CombinedCert

pub type SystemCacertificatesGetError {
  /// Error accessing CA certificate files
  Enoent
  /// No CA Certificate files found
  NoCacertsFound
  /// OS is not supported
  Enotsup
  /// Operation failed
  Eopnotsup
}

pub fn describe_error(err: SystemCacertificatesGetError) -> String {
  case err {
    Enoent -> "No such file or directory"
    Enotsup -> "Not supported"
    Eopnotsup -> "Operation not supported"
    NoCacertsFound -> "No system certificates were found"
  }
}

@external(erlang, "mug_ffi", "get_system_cacerts")
pub fn get() -> Result(List(CombinedCert), SystemCacertificatesGetError)
