import gleam/erlang/charlist.{type Charlist}
import mug/internal/system_cacerts.{type CombinedCert}

pub type SslOption {
  Active(ActiveValue)
  Mode(ModeValue)
  Verify(VerifyValue)
  Cacerts(CacertsValue)
  Cacertfile(Charlist)
  CertsKeys(List(CertKeyConf))
  Inet
  Inet6
}

pub type ModeValue {
  Binary
}

pub type ActiveValue

pub type VerifyValue {
  VerifyNone
  VerifyPeer
}

pub type CertKeyConf

pub type CacertsValue

/// Coerce a list of DER-encoded bitarrays into ssl_options.CacertsValue
@external(erlang, "mug_ffi", "coerce_unsafe")
pub fn list_into_cacerts(x: List(BitArray)) -> CacertsValue

/// Coerce the combined certs into ssl_options.CacertsValue
@external(erlang, "mug_ffi", "coerce_unsafe")
pub fn combined_cert_into_cacerts(x: CombinedCert) -> CacertsValue

@external(erlang, "mug_ffi", "passive")
pub fn passive() -> ActiveValue

@external(erlang, "mug_ffi", "active_once")
pub fn active_once() -> ActiveValue
