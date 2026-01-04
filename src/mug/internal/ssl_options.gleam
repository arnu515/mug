import gleam/erlang/charlist.{type Charlist}
import mug/internal/system_cacerts.{type CombinedCert}

pub type SslOption {
  Verify(VerifyValue)
  Cacerts(CacertsValue)
  Cacertfile(Charlist)
  CertsKeys(List(CertKeyConf))
}

pub type VerifyValue {
  VerifyNone
  VerifyPeer
}

pub type CertKeyConf

pub type CacertsValue

/// Coerce a list of DER-encoded bitarrays into ssl_options.CacertsValue
@external(erlang, "mug_ffi", "combined_certs_to_der_encoded")
pub fn combined_certs_into_der_encoded(x: List(CombinedCert)) -> List(BitArray)

/// Coerce a list of DER-encoded bitarrays into ssl_options.CacertsValue
@external(erlang, "mug_ffi", "coerce_list_into_cacerts")
pub fn der_into_cacerts(x: List(BitArray)) -> CacertsValue

/// Coerce the combined certs into ssl_options.CacertsValue
@external(erlang, "mug_ffi", "coerce_list_into_cacerts")
pub fn combined_cert_into_cacerts(x: List(CombinedCert)) -> CacertsValue
