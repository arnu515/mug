import gleam/bit_array
import gleam/bytes_tree.{from_string as bits}
import gleam/erlang/process
import gleam/option
import gleam/string
import mug

pub const port = 64_794

// CA cert used for signing the server's cert
pub const ca_crt = mug.PemEncodedCaCertificates("test/certs/ca.crt")

// another CA cert that wasn't used for signing the server's cert
pub const other_ca_crt = mug.PemEncodedCaCertificates("test/certs/ca_2.crt")

fn connect() {
  let assert Ok(socket) =
    mug.new("localhost", port: port)
    |> mug.with_tls()
    |> mug.no_system_cacerts()
    |> mug.cacerts(ca_crt)
    |> mug.connect()
  let assert True = mug.socket_is_tls(socket)
  socket
}

pub fn connect_self_signed_wrong_cert_test() {
  let assert Error(mug.ConnectFailedIpv6(mug.TlsAlert(mug.UnknownCa, _))) =
    mug.new("localhost", port: port)
    |> mug.with_tls()
    |> mug.no_system_cacerts()
    |> mug.ip_version_preference(mug.Ipv6Only)
    |> mug.cacerts(other_ca_crt)
    |> mug.connect()
}

pub fn connect_without_verification_test() {
  let assert Ok(socket) =
    mug.new("localhost", port: port)
    |> mug.with_tls()
    |> mug.dangerously_disable_verification()
    |> mug.connect()
  let assert True = mug.socket_is_tls(socket)
  let assert Ok(_) = mug.shutdown(socket)
  Nil
}

pub fn connect_with_system_ca_test() {
  let assert Ok(socket) =
    mug.new("gleam.run", port: 443)
    |> mug.timeout(milliseconds: 10_000)
    |> mug.with_tls()
    |> mug.connect()
  let assert Ok(_) = mug.shutdown(socket)
  Nil
}

pub fn connect_without_system_ca_test() {
  let assert Error(mug.ConnectFailedIpv6(mug.TlsAlert(mug.UnknownCa, desc))) =
    mug.new("gleam.run", port: 443)
    |> mug.timeout(milliseconds: 10_000)
    |> mug.with_tls()
    |> mug.no_system_cacerts()
    |> mug.ip_version_preference(mug.Ipv6Only)
    |> mug.connect()

  // This should crash with `badarg` if desc isn't a string
  let _ = mug.describe_tls_alert(mug.UnknownCa) <> " - " <> desc
}

pub fn connect_invalid_host_test() {
  assert mug.new("invalid.example.com", port: port)
    |> mug.timeout(milliseconds: 500)
    |> mug.with_tls()
    |> mug.connect()
    == Error(mug.ConnectFailedBoth(mug.Nxdomain, mug.Nxdomain))
}

pub fn connect_invalid_host_only_ipv4_test() {
  assert mug.new("invalid.example.com", port: port)
    |> mug.ip_version_preference(mug.Ipv4Only)
    |> mug.timeout(milliseconds: 500)
    |> mug.with_tls()
    |> mug.connect()
    == Error(mug.ConnectFailedIpv4(mug.Nxdomain))
}

pub fn connect_invalid_host_only_ipv6_test() {
  assert mug.new("invalid.example.com", port: port)
    |> mug.ip_version_preference(mug.Ipv6Only)
    |> mug.timeout(milliseconds: 500)
    |> mug.with_tls()
    |> mug.connect()
    == Error(mug.ConnectFailedIpv6(mug.Nxdomain))
}

pub fn connect_invalid_host_prefer_ipv4_test() {
  assert mug.new("invalid.example.com", port: port)
    |> mug.ip_version_preference(mug.Ipv4Preferred)
    |> mug.timeout(milliseconds: 500)
    |> mug.with_tls()
    |> mug.connect()
    == Error(mug.ConnectFailedBoth(mug.Nxdomain, mug.Nxdomain))
}

pub fn connect_invalid_host_prefer_ipv6_test() {
  assert mug.new("invalid.example.com", port: port)
    |> mug.ip_version_preference(mug.Ipv6Preferred)
    |> mug.timeout(milliseconds: 500)
    |> mug.with_tls()
    |> mug.connect()
    == Error(mug.ConnectFailedBoth(mug.Nxdomain, mug.Nxdomain))
}

pub fn upgrade_test() {
  let assert Ok(tcp_socket) =
    mug.new("localhost", port: port)
    |> mug.connect()
  let assert Ok(socket) =
    mug.upgrade(tcp_socket, mug.DangerouslyDisableVerification, 1000)
  let assert True = mug.socket_is_tls(socket)
  let assert Ok(Nil) = mug.send(socket, <<"Hello, Joe!\n":utf8>>)
  let assert Ok(data) = mug.receive(socket, 500)
  assert data == <<"Hello, Joe!\n":utf8>>
  let assert Ok(_) = mug.shutdown(socket)
  Nil
}

pub fn upgrade_self_signed_test() {
  let assert Ok(tcp_socket) =
    mug.new("localhost", port: port)
    |> mug.connect()
  // Erlang's SSL module currently errors on self-signed certificates,
  // but not if signed with an own (self-signed) CA.
  let assert Ok(socket) =
    mug.upgrade(
      tcp_socket,
      mug.Certificates(False, option.Some(ca_crt), []),
      1000,
    )
  let msg = <<"Hello, Robert!\n":utf8>>
  assert Ok(Nil) == mug.send(socket, msg)
  let assert Ok(data) = mug.receive(socket, 500)
  assert data == msg
  assert Ok(Nil) == mug.shutdown(socket)
}

pub fn upgrade_self_signed_wrong_cert_test() {
  let assert Ok(tcp_socket) =
    mug.new("localhost", port: port)
    |> mug.connect()
  let assert Error(mug.TlsAlert(mug.UnknownCa, _)) =
    mug.upgrade(
      tcp_socket,
      mug.Certificates(False, option.Some(other_ca_crt), []),
      1000,
    )
}

pub fn hello_world_test() {
  let socket = connect()

  // Nothing has been sent by the echo server yet, so we get a timeout if we try
  // to receive a packet.
  let assert Error(mug.Timeout) = mug.receive(socket, timeout_milliseconds: 10)

  let assert Ok(Nil) = mug.send(socket, <<"Hello, Joe!\n":utf8>>)
  let assert Ok(Nil) = mug.send(socket, <<"Hello, Mike!\n":utf8>>)
  let assert Ok(Nil) = mug.send_builder(socket, bits("System still working?\n"))
  let assert Ok(Nil) = mug.send_builder(socket, bits("Seems to be!"))

  let assert Ok(packet) = mug.receive(socket, timeout_milliseconds: 100)
  let assert Ok(packet) = bit_array.to_string(packet)
  assert string.split(packet, "\n")
    == ["Hello, Joe!", "Hello, Mike!", "System still working?", "Seems to be!"]

  let assert Ok(_) = mug.shutdown(socket)

  // if this sleep call does not exist, the below command *sometimes* gives
  // an inet:einval error instead of a mug.Closed error.
  process.sleep(1)
  let assert Error(mug.Closed) = mug.send(socket, <<"One more thing!":utf8>>)
  // the below statement times out if timeout_milliseconds is 0, instead of closing
  // the connection. Probably because of the internal workings of the SSL library.
  let assert Error(mug.Closed) = mug.receive(socket, timeout_milliseconds: 1)
}

pub fn active_mode_test() {
  let socket = connect()

  process.flush_messages()

  // Ask for the next packet to be sent as a message
  mug.receive_next_packet_as_message(socket)

  // The socket is in use, we can't receive from it directly
  assert Error(mug.Einval) == mug.receive(socket, 0)

  // Send a message to the socket
  assert Ok(Nil) == mug.send(socket, <<"Hello, Joe!\n":utf8>>)

  let selector =
    process.new_selector()
    |> mug.select_tls_messages(fn(msg) { msg })

  let assert Ok(mug.Packet(packet_socket, <<"Hello, Joe!\n":utf8>>)) =
    process.selector_receive(selector, 1000)

  assert packet_socket == socket

  // Send another packet
  let assert Ok(Nil) = mug.send(socket, <<"Hello, Mike!\n":utf8>>)

  // The socket is in passive mode, so we don't get another message.
  let assert Error(Nil) = process.selector_receive(selector, 100)

  // The socket is back in passive mode, we can receive from it directly again.
  let assert Ok(<<"Hello, Mike!\n":utf8>>) = mug.receive(socket, 0)
  let assert Error(mug.Timeout) = mug.receive(socket, 0)
}

pub fn exact_bytes_receive_test() {
  let socket = connect()

  let assert Ok(Nil) = mug.send(socket, <<"Hello":utf8>>)
  let assert Ok(Nil) = mug.send(socket, <<"World":utf8>>)

  let assert Ok(<<"Hello":utf8>>) = mug.receive_exact(socket, 5, 100)
  let assert Ok(<<"World":utf8>>) = mug.receive_exact(socket, 5, 100)

  let assert Ok(_) = mug.shutdown(socket)

  let assert Error(mug.Closed) = mug.receive_exact(socket, 5, 100)
}

pub fn exact_bytes_receive_not_enough_test() {
  let socket = connect()

  let assert Ok(Nil) = mug.send(socket, <<"Hello":utf8>>)
  let assert Ok(Nil) = mug.send(socket, <<"Worl":utf8>>)

  let assert Ok(<<"Hello":utf8>>) = mug.receive_exact(socket, 5, 100)
  let assert Error(mug.Timeout) = mug.receive_exact(socket, 5, 100)

  let assert Ok(_) = mug.shutdown(socket)

  let assert Error(mug.Closed) = mug.receive_exact(socket, 5, 100)
}
