-module(mug_ffi).

-export([send/2, shutdown/1, coerce/1, ssl_start/0, ssl_shutdown/1, ssl_connect/3, ssl_connect/4, ssl_send/2, get_certs_keys/1, ssl_downgrade/2]).

send(Socket, Packet) ->
    normalise(gen_tcp:send(Socket, Packet)).

shutdown(Socket) ->
    normalise(gen_tcp:shutdown(Socket, read_write)).

ssl_start() ->
    normalise(ssl:start()).

ssl_shutdown(Socket) ->
    normalise(ssl:shutdown(Socket, read_write)).

ssl_connect(Socket, Options, Timeout) ->
    normalise(ssl:connect(Socket, Options, Timeout)).
ssl_connect(Host, Port, Options, Timeout) ->
    normalise(ssl:connect(Host, Port, Options, Timeout)).

ssl_send(Socket, Packet) ->
    normalise(ssl:send(Socket, Packet)).

get_certs_keys(CertsKeys) ->
    case CertsKeys of
        {der_encoded_certs_keys, Cert, Key} ->
            #{ cert => unicode:characters_to_list(Cert), key => unicode:characters_to_list(Key) };
        {pem_encoded_certs_keys, Certfile, Keyfile, none} ->
            #{ certfile => unicode:characters_to_list(Certfile), keyfile => unicode:characters_to_list(Keyfile) };
        {pem_encoded_certs_keys, Certfile, Keyfile, {some, Password}} ->
            #{ certfile => unicode:characters_to_list(Certfile), keyfile => unicode:characters_to_list(Keyfile), password => unicode:characters_to_list(Password) }
    end.

ssl_downgrade(Socket, Timeout) ->
    case ssl:close(Socket, Timeout) of
        ok -> {error, closed};
        {ok, Port} -> {ok, {Port, nil}};
        {ok, Port, Data} -> {ok, {Port, {some, Data}}};
        {error, _} = E -> E
    end.

normalise(ok) -> {ok, nil};
normalise({ok, T}) -> {ok, T};
normalise({error, {timeout, _}}) -> {error, timeout};
normalise({error, {tls_alert, {Alert, Description}}}) -> {error, {tls_alert, Alert, list_to_binary(Description)}};
normalise({error, _} = E) -> E.

coerce(T) -> T.
