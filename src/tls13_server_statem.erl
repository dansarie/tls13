%%%-------------------------------------------------------------------
%% Copyright (C) 2018 Marcus Dansarie.
%%
%%  This program is free software: you can redistribute it and/or modify
%%  it under the terms of the GNU General Public License as published by
%%  the Free Software Foundation, either version 3 of the License, or
%%  (at your option) any later version.

%%  This program is distributed in the hope that it will be useful,
%%  but WITHOUT ANY WARRANTY; without even the implied warranty of
%%  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%  GNU General Public License for more details.

%%  You should have received a copy of the GNU General Public License
%%  along with this program.  If not, see <https://www.gnu.org/licenses/>.
%%%-------------------------------------------------------------------

%%%-------------------------------------------------------------------
%% @author Marcus Dansarie <marcus@dansarie.se>
%% @copyright 2018 Marcus Dansarie
%% @doc Main state machine for handling TLS 1.3 connections.
%% @end
%%%-------------------------------------------------------------------
-module(tls13_server_statem).

-include_lib("eunit/include/eunit.hrl").

-behaviour(gen_statem).

% API Exports
-export([start/2, stop/1, handle_record/2, send/2, recv/2, close/1, connection_information/1]).

% Callbacks
-export([init/1, callback_mode/0, terminate/3, handle_event/4, code_change/4]).

% State callbacks
-export([tls_start/3, wait_client_finished/3, connected/3, stop/3]).

%%====================================================================
%% Records
%%====================================================================

% State machine state record.
% TODO: Replace with map.
-record(server_data, {socket,
                      secret,
                      client_handshake_secret,
                      server_key,
                      client_key,
                      server_iv,
                      client_iv,
                      client_application_secret,
                      server_application_secret,
                      exporter_master_secret,
                      resumption_master_secret,
                      next_server_seq=0,
                      next_client_seq=0,
                      transcript = <<>>,
                      retry_sent=false,
                      connected=false,
                      selected_cipher,
                      selected_signature,
                      selected_group,
                      selected_version,
                      certificate,
                      certificate_key,
                      recv_buf = <<>>,
                      send_buf = <<>>,
                      change_cipher_spec_sent=false}).

% Record type generated from the PKCS#1 ASN1 description. Used for parsing data returned from
% functions in the public_key library.
-record('RSAPrivateKey', {version,
                          modulus,
                          publicExponent,
                          privateExponent,
                          prime1,
                          prime2,
                          exponent1,
                          exponent2,
                          coefficient,
                          otherPrimeInfos = asn1_NOVALUE}).

% Parsed ClientHello message.
-record(client_hello, {record,
                      client_hello,
                      legacy_protocol_version,
                      session_id,
                      cipher_suites,
                      supports_null_compression,
                      supported_versions,
                      supports_tls_13,
                      signature_algorithms,
                      supported_groups,
                      key_share,
                      extensions}).

%%====================================================================
%% Edoc type declarations
%%====================================================================

-type record_type() :: change_cipher_spec | alert | handshake | application_data.

-type tls_record() :: {tls_record, record_type(), Content :: binary()}.

-type hash_function() :: md5 | sha | sha224 | sha256 | sha384 | sha512.

-type signature() :: rsa_pkcs1_sha256 | rsa_pkcs1_sha384 | rsa_pkcs1_sha512 |
    ecdsa_secp256r1_sha256 | ecdsa_secp384r1_sha384 | ecdsa_secp521r1_sha512 |
    rsa_pss_rsae_sha256 | rsa_pss_rsae_sha384 | rsa_pss_rsae_sha512 | ed25519 | ed448 |
    rsa_pss_pss_sha256 | rsa_pss_pss_sha384 | rsa_pss_pss_sha512 | rsa_pkcs1_sha1 | ecdsa_sha1.

-type signature_spec() :: {integer(), signature(), hash_function() | undefined}.

-type group() :: secp256r1 | secp384r1 | secp521r1 | x25519 | x448 | ffdhe2048 | ffdhe3072 |
    ffdhe4096 | ffdhe6144 | ffdhe8192.

-type group_spec() :: {integer(), group()}.

-type cipher_suite() :: aes_128_gcm_sha256 | aes_256_gcm_sha384 | chacha20_poly1305_sha256 |
    aes_128_ccm_sha256 | aes_128_ccm_8_sha256.

-type cipher() :: aes_gcm | chacha20_poly1305 | undefined.

-type suite_spec() :: {integer(), cipher_suite(), cipher(), sha256 | sha384}.

-type alert_type() :: close_notify | unexpected_message | bad_record_mac | record_overflow |
    handshake_failure | bad_certificate | unsupported_certificate | certificate_revoked |
    certificate_expired | certificate_unknown | illegal_parameter | unknown_ca | access_denied |
    decode_error | decrypt_error | protocol_version | insufficient_security | internal_error |
    inappropriate_fallback | user_canceled | missing_extension | unsupported_extension |
    unrecognized_name | bad_certificate_status_response | unknown_psk_identity |
    certificate_required | no_application_protocol.

-type server_state() :: #server_data{}.

-type supported_extension_type() :: server_name | supported_groups | signature_algorithms |
    supported_versions | cookie | signature_algorithms_cert | key_share.

-type unsupported_extension_type() :: max_fragment_length | client_certificate_url |
    trusted_ca_keys | truncated_hmac | status_request | user_mapping | client_authz | server_authz |
    cert_type |  ec_point_formats | srp |  use_srtp | heartbeat |
    application_layer_protocol_negotiation | status_request_v2 | signed_certificate_timestamp |
    client_certificate_type | server_certificate_type | padding | encrypt_then_mac |
    extended_master_secret | token_binding | cached_info | compress_certificate |
    record_size_limit | session_ticket | pre_shared_key | early_data | psk_key_exchange_modes |
    certificate_authorities | oid_filters | post_handshake_auth | renegotiation_info.

-type extension_type() :: supported_extension_type() | unsupported_extension_type().

-type server_name_extension() :: {server_name, list(list())}.

-type supported_groups_extension() :: {supported_groups, list(group())}.

-type signature_algorithms_extension() :: {signature_algorithms, list(signature())}.

-type supported_versions_extension() :: {supported_versions, list(integer())}.

-type cookie_extension() :: {cookie, binary()}.

-type signature_algorithms_cert_extension() :: {signature_algorithms_cert, list(signature())}.

-type key_share_extension() :: {key_share, binary()}.

-type extension() :: server_name_extension() | supported_groups_extension() |
    signature_algorithms_extension() | supported_versions_extension() | cookie_extension() |
    signature_algorithms_cert_extension() | key_share_extension() |
    {unsupported_extension_type(), binary()}.

-type handshake_type() :: client_hello | server_hello | new_session_ticket | end_of_early_data |
    encrypted_extensions | certificate | certificate_request | certificate_verify | finished |
    key_update | message_hash.

-type content_type() :: change_cipher_spec | alert | handshake | application_data.

-type rsa_private_key() :: #'RSAPrivateKey'{}.

-type client_hello() :: #client_hello{}.

%%====================================================================
%% API
%%====================================================================

%%%-------------------------------------------------------------------
%% @doc Starts a server state machine.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:start(Socket :: term(), #{certificate := binary(), key := binary(),
    _ => _}) -> {ok, pid()}.
start(Socket, #{certificate := Cert, key := Key}) ->
  PKey = public_key:der_decode('RSAPrivateKey', Key),
  {ok, _Pid} = gen_statem:start_link(?MODULE, #server_data{socket=Socket, certificate=Cert,
      certificate_key=PKey}, []).

%%%-------------------------------------------------------------------
%% @doc Stops a server state machine.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:stop(Pid :: pid()) -> ok.
stop(Pid) ->
  gen_statem:stop(Pid),
  ok.

%%%-------------------------------------------------------------------
%% @doc Notifies a state machine of a received record.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:handle_record(Pid :: pid(), Record :: tls_record()) -> ok.
handle_record(Pid, Record) ->
  gen_statem:cast(Pid, Record),
  ok.

%%%-------------------------------------------------------------------
%% @doc Sends application data.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:send(Pid :: pid(), Data :: binary()) -> ok.
send(Pid, Data) ->
  gen_statem:cast(Pid, {send, Data}),
  ok.

%%%-------------------------------------------------------------------
%% @doc Receives application data. If Block is false and no received
%%      data is available, an empty binary is returned.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:recv(Pid :: pid(), Block :: boolean()) -> binary().
recv(Pid, false) ->
  gen_statem:call(Pid, recv);
recv(Pid, true) ->
  case recv(Pid, false) of
    <<>> ->
      receive
        after
          1 -> recv(Pid, true)
      end;
    Recv when is_binary(Recv) -> Recv
  end.

%%%-------------------------------------------------------------------
%% @doc Closes a TLS connection.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:close(Pid :: pid()) -> ok.
close(Pid) ->
  gen_statem:cast(Pid, close),
  ok.

%%%-------------------------------------------------------------------
%% @doc Returns information about a TLS connection.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:connection_information(Pid :: pid()) -> map().
connection_information(Pid) ->
  gen_statem:call(Pid, connection_information).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

terminate(_Reason, _State, _Data) ->
  ok.

code_change(_Version, State, Data, _Extra) -> {ok, State, Data}.

init(Data) when is_record(Data, server_data)-> {ok, tls_start, Data}.

callback_mode() -> state_functions.

handle_event(EventType, EventContent, State, Data) ->
  apply(?MODULE, State, [EventType, EventContent, Data]).

%%====================================================================
%% tls_start callback
%%====================================================================

tls_start(cast, {send, SendData}, #server_data{send_buf=SendBuf} = Data) ->
  NSendBuf = <<SendBuf/binary, SendData/binary>>,
  {keep_state, Data#server_data{send_buf=NSendBuf}};
tls_start({call, From}, recv, Data) ->
  {keep_state, Data, [{reply, From, <<>>}]};
tls_start(cast, close, #server_data{} = State) ->
  State2 = send_alert(close_notify, State),
  {next_state, stop, State2};
tls_start({call, From}, connection_information, #server_data{} = State) ->
  Ret = get_connection_information(State),
  {keep_state_and_data, [{reply, From, Ret#{state => tls_start}}]};
tls_start(cast, {tls_record, handshake,
    <<1:8, ClientHelloLength:24/big, ClientHello:ClientHelloLength/binary>> = Record},
    #server_data{transcript=Transcript} = Data) ->

  <<ProtocolVersion:16/big,
    _Random:32/binary,
    SessionIdLen:8,
    SessionId:SessionIdLen/binary,
    CipherSuiteLen:16/big,
    CipherSuites:CipherSuiteLen/binary,
    CompressionMethodLen:8,
    CompressionMethods:CompressionMethodLen/binary,
    ExtensionsVec/binary>> = ClientHello,

  Extensions = parse_extensions(ExtensionsVec),

  ClientCiphers = case split_bin(CipherSuites, 2) of
    error -> false;
    Suites -> {cipher_suites, lists:map(fun(<<S:16/big>>) -> suite_id_to_atom(S) end, Suites)}
  end,

  SupportsNullCompression = lists:member(0, binary:bin_to_list(CompressionMethods)),

  SupportedVersions = lists:keyfind(supported_versions,   1, Extensions),
  ClientSignatures  = lists:keyfind(signature_algorithms, 1, Extensions),
  ClientGroups      = lists:keyfind(supported_groups,     1, Extensions),
  KeyShare          = lists:keyfind(key_share,            1, Extensions),

  ServerVersions = [16#0304, 16#7f1c],
  {SupportsTLS13, SelectedVersion} = case SupportedVersions of
    {supported_versions, ClientVersions} when is_list(ClientVersions) ->
      case lists:filter(fun(X) -> lists:member(X, ClientVersions) end, ServerVersions) of
        [Ver|_] -> {true, Ver};
        []      -> {false, undefined}
      end;
    _ -> {false, undefined}
  end,

  HelloRecord = #client_hello{
      record=Record,
      client_hello=ClientHello,
      legacy_protocol_version=ProtocolVersion,
      session_id=SessionId,
      cipher_suites=ClientCiphers,
      supports_null_compression=SupportsNullCompression,
      supported_versions=SupportedVersions,
      supports_tls_13=SupportsTLS13,
      signature_algorithms=ClientSignatures,
      supported_groups=ClientGroups,
      key_share=KeyShare,
      extensions=Extensions},
  NewTranscript = <<Transcript/binary, Record/binary>>,
  NData = Data#server_data{transcript=NewTranscript, selected_version=SelectedVersion},
  handle_client_hello(HelloRecord, NData);
tls_start(cast, {tls_record, handshake, _Record}, #server_data{} = State) ->
  State2 = send_alert(unexpected_message, State),
  {next_state, stop, State2};
tls_start(cast, {tls_record, change_cipher_spec, _}, State) ->
  {next_state, tls_start, State};
tls_start(cast, {tls_record, application_data, _}, State) ->
  State2 = send_alert(unexpected_message, State),
  {next_state, stop, State2};
tls_start(cast, {tls_record, alert, _}, #server_data{socket=Socket} = State) ->
  gen_tcp:shutdown(Socket, read_write),
  gen_tcp:close(Socket),
  {next_state, stop, State};
tls_start(EventType, EventContent, Data) ->
    error_logger:warning_msg("State tls_start received unknown event.~nType:~p~nContent:~p~n",
      [EventType, EventContent]),
  {keep_state, Data}.

%%====================================================================
%% wait_client_finished callback
%%====================================================================

wait_client_finished(cast, {send, SendData}, #server_data{send_buf=SendBuf} = Data) ->
  NSendBuf = <<SendBuf/binary, SendData/binary>>,
  {keep_state, Data#server_data{send_buf=NSendBuf}};
wait_client_finished({call, From}, recv, Data) ->
  {keep_state, Data, [{reply, From, <<>>}]};
wait_client_finished(cast, close, #server_data{} = State) ->
  State2 = send_alert(close_notify, State),
  {next_state, stop, State2};
wait_client_finished({call, From}, connection_information, #server_data{} = State) ->
  Ret = get_connection_information(State),
  {keep_state, State, [{reply, From, Ret#{state => wait_client_finished}}]};
wait_client_finished(cast, {tls_record, application_data, Encrypted},
    #server_data{
        transcript=Transcript,
        selected_cipher=Suite,
        client_handshake_secret=ClientHandshakeSecret,
        secret=HandshakeSecret,
        socket=Socket,
        send_buf=SendBuf} = Data) ->
  {Data2, Decrypted} = decrypt_application_data(Encrypted, Data),
  Hash = suite_atom_to_hash(Suite),
  {_BlockLen, HashLen} = hash_len(Hash),

  FinishedKey = hkdf_expand_label(Hash, ClientHandshakeSecret, <<"finished">>, <<>>, HashLen),
  FinishedVerifyData = crypto:hmac(Hash, FinishedKey, get_transcript_hash(Hash, Data)),

  case Decrypted of
    {handshake, <<20:8, HashLen:24/big, FinishedVerifyData:HashLen/binary-unit:8>>} ->
      MasterSecret = hkdf_extract(Hash, derive_secret(Hash, HandshakeSecret, <<"derived">>, <<>>),
          <<0:HashLen/unit:8>>),
      ClientApplicationSecret = derive_secret(Hash, MasterSecret, <<"c ap traffic">>, Transcript),
      ServerApplicationSecret = derive_secret(Hash, MasterSecret, <<"s ap traffic">>, Transcript),
      ExporterMasterSecret    = derive_secret(Hash, MasterSecret, <<"exp master">>,   Transcript),
      ResumptionMasterSecret  = derive_secret(Hash, MasterSecret, <<"res master">>,   Transcript),
      {KeyLen, NonceLen} = get_suite_key_nonce_length(Suite),
      ClientWriteKey = hkdf_expand_label(Hash, ClientApplicationSecret, <<"key">>, <<>>, KeyLen),
      ClientWriteIv  = hkdf_expand_label(Hash, ClientApplicationSecret, <<"iv">>,  <<>>, NonceLen),
      ServerWriteKey = hkdf_expand_label(Hash, ServerApplicationSecret, <<"key">>, <<>>, KeyLen),
      ServerWriteIv  = hkdf_expand_label(Hash, ServerApplicationSecret, <<"iv">>,  <<>>, NonceLen),

      Data3 = Data2#server_data{
          secret=MasterSecret,
          client_handshake_secret=undefined,
          server_key=ServerWriteKey,
          client_key=ClientWriteKey,
          server_iv=ServerWriteIv,
          client_iv=ClientWriteIv,
          client_application_secret=ClientApplicationSecret,
          server_application_secret=ServerApplicationSecret,
          exporter_master_secret=ExporterMasterSecret,
          resumption_master_secret=ResumptionMasterSecret,
          next_client_seq=0,
          next_server_seq=0,
          transcript=undefined,
          connected=true},
      Data4 = case SendBuf of
        <<>> ->
          Data3;
        SendBuf when is_binary(SendBuf) ->
          {CText, NData} = create_tls_ciphertext(application_data, SendBuf, Data3),
          gen_tcp:send(Socket, CText),
          NData
      end,
      {next_state, connected, Data4};
    error ->
      Data3 = send_alert(decrypt_error, Data2),
      {next_state, stop, Data3};
    _ ->
      Data3 = send_alert(unexpected_message, Data2),
      {next_state, stop, Data3}
  end;
wait_client_finished(cast, {tls_record, change_cipher_spec, _}, State) ->
  {keep_state, State};
wait_client_finished(cast, {tls_record, handshake, _}, State) ->
  State2 = send_alert(unexpected_message, State),
  {next_state, stop, State2};
wait_client_finished(cast, {tls_record, alert, _}, #server_data{socket=Socket} = State) ->
  gen_tcp:shutdown(Socket, read_write),
  gen_tcp:close(Socket),
  {next_state, stop, State};
wait_client_finished(EventType, EventContent, Data) ->
  error_logger:warning_msg("State wait_client_finished received unknown event.~nType:~p~n"
      "Content:~p~n", [EventType, EventContent]),
  {keep_state, Data}.

%%====================================================================
%% connected callback
%%====================================================================

connected(cast, {send, SendData}, #server_data{socket=Socket} = Data) ->
  {CText, NData} = create_tls_ciphertext(application_data, SendData, Data),
  gen_tcp:send(Socket, CText),
  {keep_state, NData};
connected({call, From}, recv, #server_data{recv_buf=RecvBuf} = Data) ->
  {keep_state, Data#server_data{recv_buf= <<>>}, [{reply, From, RecvBuf}]};
connected(cast, close, #server_data{} = State) ->
  State2 = send_alert(close_notify, State),
  {next_state, stop, State2};
connected({call, From}, connection_information, #server_data{} = State) ->
  Ret = get_connection_information(State),
  {keep_state, State, [{reply, From, Ret#{state => connected}}]};
connected(cast, {tls_record, application_data, Encrypted},
    #server_data{socket=Socket,
                 selected_cipher=Suite,
                 client_application_secret=ClientAppSecret,
                 server_application_secret=SrvAppSecret,
                 recv_buf=RecvBuf} = Data) ->
  {Data2, Decrypted} = decrypt_application_data(Encrypted, Data),
  Data3 = case Decrypted of
    {handshake, <<24, 1:24, 1:8>>} ->
      {NewClAppSecret, NewClKey, NewClIV} = update_application_secret(Suite, ClientAppSecret),
      {Req, NData} = create_tls_ciphertext(handshake, <<24:8, 1:24, 0:8>>, Data2),
      gen_tcp:send(Socket, Req),
      {NewSrvAppSecret, NewSrvKey, NewSrvIV} = update_application_secret(Suite, SrvAppSecret),
      NData#server_data{
          client_application_secret=NewClAppSecret,
          server_application_secret=NewSrvAppSecret,
          client_key=NewClKey,
          client_iv=NewClIV,
          server_key=NewSrvKey,
          server_iv=NewSrvIV,
          next_client_seq=0,
          next_server_seq=0};
    {handshake, <<24, 1:24, _Requested:8>>} ->
      {NewClAppSecret, NewClKey, NewClIV} = update_application_secret(Suite, ClientAppSecret),
      Data2#server_data{
          client_application_secret=NewClAppSecret,
          client_key=NewClKey,
          client_iv=NewClIV,
          next_client_seq=0};
    {application_data, AppData} ->
      NRecvBuf = <<RecvBuf/binary, AppData/binary>>,
      Data2#server_data{recv_buf=NRecvBuf};
    % TODO: Add cases here!
    _ -> Data2
  end,
  {keep_state, Data3};
connected(cast, {tls_record, change_cipher_spec, _}, State) ->
  {keep_state, State};
connected(cast, {tls_record, handshake, _}, State) ->
  State2 = send_alert(unexpected_message, State),
  {next_state, stop, State2};
connected(cast, {tls_record, alert, _}, #server_data{socket=Socket} = State) ->
  gen_tcp:shutdown(Socket, read_write),
  gen_tcp:close(Socket),
  {next_state, stop, State};
connected(EventType, EventContent, Data) ->
  error_logger:warning_msg("State connected received unknown event.~nType:~p~nContent:~p~n",
      [EventType, EventContent]),
  {keep_state, Data}.

%%====================================================================
%% stop callback
%%====================================================================

stop(_EventType, _EventContent, _Data) ->
  {keep_state, no_data}.

%%====================================================================
%% Eunit tests
%%====================================================================

%%%-------------------------------------------------------------------
%% @doc Tests hkdf_extract and hkdf_expand using test vectors from
%%      <a href="https://tools.ietf.org/html/rfc5869#appendix-A">
%%      RFC 5869 Appendix A.</a>
%% @end
%%%-------------------------------------------------------------------
hkdf_test() ->
  test_hkdf(sha256,
      <<16#0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b:176>>,
      <<16#000102030405060708090a0b0c:104>>,
      <<16#f0f1f2f3f4f5f6f7f8f9:80>>,
      42,
      <<16#077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5:256>>,
      <<16#3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf:256,
        16#34007208d5b887185865:80>>),

  test_hkdf(sha256,
      <<16#000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:256,
        16#202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f:256,
        16#404142434445464748494a4b4c4d4e4f:128>>,
      <<16#606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f:256,
        16#808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f:256,
        16#a0a1a2a3a4a5a6a7a8a9aaabacadaeaf:128>>,
      <<16#b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf:256,
        16#d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef:256,
        16#f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff:128>>,
      82,
      <<16#06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244:256>>,
      <<16#b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c:256,
        16#59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71:256,
        16#cc30c58179ec3e87c14c01d5c1f3434f1d87:144>>),

  test_hkdf(sha256,
      <<16#0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b:176>>,
      <<>>,
      <<>>,
      42,
      <<16#19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04:256>>,
      <<16#8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d:256,
        16#9d201395faa4b61a96c8:80>>),

  test_hkdf(sha,
      <<16#0b0b0b0b0b0b0b0b0b0b0b:88>>,
      <<16#000102030405060708090a0b0c:104>>,
      <<16#f0f1f2f3f4f5f6f7f8f9:80>>,
      42,
      <<16#9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243:160>>,
      <<16#085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2:256,
        16#c22e422478d305f3f896:80>>),
  ok.

test_hkdf(Hash, IKM, Salt, Info, Len, PRK, OKM) ->
  PRK = hkdf_extract(Hash, Salt, IKM),
  OKM = hkdf_expand(Hash, PRK, Info, Len),
  ok.

%%====================================================================
%% Internal functions
%%====================================================================

%%%-------------------------------------------------------------------
%% @doc Returns the block and hash length of a hash function.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:hash_len(Hash :: hash_function()) ->
    {BlockLen :: integer(), HashLen :: integer()}.
hash_len(md5)    -> {64, 16};
hash_len(sha)    -> {64, 20};
hash_len(sha224) -> {64, 32};
hash_len(sha256) -> {64, 32};
hash_len(sha384) -> {128, 48};
hash_len(sha512) -> {128, 64}.

%%%-------------------------------------------------------------------
%% @doc Returns a list of all known signature schemes, their integer
%%      ids, identifying atoms, and associated hash functions.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:get_signatures() -> list(signature_spec()).
get_signatures() ->
  [{16#0401, rsa_pkcs1_sha256,       sha256},
   {16#0501, rsa_pkcs1_sha384,       sha384},
   {16#0601, rsa_pkcs1_sha512,       sha512},
   {16#0403, ecdsa_secp256r1_sha256, sha256},
   {16#0503, ecdsa_secp384r1_sha384, sha384},
   {16#0603, ecdsa_secp521r1_sha512, sha512},
   {16#0804, rsa_pss_rsae_sha256,    sha256},
   {16#0805, rsa_pss_rsae_sha384,    sha384},
   {16#0806, rsa_pss_rsae_sha512,    sha512},
   {16#0807, ed25519,                undefined},
   {16#0808, ed448,                  undefined},
   {16#0809, rsa_pss_pss_sha256,     sha256},
   {16#080a, rsa_pss_pss_sha384,     sha384},
   {16#080b, rsa_pss_pss_sha512,     sha512},
   {16#0201, rsa_pkcs1_sha1,         sha},
   {16#0203, ecdsa_sha1,             sha}].

%%%-------------------------------------------------------------------
%% @doc Returns a list of all known key exchange groups, with their
%%      integer ids and identifying atoms.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:get_groups() -> list(group_spec()).
get_groups() ->
  [{16#0017, secp256r1},
   {16#0018, secp384r1},
   {16#0019, secp521r1},
   {16#001D, x25519},
   {16#001E, x448},
   {16#0100, ffdhe2048},
   {16#0101, ffdhe3072},
   {16#0102, ffdhe4096},
   {16#0103, ffdhe6144},
   {16#0104, ffdhe8192}].

%%%-------------------------------------------------------------------
%% @doc Returns a list of all known AEAD algorithms, with their
%%      integer ids, identifying atoms, Erlang crypto library atoms,
%%      and associated hash functions.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:get_suites() -> list(suite_spec()).
get_suites() ->
  [{16#1301, aes_128_gcm_sha256,       aes_gcm,           sha256},
   {16#1302, aes_256_gcm_sha384,       aes_gcm,           sha384},
   {16#1303, chacha20_poly1305_sha256, chacha20_poly1305, sha256},
   {16#1304, aes_128_ccm_sha256,       undefined,         sha256},
   {16#1305, aes_128_ccm_8_sha256,     undefined,         sha256}].

%%%-------------------------------------------------------------------
%% @doc Returns the key and cipher nonce length, in bytes, associated
%%      with a certain cipher.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:get_suite_key_nonce_length(cipher_suite()) -> {integer(), integer()}.
get_suite_key_nonce_length(aes_128_gcm_sha256)       -> {16, 12};
get_suite_key_nonce_length(aes_256_gcm_sha384)       -> {32, 12};
get_suite_key_nonce_length(chacha20_poly1305_sha256) -> {32, 12};
get_suite_key_nonce_length(aes_128_ccm_sha256)       -> {16, 12};
get_suite_key_nonce_length(aes_128_ccm_8_sha256)     -> {16, 12}.

%%%-------------------------------------------------------------------
%% @doc Returns the signature atom assoicated with a signature integer
%%      id.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:signature_id_to_atom(integer()) -> signature() | unknown.
signature_id_to_atom(Id) ->
  case lists:keyfind(Id, 1, get_signatures()) of
    {Id, Atom, _Hash} -> Atom;
    false -> unknown
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the signature integer id associated with a signature
%%      atom.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:signature_atom_to_id(signature()) -> integer() | unknown.
signature_atom_to_id(Atom) ->
  case lists:keyfind(Atom, 2, get_signatures()) of
    {Id, Atom, _Hash} -> Id;
    false -> unknown
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the hash function associated with a signature atom.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:signature_atom_to_hash(signature()) -> hash_function() | unknown.
signature_atom_to_hash(Atom) ->
  case lists:keyfind(Atom, 2, get_signatures()) of
    {_Id, Atom, Hash} -> Hash;
    false -> unknown
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the key exchange group atom associated with an integer
%%      id.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:group_id_to_atom(integer()) -> group() | unknown.
group_id_to_atom(Id) ->
  case lists:keyfind(Id, 1, get_groups()) of
    {Id, Atom} -> Atom;
    false -> unknown
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the key exchange group integer id associated with an
%%      atom.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:group_atom_to_id(group()) -> integer() | unknown.
group_atom_to_id(Atom) ->
  case lists:keyfind(Atom, 2, get_groups()) of
    {Id, Atom} -> Id;
    false -> unknown
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the cipher suite atom associated with an integer id.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:suite_id_to_atom(integer()) -> cipher_suite() | undefined.
suite_id_to_atom(Id) ->
  case lists:keyfind(Id, 1, get_suites()) of
    {Id, Atom, _Cipher, _Hash} -> Atom;
    false -> undefined
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the cipher suite integer id associated with an atom.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:suite_atom_to_id(cipher_suite()) -> integer() | undefined.
suite_atom_to_id(Atom) ->
  case lists:keyfind(Atom, 2, get_suites()) of
    {Id, Atom, _Cipher, _Hash} -> Id;
    false -> undefined
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the cipher associated with a cipher suite atom.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:suite_atom_to_cipher(cipher_suite()) -> cipher().
suite_atom_to_cipher(Atom) ->
  case lists:keyfind(Atom, 2, get_suites()) of
    {_Id, Atom, Cipher, _Hash} -> Cipher;
    false -> undefined
  end.

%%%-------------------------------------------------------------------
%% @doc Returns the  hash function associated with a cipher suite atom.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:suite_atom_to_hash(cipher_suite()) -> hash_function() | undefined.
suite_atom_to_hash(Atom) ->
  case lists:keyfind(Atom, 2, get_suites()) of
    {_Id, Atom, _Cipher, Hash} -> Hash;
    false -> undefined
  end.

%%%-------------------------------------------------------------------
%% @doc Extract function of the HMAC-based Key Derivation Function
%%      (HKDF).
%%      See <a href="https://tools.ietf.org/html/rfc5869">RFC 5869</a>.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:hkdf_extract(Hash :: hash_function(), Salt :: binary(),
    IKM :: binary()) -> binary().
hkdf_extract(Hash, Salt, IKM) -> crypto:hmac(Hash, Salt, IKM).

%%%-------------------------------------------------------------------
%% @doc Expand function of the HMAC-based Key Derivation Function
%%      (HKDF).
%%      See <a href="https://tools.ietf.org/html/rfc5869">RFC 5869</a>.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:hkdf_expand(Hash :: hash_function(), Key :: binary(), Context :: binary(),
    OutLen :: integer()) -> binary().
hkdf_expand(Hash, PRK, Info, OutLen) ->
  {_BlockLen, HashLen} = hash_len(Hash),
  N = ceil(OutLen / HashLen) + 1,
  hkdf_expand(Hash, PRK, Info, OutLen, <<>>, <<>>, 1, N).

hkdf_expand(_Hash, _PRK, _Info, OutLen, In, _PrevT, N, N) ->
  <<OKM:OutLen/binary, _Tail/binary>> = In,
  OKM;
hkdf_expand(Hash, PRK, Info, OutLen, In, PrevT, Count, N) ->
  T = crypto:hmac(Hash, PRK, <<PrevT/binary, Info/binary, Count>>),
  hkdf_expand(Hash, PRK, Info, OutLen, <<In/binary, T/binary>>, T, Count + 1, N).

%%%-------------------------------------------------------------------
%% @doc HKDF-Expand-Label. See RFC 8446 Section 7.1.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:hkdf_expand_label(Hash :: hash_function(), Secret :: binary(),
    Label :: binary(), Context :: binary(), Length :: integer()) -> binary().
hkdf_expand_label(Hash, Secret, Label, Context, Length) ->
  LabelLen = byte_size(Label) + 6,
  ContextLen = byte_size(Context),
  HkdfLabel = <<Length:16/big, LabelLen:8, "tls13 ", Label/binary, ContextLen:8, Context/binary>>,
  hkdf_expand(Hash, Secret, HkdfLabel, Length).

%%%-------------------------------------------------------------------
%% @doc Derive-Secret. See RFC 8446 Section 7.1.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:derive_secret(Hash :: hash_function(), Secret :: binary(),
    Label :: binary(), Messages :: binary()) -> binary().
derive_secret(Hash, Secret, Label, Messages) ->
  {_BlockLen, HashLen} = hash_len(Hash),
  hkdf_expand_label(Hash, Secret, Label, crypto:hash(Hash, Messages), HashLen).

%%%-------------------------------------------------------------------
%% @doc Generates a TLS 1.3 nonce by exclusive oring an IV with a
%%      sequence number.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:generate_nonce(IV :: binary(), SequenceNumber :: integer()) -> binary().
generate_nonce(IV, SequenceNumber) ->
  binary:encode_unsigned(binary:decode_unsigned(IV) bxor SequenceNumber).

%%%-------------------------------------------------------------------
%% @doc Sends an alert to the connected client. If possible, the alert
%%      is sent encrypted.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:send_alert(AlertType :: alert_type(), State :: server_state()) ->
    server_state().
send_alert(AlertType, #server_data{socket=Socket, connected=Connected} = ServerData) ->
  AlertVal = case AlertType of
    close_notify                    -> 0;
    unexpected_message              -> 10;
    bad_record_mac                  -> 20;
    record_overflow                 -> 22;
    handshake_failure               -> 40;
    bad_certificate                 -> 42;
    unsupported_certificate         -> 43;
    certificate_revoked             -> 44;
    certificate_expired             -> 45;
    certificate_unknown             -> 46;
    illegal_parameter               -> 47;
    unknown_ca                      -> 48;
    access_denied                   -> 49;
    decode_error                    -> 50;
    decrypt_error                   -> 51;
    protocol_version                -> 70;
    insufficient_security           -> 71;
    internal_error                  -> 80;
    inappropriate_fallback          -> 86;
    user_canceled                   -> 90;
    missing_extension               -> 109;
    unsupported_extension           -> 110;
    unrecognized_name               -> 112;
    bad_certificate_status_response -> 113;
    unknown_psk_identity            -> 115;
    certificate_required            -> 116;
    no_application_protocol         -> 120
  end,
  error_logger:info_msg("Sending alert: ~p~n", [AlertType]),
  AlertData = <<2:8, AlertVal:8>>,
  {Alert, Data2} = case Connected of
    true -> create_tls_ciphertext(alert, AlertData, ServerData);
    false -> create_tls_plaintext(alert, AlertData, ServerData)
  end,
  gen_tcp:send(Socket, Alert),
  gen_tcp:shutdown(Socket, read_write),
  gen_tcp:close(Socket),
  Data2.

%%%-------------------------------------------------------------------
%% @doc Parses the list extensions in a ClientHello message.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:parse_extensions(Extensions :: binary()) -> list(extension()).
parse_extensions(<<>>) ->
  [];
parse_extensions(<<ExtensionsLen:16/big, Extensions:ExtensionsLen/binary>>) ->
  parse_extensions(Extensions, []).

parse_extensions(<<ExtensionType:16, ExtensionLen:16/big, Tail/binary>>, Parsed) ->
  ExtensionAtom = case ExtensionType of
     0 -> server_name;
     1 -> max_fragment_length;
     2 -> client_certificate_url;
     3 -> trusted_ca_keys;
     4 -> truncated_hmac;
     5 -> status_request;
     6 -> user_mapping;
     7 -> client_authz;
     8 -> server_authz;
     9 -> cert_type;
    10 -> supported_groups;
    11 -> ec_point_formats;
    12 -> srp;
    13 -> signature_algorithms;
    14 -> use_srtp;
    15 -> heartbeat;
    16 -> application_layer_protocol_negotiation;
    17 -> status_request_v2;
    18 -> signed_certificate_timestamp;
    19 -> client_certificate_type;
    20 -> server_certificate_type;
    21 -> padding;
    22 -> encrypt_then_mac;
    23 -> extended_master_secret;
    24 -> token_binding;
    25 -> cached_info;
    27 -> compress_certificate;
    28 -> record_size_limit;
    35 -> session_ticket;
    41 -> pre_shared_key;
    42 -> early_data;
    43 -> supported_versions;
    44 -> cookie;
    45 -> psk_key_exchange_modes;
    47 -> certificate_authorities;
    48 -> oid_filters;
    49 -> post_handshake_auth;
    50 -> signature_algorithms_cert;
    51 -> key_share;
    65281 -> renegotiation_info;
    _Other -> unrecognized
  end,
  TailLength = byte_size(Tail) - ExtensionLen,
  if
    TailLength < 0 ->
      error;
    TailLength =:= 0 ->
      ParseFun = fun({A, E}) ->
        case parse_extension(A, E) of
          unknown -> false;
          Ext -> {true, Ext}
        end
      end,
      ExtensionList = lists:filtermap(ParseFun, [{ExtensionAtom, Tail} | Parsed]),
      case lists:member(error, ExtensionList) of
        true -> error;
        false -> lists:reverse(ExtensionList)
      end;
    true ->
      <<Extension:ExtensionLen/binary, Rest:TailLength/binary>> = Tail,
      parse_extensions(Rest, [{ExtensionAtom, Extension} | Parsed])
  end.

parse_extension(server_name, Extension) ->
  case parse_server_name(Extension) of
    error -> error;
    Names -> {server_name, Names}
  end;
parse_extension(supported_groups, Extension) ->
  case split_bin(Extension, 2) of
    error -> error;
    Groups -> {supported_groups, lists:map(fun(<<I:16/big>>) -> group_id_to_atom(I) end, Groups)}
  end;
parse_extension(signature_algorithms, Extension) ->
  case split_bin(Extension, 2) of
    error -> error;
    Sigs -> {signature_algorithms, lists:map(fun(<<I:16/big>>) -> signature_id_to_atom(I) end,
        Sigs)}
  end;
parse_extension(supported_versions, <<VersionsLen:8, Versions:VersionsLen/binary>>)
    when VersionsLen >= 2 ->
  case split_bin(Versions, 2) of
    error -> error;
    Vers -> {supported_versions, lists:map(fun(<<V:16/big>>) -> V end, Vers)}
  end;
parse_extension(supported_versions, _Extension) ->
  error;
parse_extension(cookie, Extension) ->
  {cookie, Extension};
parse_extension(signature_algorithms_cert, Extension) ->
  case parse_extension(signature_algorithms, Extension) of
    error -> error;
    {signature_algorithms, Sigs} -> {signature_algorithms_cert, Sigs}
  end;
parse_extension(key_share, Extension) ->
  case parse_key_share(Extension) of
    error -> error;
    KeyShare -> {key_share, KeyShare}
  end;
parse_extension(ExtensionAtom, Extension) ->
  error_logger:info_msg("Unhandled extension: ~p. ~p bytes.~n",
      [ExtensionAtom, byte_size(Extension)]),
  unknown.

%%%-------------------------------------------------------------------
%% @doc Splits a binary in Split-sized parts.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:split_bin(binary(), integer()) -> list(binary()) | error.
split_bin(Binary, Split) ->
  split_bin(Binary, Split, []).

split_bin(<<>>, _Split, Out) ->
  lists:reverse(Out);
split_bin(Binary, Split, Out) when byte_size(Binary) >= Split, Split > 0 ->
  <<Next:Split/binary, Tail/binary>> = Binary,
  split_bin(Tail, Split, [Next | Out]);
split_bin(_Binary, _Split, _Out) ->
  error.

parse_server_name(<<ListLen:16/big, ServerNameList:ListLen/binary>>) ->
  parse_server_name(ServerNameList, []);
parse_server_name(_ServerNameList) ->
  error.

parse_server_name(<<>>, Out) ->
  lists:reverse(Out);
parse_server_name(<<0:8, NameLen:16/big, HostName:NameLen/binary, Tail/binary>>, Out) ->
  parse_server_name(Tail, [HostName | Out]);
parse_server_name(_In, _Out) ->
  error.

parse_key_share(<<KeyShareLen:16/big, KeyShare:KeyShareLen/binary>>) ->
  parse_key_share(KeyShare, []).

parse_key_share(<<Group:16/big, KeyExchangeLen:16/big, KeyExchange:KeyExchangeLen/binary>>, Out) ->
  lists:reverse([{group_id_to_atom(Group), KeyExchange} | Out]);
parse_key_share(<<Group:16/big, KeyExchangeLen:16/big, KeyExchange:KeyExchangeLen/binary,
    Tail/binary>>, Out) ->
  parse_key_share(Tail, [{group_id_to_atom(Group), KeyExchange} | Out]);
parse_key_share(_In, _Out) ->
  error_logger:info_msg("Received malformed key share.~n"),
  [].

%%%-------------------------------------------------------------------
%% @doc Creates a handshake record.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:create_handshake_record(Type :: handshake_type(), Data :: binary()) ->
    binary().
create_handshake_record(HandshakeType, Data) ->
  HandshakeInt = case HandshakeType of
    client_hello         -> 1;
    server_hello         -> 2;
    new_session_ticket   -> 4;
    end_of_early_data    -> 5;
    encrypted_extensions -> 8;
    certificate          -> 11;
    certificate_request  -> 13;
    certificate_verify   -> 15;
    finished             -> 20;
    key_update           -> 24;
    message_hash         -> 254
  end,
  HandshakeLen = byte_size(Data),
  <<HandshakeInt, HandshakeLen:24/big, Data/binary>>.

%%%-------------------------------------------------------------------
%% @doc Returns the integer value corresponding to a content type
%%      atom.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:content_type_to_int(content_type()) -> integer().
content_type_to_int(change_cipher_spec) -> 20;
content_type_to_int(alert) -> 21;
content_type_to_int(handshake) -> 22;
content_type_to_int(application_data) -> 23.

%%%-------------------------------------------------------------------
%% @doc Creates a TLS plaintext record.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:create_tls_plaintext(Type :: content_type(), Data :: binary(),
    State :: server_state()) -> {PlaintextRecord :: binary(), NewState :: server_state()}.
create_tls_plaintext(Type, Data, #server_data{transcript=Transcript} = ServerData) ->
  ContentType = content_type_to_int(Type),
  DataLen = byte_size(Data),
  Plaintext = <<ContentType:8, 16#0303:16/big, DataLen:16/big, Data/binary>>,
  NextServerData = case Type of
    handshake ->
      NewTranscript = <<Transcript/binary, Data/binary>>,
      ServerData#server_data{transcript=NewTranscript};
    _Other -> ServerData
  end,
  {Plaintext, NextServerData}.

%%%-------------------------------------------------------------------
%% @doc Creates a TLS ciphertext record.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:create_tls_ciphertext(Type :: content_type(), Data :: binary(),
    State :: server_state()) -> {CiphertextRecord :: binary(), NewState :: server_state()}.
create_tls_ciphertext(Type, Data, ServerData) when byte_size(Data) > 16384 ->
  <<Head:16384/binary, Tail/binary>> = Data,
  {HeadRecord, ServerData2}  = create_tls_ciphertext(Type, Head, ServerData),
  {TailRecords, ServerData3} = create_tls_ciphertext(Type, Tail, ServerData2),
  {<<HeadRecord/binary, TailRecords/binary>>, ServerData3};
create_tls_ciphertext(Type, Data, #server_data{server_key=ServerKey, server_iv=ServerIV,
    next_server_seq=Seq, transcript=Transcript, selected_cipher=Suite} = ServerData) ->
  ContentType = content_type_to_int(Type),
  TLSInnerPlaintext = <<Data/binary, ContentType:8>>,
  Nonce = generate_nonce(ServerIV, Seq),
  CTLen = byte_size(TLSInnerPlaintext) + 16,
  Header = <<23:8, 16#0303:16/big, CTLen:16/big>>,
  Cipher = suite_atom_to_cipher(Suite),
  {CText, CTag} = crypto:block_encrypt(Cipher, ServerKey, Nonce, {Header, TLSInnerPlaintext}),
  NewSeq = Seq + 1,
  NextServerData = case Type of
    handshake ->
      NewTranscript = case Transcript of
        undefined -> undefined;
        _Other    -> <<Transcript/binary, Data/binary>>
      end,
      ServerData#server_data{transcript=NewTranscript, next_server_seq=NewSeq};
    _Other ->
      ServerData#server_data{next_server_seq=NewSeq}
  end,
  {<<Header/binary, CText/binary, CTag/binary>>, NextServerData}.

%%%-------------------------------------------------------------------
%% @doc Calculates and returns the transcript hash. Used during the
%%      TLS handshaking process.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:get_transcript_hash(Hash :: hash_function(), State :: server_state()) ->
  binary().
get_transcript_hash(Hash, #server_data{transcript=Transcript}) ->
  crypto:hash(Hash, Transcript).

%%%-------------------------------------------------------------------
%% @doc Mask Generation Function 1 (MGF1).
%%      See <a href="https://tools.ietf.org/html/rfc8017#appendix-B.2.1">
%%      RFC 8017 Appendix B 2.1.</a>
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:mgf1(Hash :: hash_function(), Seed :: binary(), MaskLen :: integer()) ->
  binary().
mgf1(Hash, Seed, MaskLen) ->
  {_BlockLen, HashLen} = hash_len(Hash),
  Stop = ceil(MaskLen / HashLen),
  mgf1(Hash, Seed, MaskLen, <<>>, 0, Stop).

mgf1(_Hash, _Seed, MaskLen, T, Stop, Stop) ->
  <<Out:MaskLen/binary, _Tail/binary>> = T,
  Out;
mgf1(Hash, Seed, MaskLen, T, Count, Stop) ->
  C = <<Count:32/big>>,
  H = crypto:hash(Hash, <<Seed/binary, C/binary>>),
  mgf1(Hash, Seed, MaskLen, <<T/binary, H/binary>>, Count + 1, Stop).

%%%-------------------------------------------------------------------
%% @doc EMSA-PSS-ENCODE.
%%      See <a href="https://tools.ietf.org/html/rfc8017#section-9.1.1">
%%      RFC 8017 Section 9.1.1.</a>
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:emsa_pss_encode(Hash :: hash_function(), Message :: binary(),
    EmBits :: integer()) -> binary().
emsa_pss_encode(Hash, Message, EmBits) ->
  {_BlockLen, HashLen} = hash_len(Hash),
  EmLen = ceil(EmBits/8),
  MinEmLen = HashLen * 2 + 2,
  emsa_pss_encode(Hash, Message, EmBits, HashLen, EmLen, MinEmLen).

emsa_pss_encode(Hash, Message, EmBits, HashLen, EmLen, MinEmLen) when EmLen >= MinEmLen ->
  MHash = crypto:hash(Hash, Message),
  Salt = crypto:strong_rand_bytes(HashLen),
  Mp = <<0:64, MHash/binary, Salt/binary>>,
  H = crypto:hash(Hash, Mp),
  PSLen = (EmLen - 2 * HashLen - 2) * 8,
  DB = <<0:PSLen, 1:8, Salt/binary>>,
  DBLen = byte_size(DB),
  DBMask = mgf1(Hash, H, DBLen),
  ZeroBits = 8 * EmLen - EmBits,
  <<_ZB:ZeroBits, MaskedDB/bitstring>> =
      binary:encode_unsigned(binary:decode_unsigned(DB) bxor binary:decode_unsigned(DBMask)),
  <<0:ZeroBits, MaskedDB/bitstring, H/binary, 16#bc>>;
emsa_pss_encode(_Hash, _Message, _EmBits, _HashLen, _EmLen, _MinEmLen) ->
  encoding_error.

%%%-------------------------------------------------------------------
%% @doc Computes B^N mod M.
%%      See: Rosen, Kenneth H.: Discrete Mathematics and Its
%%      Applicatios (7th ed.), p. 253 f.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:mod_exp(B :: integer(), N :: integer(), M :: integer()) -> integer().
mod_exp(B, N, M) ->
  K = bit_size(binary:encode_unsigned(N)),
  Power = B rem M,
  mod_exp(N, M, 1, Power, 0, K).

mod_exp(_N, _M, X, _Power, Stop, Stop) ->
  X;
mod_exp(N, M, X, Power, I, Stop) ->
  Head = Stop - 1 - I,
  <<_:Head, AI:1, _Tail/bitstring>> = binary:encode_unsigned(N),
  Factor = case AI of
    0 -> 1;
    1 -> Power
  end,
  X2 = (X * Factor) rem M,
  % X2 = case AI of
  %   0 -> X;
  %   1 -> (X * Power) rem M
  % end,
  Power2 = (Power * Power) rem M,
  mod_exp(N, M, X2, Power2, I + 1, Stop).

%%%-------------------------------------------------------------------
%% @doc RSASP1.
%%      See <a href="https://tools.ietf.org/html/rfc8017#section-5.2.1">
%%      RFC 8017 Section 5.2.1.</a>
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:rsasp1(PKey :: rsa_private_key(), Message :: integer()) -> integer().
rsasp1(#'RSAPrivateKey'{modulus=N, privateExponent=D}, M) ->
  mod_exp(M, D, N).

%rsavp1(#'RSAPrivateKey'{modulus=N, publicExponent=E}, S) ->
%  mod_exp(S, E, N).

%%%-------------------------------------------------------------------
%% @doc RSASSA-PSS-SIGN.
%%      See <a href="https://tools.ietf.org/html/rfc8017#section-8.1.1">
%%      RFC 8017 Section 8.1.1.</a>
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:rsassa_pss_sign(Hash :: hash_function(), PKey :: rsa_private_key(),
    Message :: binary()) -> binary().
rsassa_pss_sign(Hash, #'RSAPrivateKey'{modulus=N} = PrivateKey, Message) ->
  ModBits = bit_size(binary:encode_unsigned(N)),
  EM = emsa_pss_encode(Hash, Message, ModBits - 1),
  S = rsasp1(PrivateKey, binary:decode_unsigned(EM)),
  binary:encode_unsigned(S).

%%%-------------------------------------------------------------------
%% @doc Called by tls_start after parsing the ClientHello record.
%%      Performs parameter selection and responds to client with an
%%      alert, a ServerHello, or a HelloRetryRequest.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:handle_client_hello(Hello :: client_hello(), State :: server_state()) ->
  {keep_state, NewState :: server_state()} |
  {next_state, wait_client_finished, NewState :: server_state()}.
handle_client_hello(
    #client_hello{
      legacy_protocol_version=PV,
      supports_tls_13=TLS13},
    Data) when PV =/= 16#0303; TLS13 =/= true ->
  NData = send_alert(protocol_version, Data),
  {next_state, stop, NData};
handle_client_hello(
    #client_hello{
      signature_algorithms=SA,
      supported_groups=SG,
      key_share=KS},
    Data) when SA =:= false; SG =:= false; KS =:= false ->
  NData = send_alert(missing_extension, Data),
  {next_state, stop, NData};
handle_client_hello(
    #client_hello{
      legacy_protocol_version=16#0303,
      supports_tls_13=true,
      cipher_suites={cipher_suites, ClientCiphers},
      signature_algorithms={signature_algorithms, ClientSigs},
      supported_groups={supported_groups, ClientGroups},
      key_share={key_share, KeyShare}} = ClientHello,
    #server_data{
      selected_cipher=undefined,
      selected_signature=undefined,
      selected_group=undefined} = Data) ->

  ServerCiphers    = [aes_256_gcm_sha384, aes_128_gcm_sha256, chacha20_poly1305_sha256],
  ServerSignatures = [rsa_pss_pss_sha512, rsa_pss_pss_sha384, rsa_pss_pss_sha256],
  ServerGroups     = [secp521r1, secp384r1, secp256r1],

  CommonCiphers    = lists:filter(fun(X) -> lists:member(X, ClientCiphers) end, ServerCiphers),
  CommonSignatures = lists:filter(fun(X) -> lists:member(X, ClientSigs)    end, ServerSignatures),
  CommonGroups     = lists:filter(fun(X) -> lists:member(X, ClientGroups)  end, ServerGroups),

  UsableKeyShares = lists:filtermap(fun(Group) ->
      case lists:keyfind(Group, 1, KeyShare) of
        {Group, Share} -> {true, {Group, Share}};
        false -> false
      end
    end, CommonGroups),
  handle_client_hello(ClientHello, CommonCiphers, CommonSignatures, CommonGroups, UsableKeyShares,
      Data);
handle_client_hello(
  #client_hello{
    legacy_protocol_version=16#0303,
    session_id=SessionId,
    supports_tls_13=true,
    key_share={key_share, KeyShare}},
  #server_data{
    socket=Socket,
    selected_cipher=Cipher,
    selected_signature=Signature,
    selected_group=Group,
    certificate=Cert,
    certificate_key=CertPrivateKey,
    retry_sent=RetrySent,
    selected_version=SelectedVersion} = Data) ->

  case lists:keyfind(Group, 1, KeyShare) of
    false ->
      NData = send_alert(handshake_failure, Data),
      {next_state, stop, NData};

    {Group, OtherPub} ->
      {PublicKey, PrivateKey} = crypto:generate_key(ecdh, Group),
      SharedSecret = crypto:compute_key(ecdh, OtherPub, PrivateKey, Group),
      Hash = suite_atom_to_hash(Cipher),
      {_BlockLen, HashLen} = hash_len(Hash),
      ZeroVec = <<0:HashLen/unit:8>>,
      EarlySecret = hkdf_extract(Hash, ZeroVec, ZeroVec),
      HandshakeSecret = hkdf_extract(Hash,
          derive_secret(Hash, EarlySecret, <<"derived">>, <<>>), SharedSecret),
      {ServerHello, Data2} = create_tls_plaintext(handshake,
          create_server_hello(SessionId, Cipher, Group, PublicKey, SelectedVersion), Data),
      {ChangeCipherSpec, Data3} = if
        RetrySent =:= false -> create_tls_plaintext(change_cipher_spec, <<1>>, Data2);
        true -> {<<>>, Data2}
      end,

      #server_data{transcript=Transcript} = Data3,
      ClientHandshakeSecret = derive_secret(Hash, HandshakeSecret, <<"c hs traffic">>,
          <<Transcript/binary>>),
      ServerHandshakeSecret = derive_secret(Hash, HandshakeSecret, <<"s hs traffic">>,
          <<Transcript/binary>>),
      {KeyLen, NonceLen} = get_suite_key_nonce_length(Cipher),
      ClientWriteKey = hkdf_expand_label(Hash, ClientHandshakeSecret, <<"key">>, <<>>, KeyLen),
      ClientWriteIv  = hkdf_expand_label(Hash, ClientHandshakeSecret, <<"iv">>,  <<>>, NonceLen),
      ServerWriteKey = hkdf_expand_label(Hash, ServerHandshakeSecret, <<"key">>, <<>>, KeyLen),
      ServerWriteIv  = hkdf_expand_label(Hash, ServerHandshakeSecret, <<"iv">>,  <<>>, NonceLen),
      Data4 = Data3#server_data{secret=HandshakeSecret, client_key=ClientWriteKey,
          server_key=ServerWriteKey, client_iv=ClientWriteIv, server_iv=ServerWriteIv,
          client_handshake_secret=ClientHandshakeSecret},
      EncryptedExtensions = create_handshake_record(encrypted_extensions, <<0:16>>),
      {EncryptedExtensionsCiphertext, Data5} =
          create_tls_ciphertext(handshake, EncryptedExtensions, Data4),

      CertLen = byte_size(Cert),
      ListLen = CertLen + 5,
      Certificate = create_handshake_record(certificate,
          <<0:8, ListLen:24/big, CertLen:24/big, Cert/binary, 0:16/big>>),
      {CertificateCiphertext, Data6} = create_tls_ciphertext(handshake, Certificate, Data5),

      CertificateHash = signature_atom_to_hash(Signature),
      CertificateVerifyHash = get_transcript_hash(Hash, Data6),
      CertificateVerifyContent = <<
          16#2020202020202020202020202020202020202020202020202020202020202020:256,
          16#2020202020202020202020202020202020202020202020202020202020202020:256,
          "TLS 1.3, server CertificateVerify", 0:8, CertificateVerifyHash/binary>>,
      VerifySignature = rsassa_pss_sign(CertificateHash, CertPrivateKey, CertificateVerifyContent),
      SignatureLen = byte_size(VerifySignature),
      SignatureId = signature_atom_to_id(Signature),
      CertificateVerifyRecord = create_handshake_record(certificate_verify,
          <<SignatureId:16/big, SignatureLen:16/big, VerifySignature/binary>>),
      {CertificateVerifyCiphertext, Data7} =
          create_tls_ciphertext(handshake, CertificateVerifyRecord, Data6),

      FinishedKey = hkdf_expand_label(Hash, ServerHandshakeSecret, <<"finished">>, <<>>, HashLen),
      FinishedVerifyData = crypto:hmac(Hash, FinishedKey, get_transcript_hash(Hash, Data7)),
      FinishedPlaintext = create_handshake_record(finished, FinishedVerifyData),
      {FinishedCiphertext, Data8} = create_tls_ciphertext(handshake, FinishedPlaintext, Data7),

      gen_tcp:send(Socket, <<ServerHello/binary, ChangeCipherSpec/binary,
          EncryptedExtensionsCiphertext/binary, CertificateCiphertext/binary,
          CertificateVerifyCiphertext/binary, FinishedCiphertext/binary>>),
      {next_state, wait_client_finished, Data8}
  end.

handle_client_hello(_ClientHello, [], _CommonSignatures, _CommonGroups, _UsableKeyShares, Data) ->
  NData = send_alert(handshake_failure, Data),
  {next_state, stop, NData};
handle_client_hello(_ClientHello, _CommonCiphers, [], _CommonGroups, _UsableKeyShares, Data) ->
  NData = send_alert(handshake_failure, Data),
  {next_state, stop, NData};
handle_client_hello(_ClientHello, _CommonCiphers, _CommonSignatures, [], _UsableKeyShares, Data) ->
  NData = send_alert(handshake_failure, Data),
  {next_state, stop, NData};
handle_client_hello(#client_hello{session_id=SessionId}, [Cipher|_], [Signature|_], [Group|_], [],
    #server_data{retry_sent=false,
                 socket=Socket,
                 transcript=Transcript,
                 selected_version=SelectedVersion} = Data) ->

  Hash = suite_atom_to_hash(Cipher),
  {_BlockLen, HashLen} = hash_len(Hash),
  HelloHash = crypto:hash(Hash, Transcript),
  NewTranscript = <<254:8, HashLen:24/big, HelloHash/binary>>,
  Data1 = Data#server_data{transcript=NewTranscript},

  HelloRetryRequest = create_hello_retry_request(SessionId, Cipher, Group, SelectedVersion),
  {HelloRetryRecord, Data2} = create_tls_plaintext(handshake, HelloRetryRequest, Data1),
  {ChangeCipherSpec, Data3} = create_tls_plaintext(change_cipher_spec, <<1>>, Data2),
  NData = Data3#server_data{selected_cipher=Cipher, selected_signature=Signature,
      selected_group=Group, retry_sent=true},
  gen_tcp:send(Socket, <<HelloRetryRecord/binary, ChangeCipherSpec/binary>>),
  {keep_state, NData};
handle_client_hello(#client_hello{} = ClientHello, [Cipher|_], [Signature|_], [Group|_],
    _UsableKeyShares, #server_data{} = Data) ->
  NData = Data#server_data{selected_cipher=Cipher, selected_signature=Signature,
      selected_group=Group},
  handle_client_hello(ClientHello, NData).

%%%-------------------------------------------------------------------
%% @doc Creates a HelloRetryRequest.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:create_hello_retry_request(SessionId :: binary(),
    Cipher :: cipher_suite(), Group :: group(), SelectedVersion :: integer()) -> binary().
create_hello_retry_request(SessionId, Cipher, Group, SelectedVersion) ->
  GroupId = group_atom_to_id(Group),
  KeyShare = <<GroupId:16/big>>,
  % SHA256("HelloRetryRequest")
  Random = <<16#CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C:256>>,
  create_server_hello(SessionId, Cipher, Group, KeyShare, SelectedVersion, Random).

%%%-------------------------------------------------------------------
%% @doc Creates a ServerHello.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:create_server_hello(SessionId :: binary(),
    Cipher :: cipher_suite(), Group :: group(), KeyShareKey :: binary(),
    SelectedVersion :: integer()) -> binary().
create_server_hello(SessionId, Cipher, Group, KeyShareKey, SelectedVersion) ->
  GroupId = group_atom_to_id(Group),
  KeyShareKeyLen = byte_size(KeyShareKey),
  KeyShare = <<GroupId:16/big, KeyShareKeyLen:16/big, KeyShareKey/binary>>,
  Random = crypto:strong_rand_bytes(32),
  create_server_hello(SessionId, Cipher, Group, KeyShare, SelectedVersion, Random).

create_server_hello(SessionId, Cipher, Group, KeyShare, SelectedVersion, Random) ->
  SessionIdLen = byte_size(SessionId),
  CipherId = suite_atom_to_id(Cipher),
  _GroupId = group_atom_to_id(Group),
  KeyShareLen = byte_size(KeyShare),
  ExtensionsLen = KeyShareLen + 10,
  create_handshake_record(server_hello,
      <<16#0303:16/big,                 % Legacy version (TLS 1.2)     (2 bytes)
        Random/binary,                  %                              (32 bytes)
        SessionIdLen:8,                 %                              (1 byte)
        SessionId:SessionIdLen/binary,  % Session ID                   (SessionIdLen bytes)
        CipherId:16/big,                % CipherSuite                  (2 bytes)
        0:8,                            % No compression               (1 byte)

        ExtensionsLen:16/big,           % ExtensionsLen                (2 bytes)

        43:16,                          % Supported Versions Extension (2 bytes)
        2:16/big,                       % Extension length             (2 bytes)
        SelectedVersion:16/big,         % TLS 1.3 (final or draft 28)  (2 bytes)

        51:16/big,                      % Key share                    (2 bytes)
        KeyShareLen:16/big,             %                              (2 bytes)
        KeyShare/binary>>).             % Key share                    (KeyShareLen bytes)

%%%-------------------------------------------------------------------
%% @doc Update the connection traffic keys.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:update_application_secret(Suite :: cipher_suite(),
    OldSecret :: binary()) -> {NewSecret :: binary(), NewKey :: binary(), NewIV :: binary()}.
update_application_secret(Suite, OldSecret) ->
  Hash = suite_atom_to_hash(Suite),
  {_BlockLen, HashLen} = hash_len(Hash),
  NewSecret = hkdf_expand_label(Hash, OldSecret, <<"traffic upd">>, <<>>, HashLen),
  {KeyLen, NonceLen} = get_suite_key_nonce_length(Suite),
  NewKey = hkdf_expand_label(Hash, NewSecret, <<"key">>, <<>>, KeyLen),
  NewIV  = hkdf_expand_label(Hash, NewSecret, <<"iv">>,  <<>>, NonceLen),
  {NewSecret, NewKey, NewIV}.

%%%-------------------------------------------------------------------
%% @doc Decrypts received data.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:decrypt_application_data(Encrypted :: binary(),
    State :: server_state()) ->
      {NewState :: server_state(), {Type :: content_type(), Plaintext :: binary()}} |
      {NewState :: server_state(), error}.
decrypt_application_data(Encrypted,
    #server_data{
        selected_cipher=Suite,
        client_key = Key,
        client_iv=IV,
        next_client_seq=Seq} = Data)
    when byte_size(Encrypted) >= 16->
  EncryptedLen = byte_size(Encrypted),
  CTextLen = EncryptedLen - 16,
  CTagLen = 16,
  Header = <<23:8, 16#0303:16/big, EncryptedLen:16/big>>,
  <<CText:CTextLen/binary, CTag:CTagLen/binary>> = Encrypted,
  Cipher = suite_atom_to_cipher(Suite),
  Nonce = generate_nonce(IV, Seq),
  Decrypted = crypto:block_decrypt(Cipher, Key, Nonce, {Header, CText, CTag}),
  NSeq = Seq + 1,
  Data2 = Data#server_data{next_client_seq=NSeq},
  case parse_inner_plaintext(Decrypted) of
    error -> {Data2, error};
    {Type, Plaintext} -> {Data2, {Type, Plaintext}}
  end;
decrypt_application_data(_, Data) ->
  {Data, error}.

%%%-------------------------------------------------------------------
%% @doc Parses the inner plaintext of decrypted application data.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server_statem:parse_inner_plaintext(InnerPlaintext :: binary() | error) ->
  {Type :: content_type(), Plaintext :: binary()} | error.
parse_inner_plaintext(<<>>) ->
  error;
parse_inner_plaintext(InnerPlaintext) when is_binary(InnerPlaintext) ->
  Len = byte_size(InnerPlaintext) - 1,
  <<Head:Len/binary, Tail:8>> = InnerPlaintext,
  case Tail of
    0  -> parse_inner_plaintext(Head);
    20 -> {change_cipher_spec, Head};
    21 -> {alert, Head};
    22 -> {handshake, Head};
    23 -> {application_data, Head};
    _  -> error
  end;
parse_inner_plaintext(_) ->
  error.

get_connection_information(#server_data{socket=Socket, selected_cipher=Suite,
    selected_signature=Signature, selected_group=Group}) ->
  Ret1 = case inte:sockname(Socket) of
    {ok, {ListenIpAddr, ListenPort}} ->
      #{listen_ip => ListenIpAddr, listen_port => ListenPort};
    {ok, _ListenNonIpAddr} ->
      #{};
    {error, _ListenErr} ->
      #{}
  end,
  Ret2 = case inet:peername(Socket) of
    {ok, {PeerIpAddr, PeerPort}} ->
      Ret1#{peer_ip => PeerIpAddr, peer_port => PeerPort};
    {ok, _PeerNonIpAddr} ->
      Ret1;
    {error, _PeerErr} ->
      Ret1
  end,
  Ret3 = case Suite of
    undefined -> Ret2;
    Suite -> Ret2#{selected_suite => Suite}
  end,
  Ret4 = case Signature of
    undefined -> Ret3;
    Signature -> Ret3#{selected_signature => Signature}
  end,
  case Group of
    undefined -> Ret4;
    Group -> Ret4#{selected_group => Group}
  end.
