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
%% @doc Listens for incoming connections on a port and parses TLS
%%      received records.
%% @end
%%%-------------------------------------------------------------------
-module(tls13_server).

-export([start_link/1]).

-export([run/1, loop/1, handle_socket/2, handle_socket/3]).

%%====================================================================
%% Edoc type declarations
%%====================================================================

-type tls_server_params() :: #{certfile:=string(), keyfile:=string(), address:=tuple(),
    port:=integer(), connect_fun:=fun()}.

-type content_type() :: change_cipher_spec | alert | handshake | application_data.

-type tls_record() :: {tls_record, content_type(), Data :: binary()}.

%%====================================================================
%% API
%%====================================================================

%%%-------------------------------------------------------------------
%% @doc Starts a TLS 1.3 server.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server:start_link(Params :: tls_server_params()) -> {ok, pid()}.
start_link(#{certfile := Certfile, keyfile := Keyfile} = Params) ->
  {ok, CertPem} = file:read_file(Certfile),
  [{'Certificate', Cert, not_encrypted}] = public_key:pem_decode(CertPem),
  {ok, KeyPem}  = file:read_file(Keyfile),
  [KeyEntry] = public_key:pem_decode(KeyPem),
  {'PrivateKeyInfo', _, _, Key, _} = public_key:pem_entry_decode(KeyEntry),
  {ok, spawn_link(?MODULE, run, [Params#{certificate=>Cert, key=>Key}])}.

%%====================================================================
%% Internal functions
%%====================================================================

run(#{certificate := Cert, key := Key, address := Address, port := Port, connect_fun := Fun}) ->
  {ok, ListenSocket} = gen_tcp:listen(Port, [binary, {backlog, 5}, {ip, Address}, {active, false}]),
  loop(#{certificate => Cert, key => Key, socket => ListenSocket, connect_fun => Fun}).

%%%-------------------------------------------------------------------
%% @doc Main server loop. Spawns a new process for each new
%%      connection.
%% @end
%%%-------------------------------------------------------------------
loop(#{socket := Socket} = Params) ->
  case gen_tcp:accept(Socket, 1000) of
    {ok, Port} -> spawn(fun() -> handle_socket(Port, Params) end);
    {error, timeout} -> ok
  end,
  ?MODULE:loop(Params).

%%%-------------------------------------------------------------------
%% @doc Handles incoming data from an open socket, parses the received
%%      records, and sends them to the server state machine.
%% @end
%%%-------------------------------------------------------------------
handle_socket(Socket, #{connect_fun := Fun} = Params) ->
  process_flag(trap_exit, true),
  {ok, Pid} = tls13_server_statem:start(Socket, Params),
  spawn(fun() -> Fun(Pid) end),
  handle_socket(Socket, Params#{statem_pid => Pid}, <<>>).

handle_socket(Socket, #{statem_pid := Pid} = Params, Buf) ->
  receive
    {'EXIT', Pid, _ExitReason} ->
      % Send internal error alert
      gen_tcp:send(Socket, <<21:8, 16#0303:16/big, 2:16/big, 2:8, 80:8>>),
      gen_tcp:close(Socket),
      ?MODULE:handle_socket(Socket, Params, Buf);
    Other ->
      error_logger:warning_msg("tls13_server process received unknown message:~p~n",
          [Other]),
      ?MODULE:handle_socket(Socket, Params, Buf)
  after
    0 ->
      case gen_tcp:recv(Socket, 0, 100) of
        {ok, Bin} ->
          case buf_to_records(<<Buf/binary, Bin/binary>>) of
            {Records, Tail} ->
              lists:foreach(fun(Rec) -> tls13_server_statem:handle_record(Pid, Rec) end, Records),
              ?MODULE:handle_socket(Socket, Params, Tail);
            record_overflow ->
              error_logger:info_msg("Record overflow.~n"),
              % Record overflow alert
              gen_tcp:send(Socket, <<21:8, 16#0303:16/big, 2:16/big, 2:8, 22:8>>),
              gen_tcp:close(Socket),
              tls13_server_statem:stop(Pid);
            bad_content_type ->
              error_logger:info_msg("Unexpected message.~n"),
              % Unexpected message alert
              gen_tcp:send(Socket, <<21:8, 16#0303:16/big, 2:16/big, 2:8, 50:8>>),
              gen_tcp:close(Socket),
              tls13_server_statem:stop(Pid)
          end;
        {error, timeout} -> ?MODULE:handle_socket(Socket, Params, Buf);
        {error, _Reason} -> tls13_server_statem:stop(Pid)
      end
  end.

%%%-------------------------------------------------------------------
%% @doc Parses incoming data into records.
%% @end
%%%-------------------------------------------------------------------
-spec tls13_server:buf_to_records(Buf :: binary()) ->
    {Records :: list(tls_record()), Tail :: binary()} | record_overflow | bad_content_type.
buf_to_records(Buf) ->
  buf_to_records(Buf, []).

buf_to_records(<<ContentType:8, _ProtocolVersion:16, Length:16, Tail/binary>> = Buf, Records)
    when Length =< 16384, ContentType >= 20, ContentType =< 23, byte_size(Tail) < Length ->
  {lists:reverse(Records), Buf};
buf_to_records(<<ContentType:8, _ProtocolVersion:16, Length:16, Tail/binary>>, Records)
    when Length =< 16384, ContentType >= 20, ContentType =< 23 ->
  ContentAtom = case ContentType of
    20 -> change_cipher_spec;
    21 -> alert;
    22 -> handshake;
    23 -> application_data
  end,
  TailLength = byte_size(Tail) - Length,
  <<Fragment:Length/binary, Rest:TailLength/binary>> = Tail,
  buf_to_records(Rest, [{tls_record, ContentAtom, Fragment} | Records]);
buf_to_records(<<_ContentType:8, _ProtocolVersion:16, Length:16, _Tail/binary>>, _Records)
    when Length > 16384 ->
  record_overflow;
buf_to_records(<<ContentType:8, _Tail/binary>>, _Records) when ContentType < 20; ContentType > 23 ->
  bad_content_type;
buf_to_records(Buf, Records) when is_binary(Buf) ->
  {lists:reverse(Records), Buf}.
