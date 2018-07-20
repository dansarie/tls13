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
%% @doc API module for the tls13 application.
%% @end
%%%-------------------------------------------------------------------
-module(tls13).

-export([listen/5, send/2, recv/2, close/1, connection_information/1]).
-export([test/0, test/1]).

-opaque tls13_ref() :: pid().

%%====================================================================
%% API
%%====================================================================

%%%-------------------------------------------------------------------
%% @doc Listens for TLS connections on Address:Port. Certfile and
%%      Keyfile are paths to the certificate and private key files in
%%      pem format.
%%      Fun is called whenever a new connection is opened, with a
%%      reference to the connection that can be used with the other
%%      functions in this module.
%% @end
%%%-------------------------------------------------------------------
-spec tls13:listen(Address :: tuple(), Port :: integer(), Certfile :: string(),
    Keyfile :: string(), Fun :: function()) -> ok.
listen(Address, Port, Certfile, Keyfile, Fun) ->
  tls13_sup:listen(Address, Port, Certfile, Keyfile, Fun).

%%%-------------------------------------------------------------------
%% @doc Sends data to a TLS connection.
%% @end
%%%-------------------------------------------------------------------
-spec tls13:send(Ref :: tls13_ref(), Data :: binary() | list()) -> ok.
send(Ref, Data) when is_binary(Data) ->
  tls13_server_statem:send(Ref, Data);
send(Ref, Data) when is_list(Data) ->
  send(Ref, list_to_binary(Data)).

%%%-------------------------------------------------------------------
%% @doc Receives data from a TLS connection. If block is false and
%%      there is no data available, an empty binary will be returned.
%% @end
%%%-------------------------------------------------------------------
-spec tls13:recv(Ref :: tls13_ref(), Block :: boolean()) -> binary().
recv(Ref, Block) ->
  tls13_server_statem:recv(Ref, Block).

%%%-------------------------------------------------------------------
%% @doc Closes a TLS connection.
%% @end
%%%-------------------------------------------------------------------
-spec tls13:close(Ref :: tls13_ref()) -> ok.
close(Ref) ->
  tls13_server_statem:close(Ref).

%%%-------------------------------------------------------------------
%% @doc Returns information about a TLS connection.
%% @end
%%%-------------------------------------------------------------------
-spec tls13:connection_information(Ref :: tls13_ref()) -> map().
connection_information(Ref) ->
  tls13_server_statem:connection_information(Ref).
