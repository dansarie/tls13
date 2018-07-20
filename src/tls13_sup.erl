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
%% @doc tls13 top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(tls13_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, stop/1]).
-export([listen/5]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
  supervisor:start_link({global, ?SERVER}, ?MODULE, []).

stop(Pid) ->
  exit(Pid, normal).

listen(Address, Port, Certfile, Keyfile, Fun) ->
  {ok, _Child} = supervisor:start_child({global, tls13_sup}, [#{address=>Address, port=>Port,
      certfile=>Certfile, keyfile=>Keyfile, connect_fun=>Fun}]),
  ok.

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
  SupFlags   =  #{strategy  => simple_one_for_one,
                  intensity => 5,
                  period    => 60},
  ChildSpecs = [#{id        => tls13_server_instance,
                  start     => {tls13_server, start_link, []},
                  restart   => transient,
                  shutdown  => 5000,
                  modules   => [tls13_server]}],
  {ok, {SupFlags, ChildSpecs}}.
