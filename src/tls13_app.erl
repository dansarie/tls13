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
%% @doc tls13 public API
%% @end
%%%-------------------------------------------------------------------

-module(tls13_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
  case tls13_sup:start_link() of
    {ok, Pid} ->
      {ok, Pid, {tls13_application_state, #{pid=>Pid}}};
    Error ->
      Error
  end.


stop({tls13_application_state, #{pid:=Pid}}) ->
  tls13_sup:stop(Pid),
  ok.
