# tls13

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Quick and dirty implementation of TLS 1.3 (RFC-to-be 8446) in Erlang.

## Dependencies

* [rebar3](https://github.com/erlang/rebar3) for building.

## Build

```console
$ rebar3 release
```

## Use

All API functions can be found in the tls13 module. The following short example shows how to
create a simple echo server.

```erlang
echo_loop(Ref) ->
  Data = tls13:recv(Ref, true),
  tls13:send(Ref, Data),
  echo_loop(Ref).

% IP address argument formatted as {127, 0, 0, 1}.
start_echo_server(IP, Port) ->
  application:start(tls13),
  Fun = fun(Ref) -> echo_loop(Ref) end,
  tls13:listen(IP, Port, "path/to/cert.pem", "path/to/private/key.pem", Fun).
```

## License

This project is licensed under the GNU General Public License — see the [LICENSE](LICENSE)
file for details.

