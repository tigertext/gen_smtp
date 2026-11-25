%% Tests for the TLS versions offered on STARTTLS: a {versions, ...} entry in the
%% session's tls_options is used as-is, and without one the server falls back to a
%% default that no longer includes SSLv3, TLS 1.0 or TLS 1.1.
-module(starttls_versions_tests).

-include_lib("eunit/include/eunit.hrl").

-define(CALLER_PORT, 9878).
-define(DEFAULT_PORT, 9879).
-define(LEGACY_CERT_PORT, 9881).

caller_versions_test_() ->
	{setup, fun() -> start_server(caller_versions_server, ?CALLER_PORT, [{versions, ['tlsv1.2']}]) end,
	 fun(_) -> gen_smtp_server:stop(caller_versions_server) end,
	 [{"rejects TLS 1.0 when the caller allows only TLS 1.2",
	   ?_assertMatch({error, _}, starttls_handshake(?CALLER_PORT, 'tlsv1'))},
	  {"rejects TLS 1.1 when the caller allows only TLS 1.2",
	   ?_assertMatch({error, _}, starttls_handshake(?CALLER_PORT, 'tlsv1.1'))},
	  {"accepts TLS 1.2 when the caller allows it",
	   ?_assertMatch({ok, _}, starttls_handshake(?CALLER_PORT, 'tlsv1.2'))},
	  %% the default would accept 1.3, so this fails if the caller's list is ignored
	  {"rejects TLS 1.3 when the caller allows only TLS 1.2",
	   ?_assertMatch({error, _}, starttls_handshake(?CALLER_PORT, 'tlsv1.3'))}]}.

default_versions_test_() ->
	{setup, fun() -> start_server(default_versions_server, ?DEFAULT_PORT, []) end,
	 fun(_) -> gen_smtp_server:stop(default_versions_server) end,
	 [{"default rejects TLS 1.0",
	   ?_assertMatch({error, _}, starttls_handshake(?DEFAULT_PORT, 'tlsv1'))},
	  {"default rejects TLS 1.1",
	   ?_assertMatch({error, _}, starttls_handshake(?DEFAULT_PORT, 'tlsv1.1'))},
	  {"default accepts TLS 1.2",
	   ?_assertMatch({ok, _}, starttls_handshake(?DEFAULT_PORT, 'tlsv1.2'))},
	  {"default accepts TLS 1.3",
	   ?_assertMatch({ok, _}, starttls_handshake(?DEFAULT_PORT, 'tlsv1.3'))}]}.

%% certfile/keyfile as top-level session options (deprecated, but how email_gateway
%% passes them) must not stop the caller's versions from applying.
caller_versions_with_top_level_cert_test_() ->
	{setup, fun start_legacy_cert_server/0,
	 fun(_) -> gen_smtp_server:stop(legacy_cert_server) end,
	 [{"rejects TLS 1.0 when the cert is a top-level option",
	   ?_assertMatch({error, _}, starttls_handshake(?LEGACY_CERT_PORT, 'tlsv1'))},
	  {"accepts TLS 1.2 when the cert is a top-level option",
	   ?_assertMatch({ok, _}, starttls_handshake(?LEGACY_CERT_PORT, 'tlsv1.2'))},
	  {"rejects TLS 1.3 when the cert is a top-level option and the caller allows only TLS 1.2",
	   ?_assertMatch({error, _}, starttls_handshake(?LEGACY_CERT_PORT, 'tlsv1.3'))}]}.

start_server(Name, Port, ExtraTlsOpts) ->
	start_session_server(Name, Port,
		[{tls_options,
		  [{keyfile, "test/fixtures/mx1.example.com-server.key"},
		   {certfile, "test/fixtures/mx1.example.com-server.crt"} | ExtraTlsOpts]}]).

start_legacy_cert_server() ->
	start_session_server(legacy_cert_server, ?LEGACY_CERT_PORT,
		[{keyfile, "test/fixtures/mx1.example.com-server.key"},
		 {certfile, "test/fixtures/mx1.example.com-server.crt"},
		 {tls_options, [{versions, ['tlsv1.2']}]}]).

start_session_server(Name, Port, SessionOpts) ->
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, Pid} = gen_smtp_server:start(
		{local, Name},
		smtp_server_example,
		%% smtp_server_example only advertises STARTTLS when auth is on
		[{sessionoptions, [{callbackoptions, [{auth, true}]} | SessionOpts]},
		 {domain, "localhost"},
		 {port, Port}]),
	Pid.

%% Runs EHLO + STARTTLS and attempts the TLS handshake offering only ClientVersion.
starttls_handshake(Port, ClientVersion) ->
	{ok, Sock} = smtp_socket:connect(tcp, "localhost", Port),
	{ok, "220 " ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
	ok = recv_until_last_ehlo_line(Sock),
	ok = smtp_socket:send(Sock, "STARTTLS\r\n"),
	{ok, "220 " ++ _} = recv_line(Sock),
	Result = smtp_socket:to_ssl_client(Sock, [{versions, [ClientVersion]}], 5000),
	case Result of
		{ok, SslSock} -> smtp_socket:close(SslSock);
		{error, _} -> smtp_socket:close(Sock)
	end,
	Result.

recv_line(Sock) -> smtp_socket:recv(Sock, 0, 5000).

recv_until_last_ehlo_line(Sock) ->
	case recv_line(Sock) of
		{ok, "250 " ++ _} -> ok;
		{ok, "250-" ++ _} -> recv_until_last_ehlo_line(Sock)
	end.
