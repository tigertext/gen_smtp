%% Tests for a STARTTLS handshake that fails (here: the client only offers a TLS
%% version the server does not accept). The session must end cleanly instead of
%% crashing on the socket that ssl already closed.
%%
%% This module is also the callback module under test: it delegates every callback to
%% smtp_server_example and reports the terminate/2 reason to the registered test process.
-module(starttls_failure_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_STARTTLS/1, code_change/3, terminate/2]).

-define(PORT, 9880).
-define(TEST_PROC, starttls_failure_test_proc).

init(Hostname, SessionCount, Address, Options) ->
	smtp_server_example:init(Hostname, SessionCount, Address, Options).
handle_HELO(Hostname, State) -> smtp_server_example:handle_HELO(Hostname, State).
handle_EHLO(Hostname, Extensions, State) ->
	smtp_server_example:handle_EHLO(Hostname, Extensions, State).
handle_MAIL(From, State) -> smtp_server_example:handle_MAIL(From, State).
handle_MAIL_extension(Ext, State) -> smtp_server_example:handle_MAIL_extension(Ext, State).
handle_RCPT(To, State) -> smtp_server_example:handle_RCPT(To, State).
handle_RCPT_extension(Ext, State) -> smtp_server_example:handle_RCPT_extension(Ext, State).
handle_DATA(From, To, Data, State) -> smtp_server_example:handle_DATA(From, To, Data, State).
handle_RSET(State) -> smtp_server_example:handle_RSET(State).
handle_VRFY(Address, State) -> smtp_server_example:handle_VRFY(Address, State).
handle_other(Verb, Args, State) -> smtp_server_example:handle_other(Verb, Args, State).
handle_STARTTLS(State) -> smtp_server_example:handle_STARTTLS(State).
code_change(OldVsn, State, Extra) -> smtp_server_example:code_change(OldVsn, State, Extra).
terminate(Reason, State) ->
	catch ?TEST_PROC ! {session_terminated, Reason},
	smtp_server_example:terminate(Reason, State).

failed_handshake_ends_session_normally_test_() ->
	{setup, fun start_server/0, fun stop_server/1,
	 fun(_) ->
		{timeout, 20, fun() ->
			register(?TEST_PROC, self()),
			try
				{error, _} = starttls_handshake('tlsv1'),
				Reason = receive {session_terminated, R} -> R
						 after 5000 -> error(session_not_terminated)
						 end,
				?assertEqual(normal, Reason)
			after
				unregister(?TEST_PROC)
			end
		end}
	 end}.

start_server() ->
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, Pid} = gen_smtp_server:start(
		{local, starttls_failure_test_server},
		?MODULE,
		[{sessionoptions,
		  [{tls_options,
			[{keyfile, "test/fixtures/mx1.example.com-server.key"},
			 {certfile, "test/fixtures/mx1.example.com-server.crt"},
			 {versions, ['tlsv1.2']}]},
		   %% smtp_server_example only advertises STARTTLS when auth is on
		   {callbackoptions, [{auth, true}]}]},
		 {domain, "localhost"},
		 {port, ?PORT}]),
	Pid.

stop_server(_Pid) ->
	gen_smtp_server:stop(starttls_failure_test_server).

starttls_handshake(ClientVersion) ->
	{ok, Sock} = smtp_socket:connect(tcp, "localhost", ?PORT),
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
