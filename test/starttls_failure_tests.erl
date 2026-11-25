%% Tests for a STARTTLS handshake that fails, or that succeeds and is closed by the client
%% straight away. The session must end cleanly instead of crashing on the closed socket.
%%
%% This module is also the callback module under test: it delegates every callback to
%% smtp_server_example and reports handle_error/3 and terminate/2 calls to the registered
%% test process, tagged with the session pid.
-module(starttls_failure_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_STARTTLS/1, handle_error/3, code_change/3, terminate/2]).

-define(SERVER, starttls_failure_test_server).
-define(CLOSE_SERVER, starttls_close_test_server).
-define(TEST_PROC, starttls_failure_test_proc).
%% Client options that make the client abort the handshake with an alert.
-define(REJECT_CERT, [{verify, verify_peer},
		      {verify_fun, {fun(_Cert, _Event, St) -> {fail, St} end, rejected_by_test}}]).

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
handle_error(Class, Details, State) ->
	catch ?TEST_PROC ! {handle_error, self(), Class},
	smtp_server_example:handle_error(Class, Details, State).
terminate(Reason, State) ->
	catch ?TEST_PROC ! {session_terminated, self(), Reason},
	smtp_server_example:terminate(Reason, State).

%% Each way a STARTTLS handshake can fail must end the session with reason normal, and
%% promptly: after a failure ssl has closed the socket, and a session that kept going
%% crashed in setopts/2 ({badmatch, {error, einval}}). The callback's handle_error/3 must
%% still see the failure first, since that is where callback modules log it.
failed_handshake_ends_session_normally_test_() ->
	{setup, fun() -> start_server(?SERVER) end, fun(_) -> stop_server(?SERVER) end,
	 fun(_) ->
		[{Name, {timeout, 20, fun() -> assert_session_ends_normally(Client) end}}
		 || {Name, Client} <-
			[%% The client aborts with an alert (it rejects the server's certificate), then hangs up.
			 {"client sends an alert, then closes", fun(Sock) -> handshake(Sock, ?REJECT_CERT, close) end},
			 %% Same, but the client keeps the TCP connection open and says nothing.
			 {"client sends an alert, then stays silent", fun(Sock) -> handshake(Sock, ?REJECT_CERT, keep) end},
			 %% The client answers the 220 with something that is not TLS.
			 {"client sends plain text", fun(Sock) ->
				ok = smtp_socket:send(Sock, "MAIL FROM:<a@b.com>\r\n"), {error, not_tls} end},
			 %% The client hangs up right after the 220, before any handshake.
			 {"client closes before the handshake", fun(Sock) -> smtp_socket:close(Sock), {error, closed} end}]]
	 end}.

assert_session_ends_normally(Client) ->
	register(?TEST_PROC, self()),
	try
		Sock = starttls_220(?SERVER),
		%% Close the client socket on every exit, including a timeout below.
		try
			{error, _} = Client(Sock),
			Session = receive {handle_error, Pid, ssl_handshake_error} -> Pid
					  after 5000 -> error(handle_error_not_called)
					  end,
			Reason = receive {session_terminated, Session, R} -> R
					 after 5000 -> error(session_not_terminated)
					 end,
			?assertEqual(normal, Reason)
		after
			catch smtp_socket:close(Sock)
		end
	after
		unregister(?TEST_PROC)
	end.

%% A client that completes the handshake and closes at once (scanners and probes do this)
%% races the session's next setopts/2 on the TLS socket. That used to crash the session with
%% {badmatch, {error, closed}} (CP-918). Repeated, because the race is lost only some of the
%% time: 6 crashes in 30 tries on OTP 22.2.
-define(CLOSE_AFTER_HANDSHAKE_TRIES, 30).

closed_right_after_handshake_ends_session_normally_test_() ->
	{setup, fun() -> start_server(?CLOSE_SERVER) end, fun(_) -> stop_server(?CLOSE_SERVER) end,
	 fun(_) ->
		{timeout, 120, fun() ->
			Reasons = [close_right_after_handshake() || _ <- lists:seq(1, ?CLOSE_AFTER_HANDSHAKE_TRIES)],
			?assertEqual([], [R || R <- Reasons, R =/= normal])
		end}
	 end}.

%% Returns the reason the session ended with.
close_right_after_handshake() ->
	register(?TEST_PROC, self()),
	try
		Sock = starttls_220(?CLOSE_SERVER),
		try
			{ok, SslSock} = ssl:connect(Sock, [{active, false}, {verify, verify_none}], 5000),
			ok = ssl:close(SslSock),
			%% handle_error/3 hears about the closed TLS socket first, whichever way the
			%% race went
			Session = receive {handle_error, Pid, ssl_closed} -> Pid
					  after 5000 -> error(handle_error_not_called)
					  end,
			receive {session_terminated, Session, Reason} -> Reason
			after 5000 -> error(session_not_terminated)
			end
		after
			catch smtp_socket:close(Sock)
		end
	after
		unregister(?TEST_PROC)
	end.

start_server(Name) ->
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, Pid} = gen_smtp_server:start(
		{local, Name},
		?MODULE,
		[{sessionoptions,
		  [{tls_options,
			[{keyfile, "test/fixtures/mx1.example.com-server.key"},
			 {certfile, "test/fixtures/mx1.example.com-server.crt"}]},
		   %% smtp_server_example only advertises STARTTLS when auth is on
		   {callbackoptions, [{auth, true}]}]},
		 {domain, "localhost"},
		 %% Port 0: the OS picks a free one, so parallel runs cannot collide.
		 {port, 0}]),
	Pid.

stop_server(Name) ->
	gen_smtp_server:stop(Name).

%% Connects, sends EHLO and STARTTLS, and returns the plain socket once the server said 220.
starttls_220(Name) ->
	{ok, Sock} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, Name})),
	{ok, "220 " ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
	ok = recv_until_last_ehlo_line(Sock),
	ok = smtp_socket:send(Sock, "STARTTLS\r\n"),
	{ok, "220 " ++ _} = recv_line(Sock),
	Sock.

%% Attempts the client side of the handshake; on failure, closes the socket or keeps it open.
handshake(Sock, SslOpts, AfterFailure) ->
	case ssl:connect(Sock, [{active, false} | SslOpts], 5000) of
		{ok, SslSock} -> smtp_socket:close(SslSock), ok;
		{error, _} = Error ->
			AfterFailure =:= close andalso smtp_socket:close(Sock),
			Error
	end.

recv_line(Sock) -> smtp_socket:recv(Sock, 0, 5000).

recv_until_last_ehlo_line(Sock) ->
	case recv_line(Sock) of
		{ok, "250 " ++ _} -> ok;
		{ok, "250-" ++ _} -> recv_until_last_ehlo_line(Sock)
	end.
