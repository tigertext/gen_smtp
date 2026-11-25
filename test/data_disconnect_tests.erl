%% Tests for a client that disconnects in the middle of DATA (CP-963).
%%
%% This module is also the callback module under test: it delegates every callback to
%% smtp_server_example and reports handle_error/3 and terminate/2 calls to the registered
%% test process, tagged with the session pid.
-module(data_disconnect_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_STARTTLS/1, handle_error/3, code_change/3, terminate/2]).

-define(SERVER, data_disconnect_test_server).
-define(TEST_PROC, data_disconnect_test_proc).

init(Hostname, SessionCount, Address, Options) ->
	catch ?TEST_PROC ! {session_started, self()},
	smtp_server_example:init(Hostname, SessionCount, Address, Options).
handle_HELO(Hostname, State) -> smtp_server_example:handle_HELO(Hostname, State).
handle_EHLO(Hostname, Extensions, State) ->
	smtp_server_example:handle_EHLO(Hostname, Extensions, State).
handle_MAIL(From, State) -> smtp_server_example:handle_MAIL(From, State).
handle_MAIL_extension(Ext, State) -> smtp_server_example:handle_MAIL_extension(Ext, State).
handle_RCPT(To, State) -> smtp_server_example:handle_RCPT(To, State).
handle_RCPT_extension(Ext, State) -> smtp_server_example:handle_RCPT_extension(Ext, State).
handle_DATA(From, To, Data, State) ->
	catch ?TEST_PROC ! {handle_data, self()},
	smtp_server_example:handle_DATA(From, To, Data, State).
handle_RSET(State) -> smtp_server_example:handle_RSET(State).
handle_VRFY(Address, State) -> smtp_server_example:handle_VRFY(Address, State).
handle_other(Verb, Args, State) -> smtp_server_example:handle_other(Verb, Args, State).
handle_STARTTLS(State) -> smtp_server_example:handle_STARTTLS(State).
code_change(OldVsn, State, Extra) -> smtp_server_example:code_change(OldVsn, State, Extra).
handle_error(Class, Details, State) ->
	catch ?TEST_PROC ! {handle_error, self(), Class, Details},
	smtp_server_example:handle_error(Class, Details, State).
terminate(Reason, State) ->
	catch ?TEST_PROC ! {session_terminated, self(), Reason},
	smtp_server_example:terminate(Reason, State).

%% A client that disconnects, or a socket that fails, in the middle of DATA must end the
%% session with reason normal, after handle_error/3 has seen the close or the error, and
%% the partial body must never reach handle_DATA/4. The body is read by a receiver process linked to the session.
disconnect_mid_data_ends_session_normally_test_() ->
	{setup, fun start_server/0, fun stop_server/1,
	 fun(_) ->
		[{"plain TCP: client closes mid-DATA",
		  {timeout, 20, fun() -> assert_session_ends_normally(tcp, fun close/2, {tcp_closed, []}) end}},
		 {"after STARTTLS: client closes mid-DATA",
		  {timeout, 20, fun() -> assert_session_ends_normally(ssl, fun close/2, {ssl_closed, []}) end}},
		 %% Covers the session side only: the test sends the session what its receiver sends
		 %% when recv fails with einval, while the real receiver stays blocked in recv.
		 {"plain TCP: session handles a receive error other than closed",
		  {timeout, 20, fun() -> assert_session_ends_normally(tcp, fun recv_error/2, {tcp_error, einval}) end}}]
	 end}.

close(Sock, _Session) -> ok = smtp_socket:close(Sock).

%% Sends the session the message its receiver sends when Transport:recv fails with einval.
recv_error(_Sock, Session) -> Session ! {receive_data, {error, {recv, einval}}}.

assert_session_ends_normally(Mode, Trigger, {ExpectedClass, ExpectedDetails}) ->
	register(?TEST_PROC, self()),
	try
		Sock = mid_data(Mode),
		Session = receive {session_started, Pid} -> Pid after 5000 -> error(session_not_started) end,
		try
			%% Act only once the receiver is reading the body. The session sends the 354 before
			%% it starts the receiver; a close in that window may end the session before the
			%% receiver runs, and the test would not exercise it.
			ok = wait_for_receiver(Session, 50),
			Trigger(Sock, Session),
			receive {handle_error, Session, ExpectedClass, Details} ->
				?assertEqual(ExpectedDetails, Details)
			after 5000 -> error({handle_error_not_called, ExpectedClass})
			end,
			Reason = receive {session_terminated, Session, R} -> R
					 after 5000 -> error(session_not_terminated)
					 end,
			?assertEqual(normal, Reason),
			%% Checked after terminate/2: handle_DATA/4 would have run before it, so its
			%% message would already be in the mailbox.
			receive {handle_data, Session} -> error(partial_body_reached_handle_DATA)
			after 0 -> ok
			end
		after
			catch smtp_socket:close(Sock)
		end
	after
		unregister(?TEST_PROC)
	end.

%% Waits until a process linked to Session is inside gen_smtp_server_session:receive_data/8.
wait_for_receiver(_Session, 0) ->
	error(receiver_not_started);
wait_for_receiver(Session, Tries) ->
	{links, Links} = erlang:process_info(Session, links),
	Reading = [P || P <- Links, is_pid(P), in_receive_data(P)],
	case Reading of
		[_ | _] -> ok;
		[] -> timer:sleep(20), wait_for_receiver(Session, Tries - 1)
	end.

in_receive_data(Pid) ->
	case erlang:process_info(Pid, current_stacktrace) of
		{current_stacktrace, Stack} ->
			lists:any(fun({gen_smtp_server_session, receive_data, _, _}) -> true; (_) -> false end, Stack);
		undefined -> false
	end.

start_server() ->
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, Pid} = gen_smtp_server:start(
		{local, ?SERVER},
		?MODULE,
		[{sessionoptions,
		  [{tls_options,
			[{keyfile, "test/fixtures/mx1.example.com-server.key"},
			 {certfile, "test/fixtures/mx1.example.com-server.crt"}]},
		   %% smtp_server_example only advertises STARTTLS when auth is on
		   {callbackoptions, [{auth, true}]}]},
		 {domain, "localhost"},
		 %% Port 0: the OS picks a free port.
		 {port, 0}]),
	Pid.

stop_server(_Pid) ->
	gen_smtp_server:stop(?SERVER).

%% Opens a session (upgraded with STARTTLS when Mode is ssl), gets the 354 for DATA and
%% sends part of a body without the terminating dot. Returns the client socket.
mid_data(Mode) ->
	{ok, Plain} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, ?SERVER})),
	{ok, "220 " ++ _} = recv_line(Plain),
	ehlo(Plain),
	Sock = case Mode of
		tcp -> Plain;
		ssl ->
			ok = smtp_socket:send(Plain, "STARTTLS\r\n"),
			{ok, "220 " ++ _} = recv_line(Plain),
			{ok, SslSock} = smtp_socket:to_ssl_client(Plain, [{verify, verify_none}], 5000),
			ehlo(SslSock),
			SslSock
	end,
	ok = smtp_socket:send(Sock, "MAIL FROM:<a@example.com>\r\n"),
	{ok, "250" ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "RCPT TO:<b@example.com>\r\n"),
	{ok, "250" ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "DATA\r\n"),
	{ok, "354" ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "Subject: cut off\r\n\r\nthe client goes away before the dot\r\n"),
	Sock.

ehlo(Sock) ->
	ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
	ok = recv_until_last_ehlo_line(Sock).

recv_line(Sock) -> smtp_socket:recv(Sock, 0, 5000).

recv_until_last_ehlo_line(Sock) ->
	case recv_line(Sock) of
		{ok, "250 " ++ _} -> ok;
		{ok, "250-" ++ _} -> recv_until_last_ehlo_line(Sock)
	end.
