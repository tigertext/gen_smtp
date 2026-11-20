%% Each place the session re-arms its socket must end the session with reason normal, after
%% reporting the closed or broken socket to handle_error/3, when setopts/2 fails because the
%% client has gone (CP-918). fail_setopts_transport makes setopts/2 fail from a chosen call
%% on, so every path is hit deterministically.
%%
%% This module is also the callback module under test: it delegates every callback to
%% smtp_server_example and reports handle_error/3, handle_DATA/4 and terminate/2 calls to
%% the registered test process.
-module(setopts_failure_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_STARTTLS/1, handle_error/3, code_change/3, terminate/2]).

-define(LISTENER, setopts_failure_test_listener).
-define(TEST_PROC, setopts_failure_test_proc).
-define(MAXSIZE, 50).
%% Re-arming after the DATA reply is the fourth {active, once}: the replies to EHLO, MAIL and
%% RCPT come first.
-define(AFTER_DATA, {[{active, once}], closed, 3}).

init(Hostname, SessionCount, Address, Options) ->
	smtp_server_example:init(Hostname, SessionCount, Address, Options).
handle_HELO(Hostname, State) -> smtp_server_example:handle_HELO(Hostname, State).
handle_EHLO(<<"small.com">>, Extensions, State) ->
	%% a small SIZE limit, for the message-too-large paths
	{ok, Exts, State1} = smtp_server_example:handle_EHLO(<<"small.com">>, Extensions, State),
	{ok, lists:keystore("SIZE", 1, Exts, {"SIZE", integer_to_list(?MAXSIZE)}), State1};
handle_EHLO(Hostname, Extensions, State) ->
	smtp_server_example:handle_EHLO(Hostname, Extensions, State).
handle_MAIL(From, State) -> smtp_server_example:handle_MAIL(From, State).
handle_MAIL_extension(Ext, State) -> smtp_server_example:handle_MAIL_extension(Ext, State).
handle_RCPT(To, State) -> smtp_server_example:handle_RCPT(To, State).
handle_RCPT_extension(Ext, State) -> smtp_server_example:handle_RCPT_extension(Ext, State).
handle_DATA(From, To, Data, State) ->
	report(handle_DATA),
	smtp_server_example:handle_DATA(From, To, Data, State).
handle_RSET(State) -> smtp_server_example:handle_RSET(State).
handle_VRFY(Address, State) -> smtp_server_example:handle_VRFY(Address, State).
handle_other(Verb, Args, State) -> smtp_server_example:handle_other(Verb, Args, State).
handle_STARTTLS(State) -> smtp_server_example:handle_STARTTLS(State).
code_change(OldVsn, State, Extra) -> smtp_server_example:code_change(OldVsn, State, Extra).
handle_error(Class, Details, State) ->
	report({handle_error, Class}),
	smtp_server_example:handle_error(Class, Details, State).
terminate(Reason, State) ->
	report({terminate, Reason}),
	smtp_server_example:terminate(Reason, State).

report(Event) -> catch ?TEST_PROC ! {session_event, Event}.

setopts_failure_test_() ->
	{setup, fun start_listener/0, fun stop_listener/1,
	 fun(_) ->
		{inorder,
		 [{"init: the socket fails right after the banner",
		   {timeout, 15, fun() ->
			?assertEqual([{handle_error, tcp_closed}, {terminate, normal}],
						 run({[{active, once}, {packet, line}], closed}, fun(_Sock) -> ok end))
		   end}},
		  {"init: a failure other than closed is reported as tcp_error",
		   {timeout, 15, fun() ->
			?assertEqual([{handle_error, tcp_error}, {terminate, normal}],
						 run({[{active, once}, {packet, line}], einval}, fun(_Sock) -> ok end))
		   end}},
		  {"DATA: the switch to raw mode fails before any message is read",
		   {timeout, 15, fun() ->
			?assertEqual([{handle_error, tcp_closed}, {terminate, normal}],
						 run({[{packet, raw}], closed}, fun(Sock) -> start_data(Sock) end))
		   end}},
		  {"DATA: a complete message is still handled when the client has gone",
		   {timeout, 15, fun() ->
			?assertEqual([handle_DATA, {handle_error, tcp_closed}, {terminate, normal}],
						 run({[{packet, line}], closed},
							 fun(Sock) ->
								 start_data(Sock),
								 ok = smtp_socket:send(Sock, "Subject: t\r\n\r\nbody\r\n.\r\n")
							 end))
		   end}},
		  {"a command: re-arming the socket after the reply fails",
		   {timeout, 15, fun() ->
			%% the first {active, once} after the banner is the one re-arming after EHLO
			?assertEqual([{handle_error, tcp_closed}, {terminate, normal}],
						 run({[{active, once}], closed}, fun(Sock) -> ehlo(Sock) end))
		   end}},
		  {"DATA: re-arming after handle_DATA rejects the message fails",
		   {timeout, 15, fun() ->
			%% an empty body: smtp_server_example:handle_DATA/4 answers 552 Message too small
			?assertEqual([handle_DATA, {handle_error, tcp_closed}, {terminate, normal}],
						 run(?AFTER_DATA, fun(Sock) -> send_message(Sock, "somehost.com", "\r\n.\r\n") end))
		   end}},
		  {"DATA: re-arming after a bare newline is rejected fails",
		   {timeout, 15, fun() ->
			?assertEqual([{handle_error, data_rejected}, {handle_error, tcp_closed}, {terminate, normal}],
						 run(?AFTER_DATA, fun(Sock) -> send_message(Sock, "somehost.com", "a\nb\r\n.\r\n") end))
		   end}},
		  {"DATA: re-arming after the body outgrows SIZE while it is read fails",
		   {timeout, 15, fun() ->
			%% no end marker, so receive_data/8 stops on size and reports size_exceeded
			?assertEqual([{handle_error, data_rejected}, {handle_error, tcp_closed}, {terminate, normal}],
						 run(?AFTER_DATA, fun(Sock) -> send_message(Sock, "small.com", big_body()) end))
		   end}},
		  {"DATA: re-arming after a complete message over SIZE is rejected fails",
		   {timeout, 15, fun() ->
			%% the whole message arrives in one packet, so it completes before the size check
			%% in receive_data/8 and is rejected after it is read
			?assertEqual([{handle_error, tcp_closed}, {terminate, normal}],
						 run(?AFTER_DATA,
							 fun(Sock) -> send_message(Sock, "small.com", big_body() ++ "\r\n.\r\n") end))
		   end}}]}
	 end}.

%% Connects, plays Client, and returns the session's events, ending at terminate/2.
run(FailFrom, Client) ->
	register(?TEST_PROC, self()),
	application:set_env(gen_smtp, fail_setopts_from, FailFrom),
	try
		{ok, Sock} = smtp_socket:connect(tcp, "localhost", ranch:get_port(?LISTENER)),
		try
			{ok, "220 " ++ _} = recv_line(Sock),
			Client(Sock),
			collect([])
		after
			catch smtp_socket:close(Sock)
		end
	after
		application:unset_env(gen_smtp, fail_setopts_from),
		unregister(?TEST_PROC)
	end.

collect(Acc) ->
	receive
		{session_event, {terminate, _} = Event} -> lists:reverse([Event | Acc]);
		{session_event, Event} -> collect([Event | Acc])
	after 3000 -> error({session_not_terminated, lists:reverse(Acc)})
	end.

start_listener() ->
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, Pid} = ranch:start_listener(?LISTENER, fail_setopts_transport,
									 #{socket_opts => [{port, 0}]},
									 gen_smtp_server_session,
									 {?MODULE, gte16, [{hostname, "localhost"}]}),
	Pid.

stop_listener(_) ->
	ranch:stop_listener(?LISTENER).

ehlo(Sock) ->
	ehlo(Sock, "somehost.com").

ehlo(Sock, Host) ->
	ok = smtp_socket:send(Sock, ["EHLO ", Host, "\r\n"]),
	recv_until_last_ehlo_line(Sock).

send_message(Sock, Host, Body) ->
	start_data(Sock, Host),
	ok = smtp_socket:send(Sock, Body).

big_body() -> lists:duplicate(4 * ?MAXSIZE, $x).

start_data(Sock) ->
	start_data(Sock, "somehost.com").

start_data(Sock, Host) ->
	ok = ehlo(Sock, Host),
	ok = smtp_socket:send(Sock, "MAIL FROM:<a@b.com>\r\n"),
	{ok, "250" ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "RCPT TO:<c@d.com>\r\n"),
	{ok, "250" ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "DATA\r\n"),
	{ok, "354" ++ _} = recv_line(Sock),
	ok.

recv_line(Sock) -> smtp_socket:recv(Sock, 0, 5000).

recv_until_last_ehlo_line(Sock) ->
	case recv_line(Sock) of
		{ok, "250 " ++ _} -> ok;
		{ok, "250-" ++ _} -> recv_until_last_ehlo_line(Sock)
	end.
