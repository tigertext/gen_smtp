%% Tests for the PROXY command (HAProxy protocol v1, CP-899). Only the first line
%% of a session may set the client's source address, and when
%% proxy_trusted_sources is set, only if the TCP peer is one of those sources.
%%
%% This module is also the callback module under test: it delegates every
%% callback to smtp_server_example and reports update_source_ip/2 calls to the
%% registered test process.
-module(proxy_command_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_STARTTLS/1, handle_error/3, code_change/3, terminate/2,
	update_source_ip/2]).

-define(TEST_PROC, proxy_command_test_proc).
-define(PROXY(Ip), "PROXY TCP4 " Ip " 10.0.0.1 56324 25\r\n").

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
handle_error(Class, Details, State) -> smtp_server_example:handle_error(Class, Details, State).
terminate(Reason, State) -> smtp_server_example:terminate(Reason, State).
update_source_ip(Ip, State) ->
	catch ?TEST_PROC ! {update_source_ip, Ip},
	{ok, State}.

%% Default (proxy_trusted_sources unset): any peer, but only on the first line.
first_line_only_test_() ->
	with_server(proxy_any, [],
		[{"PROXY as the first line sets the source address", fun() ->
			Sock = connect(proxy_any),
			ok = smtp_socket:send(Sock, ?PROXY("203.0.113.7")),
			ok = ehlo(Sock),
			?assertEqual([{203, 0, 113, 7}], source_ips(Sock))
		 end},
		 {"PROXY after EHLO is rejected and changes nothing", fun() ->
			Sock = connect(proxy_any),
			ok = ehlo(Sock),
			ok = smtp_socket:send(Sock, ?PROXY("10.1.2.3")),
			{ok, "503 " ++ _} = recv_line(Sock),
			?assertEqual([], source_ips(Sock))
		 end},
		 {"a second PROXY is rejected; the first one stands", fun() ->
			Sock = connect(proxy_any),
			ok = smtp_socket:send(Sock, ?PROXY("203.0.113.7")),
			ok = smtp_socket:send(Sock, ?PROXY("10.1.2.3")),
			{ok, "503 " ++ _} = recv_line(Sock),
			ok = ehlo(Sock),
			?assertEqual([{203, 0, 113, 7}], source_ips(Sock))
		 end}]).

%% proxy_trusted_sources set: PROXY counts only when the TCP peer (127.0.0.1
%% here) is inside one of the listed ranges.
trusted_sources_test_() ->
	[with_server(proxy_untrusted, [{proxy_trusted_sources, ["10.0.0.0/8", "fd00::/8"]}],
		[{"PROXY from a peer outside the list is ignored, without a reply", fun() ->
			Sock = connect(proxy_untrusted),
			ok = smtp_socket:send(Sock, ?PROXY("10.1.2.3")),
			%% the next reply must be EHLO's: a reply to PROXY would put the
			%% client one response out of step
			ok = ehlo(Sock),
			?assertEqual([], source_ips(Sock))
		 end}]),
	 with_server(proxy_trusted, [{proxy_trusted_sources, ["10.0.0.0/8", "127.0.0.0/8"]}],
		[{"PROXY from a peer inside the list sets the source address", fun() ->
			Sock = connect(proxy_trusted),
			ok = smtp_socket:send(Sock, ?PROXY("203.0.113.7")),
			ok = ehlo(Sock),
			?assertEqual([{203, 0, 113, 7}], source_ips(Sock))
		 end}])].

ip_in_cidrs_test_() ->
	In = fun(Ip, Cidrs) -> smtp_util:ip_in_cidrs(Ip, Cidrs) end,
	[?_assert(In({10, 1, 2, 3}, ["10.0.0.0/8"])),
	 ?_assertNot(In({11, 1, 2, 3}, ["10.0.0.0/8"])),
	 ?_assert(In({192, 168, 1, 77}, ["192.168.1.64/26"])),
	 ?_assertNot(In({192, 168, 1, 128}, ["192.168.1.64/26"])),
	 ?_assert(In({127, 0, 0, 1}, ["127.0.0.1"])),
	 ?_assertNot(In({127, 0, 0, 2}, ["127.0.0.1"])),
	 ?_assert(In({1, 2, 3, 4}, ["0.0.0.0/0"])),
	 ?_assert(In({16#fd00, 0, 0, 0, 0, 0, 0, 1}, [<<"fd00::/8">>])),
	 ?_assertNot(In({16#fe80, 0, 0, 0, 0, 0, 0, 1}, ["fd00::/8"])),
	 %% families don't mix, and bad entries never match
	 ?_assertNot(In({10, 1, 2, 3}, ["::/0"])),
	 ?_assertNot(In({10, 1, 2, 3}, ["10.0.0.0/33", "10.0.0.0/x", "not-an-ip/8", "10.0.0.0/"])),
	 ?_assertNot(In(undefined, ["0.0.0.0/0"])),
	 ?_assertNot(In({10, 1, 2, 3}, []))].

%%% helpers

with_server(Name, SessionOptions, Tests) ->
	{setup,
	 fun() ->
		gen_smtp_application:ensure_all_started(gen_smtp),
		{ok, _} = gen_smtp_server:start({local, Name}, ?MODULE,
			[{sessionoptions, SessionOptions}, {domain, "localhost"}, {port, 0}]),
		Name
	 end,
	 fun(_) ->
		gen_smtp_server:stop(Name),
		catch unregister(?TEST_PROC)
	 end,
	 {inorder, [{Desc, {timeout, 10, F}} || {Desc, F} <- Tests]}}.

%% eunit may run each test in its own process, so each test registers itself.
connect(Name) ->
	catch unregister(?TEST_PROC),
	register(?TEST_PROC, self()),
	flush(),
	{ok, Sock} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, Name})),
	{ok, "220 " ++ _} = recv_line(Sock),
	Sock.

ehlo(Sock) ->
	ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
	recv_until_last_ehlo_line(Sock).

%% The session handles lines in order, so once EHLO (or a 503) has been answered,
%% any update_source_ip/2 call for an earlier line has already been sent.
source_ips(Sock) ->
	smtp_socket:close(Sock),
	collect([]).

collect(Acc) ->
	receive {update_source_ip, Ip} -> collect([Ip | Acc])
	after 200 -> lists:reverse(Acc)
	end.

flush() ->
	receive {update_source_ip, _} -> flush() after 0 -> ok end.

recv_line(Sock) -> smtp_socket:recv(Sock, 0, 5000).

recv_until_last_ehlo_line(Sock) ->
	case recv_line(Sock) of
		{ok, "250 " ++ _} -> ok;
		{ok, "250-" ++ _} -> recv_until_last_ehlo_line(Sock)
	end.
