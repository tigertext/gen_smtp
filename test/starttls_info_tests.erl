%% Tests for the optional handle_STARTTLS/2 callback: after a successful STARTTLS
%% handshake, a callback module that exports it receives the negotiated TLS protocol
%% and cipher suite (from ssl:connection_information/2).
%%
%% This module is also the callback module under test: it delegates every callback to
%% smtp_server_example and adds handle_STARTTLS/2, which reports what it received to
%% the registered test process.
-module(starttls_info_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_STARTTLS/1, handle_STARTTLS/2, code_change/3, terminate/2]).

-define(TEST_PROC, starttls_info_test_proc).

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
handle_STARTTLS(State) ->
	?TEST_PROC ! starttls_1_called,
	smtp_server_example:handle_STARTTLS(State).
handle_STARTTLS(TlsInfo, State) ->
	?TEST_PROC ! {starttls_2_called, TlsInfo},
	smtp_server_example:handle_STARTTLS(State).
code_change(OldVsn, State, Extra) -> smtp_server_example:code_change(OldVsn, State, Extra).
terminate(Reason, State) -> smtp_server_example:terminate(Reason, State).

handle_starttls_2_receives_negotiated_protocol_and_cipher_test_() ->
	{setup, fun start_server/0, fun stop_server/1,
	 fun(_) ->
		{timeout, 20, fun() ->
			register(?TEST_PROC, self()),
			try
				{ok, _SslSock} = starttls_handshake(),
				TlsInfo = receive {starttls_2_called, Info} -> Info
						  after 5000 -> error(handle_starttls_2_not_called)
						  end,
				Protocol = proplists:get_value(protocol, TlsInfo),
				?assert(lists:member(Protocol, ['tlsv1', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'])),
				?assertMatch(#{cipher := _}, proplists:get_value(selected_cipher_suite, TlsInfo)),
				%% /2 replaces /1 for modules that export it: no double callback.
				receive starttls_1_called -> error(handle_starttls_1_also_called)
				after 200 -> ok
				end
			after
				unregister(?TEST_PROC)
			end
		end}
	 end}.

%% The info lookup must never crash the session after a successful handshake: an error
%% tuple or an exception from ssl:connection_information/2 both give [].
tls_info_falls_back_to_empty_list_test_() ->
	[{"error tuple (socket already closed)",
	  {timeout, 20, fun() ->
		{ok, Listen} = ssl:listen(0, [{keyfile, "test/fixtures/mx1.example.com-server.key"},
		                               {certfile, "test/fixtures/mx1.example.com-server.crt"},
		                               {reuseaddr, true}]),
		{ok, {_, Port}} = ssl:sockname(Listen),
		Self = self(),
		spawn_link(fun() ->
			{ok, T} = ssl:transport_accept(Listen),
			{ok, S} = ssl:handshake(T),
			Self ! {server_socket, S}
		end),
		{ok, Client} = ssl:connect("localhost", Port, [{verify, verify_none}]),
		Server = receive {server_socket, S} -> S after 5000 -> error(no_handshake) end,
		ok = ssl:close(Server),
		ok = ssl:close(Client),
		ssl:close(Listen),
		?assertEqual([], gen_smtp_server_session:tls_info(Server))
	  end}},
	 {"exception (not an ssl socket)",
	  ?_assertEqual([], gen_smtp_server_session:tls_info(not_a_socket))}].

start_server() ->
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, Pid} = gen_smtp_server:start(
		{local, starttls_info_test_server},
		?MODULE,
		[{sessionoptions,
		  [{tls_options,
			[{keyfile, "test/fixtures/mx1.example.com-server.key"},
			 {certfile, "test/fixtures/mx1.example.com-server.crt"}]},
		   %% smtp_server_example only advertises STARTTLS when auth is on
		   {callbackoptions, [{auth, true}]}]},
		 {domain, "localhost"},
		 %% Port 0: the OS picks a free one, so this can't collide with other suites.
		 {port, 0}]),
	Pid.

stop_server(_Pid) ->
	gen_smtp_server:stop(starttls_info_test_server).

starttls_handshake() ->
	{ok, Sock} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, starttls_info_test_server})),
	{ok, "220 " ++ _} = recv_line(Sock),
	ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
	ok = recv_until_last_ehlo_line(Sock),
	ok = smtp_socket:send(Sock, "STARTTLS\r\n"),
	{ok, "220 " ++ _} = recv_line(Sock),
	smtp_socket:to_ssl_client(Sock).

recv_line(Sock) -> smtp_socket:recv(Sock, 0, 5000).

recv_until_last_ehlo_line(Sock) ->
	case recv_line(Sock) of
		{ok, "250 " ++ _} -> ok;
		{ok, "250-" ++ _} -> recv_until_last_ehlo_line(Sock)
	end.
