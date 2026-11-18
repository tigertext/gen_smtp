%% What a session shows in sys:get_status/1 and in its crash report (format_status/2).
%% The session holds the AUTH credential and the callback module's state, which may hold
%% secrets of its own; neither may be shown as is.
%%
%% This module is also a callback module under test: it delegates every callback to
%% smtp_server_example and adds format_status/2, so the callback's own choice is used.
-module(session_status_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_AUTH/4, handle_STARTTLS/1, handle_error/3, code_change/3,
	terminate/2, format_status/2]).

-define(PASSWORD, "PaSSw0rd").

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
handle_AUTH(Type, User, Credential, State) ->
	smtp_server_example:handle_AUTH(Type, User, Credential, State).
handle_STARTTLS(State) -> smtp_server_example:handle_STARTTLS(State).
code_change(OldVsn, State, Extra) -> smtp_server_example:code_change(OldVsn, State, Extra).
handle_error(Class, Details, State) -> smtp_server_example:handle_error(Class, Details, State).
terminate(Reason, State) -> smtp_server_example:terminate(Reason, State).
format_status(Opt, [_PDict, _State]) -> {shown_by_callback, Opt}.

%% smtp_server_example has no format_status/2: its state is not shown at all.
without_callback_format_status_test_() ->
	with_authenticated_session(status_plain, smtp_server_example, fun(Pid) ->
		Normal = sys:get_status(Pid),
		Terminate = gen_smtp_server_session:format_status(terminate, [[], sys:get_state(Pid)]),
		[?_assertNot(contains(Normal, ?PASSWORD)),
		 ?_assertNot(contains(Terminate, ?PASSWORD)),
		 %% the raw state does hold it: the check above would catch a leak
		 ?_assert(contains(sys:get_state(Pid), ?PASSWORD)),
		 ?_assert(contains(Normal, redacted)),
		 %% the username stays, for debugging
		 ?_assert(contains(Terminate, "username"))]
	end).

%% A callback module with format_status/2 decides what of its own state is shown.
with_callback_format_status_test_() ->
	with_authenticated_session(status_callback, ?MODULE, fun(Pid) ->
		Terminate = gen_smtp_server_session:format_status(terminate, [[], sys:get_state(Pid)]),
		[?_assert(contains(sys:get_status(Pid), {shown_by_callback, normal})),
		 ?_assert(contains(Terminate, {shown_by_callback, terminate})),
		 ?_assertNot(contains(Terminate, ?PASSWORD))]
	end).

%% Message data is replaced by its size.
message_data_is_not_shown_test() ->
	{redacted, 5} = element(2, redact_data(<<"hello">>)).

%%% helpers

with_authenticated_session(Name, Module, Tests) ->
	{setup,
	 fun() ->
		gen_smtp_application:ensure_all_started(gen_smtp),
		{ok, _} = gen_smtp_server:start({local, Name}, Module,
			[{sessionoptions, [{callbackoptions, [{auth, true}]}]},
			 {domain, "localhost"}, {port, 0}]),
		{ok, Sock} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, Name})),
		{ok, "220 " ++ _} = recv(Sock),
		ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
		ok = recv_until_last_ehlo_line(Sock),
		Plain = base64:encode_to_string(<<0, "username", 0, ?PASSWORD>>),
		ok = smtp_socket:send(Sock, "AUTH PLAIN " ++ Plain ++ "\r\n"),
		{ok, "235 " ++ _} = recv(Sock),
		[Pid] = ranch:procs({local, Name}, connections),
		{Name, Sock, Pid}
	 end,
	 fun({N, Sock, _}) ->
		catch smtp_socket:close(Sock),
		gen_smtp_server:stop(N)
	 end,
	 fun({_, _, Pid}) -> Tests(Pid) end}.

%% A session status with only data set, through the same function the session uses.
redact_data(Data) ->
	Status = gen_smtp_server_session:format_status(terminate, [[], fake_state(Data)]),
	{data, find_data(Status)}.

%% Only to reach the envelope's data field without the record definitions: start from a
%% real session state and swap the data in.
fake_state(Data) ->
	{ok, _} = gen_smtp_server:start({local, status_data}, smtp_server_example,
		[{domain, "localhost"}, {port, 0}]),
	try
		{ok, S} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, status_data})),
		{ok, "220 " ++ _} = recv(S),
		ok = smtp_socket:send(S, "EHLO somehost.com\r\n"),
		ok = recv_until_last_ehlo_line(S),
		ok = smtp_socket:send(S, "MAIL FROM:<a@example.com>\r\n"),
		{ok, "250 " ++ _} = recv(S),
		[Pid] = ranch:procs({local, status_data}, connections),
		replace_data(sys:get_state(Pid), Data)
	after
		gen_smtp_server:stop(status_data)
	end.

%% The envelope is the only #envelope{} record in the state; its data field holds <<>>
%% right after MAIL FROM.
replace_data(State, Data) ->
	list_to_tuple([case E of
		Env when is_tuple(Env), element(1, Env) =:= envelope ->
			setelement(data_index(Env), Env, Data);
		_ -> E
	end || E <- tuple_to_list(State)]).

data_index(Env) ->
	[I] = [I || I <- lists:seq(2, tuple_size(Env)), element(I, Env) =:= <<>>,
	            not is_tuple(element(I, Env))],
	I.

find_data(Status) ->
	[Env] = [E || E <- tuple_to_list(Status), is_tuple(E), element(1, E) =:= envelope],
	[D] = [V || V <- tuple_to_list(Env), is_tuple(V), element(1, V) =:= redacted],
	D.

contains(Term, Needle) when is_list(Needle) ->
	string:find(lists:flatten(io_lib:format("~p", [Term])), Needle) =/= nomatch;
contains(Term, Needle) ->
	contains(Term, lists:flatten(io_lib:format("~p", [Needle]))).

recv(Sock) -> smtp_socket:recv(Sock, 0, 5000).

recv_until_last_ehlo_line(Sock) ->
	case recv(Sock) of
		{ok, "250 " ++ _} -> ok;
		{ok, "250-" ++ _} -> recv_until_last_ehlo_line(Sock)
	end.
