%% What a session shows in sys:get_status/1 and in its crash report (format_status/2).
%% The session holds the AUTH credential and the callback module's state, which may hold
%% secrets of its own; neither may be shown as is.
%%
%% This module is also a callback module under test: it delegates every callback to
%% secret_state_callback (whose state holds the credential) and adds format_status/2, so
%% the callback's own choice is used.
-module(session_status_tests).

-include_lib("eunit/include/eunit.hrl").

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_AUTH/4, handle_STARTTLS/1, handle_error/3, code_change/3,
	terminate/2, format_status/2, log/2]).

-define(PASSWORD, "PaSSw0rd").

-define(CB, secret_state_callback).

init(Hostname, SessionCount, Address, Options) -> ?CB:init(Hostname, SessionCount, Address, Options).
handle_HELO(Hostname, State) -> ?CB:handle_HELO(Hostname, State).
handle_EHLO(Hostname, Extensions, State) -> ?CB:handle_EHLO(Hostname, Extensions, State).
handle_MAIL(From, State) -> ?CB:handle_MAIL(From, State).
handle_MAIL_extension(Ext, State) -> ?CB:handle_MAIL_extension(Ext, State).
handle_RCPT(To, State) -> ?CB:handle_RCPT(To, State).
handle_RCPT_extension(Ext, State) -> ?CB:handle_RCPT_extension(Ext, State).
handle_DATA(From, To, Data, State) -> ?CB:handle_DATA(From, To, Data, State).
handle_RSET(State) -> ?CB:handle_RSET(State).
handle_VRFY(Address, State) -> ?CB:handle_VRFY(Address, State).
handle_other(Verb, Args, State) -> ?CB:handle_other(Verb, Args, State).
handle_AUTH(Type, User, Credential, State) -> ?CB:handle_AUTH(Type, User, Credential, State).
handle_STARTTLS(State) -> ?CB:handle_STARTTLS(State).
code_change(OldVsn, State, Extra) -> ?CB:code_change(OldVsn, State, Extra).
handle_error(Class, Details, State) -> ?CB:handle_error(Class, Details, State).
terminate(Reason, State) -> ?CB:terminate(Reason, State).
format_status(_Opt, [[crash_format_status], _State]) -> error(boom);
format_status(Opt, [_PDict, _State]) -> {shown_by_callback, Opt}.

%% logger handler: forwards every event to the process registered as ?LOG_SINK.
-define(LOG_SINK, session_status_tests_logs).
log(Event, _Config) -> catch ?LOG_SINK ! {log, Event}.

%% secret_state_callback has no format_status/2: its state, which holds the credential, is
%% shown as `redacted'.
without_callback_format_status_test_() ->
	with_authenticated_session(status_plain, ?CB, fun(Pid) ->
		Raw = sys:get_state(Pid),
		I = callback_state_index(Raw),
		Normal = status_state(sys:get_status(Pid)),
		Terminate = gen_smtp_server_session:format_status(terminate, [[], Raw]),
		%% the raw state holds it twice (envelope and callback state): the checks below are live
		[?_assertMatch({secret_state, _, <<?PASSWORD>>}, element(I, Raw)),
		 ?_assert(contains(setelement(I, Raw, none), ?PASSWORD)),   % the envelope's copy
		 ?_assertEqual(redacted, element(I, Normal)),
		 ?_assertEqual(redacted, element(I, Terminate)),
		 ?_assertNot(contains(sys:get_status(Pid), ?PASSWORD)),
		 ?_assertNot(contains(Terminate, ?PASSWORD)),
		 %% the username stays, for debugging
		 ?_assert(contains(Terminate, "username"))]
	end).

%% A callback module with format_status/2 decides what of its own state is shown.
with_callback_format_status_test_() ->
	with_authenticated_session(status_callback, ?MODULE, fun(Pid) ->
		Raw = sys:get_state(Pid),
		I = callback_state_index(Raw),
		Terminate = gen_smtp_server_session:format_status(terminate, [[], Raw]),
		[?_assertEqual({shown_by_callback, normal}, element(I, status_state(sys:get_status(Pid)))),
		 ?_assertEqual({shown_by_callback, terminate}, element(I, Terminate)),
		 ?_assertNot(contains(Terminate, ?PASSWORD))]
	end).

%% A callback whose format_status/2 crashes falls back to `redacted', not to the raw state.
callback_format_status_crash_test_() ->
	with_authenticated_session(status_crashing_cb, ?MODULE, fun(Pid) ->
		Raw = sys:get_state(Pid),
		Shown = gen_smtp_server_session:format_status(terminate, [[crash_format_status], Raw]),
		[?_assertEqual(redacted, element(callback_state_index(Raw), Shown)),
		 ?_assertNot(contains(Shown, ?PASSWORD))]
	end).

%% A term that is not a session state is returned as is.
non_session_state_is_returned_as_is_test() ->
	?assertEqual(not_a_state, gen_smtp_server_session:format_status(terminate, [[], not_a_state])).

%% Mid-exchange AUTH state: the CRAM-MD5 challenge (authdata) is replaced by its size, and
%% an AUTH LOGIN that has only sent the username shows it, with no credential.
auth_in_progress_test_() ->
	{setup,
	 fun() ->
		start_server(status_in_progress, smtp_server_example),
		status_in_progress
	 end,
	 fun(Name) -> gen_smtp_server:stop(Name) end,
	 fun(Name) ->
		{Cram, CramRaw} = in_progress(Name, ["AUTH CRAM-MD5"]),
		{Login, _} = in_progress(Name, ["AUTH LOGIN", base64:encode_to_string("username")]),
		[?_assertMatch({_, _}, find_authdata(CramRaw)),
		 ?_assertNot(contains(Cram, element(2, find_authdata(CramRaw)))),
		 ?_assert(contains(Login, "username"))]
	 end}.

%% Base64 the client sends that does not decode gets a 501; the session goes on, so a
%% malformed AUTH line never ends up in a crash report.
undecodable_auth_test_() ->
	{setup,
	 fun() -> start_server(status_bad_base64, ?CB), status_bad_base64 end,
	 fun(Name) -> gen_smtp_server:stop(Name) end,
	 fun(Name) ->
		[{Desc, ?_test(begin
			{Sock, Pid} = connect_ehlo(Name),
			Ref = erlang:monitor(process, Pid),
			[begin ok = smtp_socket:send(Sock, L ++ "\r\n"), {ok, "334" ++ _} = recv(Sock) end
			 || L <- Before],
			ok = smtp_socket:send(Sock, "!!!notbase64\r\n"),
			?assertMatch({ok, "501 " ++ _}, recv(Sock)),
			ok = smtp_socket:send(Sock, "NOOP\r\n"),
			?assertMatch({ok, "250 " ++ _}, recv(Sock)),
			?assertEqual([], [R || {'DOWN', R0, _, _, R} <- flush(), R0 =:= Ref]),
			smtp_socket:close(Sock)
		 end)} || {Desc, Before} <- [{"PLAIN reply", ["AUTH PLAIN"]},
		                             {"LOGIN username", ["AUTH LOGIN"]},
		                             {"LOGIN password", ["AUTH LOGIN", base64:encode_to_string("username")]},
		                             {"CRAM-MD5 reply", ["AUTH CRAM-MD5"]}]]
		++ [{"PLAIN inline", ?_test(begin
			{Sock, Pid} = connect_ehlo(Name),
			Ref = erlang:monitor(process, Pid),
			ok = smtp_socket:send(Sock, "AUTH PLAIN !!!notbase64\r\n"),
			?assertMatch({ok, "501 " ++ _}, recv(Sock)),
			ok = smtp_socket:send(Sock, "NOOP\r\n"),
			?assertMatch({ok, "250 " ++ _}, recv(Sock)),
			?assertEqual([], [R || {'DOWN', R0, _, _, R} <- flush(), R0 =:= Ref]),
			smtp_socket:close(Sock)
		 end)}]
	 end}.

%% At debug level the session logs each line it receives; AUTH credentials are left out.
debug_log_has_no_credential_test_() ->
	{setup,
	 fun() ->
		start_server(status_debug_log, ?CB),
		Old = {application:get_env(hut, level), maps:get(level, logger:get_primary_config())},
		application:set_env(hut, level, debug),
		logger:set_primary_config(level, all),
		catch unregister(?LOG_SINK),
		ok = logger:add_handler(?LOG_SINK, ?MODULE, #{level => all}),
		{status_debug_log, Old}
	 end,
	 fun({Name, {HutLevel, PrimaryLevel}}) ->
		logger:remove_handler(?LOG_SINK),
		logger:set_primary_config(level, PrimaryLevel),
		case HutLevel of
			{ok, L} -> application:set_env(hut, level, L);
			undefined -> application:unset_env(hut, level)
		end,
		gen_smtp_server:stop(Name)
	 end,
	 fun({Name, _}) -> {timeout, 10, ?_test(begin
		register(?LOG_SINK, self()),
		Plain = base64:encode_to_string(<<0, "username", 0, ?PASSWORD>>),
		Pass64 = base64:encode_to_string(?PASSWORD),
		{S1, _} = connect_ehlo(Name),
		ok = smtp_socket:send(S1, "AUTH PLAIN " ++ Plain ++ "\r\n"),
		{ok, "235 " ++ _} = recv(S1),
		smtp_socket:close(S1),
		{S2, _} = connect_ehlo(Name),
		ok = smtp_socket:send(S2, "AUTH LOGIN\r\n"),
		{ok, "334 " ++ _} = recv(S2),
		ok = smtp_socket:send(S2, base64:encode_to_string("username") ++ "\r\n"),
		{ok, "334 " ++ _} = recv(S2),
		ok = smtp_socket:send(S2, Pass64 ++ "\r\n"),
		{ok, "235 " ++ _} = recv(S2),
		smtp_socket:close(S2),
		Logs = [format_log(L) || L <- drain_logs([])],
		unregister(?LOG_SINK),
		%% debug lines were captured, so the check below is live
		?assert(lists:any(fun(L) -> string:find(L, "got an AUTH request") =/= nomatch end, Logs)),
		?assertEqual([], [L || L <- Logs, lists:any(fun(N) -> string:find(L, N) =/= nomatch end,
		                                          [?PASSWORD, Plain, Pass64])])
	 end)} end}.

%% Message data is replaced by its size.
message_data_is_not_shown_test() ->
	{redacted, 5} = element(2, redact_data(<<"hello">>)).

%%% helpers

start_server(Name, Module) ->
	gen_smtp_application:ensure_all_started(gen_smtp),
	{ok, _} = gen_smtp_server:start({local, Name}, Module,
		[{sessionoptions, [{callbackoptions, [{auth, true}]}]},
		 {domain, "localhost"}, {port, 0}]).

connect_ehlo(Name) ->
	%% the previous session of this listener may still be closing
	wait_no_sessions(Name, 100),
	{ok, Sock} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, Name})),
	{ok, "220 " ++ _} = recv(Sock),
	ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
	ok = recv_until_last_ehlo_line(Sock),
	[Pid] = ranch:procs({local, Name}, connections),
	{Sock, Pid}.

wait_no_sessions(_Name, 0) -> ok;
wait_no_sessions(Name, N) ->
	case ranch:procs({local, Name}, connections) of
		[] -> ok;
		_ -> timer:sleep(10), wait_no_sessions(Name, N - 1)
	end.

flush() ->
	receive M -> [M | flush()] after 0 -> [] end.

%% The position of the callback module's state in the session state: the field holding the
%% {secret_state, ...} term.
callback_state_index(State) ->
	[I] = [I || I <- lists:seq(1, tuple_size(State)),
	            is_tuple(element(I, State)), element(1, element(I, State)) =:= secret_state],
	I.

%% The session state as sys:get_status/1 shows it: format_status(normal, ...) must return
%% [{data, [{"State", Shown}]}].
status_state({status, _Pid, _Mod, [_PDict, _SysState, _Parent, _Debug, Misc]}) ->
	[Shown] = [S || {data, [{"State", S}]} <- Misc],
	Shown.

format_log({Msg, _Meta}) ->
	case Msg of
		{string, S} -> lists:flatten(io_lib:format("~ts", [S]));
		{report, R} -> lists:flatten(io_lib:format("~p", [R]));
		{F, A} -> lists:flatten(io_lib:format(F, A))
	end.

%% Opens a session, sends EHLO and Lines (each must get a 334), and returns the session's
%% status as format_status(terminate, ...) shows it and its raw state.
in_progress(Name, Lines) ->
	wait_no_sessions(Name, 100),
	{ok, Sock} = smtp_socket:connect(tcp, "localhost", ranch:get_port({local, Name})),
	{ok, "220 " ++ _} = recv(Sock),
	ok = smtp_socket:send(Sock, "EHLO somehost.com\r\n"),
	ok = recv_until_last_ehlo_line(Sock),
	[begin ok = smtp_socket:send(Sock, L ++ "\r\n"), {ok, "334 " ++ _} = recv(Sock) end || L <- Lines],
	[Pid] = ranch:procs({local, Name}, connections),
	Raw = sys:get_state(Pid),
	smtp_socket:close(Sock),
	timer:sleep(50),
	{gen_smtp_server_session:format_status(terminate, [[], Raw]), Raw}.

%% The CRAM-MD5 challenge is the only binary field of the state that starts with "<".
find_authdata(State) ->
	case [B || B <- tuple_to_list(State), is_binary(B), byte_size(B) > 0, binary:first(B) =:= $<] of
		[B] -> {authdata, B};
		[] -> none
	end.

drain_logs(Acc) ->
	receive {log, #{msg := Msg, meta := Meta}} -> drain_logs([{Msg, Meta} | Acc])
	after 300 -> lists:reverse(Acc)
	end.

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
