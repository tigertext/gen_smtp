%% A ranch transport for tests: ranch_tcp, except that setopts/2 starts failing once it is
%% called with the options set in the application env gen_smtp/fail_setopts_from, as
%% {Opts, Reason}. From that call on, every setopts/2 returns {error, Reason}, as on a socket
%% the client has closed. The socket itself stays open; the session has to end on its own.
-module(fail_setopts_transport).

-export([name/0, secure/0, messages/0, listen/1, disallowed_listen_options/0, accept/2,
	accept_ack/2, handshake/3, connect/3, connect/4, recv/3, send/2, sendfile/2, sendfile/4,
	sendfile/5, setopts/2, getopts/2, getstat/1, getstat/2, controlling_process/2,
	peername/1, sockname/1, shutdown/2, close/1]).

-define(FAILING, {?MODULE, failing}).

setopts(Socket, Opts) ->
	case {get(?FAILING), application:get_env(gen_smtp, fail_setopts_from)} of
		{{true, Reason}, _} ->
			{error, Reason};
		{_, {ok, {Opts, Reason}}} ->
			%% the session process calls setopts/2, so the process dictionary is per session
			put(?FAILING, {true, Reason}),
			{error, Reason};
		_ ->
			ranch_tcp:setopts(Socket, Opts)
	end.

name() -> tcp.
secure() -> ranch_tcp:secure().
messages() -> ranch_tcp:messages().
listen(Opts) -> ranch_tcp:listen(Opts).
disallowed_listen_options() -> ranch_tcp:disallowed_listen_options().
accept(LSocket, Timeout) -> ranch_tcp:accept(LSocket, Timeout).
accept_ack(Socket, Timeout) -> ranch_tcp:accept_ack(Socket, Timeout).
handshake(Socket, Opts, Timeout) -> ranch_tcp:handshake(Socket, Opts, Timeout).
connect(Host, Port, Opts) -> ranch_tcp:connect(Host, Port, Opts).
connect(Host, Port, Opts, Timeout) -> ranch_tcp:connect(Host, Port, Opts, Timeout).
recv(Socket, Length, Timeout) -> ranch_tcp:recv(Socket, Length, Timeout).
send(Socket, Packet) -> ranch_tcp:send(Socket, Packet).
sendfile(Socket, File) -> ranch_tcp:sendfile(Socket, File).
sendfile(Socket, File, Offset, Bytes) -> ranch_tcp:sendfile(Socket, File, Offset, Bytes).
sendfile(Socket, File, Offset, Bytes, Opts) -> ranch_tcp:sendfile(Socket, File, Offset, Bytes, Opts).
getopts(Socket, Opts) -> ranch_tcp:getopts(Socket, Opts).
getstat(Socket) -> ranch_tcp:getstat(Socket).
getstat(Socket, Opts) -> ranch_tcp:getstat(Socket, Opts).
controlling_process(Socket, Pid) -> ranch_tcp:controlling_process(Socket, Pid).
peername(Socket) -> ranch_tcp:peername(Socket).
sockname(Socket) -> ranch_tcp:sockname(Socket).
shutdown(Socket, How) -> ranch_tcp:shutdown(Socket, How).
close(Socket) -> ranch_tcp:close(Socket).
