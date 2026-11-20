%% A callback module for tests whose state holds the AUTH credential, as a real one may
%% (email_gateway keeps it in sender_credential). It wraps smtp_server_example's state as
%% {secret_state, ExampleState, Credential} and has no format_status/2.
-module(secret_state_callback).

-export([init/4, handle_HELO/2, handle_EHLO/3, handle_MAIL/2, handle_MAIL_extension/2,
	handle_RCPT/2, handle_RCPT_extension/2, handle_DATA/4, handle_RSET/1, handle_VRFY/2,
	handle_other/3, handle_AUTH/4, handle_STARTTLS/1, handle_error/3, code_change/3,
	terminate/2]).

init(Hostname, SessionCount, Address, Options) ->
	wrap(smtp_server_example:init(Hostname, SessionCount, Address, Options), none).
handle_HELO(Hostname, {secret_state, S, C}) -> wrap(smtp_server_example:handle_HELO(Hostname, S), C).
handle_EHLO(Hostname, Extensions, {secret_state, S, C}) ->
	wrap(smtp_server_example:handle_EHLO(Hostname, Extensions, S), C).
handle_MAIL(From, {secret_state, S, C}) -> wrap(smtp_server_example:handle_MAIL(From, S), C).
handle_MAIL_extension(Ext, {secret_state, S, C}) ->
	wrap(smtp_server_example:handle_MAIL_extension(Ext, S), C).
handle_RCPT(To, {secret_state, S, C}) -> wrap(smtp_server_example:handle_RCPT(To, S), C).
handle_RCPT_extension(Ext, {secret_state, S, C}) ->
	wrap(smtp_server_example:handle_RCPT_extension(Ext, S), C).
handle_DATA(From, To, Data, {secret_state, S, C}) ->
	wrap(smtp_server_example:handle_DATA(From, To, Data, S), C).
handle_RSET({secret_state, S, C}) -> wrap(smtp_server_example:handle_RSET(S), C).
handle_VRFY(Address, {secret_state, S, C}) -> wrap(smtp_server_example:handle_VRFY(Address, S), C).
handle_other(Verb, Args, {secret_state, S, C}) -> wrap(smtp_server_example:handle_other(Verb, Args, S), C).
%% keeps the credential once AUTH succeeds
handle_AUTH(Type, User, Credential, {secret_state, S, C}) ->
	case smtp_server_example:handle_AUTH(Type, User, Credential, S) of
		{ok, S1} -> {ok, {secret_state, S1, Credential}};
		Other -> wrap(Other, C)
	end.
handle_STARTTLS({secret_state, S, C}) -> wrap(smtp_server_example:handle_STARTTLS(S), C).
code_change(OldVsn, {secret_state, S, C}, Extra) -> wrap(smtp_server_example:code_change(OldVsn, S, Extra), C).
handle_error(Class, Details, {secret_state, S, C}) -> wrap(smtp_server_example:handle_error(Class, Details, S), C).
terminate(Reason, {secret_state, S, C}) -> wrap(smtp_server_example:terminate(Reason, S), C).

%% smtp_server_example returns its state either bare or as the last element of a tuple
wrap(R, C) when is_tuple(R), element(1, R) =:= state -> {secret_state, R, C};
wrap(R, C) when is_tuple(R) ->
	setelement(tuple_size(R), R, {secret_state, element(tuple_size(R), R), C});
wrap(R, _) -> R.
