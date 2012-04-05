%% Copyright (c) 2010-2012, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(spood_snuff).
-behaviour(gen_server).

-define(SERVER, ?MODULE).

-include_lib("pkt/include/pkt.hrl").

-export([start_link/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).

-record(state, {
        ns,         % real name server
        port
    }).


start_link(Dev, NS) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Dev, NS], []).

init([Dev, NS]) ->
    {ok, Socket} = packet:socket(),
    ok = packet:promiscuous(Socket, packet:ifindex(Socket, Dev)),

    error_logger:info_report([
            {dev, Dev},
            {ns,NS}
            ]),

    Port = erlang:open_port({fd, Socket, Socket}, [stream, binary]),

    {ok, #state{
            ns = NS,
            port = Port
        }}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({Port, {data, Data}}, #state{port = Port, ns = NS} = State) ->
    spawn(fun() -> send(NS, Data) end),
    {noreply, State};
% WTF?
handle_info(Info, State) ->
    error_logger:error_report([{wtf, Info}]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
send(NS, Data) ->
    P = pkt:decapsulate(Data),
    case filter(NS, P) of
        false ->
            ok;
        {ok, IP, Port, Payload} ->
            spood_dns:send(Port, Payload),
            spood_spoof:source(IP)
    end.

filter(NS, [#ether{},
        #ipv4{
            saddr = NS,
            daddr = IP
        },
        #udp{
            sport = 53,
            dport = Port,
            ulen = Len
        },
        Payload
    ]) when Len > 0, Len < 512 ->
    {ok, IP, Port, Payload};
filter(_,_) ->
    false.
