%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
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
-module(spoof).
-behaviour(gen_server).

-include("pkt.hrl").
-define(SERVER, ?MODULE).

-export([start_link/3, send/2, source/1]).
-export([dns_query/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).

-define(IPV4HDRLEN, 20).
-define(UDPHDRLEN, 8).

-record(state, {
        s,          % socket
        i,          % interface index
        shost,      % Client MAC Address
        dhost,      % NS MAC Address
        daddr,      % NS IP Address
        saddr       % Strategy for selecting client IP address
    }).

send(Port, Data) when is_integer(Port), is_binary(Data) ->
    gen_server:call(?MODULE, {dns_query, Port, Data}).

source(IP) when is_tuple(IP) ->
    gen_server:call(?MODULE, {sourceip, IP}).


start_link(Dev, Client, NS) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Dev, Client, NS], []).

init([Dev, {SrcMAC, Strategy}, {DstMAC, NSIP}]) ->
    crypto:start(),
    {ok, Socket} = packet:socket(),
    Ifindex = packet:ifindex(Socket, Dev),

    Source = case Strategy of
        discover ->
            {SA1,SA2,SA3,SA4} = packet:ipv4address(Socket, Dev),
            {learn, [{SA1,SA2,SA3,SA4}]};
        {discover, IPList} ->
            {learn, IPList};
        N -> N
    end,

    {ok, #state{
            s = Socket,
            i = Ifindex,
            shost = SrcMAC,
            saddr = Source,

            dhost = DstMAC,
            daddr = NSIP
        }}.

% DNS request from dns server
handle_call({dns_query, Port, Data}, _From, #state{s = Socket, i = Ifindex} = State) ->
    Packet = dns_query(Port, Data, State),
    packet:send(Socket, Ifindex, Packet),
    error_logger:info_report([
            {spoofing, Port},
            {packet, inet_dns:decode(Data)}
        ]),
    {reply, ok, State};
% Add a new source IP address
handle_call({sourceip, IP}, _From, #state{saddr = {learn, IPList}} = State) ->
    N = case lists:member(IP, IPList) of
        true -> IPList;
        false -> [IP|IPList]
    end,
    {reply, ok, State#state{
            saddr = {learn, N}
        }};
handle_call({sourceip, _IP}, _From, State) ->
    {reply, ok, State};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

% WTF?
handle_info(Info, State) ->
    error_logger:error_report([wtf, Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


dns_query(SourcePort, Data, #state{
    shost = {SM1,SM2,SM3,SM4,SM5,SM6},
    dhost = {DM1,DM2,DM3,DM4,DM5,DM6},
    saddr = Strategy,
    daddr = {DA1,DA2,DA3,DA4}
    }) ->

    {SA1,SA2,SA3,SA4} = strategy(Strategy),

    UDPlen = ?UDPHDRLEN + byte_size(Data),

    Ether = #ether{
        dhost = <<DM1,DM2,DM3,DM4,DM5,DM6>>,
        shost = <<SM1,SM2,SM3,SM4,SM5,SM6>>
    },

    IP = #ipv4{
        id = 1,
        p = ?IPPROTO_UDP,
        len = ?IPV4HDRLEN + UDPlen,
        saddr = {SA1,SA2,SA3,SA4},
        daddr = {DA1,DA2,DA3,DA4}
    },

    UDP = #udp{
        sport = SourcePort,
        dport = 53,
        ulen = UDPlen
    },

    IPsum = pkt:makesum(IP),
    UDPsum = pkt:makesum([IP, UDP, Data]),

    <<(pkt:ether(Ether))/bits,
    (pkt:ipv4(IP#ipv4{sum = IPsum}))/bits,
    (pkt:udp(UDP#udp{sum = UDPsum}))/bits,
    Data/bits>>.

%%
%% Strategies for choosing a source IP address
%%

% Single source IP address
strategy(Address) when is_list(Address) ->
    {ok, SA} = inet_parse:address(Address),
    SA;
strategy({_,_,_,_} = SA) ->
    SA;

% A manually specified list
strategy({list, IPList}) when is_list(IPList) ->
    error_logger:info_report([{shuffle, IPList}]),
    lists:nth(crypto:rand_uniform(1, length(IPList)+1), IPList);

% Learn what's on the network
% XXX should add a timeout to force removal of stale entries
strategy({learn , IPList}) when is_list(IPList) ->
    error_logger:info_report([{discovered, IPList}]),
    lists:nth(crypto:rand_uniform(1, length(IPList)+1), IPList).


