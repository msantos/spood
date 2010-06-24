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

-include("epcap_net.hrl").
-define(SERVER, ?MODULE).

-export([start_link/3, send/2]).
-export([dns_query/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).

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


start_link(Dev, Client, NS) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Dev, Client, NS], []).

init([Dev, {ClientMAC, Strategy}, {NSMAC, NSIP}]) ->
    crypto:start(),
    {ok, Socket} = packet:socket(),
    Ifindex = packet:ifindex(Socket, Dev),
    {ok, #state{
            s = Socket,
            i = Ifindex,
            shost = ClientMAC,
            saddr = Strategy,

            dhost = NSMAC,
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

    Id = 1,
    TTL = 64,

    UDPlen = 8 + byte_size(Data),

    IPlen = 20 + UDPlen,

    IPsum = epcap_net:makesum(
        <<
        % IPv4 header
        4:4, 5:4, 0:8, IPlen:16,
        Id:16, 0:1, 1:1, 0:1,
        0:13, TTL:8, 17:8, 0:16,
        SA1:8, SA2:8, SA3:8, SA4:8,
        DA1:8, DA2:8, DA3:8, DA4:8
        >>
    ),

    UDPpad = case UDPlen rem 2 of 
        0 -> 0;
        1 -> 8
    end,

    UDPsum = epcap_net:makesum(
        <<
        SA1:8,SA2:8,SA3:8,SA4:8,
        DA1:8,DA2:8,DA3:8,DA4:8,
        0:8,
        17:8,
        UDPlen:16,

        SourcePort:16,
        53:16,
        UDPlen:16,
        0:16,
        Data/binary,
        0:UDPpad
        >>),

    <<
    % Ethernet header
    DM1:8,DM2:8,DM3:8,DM4:8,DM5:8,DM6:8,
    SM1:8,SM2:8,SM3:8,SM4:8,SM5:8,SM6:8,
    16#08, 16#00,

    % IPv4 header
    4:4, 5:4, 0:8, IPlen:16,
    Id:16, 0:1, 1:1, 0:1,
    0:13, TTL:8, 17:8, IPsum:16,
    SA1:8, SA2:8, SA3:8, SA4:8,
    DA1:8, DA2:8, DA3:8, DA4:8,

    % UDP header
    SourcePort:16,
    53:16,
    UDPlen:16,
    UDPsum:16,
    Data/binary
    >>.

strategy(Address) when is_list(Address) ->
    {ok, SA} = inet_parse:address(Address),
    SA;
strategy({_,_,_,_} = SA) ->
    SA;
strategy({list, [IPList]}) when is_tuple(IPList) ->
    error_logger:info_report([{iplist, IPList}]),
    IPList;
strategy({list, IPList}) when is_list(IPList) ->
    error_logger:info_report([{shuffle, IPList}]),
    lists:nth(crypto:rand_uniform(1, length(IPList)), IPList).
