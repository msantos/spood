%% Copyright (c) 2012, Michael Santos <michael.santos@gmail.com>
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
-module(spood_pinger).

-export([start/1, start/2]).
-export([range/2]).

-define(INTERVAL, 15*60000).   % 15 minutes

%% Populate the local ARP cache by periodically scanning the network
start(Dev) ->
    start(Dev, ?INTERVAL).

start(Dev, Interval) when is_binary(Dev) ->
    start(binary_to_list(Dev), Interval);
start(Dev, Interval) when is_list(Dev), Interval > 0 ->
    {ok, Ifs} = inet:getifaddrs(),
    Cfg = proplists:get_value(Dev, Ifs),

    [Addr] = [ {A,B,C,D} || {addr, {A,B,C,D}} <- Cfg ],
    [Netmask] = [ {A,B,C,D} || {netmask, {A,B,C,D}} <- Cfg ],

    {Network, Broadcast} = range(Addr, Netmask),

    {ok, Socket} = gen_udp:open(0, [
                {active, false}
                ]),

    poll(Socket, Interval, ipv4_to_int(Network)+1, ipv4_to_int(Broadcast)).

range({A1,A2,A3,A4}, {M1,M2,M3,M4}) ->
    Addr = (A1 bsl 24) bor (A2 bsl 16) bor (A3 bsl 8) bor A4,
    Mask = (M1 bsl 24) bor (M2 bsl 16) bor (M3 bsl 8) bor M4,

    {int_to_ipv4(Addr band Mask), int_to_ipv4(Addr bor (bnot Mask))}.

int_to_ipv4(N) ->
    <<A, B, C, D>> = <<N:4/unsigned-integer-unit:8>>,
    {A,B,C,D}.

ipv4_to_int({A,B,C,D}) ->
    <<N:4/unsigned-integer-unit:8>> = <<A, B, C, D>>,
    N.

poll(Socket, Interval, Start, End) ->
    scan(Socket, Start, End),
    timer:sleep(Interval),
    poll(Socket, Interval, Start, End).

scan(Socket, Address, End) when Address < End ->
    Port = crypto:rand_uniform(16#0FFF, 16#FFFF),

%    error_logger:info_report([
%            {address, int_to_ipv4(Address)},
%            {port, Port}
%            ]),

    ok = gen_udp:send(Socket, int_to_ipv4(Address), Port, <<>>),
    scan(Socket, Address+1, End);
scan(_Socket, _Address, _End) ->
    ok.
