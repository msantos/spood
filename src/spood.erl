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
-module(spood).
-export([start/0,start/1]).
-export([nameserver/0, macaddr/1]).


start() ->
    start([]).
start(Options) ->
    Dev = proplists:get_value(dev, Options, hd(packet:default_interface())),

    Saddr = proplists:get_value(saddr, Options, discover),
    Daddr = proplists:get_value(nameserver, Options, nameserver()),

    Smac = proplists:get_value(srcmac, Options, macaddr({client, Dev})),
    Dmac = proplists:get_value(dstmac, Options, macaddr({server, Daddr})),

    spood_spoof:start_link(Dev, {Smac,Saddr}, {Dmac, Daddr}),
    spood_dns:start_link(),
    spawn(spood_pinger, start, [Dev, timer:minutes(15)]),
    spood_snuff:start_link(Dev, Daddr).

nameserver() ->
    {ok, PL} = inet_parse:resolv(
        proplists:get_value(resolv_conf, inet_db:get_rc(), "/etc/resolv.conf")),
    proplists:get_value(nameserver, PL).

macaddr({Type, Dev}) when is_binary(Dev) ->
    macaddr({Type, binary_to_list(Dev)});
macaddr({client, Dev}) when is_list(Dev) ->
    {ok, Ifs} = inet:getifaddrs(),
    Cfg = proplists:get_value(Dev, Ifs),
    [MAC] = [ list_to_tuple(N) || {hwaddr, N} <- Cfg ],
    MAC;
macaddr({server, IPAddr}) ->
    % Force an ARP cache entry
    {ok, Socket} = gen_udp:open(0, [{active, false}]),
    ok = gen_udp:send(Socket, IPAddr, 53, <<>>),
    ok = gen_udp:close(Socket),

    packet:arplookup(IPAddr).
