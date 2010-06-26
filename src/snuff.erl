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

-module(snuff).
-export([service/2]).

-include("epcap_net.hrl").


service(Dev, NS) ->
    {ok, Socket} = packet:socket(),
    ok = packet:promiscuous(Socket, packet:ifindex(Socket, Dev)),
    error_logger:info_report({ns,NS}),
    loop(Socket, NS).

loop(Socket, NS) ->
    case procket:recvfrom(Socket, 65535) of
        nodata ->
            timer:sleep(10),
            loop(Socket, NS);
        {ok, Data} ->
            P = epcap_net:decapsulate(Data),
            filter(NS, P),
            loop(Socket, NS);
        Error ->
            error_logger:error_report(Error)
    end.

filter(NS, [
        #ether{},
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
    dns:send(Port, Payload),
    spoof:source(IP);
filter(_,_) ->
    ok.

