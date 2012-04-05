spood is a spoofing DNS proxy with a vaguely obscene name. All in Erlang.


# WHAT IS IT

spood is a DNS proxy that listens for requests on localhost and proxies
the requests by spoofing the packets from the IP addresses of other
clients. spood might be useful if you're using a DNS tunnel like sods:

    http://github.com/msantos/sods


# REQUIREMENTS

    * procket: http://github.com/msantos/procket
    * pkt: http://github.com/msantos/pkt


# SETUP

1. Build it and run:

        make
        ./start.sh

2. Test it:

        $ nslookup
        > server 127.0.0.1
        Default server: 127.0.0.1
        Address: 127.0.0.1#53
        > www.google.com
        Server:         127.0.0.1
        Address:        127.0.0.1#53

        Non-authoritative answer:
        www.google.com  canonical name = www.l.google.com.
        Name:   www.l.google.com
        Address: 173.194.33.104


# TODO

* support multiple name servers

* add ability to turn on/off debug output

* add sanity checks on sniffed DNS packets, like checking domain
