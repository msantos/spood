{application, spood,
    [
    {description, "Spoofing DNS Proxy"},
    {vsn, "0.01"},
    {modules, [
        spood,
        spoof,
        snuff,
        dns
            ]},
    {registered, []},
    {applications, [
        kernel,
        stdlib
            ]},
    {env, []}
    ]}.

