;
; BIND data file for example.com
;
$TTL    60
@       IN      SOA     example.com. root.example.com. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

; name servers
@       IN      NS      ns.example.com.

; name server records
ns      IN      A       172.17.31.1
ns      IN      AAAA    fdff:db8:c58:31::1
ns      IN      AAAA    2001:db8:c58:31::1

; other records
@       IN      A       172.17.31.1
@       IN      AAAA    fdff:db8:c58:31::1
@       IN      AAAA    2001:db8:c58:31::1
v4lonly IN      A       172.17.31.4
v4gonly IN      A       198.51.100.4
v6lonly IN      AAAA    fdff:db8:c58:31::6
v6gonly IN      AAAA    2001:db8:c58:31::6
v64l    IN      A       172.17.31.64
v64l    IN      AAAA    fdff:db8:c58:31::64
v64g    IN      A       198.51.100.64
v64g    IN      AAAA    2001:db8:c58:31::64
