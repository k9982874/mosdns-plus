# mosdns plus

This repository forked from [mosdns](https://github.com/IrineSistiana/mosdns), a great dns server.

This branch aims to add some enhanced features that that are not officially accepted by mosdns.

### Feature list
**AdGurad DNSProxy**
Gives mosdsn the ability to query DNS records using AdGuard DNSProxy.

Supported protocols: *DNS-over-TLS*, *DNS-over-HTTPS*, *DNSCrypt*, and *DNS-over-QUIC*

Reference: https://github.com/AdguardTeam/dnsproxy

### A configuration example
```yaml
## config.example.yaml
## -- Log Config -- ##
log:
  # ["debug", "info", "warn", and "error"], default is set to "info"
  level: debug

## -- API Config -- ##
api:
  http: "0.0.0.0:9091"

## -- Plugins Config -- ##
plugins:
  # proxy dns query to quad9
  - tag: quad9
    type: dnsproxy
    args:
      insecure_skip_verify: false # allow insecure ssl, true or false
      # specify a DNS resolver to resolve the value in the addr field, nullable
      bootstrap:
        - 223.5.5.5
        - 119.29.29.29
      timeout: 5 # query timeout
      upstreams:
        - tag: Quad9-DNS-IPv4
          addr: 9.9.9.9
        - tag: Quad9-DNSCrypt-IPv4
          addr: sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0
        - tag: Quad9-DNS-over-HTTPS
          addr: https://dns.quad9.net/dns-query
          insecure_skip_verify: true
          bootstrap:
            - 8.8.8.8
            - 1.1.1.1
          timeout: 15
        - tag: Quad9-DNS-over-TLS
          addr: https://dns.quad9.net/dns-query
          insecure_skip_verify: true
          bootstrap:
            - 8.8.8.8
            - 1.1.1.1
          timeout: 15 # query timeout

  - tag: query_dnsproxy
    type: sequence
    args:
      - exec: $quad9

  ## --- Main Sequence --- ##
  - tag: main
    type: sequence
    args:
      - exec: query_summary entry

      # query taobao.com with DNS-over-QUIC protocol on ali
      - matches:
        - qname taobao.com
        exec: dnsproxy quic://dns.alidns.com:853
      - matches: has_resp
        exec: accept

      # query google.com with DNSCrypt protocol on adguard
      - matches:
        - qname google.com
        exec: dnsproxy sdns://AQIAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20
      - matches: has_resp
        exec: accept

      # forward the reset to quad9
      - exec: $query_dnsproxy

  ## --- Server Configuration --- ##
  - type: udp_server
    args:
      entry: main
      listen: :54
  - type: tcp_server
    args:
      entry: main
      listen: :54
```