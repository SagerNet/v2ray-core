# Project V for SagerNet

### Important changes

#### Rewritten DNS

- added DNS Over TLS and QUIC support

example:

```
tls://dns.google
quic://dns.adguard.com
```

All available DNS schemes:

```
tcp
tcp+local
udp
udp+local
tls
tls+local
https
https+local
quic
quic+local
```

- multiple DNS now share the cache.
- concurrent query support

```json
{
  "dns": [
    {
      "address": "tls://1.0.0.1",
      "concurrency": true
    }
  ]
}
```

#### Other

- concurrency option for outbound observation

```json
{
  "observatory": {
    "enableConcurrency": true
  }
}
```

- DNS sniffer

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "protocol": "dns",
        "outbound": "dns-out"
      }
    ]
  }
}
```

- disableExpire dns option

```json
{
  "dns": {
    "disableExpire": true
  }
}
```

- removed FakeDNS

```
FakeDNS is a bad idea, and v2ray's current implementation
causes memory leaks, whether enabled or not.
```

- wireguard outbound

```
WireGuard outbound supports proxy ping requests.
```

```json
{
  "outbounds": [
    {
      "protocol": "wireguard",
      "settings": {
        "address": "engage.cloudflareclient.com",
        "localAddresses": [
          "<ipv4 address>",
          "<ipv6 address>"
        ],
        "peerPublicKey": "<public key>",
        "port": 2408,
        "preSharedKey": "<psk>",
        "privateKey": "<private key>",
        "mtu": 1500,
        "userLevel": 0
      }
    }
  ]
}
```

- ssh outbound

```json
{
  "outbounds": [
    {
      "protocol": "ssh",
      "settings": {
        "address": "<your ip>",
        "port": 22,
        "user": "root",
        "password": "<password or passphrase of private key>",
        "privateKey": "<x509 private key>",
        "publicKey": "<public key to verify server>",
        "clientVersion": "SSH-2.0-OpenSSH_114514 (random if empty)",
        "hostKeyAlgorithms": [
          "ssh-ed25519",
          "any u want"
        ],
        "userLevel": 0
      }
    }
  ]
}
```

- add domainStrategy to outbound & preferIPv4/6 to domainStrategy

```json
{
  "outbounds": [
    {
      "protocol": "shadowsocks",
      "settings": {
        ...
      },
      "domainStrategy": "AsIs/UseIP/UseIPv[4/6]/PreferIPv[4/6]"
    }
  ]
}
```

- shadowsocks AEAD 2022 ciphers

```json
{
  "outbounds": [
    {
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 1234,
            "method": "2022-blake3-aes-128-gcm",
            "password": "<psk>"
          }
        ]
      }
    }
  ]
}
```

- shadowsocks stream ciphers and xchacha-ietf-poly1305

```
supported cipher list:

none

2022-blake3-aes-128-gcm
2022-blake3-aes-256-gcm
2022-blake3-chacha20-poly1305

aes-128-gcm
aes-192-gcm
aes-256-gcm
chacha20-ietf-poly1305
xchacha20-ietf-poly1305

rc4
rc4-md5
aes-128-ctr
aes-192-ctr
aes-256-ctr
aes-128-cfb
aes-192-cfb
aes-256-cfb
aes-128-cfb8
aes-192-cfb8
aes-256-cfb8
aes-128-ofb
aes-192-ofb
aes-256-ofb
bf-cfb
cast5-cfb
des-cfb
idea-cfb
rc2-cfb
seed-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
camellia-128-cfb8
camellia-192-cfb8
camellia-256-cfb8
salsa20
chacha20
chacha20-ietf
xchacha20
```

- shadowsocks sing outbound

high performance shadowsocks outbound, with AEAD 2022 Extensible Identity Headers support.

```
supported cipher list:

none

2022-blake3-aes-128-gcm
2022-blake3-aes-256-gcm
2022-blake3-chacha20-poly1305

aes-128-gcm
aes-192-gcm
aes-256-gcm
chacha20-ietf-poly1305
xchacha20-ietf-poly1305
```

```json
{
  "outbounds": [
    {
      "protocol": "shadowsocks_sing",
      "settings": {
        "address": "127.0.0.1",
        "port": 1234,
        "method": "aes-128-gcm",
        "password": "my password"
      }
    }
  ]
}
```

for shadowsocks 2022 ciphers

```json
{
  "outbounds": [
    {
      "protocol": "shadowsocks_sing",
      "settings": {
        "address": "127.0.0.1",
        "port": 1234,
        "method": "2022-blake3-aes-128-gcm",
        "password": "<psk>"
      }
    }
  ]
}
```

- shadowsocks SIP003 plugin

```json
{
  "outbounds": [
    {
      "protocol": "shadowsocks",
      "settings": {
        ...
        "plugin": "path to plugin",
        "pluginOpts": "args;args2",
        "pluginArgs": [
          "--arg1=true"
        ]
      }
    }
  ]
}
```

- embed v2ray-plugin for shadowsocks

```json
{
  "outbounds": [
    {
      "protocol": "shadowsocks",
      "settings": {
        ...
        "plugin": "v2ray-plugin",
        "pluginOpts": "host=shadow.v2fly.org"
      }
    }
  ]
}
```

- trojan_sing outbound

high performance trojan outbound.

notice: only the origin trojan (tls) protocol is supported.

```json
{
  "outbounds": [
    {
      "protocol": "trojan_sing",
      "settings": {
        "address": "my.address",
        "serverName": "my.domain",
        "port": 443,
        "password": "my password",
        "insecure": false
      }
    }
  ]
}
```

- route only sniffing option

```
Allows the sniffed domain to be used for routing only, 
without overriding the destination address. 
This improves the routing accuracy of AsIs, 
and provides the expected connection behavior of the client 
(not resolving the domain name again on the server side)
```

```json
{
  "inbounds": [
    {
      ...
      "sniffing": {
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "enabled": true,
        "routeOnly": true
      },
      "tag": "socks"
    }
  ]
}
```

- endpoint independent mapping support (aka full cone NAT)

`for protocols other than v*ess, no configuration is required.`

```json
{
  "outbounds": [
    {
      "protocol": "v[m/l]ess",
      "settings": {
        "vnext": ...,
        "packetEncoding": "[none/packet/xudp]"
        // none: disabled
        // packet: requires v2fly/v2ray-core v5.0.2+ or SagerNet/v2ray-core
        // xudp: requires XTLS/Xray-core or SagerNet/v2ray-core
      },
      "mux": {
        "enabled": true,
        "packetEncoding": "[none/packet/xudp]"
        // packetEncoding for mux
      }
    }
  ]
}
```

- ping proxy support

```json
{
  "ping": {
    "protocol": "<default/unprivileged>",
    "gateway4": "<0.0.0.0>",
    "gateway6": "<::>",
    "disableIPv6": true
  }
}
```

`protocol: udp connection with port 7.`

- XTLS protocol compatibility for vless and trojan

- gRPC multi/raw mode

### License

[GPL v3](https://raw.githubusercontent.com/SagerNet/v2ray-core/main/LICENSE)

### Credits

This repo relies on the following projects:

- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- [Shadowsocks-NET/v2ray-go](https://github.com/Shadowsocks-NET/v2ray-go)
