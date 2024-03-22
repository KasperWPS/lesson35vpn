# Домашнее задание № 22 по теме: "Мосты, туннели и VPN". К курсу Administrator Linux. Professional

## Задание

- Настроить VPN между двумя ВМ в tun/tap режимах, замерить скорость в туннелях, сделать вывод об отличающихся показателях
- Поднять RAS на базе OpenVPN с клиентскими сертификатами, подключиться с локальной машины на ВМ
- (\*) Самостоятельно изучить и настроить ocserv, подключиться с хоста к ВМ

Конфигурация стенда:
```json
[
  {
    "name": "ovpnsrv",
    "cpus": 1,
    "gui": false,
    "box": "generic/debian11",
    "private_network":
    [
      { "ip": "192.168.10.1",  "adapter": 2, "netmask": "255.255.255.0",   "virtualbox__intnet": "net1"  },
      { "ip": "192.168.56.10", "adapter": 3, "netmask": "255.255.255.0" }
    ],
    "memory": "640",
    "no_share": true
  },
  {
    "name": "client",
    "cpus": 1,
    "gui": false,
    "box": "generic/debian11",
    "private_network":
    [
      { "ip": "192.168.56.20", "adapter": 2, "netmask": "255.255.255.0" }
    ],
    "memory": 640,
    "no_share": true
  },
  {
    "name": "rasvpn",
    "cpus": 1,
    "gui": false,
    "box": "generic/debian11",
    "private_network":
    [
      { "ip": "192.168.20.1",  "adapter": 2, "netmask": "255.255.255.0",   "virtualbox__intnet": "net2"  },
      { "ip": "192.168.56.12", "adapter": 3, "netmask": "255.255.255.0" }
    ],
    "memory": "640",
    "no_share": true
  },
  {
    "name": "rasclient",
    "cpus": 1,
    "gui": false,
    "box": "generic/debian11",
    "private_network":
    [
      { "ip": "192.168.56.13", "adapter": 2, "netmask": "255.255.255.0" }
    ],
    "memory": "640",
    "no_share": true
  },
  {
    "name": "ocserv",
    "cpus": 1,
    "gui": false,
    "box": "generic/debian11",
    "private_network":
    [
      { "ip": "192.168.30.1",  "adapter": 2, "netmask": "255.255.255.0",   "virtualbox__intnet": "net3"  },
      { "ip": "192.168.56.11", "adapter": 3, "netmask": "255.255.255.0" }
    ],
    "memory": "640",
    "no_share": true
  },
  {
    "name": "occlient",
    "cpus": 1,
    "gui": false,
    "box": "generic/debian11",
    "private_network":
    [
      { "ip": "192.168.56.14", "adapter": 2, "netmask": "255.255.255.0" }
    ],
    "memory": "640",
    "no_share": true
  }
]
```

### Схема стенда:
![Network topology](https://github.com/KasperWPS/lesson35vpn/blob/main/topology.svg)

### Задание 1

Использованы следующие ВМ:
- ovpnsrv - OpenVPN-сервер
- client - OpenVPN-клиент

Конфиг сервера:
```
dev tun
ifconfig 10.10.10.1 255.255.255.0
topology subnet
secret /etc/openvpn/static.key
comp-lzo
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
```

Конфиг клиента:
```
dev tun
remote 192.168.56.10
route 192.168.56.0 255.255.255.0
ifconfig 10.10.10.2 255.255.255.0
topology subnet
secret /etc/openvpn/static.key
comp-lzo
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
```

- На OpenVPN-сервере выполнить:
```bash
iperf3 -s &
```

- Далее замеряем скорость на клиенте (для смены типа интерфейса отредактировать переменную openvpn\_device в файле provisioning/defaults/main.yml):

**tap**

```bash
iperf3 -c 10.10.10.1 -t 40 -i 5
```
```
Connecting to host 10.10.10.1, port 5201
[  5] local 10.10.10.2 port 43470 connected to 10.10.10.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-5.00   sec  87.3 MBytes   146 Mbits/sec   90    406 KBytes       
[  5]   5.00-10.00  sec  82.5 MBytes   138 Mbits/sec    3    440 KBytes       
[  5]  10.00-15.00  sec  83.8 MBytes   141 Mbits/sec    0    557 KBytes       
[  5]  15.00-20.00  sec  82.5 MBytes   138 Mbits/sec   23    359 KBytes       
[  5]  20.00-24.58  sec  75.0 MBytes   137 Mbits/sec    0    485 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-24.58  sec   411 MBytes   140 Mbits/sec  116             sender
[  5]   0.00-24.58  sec  0.00 Bytes  0.00 bits/sec                  receiver
iperf3: interrupt - the client has terminated
```

**tun**

```bash
iperf3 -c 10.10.10.1 -t 40 -i 5
```
```
Connecting to host 10.10.10.1, port 5201
[  5] local 10.10.10.2 port 43586 connected to 10.10.10.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-5.00   sec  86.6 MBytes   145 Mbits/sec  125    337 KBytes       
[  5]   5.00-10.00  sec  85.2 MBytes   143 Mbits/sec   24    386 KBytes       
[  5]  10.00-15.00  sec  84.2 MBytes   141 Mbits/sec    6    418 KBytes       
[  5]  15.00-20.00  sec  85.3 MBytes   143 Mbits/sec   38    341 KBytes       
[  5]  20.00-23.06  sec  52.5 MBytes   144 Mbits/sec    7    344 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-23.06  sec   394 MBytes   143 Mbits/sec  200             sender
[  5]   0.00-23.06  sec  0.00 Bytes  0.00 bits/sec                  receiver
iperf3: interrupt - the client has terminated
```

- *Замеры скорости не выявили большой разницы, однако необходимо учитывать следующее:  TAP эмулирует Ethernet-устройство и работает на канальном уровне модели OSI, оперируя кадрами Ethernet. TUN (сетевой туннель) работает на сетевом уровне модели OSI, оперируя IP-пакетами. TAP используется для создания сетевого моста, тогда как TUN — для маршрутизации.*


### Задание 2. RAS на базе OpenVPN

ВМ:
 - rasvpn - VPN-сервер
 - rasclient - клиент

Конфиг сервера:
```
dev tun
port 1207
proto udp
ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key
dh /etc/openvpn/pki/dh.pem
server 10.10.10.0 255.255.255.0
ifconfig-pool-persist ipp.txt
client-to-client
client-config-dir /etc/openvpn/client
keepalive 10 120
comp-lzo
persist-key
persist-tun
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
```

Конфиг клиента:
```
dev tun
proto udp
remote 192.168.56.12 1207
client
resolv-retry infinite
remote-cert-tls server
ca ./ca.crt
cert ./client.crt
key ./client.key
comp-lzo
persist-key
persist-tun
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
```

Генерация ключевых пар и прочей криптографии осуществляется bash-скриптом:
```bash
#!/bin/bash

if [ -f /usr/share/easy-rsa/vars ]; then

  cd /etc/openvpn

  /usr/share/easy-rsa/easyrsa init-pki
  /usr/share/easy-rsa/easyrsa build-ca nopass

  echo 'rasvpn' | /usr/share/easy-rsa/easyrsa gen-req server nopass
  echo 'yes' | /usr/share/easy-rsa/easyrsa sign-req server server

  /usr/share/easy-rsa/easyrsa gen-dh

  openvpn --genkey secret ca.key

  echo 'client' | /usr/share/easy-rsa/easyrsa gen-req client nopass
  echo 'yes' | /usr/share/easy-rsa/easyrsa sign-req client client

fi
```

vars(/usr/share/easy-rsa/vars):
```
set_var EASYRSA_OPENSSL "openssl"
set_var EASYRSA_PKI             "/etc/openvpn/pki"
set_var EASYRSA_REQ_COUNTRY     "RU"
set_var EASYRSA_REQ_PROVINCE    "CHR"
set_var EASYRSA_REQ_CITY        "NCHK"
set_var EASYRSA_REQ_ORG         "NGSP"
set_var EASYRSA_REQ_EMAIL       "noreply@my.local"
set_var EASYRSA_REQ_OU          "IT"
set_var EASYRSA_KEY_SIZE        2048
set_var EASYRSA_ALGO            rsa
set_var EASYRSA_CA_EXPIRE       3650
set_var EASYRSA_RAND_SN         "yes"
set_var EASYRSA_REQ_CN          "RASVPN"
set_var EASYRSA_DIGEST          "sha256"
set_var EASYRSA_BATCH           "1"
```

Проверить состояние канала:
```bash
vagrant ssh rasclient -c 'ping -c1 10.10.10.1'
```
```
PING 10.10.10.1 (10.10.10.1) 56(84) bytes of data.
64 bytes from 10.10.10.1: icmp_seq=1 ttl=64 time=0.503 ms

--- 10.10.10.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.503/0.503/0.503/0.000 ms
```

- Канал поднят
- ВМ поднимаются и настраиваются с применение provisioner ansible с применением шаблонов


### Задание 3. (\*) OpenConnect-сервер

ВМ:
- ocserv - OpenConnect server
- occlient - OpenConnect client

- Сертификаты не гененрировались, используются дефолтные

Конфиг:
```
auth = "plain[passwd=/etc/ocserv/ocpasswd]"

#listen-host = [IP|HOSTNAME]
#udp-listen-host = [IP|HOSTNAME]
#listen-host-is-dyndns = true

tcp-port = 443
#udp-port = 443

run-as-user = nobody
run-as-group = daemon

socket-file = /run/ocserv.socket

server-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem
server-key = /etc/ssl/private/ssl-cert-snakeoil.key

#dh-params = /etc/ocserv/dh.pem

ca-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem

isolate-workers = true

max-clients = 5
max-same-clients = 1

server-stats-reset-time = 604800

keepalive = 300
dpd = 60
mobile-dpd = 300
switch-to-tcp-timeout = 25

# MTU discovery (DPD must be enabled)
try-mtu-discovery = false

# The object identifier that will be used to read the user ID in the client
# certificate. The object identifier should be part of the certificate's DN
# Useful OIDs are:
#  CN = 2.5.4.3, UID = 0.9.2342.19200300.100.1.1
cert-user-oid = 0.9.2342.19200300.100.1.1

# The object identifier that will be used to read the user group in the
# client certificate. The object identifier should be part of the certificate's
# DN. If the user may belong to multiple groups, then use multiple such fields
# in the certificate's DN. Useful OIDs are:
#  OU (organizational unit) = 2.5.4.11
#cert-group-oid = 2.5.4.11

compression = true
no-compress-limit = 256

tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-SSL3.0:-ARCFOUR-128"

auth-timeout = 240
idle-timeout = 1200
mobile-idle-timeout = 1800

min-reauth-time = 300

max-ban-score = 80
ban-reset-time = 300

cookie-timeout = 300

deny-roaming = false

rekey-time = 172800

rekey-method = ssl

# Whether to enable support for the occtl tool (i.e., either through D-BUS,
# or via a unix socket).
use-occtl = true

pid-file = /run/ocserv.pid

device = vpns

predictable-ips = true

default-domain = 192.168.56.11

ipv4-network = 10.10.10.0/24

dns = 8.8.8.8
dns = 1.1.1.1

ping-leases = false

#mtu = 1420

route = 10.10.10.0/24

cisco-client-compat = true

dtls-legacy = true
```

Логин: **otus**
Пароль: **otus**

Проверка состояния канала:

```bash
vagrant ssh occlient
```
```bash
openconnect -b 192.168.56.11:443
```
```bash
ping 10.10.10.1
```
```
PING 10.10.10.1 (10.10.10.1) 56(84) bytes of data.
64 bytes from 10.10.10.1: icmp_seq=1 ttl=64 time=0.820 ms
64 bytes from 10.10.10.1: icmp_seq=2 ttl=64 time=1.73 ms
^C
--- 10.10.10.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.820/1.275/1.731/0.455 ms
```

### Playbook
```yaml
---
- hosts: all
  become: true
  gather_facts: true

  vars_files:
    - defaults/main.yml

  tasks:
  - name: Accept login with password from sshd
    ansible.builtin.lineinfile:
      path: /etc/ssh/sshd_config
      regexp: '^PasswordAuthentication no$'
      line: 'PasswordAuthentication yes'
      state: present
    notify:
      - Restart sshd

  - name: Set timezone
    community.general.timezone:
      name: Europe/Moscow

  - name: set up forward packages across routers
    sysctl:
      name: net.ipv4.conf.all.forwarding
      value: '1'
      state: present
    when: "'routers' in group_names"

  - name: Install soft
    ansible.builtin.apt:
      name:
        - vim
        - tcpdump
        - traceroute
        - nmap
        - iperf3
      state: present
      update-cache: true

  - name: Install OpenVPN
    ansible.builtin.apt:
      name:
        - openvpn
      state: present
    when: (ansible_hostname != "ocserv")

  - name: Install easy-rsa for rasvpn
    ansible.builtin.apt:
      name: easy-rsa
      state: present
    when: (ansible_hostname == 'rasvpn')

  - name: Generate secret OpenVPN
    ansible.builtin.command: openvpn --genkey secret /etc/openvpn/static.key
    args:
      creates: /etc/openvpn/static.key
    when: (ansible_hostname == 'ovpnsrv')
    notify: Restart openvpn

  - name: Copy static.key
    ansible.builtin.fetch:
      src: /etc/openvpn/static.key
      dest: files/openvpn-static.key
      flat: true
    when: (ansible_hostname == 'ovpnsrv')

  - name: Copy static.key to client
    ansible.builtin.copy:
      src: files/openvpn-static.key
      dest: /etc/openvpn/static.key
      mode: '0640'
      owner: root
      group: root
    notify: Restart openvpn
    when: (ansible_hostname == 'client')

  - name: Configure OpenVPN
    ansible.builtin.template:
      src: openvpn-server.conf.j2
      dest: /etc/openvpn/server.conf
      owner: root
      group: root
      mode: '0640'
    when: (ansible_hostname == "ovpnsrv" or ansible_hostname == 'client')
    notify: Restart openvpn

  - name: Copy systemd OpenVPN service file
    ansible.builtin.copy:
      src: files/openvpn@.service
      dest: /etc/systemd/system/openvpn@.service
      owner: root
      group: root
      mode: '0640'
    when: (ansible_hostname != "ocserv")

  - name: Copy vars easyrsa
    ansible.builtin.copy:
      src: files/rasvpn-vars
      dest: /usr/share/easy-rsa/vars
    when: (ansible_hostname == 'rasvpn')

  - name: Copy script for generate key pairs
    ansible.builtin.copy:
      src: files/rasvpn-gencerts.sh
      dest: /home/vagrant/gencerts.sh
      mode: '0750'
      owner: root
      group: root
    when: (ansible_hostname == 'rasvpn')

  - name: Check pki exists
    ansible.builtin.stat:
      path: /etc/openvpn/pki
    register: pkidir

  - name: Generate RSA key pairs
    ansible.builtin.shell: /home/vagrant/gencerts.sh
    when: (ansible_hostname == 'rasvpn' and not pkidir.stat.exists)

  - name: Copy client config on rasvpn server
    ansible.builtin.copy:
      src: files/rasvpn-client-config
      dest: /etc/openvpn/client/client
    when: ansible_hostname == 'rasvpn'

  - name: Get client certs in local directory
    ansible.builtin.fetch:
      src: /etc/openvpn/pki/{{ item }}
      dest: files/clientk/
      flat: true
    with_items:
      - ca.crt
      - issued/client.crt
      - private/client.key
    when: ansible_hostname == 'rasvpn'

  - name: Copy client certs on rasclient
    ansible.builtin.copy:
      src: files/clientk/{{ item }}
      dest: /etc/openvpn/{{ item }}
      mode: '0600'
      owner: root
      group: 'root'
    with_items:
      - ca.crt
      - client.crt
      - client.key
    when: ansible_hostname == 'rasclient'

  - name: Configure OpenVPN
    ansible.builtin.template:
      src: rasvpn-server.conf.j2
      dest: /etc/openvpn/server.conf
      owner: root
      group: root
      mode: '0640'
    when: (ansible_hostname == "rasclient" or ansible_hostname == 'rasvpn')
    notify: Restart openvpn

  # OpenConnect

  - name: Install OpenConnect
    ansible.builtin.apt:
      name:
        - ocserv
      state: present
    when: (ansible_hostname == "ocserv")

  - name: Copy config OpenConnect server
    ansible.builtin.copy:
      src: files/ocserv-conf
      dest: /etc/ocserv/ocserv.conf
    notify: Restart ocserv
    when: (ansible_hostname == "ocserv")

  - name: Copy ocpaccwd OpenConnect server
    ansible.builtin.copy:
      src: files/ocserv-ocpasswd
      dest: /etc/ocserv/ocpasswd
    when: (ansible_hostname == "ocserv")

  - name: Install OpenConnect client
    ansible.builtin.apt:
      name:
        - openconnect
      state: present
    when: (ansible_hostname == "occlient")

  handlers:

  - name: Restart openvpn
    ansible.builtin.service:
      name: openvpn@server
      state: restarted
      enabled: true

  - name: Restart ocserv
    ansible.builtin.service:
      name: ocserv
      state: restarted
      enabled: true

  - name: Restart sshd
    ansible.builtin.service:
      name: sshd
      state: restarted
```
