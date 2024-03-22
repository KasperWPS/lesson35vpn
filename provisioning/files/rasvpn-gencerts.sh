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

