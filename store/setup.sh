#!/bin/bash

# From https://github.com/thojansen/client-certificates/blob/master/ssl/setup.sh
# create rootCA certificate
# openssl genrsa -out rootCA.key 2048
# openssl req -x509 -new -nodes -key rootCA.key -days 1024 -out rootCA.crt -subj "/C=DE/ST=Germany/L=Walldorf/O=SAP SE/OU=Tools/CN=rootCA"

# create server key and certificate
# openssl genrsa -out server.key 2048
# openssl req -new -key server.key -out server.csr -subj "/C=DE/ST=Germany/L=Walldorf/O=SAP SE/OU=Tools/CN=localhost"
# openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out server.crt -days 500

# create client key and certificate
openssl genrsa -out clientTestuserUntrusted.key 2048
openssl req -new -key clientTestuserUntrusted.key -out clientTestuserUntrusted.csr -subj "/C=US/ST=HI/L=Walldorf/O=Org 10/OU=Test-OU/CN=testuserUntrusted"
openssl x509 -req -in clientTestuserUntrusted.csr -CA fakeCA.crt -CAkey fakeCA.key -CAcreateserial -out clientTestuserUntrusted.crt -days 365

# generate client.p12 file which can be easily imported to OS.
openssl pkcs12 -export -inkey clientTestuserUntrusted.key -in clientTestuserUntrusted.crt -name clientTestuserUntrusted -out clientTestuserUntrusted.p12

# generate a non-encrypt pem file with key and crt files, from p12 files
#openssl pkcs12 -in client.p12 -out client.pem -nodes -clcerts
