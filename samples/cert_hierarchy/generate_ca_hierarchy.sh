#!/bin/sh


export common_name

rm -rf root_ca
rm -rf intermediate_ca
rm -rf initiator
rm -rf responder

mkdir root_ca
mkdir root_ca/newcerts
echo 123456 > root_ca/serial
touch root_ca/index.txt

mkdir intermediate_ca
mkdir intermediate_ca/newcerts
echo 123456 > intermediate_ca/serial
touch intermediate_ca/index.txt


mkdir initiator
mkdir responder


#Root CA - self signed
#generate root key
echo generate private key for root CA
openssl ecparam -name prime256v1 -genkey -noout -out root_ca/root_priv_key.pem
#generate csr
echo generate CSR for self-signed root CA certificate
common_name=root_ca
openssl req -config root_ca.cnf -new -sha256 -key root_ca/root_priv_key.pem \
-out root_ca/root_csr.pem
#self-sign certificate
echo generate self signed root CA certificate
openssl req -x509 -sha256 -days 365 -key root_ca/root_priv_key.pem \
-in root_ca/root_csr.pem -out root_ca/root_cert.pem
echo ----------------



#Intermediate CA - key pair and certificate signed by root
#generate CA private Key
echo generate private key for Intermediate CA
openssl ecparam -name prime256v1 -genkey -noout \
-out intermediate_ca/intermediate_ca_priv_key.pem
#generate Intermediate CA csr
common_name=intermediate_ca
echo generate CSR for Intermediate CA certificate
openssl req -config root_ca.cnf -new -sha256 \
-key intermediate_ca/intermediate_ca_priv_key.pem \
-out intermediate_ca/intermediate_ca_csr.pem
#sign leaf certificate
echo generate Intermediate CA certificate
openssl ca -config root_ca.cnf -days 375 -notext -md sha256 \
-in intermediate_ca/intermediate_ca_csr.pem \
-out intermediate_ca/intermediate_ca_cert.pem
echo ----------------



#Initiator Device keys and certificate
#generate Device Private Key
echo generate private key for initiator
openssl ecparam -name prime256v1 -genkey -noout \
-out initiator/initiator_device_priv_key.pem

#generate csr
echo generate CSR for initiator certificate
common_name=initiator
openssl req -config intermediate_ca.cnf  -new -sha256 \
-key initiator/initiator_device_priv_key.pem \
-out initiator/initiator_device_csr.pem
#sign leaf certificate
echo generate certificate for initiator
openssl ca -config intermediate_ca.cnf -days 375 -notext -md sha256 \
-in initiator/initiator_device_csr.pem \
-out initiator/initiator_device_cert.pem
echo ----------------


#Responder Device keys and certificate
#generate Device Private Key
echo generate private key for responder
openssl ecparam -name prime256v1 -genkey -noout \
-out responder/responder_device_priv_key.pem

#generate csr
echo generate CSR for responder certificate
common_name=responder
openssl req -config intermediate_ca.cnf -new -sha256 \
-key responder/responder_device_priv_key.pem \
-out responder/responder_device_csr.pem

#sign leaf certificate
echo generate certificate for responder
openssl ca -config intermediate_ca.cnf -days 375 -notext -md sha256 \
-in responder/responder_device_csr.pem \
-out responder/responder_device_cert.pem
echo ----------------


#convert to der 
#openssl ec -inform pem -outform der -in root_priv_key.pem -out root_priv_key.der
#openssl ec -inform pem -outform der -in intermediate_ca_priv_key.pem -out intermediate_ca_priv_key.der
#openssl ec -inform pem -outform der -in initiator/initiator_device_priv_key.pem -out initiator/initiator_device_priv_key.der
#openssl ec -inform pem -outform der -in responder/responder_device_priv_key.pem -out responder/responder_device_priv_key.der
openssl x509 -outform der -in responder/responder_device_cert.pem -out responder/responder_device_cert.der
openssl x509 -outform der -in initiator/initiator_device_cert.pem -out initiator/initiator_device_cert.der


#show as text
openssl ec -inform pem  -in responder/responder_device_priv_key.pem -text -noout
openssl x509 -inform pem  -in responder/responder_device_cert.pem -text -noout


# print values as test vector inputs
python3 generate_test_vec_inputs.py





