#!/bin/bash

ALIASNAME=jks-js
SSL_PASSWORD=password
KEYSTORE_PATH=./feature/keystore
CERT_PATH=./feature/pem

function generateKeystore() {
	ALG=$1 # EC | RSA | DSA
	SIZE=$2 # 256 | 2048 | 1024 |
	NAME=${ALG}_${SIZE}_keystore
	COMMAND=""

	if [ -n "$3" ]; then
		SIG_ALG=$3 # SHA1withRSA | SHA256withRSA | MD5withRSA 
		NAME=${ALG}_${SIZE}_${SIG_ALG}_keystore
		COMMAND="-sigalg $SIG_ALG"
	fi

	keytool -genkey -noprompt \
		-alias $ALIASNAME \
		-dname "CN=jks-js, OU=jks-js, O=lenchv, L=jks-js, S=jks-js, C=jks-js" \
		-keyalg $ALG \
		$COMMAND \
		-keystore $KEYSTORE_PATH/$NAME.jks \
		-keysize $SIZE \
		-storepass $SSL_PASSWORD \
		-keypass $SSL_PASSWORD

	keytool -importkeystore \
		-srckeystore $KEYSTORE_PATH/$NAME.jks \
		-destkeystore $KEYSTORE_PATH/jks.p12 \
		-srcalias $ALIASNAME \
		-srcstoretype jks \
		-deststoretype pkcs12 \
		-srcstorepass $SSL_PASSWORD \
		-deststorepass $SSL_PASSWORD;

	openssl pkcs12 -in $KEYSTORE_PATH/jks.p12 -nokeys -out $CERT_PATH/$NAME.pem -passin pass:$SSL_PASSWORD;
	openssl pkcs12 -in $KEYSTORE_PATH/jks.p12 -nodes -nocerts -out $CERT_PATH/$NAME.key -passin pass:$SSL_PASSWORD;

	rm $KEYSTORE_PATH/jks.p12
}

function generateTrusstore() {
	KEYSTORE=$KEYSTORE_PATH/$1_keystore.jks
	TRUSTSTORE_FILE=$KEYSTORE_PATH/$1_truststore.jks
	keytool -export -alias $ALIASNAME -file $CERT_PATH/$ALIASNAME.crt -keystore $KEYSTORE -storepass $SSL_PASSWORD -noprompt;
	keytool -import -trustcacerts -alias $ALIASNAME -file $CERT_PATH/$ALIASNAME.crt -keystore $TRUSTSTORE_FILE -storepass $SSL_PASSWORD -noprompt;
	rm $CERT_PATH/$ALIASNAME.crt
}

rm -rf $KEYSTORE_PATH
rm -rf $CERT_PATH

mkdir $KEYSTORE_PATH
mkdir $CERT_PATH

generateKeystore EC 256
generateKeystore RSA 2048
generateKeystore DSA 1024
generateKeystore RSA 2048 MD5withRSA
generateKeystore RSA 2048 SHA1withRSA
generateKeystore RSA 2048 SHA256withRSA

generateTrusstore RSA_2048
