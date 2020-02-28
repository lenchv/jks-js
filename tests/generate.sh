ALIASNAME=jks-js
SSL_PASSWORD=password
KEYSTORE_PATH=./feature/keystore
CERT_PATH=./feature/pem

ALG=RSA # EC | RSA | DSA
SIZE=2048 # 256 | 2048 | 1024 |
SIG_ALG=SHA1withRSA
NAME=${ALG}_${SIZE}_${SIG_ALG}_keystore

keytool -genkey -noprompt \
	-alias $ALIASNAME \
	-dname "CN=jks-js, OU=jks-js, O=lenchv, L=jks-js, S=jks-js, C=jks-js" \
	-keyalg $ALG \
	-sigalg $SIG_ALG \
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
