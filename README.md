# JKS-JS

[![npm](https://img.shields.io/npm/v/jks-js?color=blue&style=flat-square)](https://www.npmjs.com/package/jks-js)
[![test](https://github.com/lenchv/jks-js/workflows/test/badge.svg?branch=master&event=push)](https://github.com/lenchv/jks-js/actions?query=workflow%3Atest+branch%3Amaster)
[![codecov](https://codecov.io/gh/lenchv/jks-js/branch/master/graph/badge.svg)](https://codecov.io/gh/lenchv/jks-js)

## Description

**jks-js** is a converter of [Java Keystore](https://en.wikipedia.org/wiki/Java_KeyStore) to PEM certificates in order to securely connect to Java based servers using node js.

## Installation

```javascript
npm install jks-js
```

## Usage

```javascript
...
const jks = require('jks-js');

const keystore = jks.toPem(
	fs.readFileSync('keystore.jks'),
	'password'
);

const { cert, key } = keystore['alias'];

```

after extraction you may use cert and key in your connection settings:

```javascript
tls.connect('<port>', '<host>', {
	key: key,
	cert: cert,
});
```

[more details](https://nodejs.org/api/tls.html#tls_tls_connect_options_callback)

## API

```javascript
const {
	/**
	 * Extracts certificates from java keystore or truststore
	 * and decrypts private key 
	 * 
	 * @param keystore content of java keystore or truststore file
	 * @param keystorePassword password for verification and decryption
	 * @param pemPassword (optional) password that is used for decryption, in case it is different from keystorePassword. If not specified, keystorePassword is used
	 * @return {
	 *     <alias name>: {
	 *         cert: string // compound certificates chain
	 *         key: string // decrypted private key 
	 *     } | {
	 *         ca: string // trusted certificate
	 *     }
	 * }
	 */
	toPem,

	/**
	 *  Only extracts certificates
	 *  @param keystore
	 *  @param keystorePassword
	 *  @param pemPassword
	 *  @return { <alias name>: KeyEntry | TrustedKeyEntry }
	 */
	parseJks,

	/**
	 * Decrypts private key from DER to PEM
	 *
	 * @param protectedPrivateKey DER encoded private key
	 * @param password password for PKCS8 decryption
	 * @return decoded private key 
	 */
	decrypt
} = require('jks-js');
```

## How it works

The implementaion is based on [JavaKeystore.java](https://github.com/frohoff/jdk8u-jdk/blob/da0da73ab82ed714dc5be94acd2f0d00fbdfe2e9/src/share/classes/sun/security/provider/JavaKeyStore.java#L605) logic, which is internally used for creation of java keystore, including `keytool`.

It is supposed the keystore contains `X.509` certificates.

But you may use the library to extract any of certificates.

The decryption constrained by alghorithms that implemented in the [crypto](https://nodejs.org/api/crypto.html#crypto_keyobject_asymmetrickeytype) module of Node.js.

## Issues

If you find any troubles feel free to create an issue.

## License

[MIT License](LICENSE)

Copyright (c) 2020 Volodymyr Liench
