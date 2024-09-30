## [1.1.4](https://github.com/lenchv/jks-js/releases/tag/v1.1.4) 2024-09-30

- Corrected types for typescripts #22
- Fixed codecov and updated mocha 

## [1.1.3](https://github.com/lenchv/jks-js/releases/tag/v1.1.3) 2024-04-20
- Add npm provenance

## [1.1.2](https://github.com/lenchv/jks-js/releases/tag/v1.1.2) 2024-04-20

- Added index.d.ts with declared types for typescript
- Added polyfill for deprecated Buffer.slice

## [1.1.1](https://github.com/lenchv/jks-js/releases/tag/v1.1.1) 2024-03-18

- Fix dependency vulnerabilities

## [1.1.0](https://github.com/lenchv/jks-js/releases/tag/v1.1.0) 2022-08-20

- Updated libraries

- Added ability to set different password for decryption key than for keystore

## [1.0.1](https://github.com/lenchv/jks-js/releases/tag/v1.0.1) 2021-07-05

- Fix parse pkcs12 method

## [1.0.0](https://github.com/lenchv/jks-js/releases/tag/v1.0.0) 2021-14-03

- In java 11 implementation of JKS was changed to PKCS12. These changes add support of extracting certificates from pkcs12 using node-forge library.

## [0.1.3](https://github.com/lenchv/jks-js/releases/tag/v0.1.3) 2020-24-03

- Add using `node-int64` in order to present long numbers from stream in nodejs version that do not support big numbers

- Use `node-rsa` to export private key in node js versions that do not support crypto.createPrivateKey

## [0.1.2](https://github.com/lenchv/jks-js/releases/tag/v0.1.2) 2020-24-03

- Hexadecimal values changed to decimal for compatibility with older nodejs versions

- Improved error handling when encrypted algorithm is not supported

## [0.1.1](https://github.com/lenchv/jks-js/releases/tag/v0.1.1) 2020-01-03

- Removed CLI from package.json

## [0.1.0](https://github.com/lenchv/jks-js/releases/tag/v0.1.0) 2020-01-03

- Implemented parsing of java keystore and truststore

- Implemented password verification

- Implemented decryption DER encoded private key
