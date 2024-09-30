export type JksResult = {
  [alias: string]: {
    ca?: string;
    cert?: string;
    key?: string;
  }
};

export type Certificate = {
  certType: 'X.509' | string;
  value: Buffer;
};

export type TrustedKeyEntry = {
  certType: 'X.509';
  alias: string;
  date: Date;
  cert: Certificate;
}

export type KeyEntry = {
  certType: 'X.509';
  alias: string;
  date: Date;
  chain: Buffer[];
  protectedPrivateKey: Buffer;
}

/**
 * Extracts certificates from java keystore or truststore
 * and decrypts private key 
 * 
 * @param {Buffer} keystore content of java keystore or truststore file
 * @param {String} keystorePassword password for verification and decryption
 * @param {String} [pemPassword] password that is used for decryption, in case it is different from keystorePassword. If not specified, keystorePassword is used
 * @return {
*     <alias name>: {
*         cert: string // compound certificates chain
*         key: string // decrypted private key 
*     } | {
*         ca: string // trusted certificate
*     }
* }
*/
export declare function toPem(keystore: Buffer, keystorePassword: string, privateKeyPassword?: string): JksResult;

/**
 * The raw function to extract certificates
 * 
 *  @param {Buffer} keystore
 *  @param {String} password
 *  @return {(KeyEntry | TrustedKeyEntry)[]}
 */
export declare function parseJks(keystore: Buffer, password: string): (KeyEntry | TrustedKeyEntry)[];

/**
 * Decrypts private key from DER to PEM
 *
 * @param {Buffer} protectedPrivateKey DER encoded private key
 * @param {String} password password for PKCS8 decryption
 * @return {String} - decoded private key 
 */
export declare function decrypt(protectedPrivateKey: Buffer, password: string): string;

/**
 * The function that parses keystore/truststore in PKCS12 format
 * 
 * @param {Buffer} keystore
 * @param {String} password
 */
export declare function parsePkcs12(keystore: Buffer, password: string): JksResult;

