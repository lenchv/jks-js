const fs = require('fs');
const jks = require('./');
const trustedStore = jks.convertJksToPem(fs.readFileSync(__dirname + '/assets/truststore.jks'), '1a2b3c');
const keyStore = jks.convertJksToPem(fs.readFileSync(__dirname + '/assets/keystore.jks'), '1a2b3c');

console.log(trustedStore, keyStore);

