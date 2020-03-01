const fs = require('fs');
const jks = require('../');
const trustedStore = jks.toPem(fs.readFileSync(__dirname + '/assets/truststore.jks'), 'password');
const keyStore = jks.toPem(fs.readFileSync(__dirname + '/assets/keystore.jks'), 'password');

console.log(trustedStore, keyStore);

