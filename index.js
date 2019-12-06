/*
key with passphrase: privkey.pem
pass: papa
key without passphrase: key.pem
openssl smime -encrypt -aes256 -in msg.eml -outform SMIME -out msg.p7m cert.pem
openssl smime -decrypt -in msg.p7m -inform SMIME -inkey privkey.pem -out msg.dec

*/

var fs = require('fs');
var pkijs = require('pkijs');
var utils = require('pvutils');
var asn1js = require('asn1js');
var atob = require('atob');
var mimeParser = require('emailjs-mime-parser');
var crypto = require("@peculiar/webcrypto").Crypto;
var webcrypto = new crypto();

let msgFile = fs.readFileSync('msg.p7m');
let certFile = fs.readFileSync('cert.pem');
let keyFile = fs.readFileSync('key.pem');

pkijs.setEngine("newEngine", webcrypto, new pkijs.CryptoEngine({
  name: "",
  crypto: webcrypto,
  subtle: webcrypto.subtle
}));

const clearEncodedCertificate = certFile.toString().replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, "");
const clearEncodedKey = keyFile.toString().replace(/(-----(BEGIN|END)( NEW)? RSA PRIVATE KEY-----|\n)/g, "");
const certificateBuffer = utils.stringToArrayBuffer(atob(clearEncodedCertificate));
const keyBuffer = utils.stringToArrayBuffer(atob(clearEncodedKey));

let asn1 = asn1js.fromBER(certificateBuffer);
const certSimpl = new pkijs.Certificate({ schema: asn1.result });
var parser  = mimeParser.default(msgFile);
asn1 = asn1js.fromBER(parser.content.buffer);
if(asn1.offset === (-1))
{
  console.log("Unable to parse your data. Please check you have \"Content-Type: charset=binary\" in your S/MIME message");
}
    
const cmsContentSimpl = new pkijs.ContentInfo({ schema: asn1.result });
const cmsEnvelopedSimp = new pkijs.EnvelopedData({ schema: cmsContentSimpl.content });

cmsEnvelopedSimp.decrypt(0,
{
    recipientCertificate: certSimpl,
    recipientPrivateKey: keyBuffer
}).then(
result =>
{
  console.log(result);
},
error => console.log(`ERROR DURING DECRYPTION PROCESS: ${error}`)
);    

