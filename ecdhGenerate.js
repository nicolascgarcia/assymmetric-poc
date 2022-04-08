const { createECDH } = require("crypto");

const alice = createECDH("secp256k1");
alice.generateKeys();

const publicKey = alice.getPublicKey().toString("base64");
const privateKey = alice.getPrivateKey().toString("base64");

console.log({ publicKey, privateKey });
