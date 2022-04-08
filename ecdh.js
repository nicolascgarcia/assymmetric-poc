const {
  createECDH,
  createCipheriv,
  randomBytes,
  createDecipheriv,
} = require("crypto");

const encryptCipheriv = (key, data) => {
  const initVector = randomBytes(16);

  const cipher = createCipheriv("aes-256-cbc", key, initVector);

  return {
    iv: initVector.toString("base64"),
    data: Buffer.concat([cipher.update(data), cipher.final()]).toString(
      "base64"
    ),
  };
};

const dencryptCipheriv = (encryptData, key, iv) => {
  const ivBuffer = Buffer.from(iv, "base64");
  const dataBuffer = Buffer.from(encryptData, "base64");

  const decipher = createDecipheriv("aes-256-cbc", key, ivBuffer);

  return Buffer.concat([decipher.update(dataBuffer), decipher.final()]);
};

console.log(
  "==== Generating Elliptic Curve Diffie-Hellman(ECDH) Key Pairs ====\n"
);

const alice = createECDH("secp256k1");
alice.generateKeys();

const alicePublicKey = alice.getPublicKey().toString("base64");
const alicePrivateKey = alice.getPrivateKey().toString("base64");

const bob = createECDH("secp256k1");
bob.generateKeys();

const bobPublicKey = bob.getPublicKey().toString("base64");
const bobPrivateKey = bob.getPrivateKey().toString("base64");

console.log("Alice's key pair:", { alicePublicKey, alicePrivateKey });
console.log("Bob's key pair:", {
  bobPublicKey,
  bobPrivateKey,
});

console.log("\n==== Generating Shared Secret Keys ====\n");

const aliceSharedKey = alice.computeSecret(bobPublicKey, "base64");
const bobSharedKey = bob.computeSecret(alicePublicKey, "base64");

console.log("Alice's shared key:", aliceSharedKey.toString("base64"));
console.log("Bob's shared key", bobSharedKey.toString("base64"));

console.log("\n==== Alice Sends Bob a Message ====\n");

const msg1 = "Hello, Bob. How are you?";
const ciphertextMsg1 = encryptCipheriv(aliceSharedKey, msg1);

console.log("Message:", msg1);
console.log("Encrypted message:", ciphertextMsg1);

console.log("\n==== Bob reads Alice's message ====\n");

const bobDecryptedMsg1 = dencryptCipheriv(
  ciphertextMsg1.data,
  bobSharedKey,
  ciphertextMsg1.iv
);

console.log("Bob reading decrypted message:", bobDecryptedMsg1.toString());
