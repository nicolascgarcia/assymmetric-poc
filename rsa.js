const {
  generateKeyPairSync,
  publicEncrypt,
  privateDecrypt,
  constants,
  sign,
  verify,
} = require("crypto");

console.log("==== Generating RSA Key Pairs ====\n");

const { publicKey: alicePublicKey, privateKey: alicePrivateKey } =
  generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

const { publicKey: bobPublicKey, privateKey: bobPrivateKey } =
  generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

console.log("Alice's key pair:", { alicePublicKey, alicePrivateKey });
console.log("Bob's key pair:", {
  bobPublicKey,
  bobPrivateKey,
});

console.log("\n==== Bob Sends Alice a Message ====\n");

const msg2 = "Hello Alice!";
const encryptedMsg2 = publicEncrypt(
  {
    key: alicePublicKey,
    oaepHash: "sha256",
  },
  Buffer.from(msg2)
);

console.log("Message:", msg2);
console.log("Encrypted message:", encryptedMsg2);

console.log("\n==== Alice reads Bob's message ====\n");

const decriptedMsg2 = privateDecrypt(
  {
    key: alicePrivateKey,
    oaepHash: "sha256",
  },
  encryptedMsg2
);

console.log("Alice reading decrypted message:", decriptedMsg2.toString());

console.log("\n==== Alice reply Bob with a signed message ====\n");

const msg3 = "I'm good Bob";
const encryptedMsg3 = publicEncrypt(
  {
    key: bobPublicKey,
    oaepHash: "sha256",
  },
  Buffer.from(msg3)
);

const signedMsg3 = sign("sha256", encryptedMsg3, {
  key: alicePrivateKey,
});

console.log("Message:", msg3);
console.log("Encrypted message:", encryptedMsg3);
console.log("Encrypted message sign:", signedMsg3);

console.log(
  "\n==== Bob verify if Alice's signture and reads the message ====\n"
);

const isSignedMsg3Verified = verify(
  "sha256",
  encryptedMsg3,
  {
    key: alicePublicKey,
  },
  signedMsg3
);

const decriptedMsg3 = privateDecrypt(
  {
    key: bobPrivateKey,
    oaepHash: "sha256",
  },
  encryptedMsg3
);

console.log("Bob verify if signture is valid:", isSignedMsg3Verified);
console.log("Bob reading decrypted message:", decriptedMsg3.toString());
