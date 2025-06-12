const { encrypt, decrypt, EncryptStream, DecryptStream, debugSetKeypair, debugSetKey } = require("../dist/encryption");
const { INPUT_STRING } = require("./data/common");

const { KEYPAIR, KEYPAIR_ALICE, KEYPAIR_BOB, KEYPAIR_MALLORY } = require("./data/encryption-keys");
const { ENCRYPTED_HEX, ENCRYPTED } = require("./data/encryption-tests");

debugSetKey(Buffer.alloc(32).fill("\x00"));
debugSetKeypair(KEYPAIR);

test("encrypt", async () => {
  const encrypted = await encrypt(INPUT_STRING, KEYPAIR_ALICE, [KEYPAIR_BOB.publicKey]);

  expect(encrypted.toString("hex")).toStrictEqual(ENCRYPTED_HEX);
});

test("encrypt stream", async () => {
  const stream = new EncryptStream(KEYPAIR_ALICE, [KEYPAIR_BOB.publicKey]);

  const result = [];

  await new Promise((rs, rj) => {
    stream.on("error", rj);
    stream.on("end", rs);
    stream.on("data", (chunk) => result.push(chunk));

    stream.end(INPUT_STRING);
  });

  expect(Buffer.concat(result).toString("hex")).toStrictEqual(ENCRYPTED_HEX);
});

test("decrypt", async () => {
  const data = await decrypt(ENCRYPTED, KEYPAIR_BOB, KEYPAIR_ALICE.publicKey);

  expect(data.toString()).toBe(INPUT_STRING);
  expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test("decrypt doesn't require sender public key", async () => {
  const data = await decrypt(ENCRYPTED, KEYPAIR_BOB);

  expect(data.toString()).toBe(INPUT_STRING);
  expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test("decrypt stream", async () => {
  const stream = new DecryptStream(KEYPAIR_BOB, KEYPAIR_ALICE.publicKey);
  const result = [];

  await new Promise((rs, rj) => {
    stream.on("error", rj);
    stream.on("end", rs);
    stream.on("data", (chunk) => result.push(chunk));

    stream.end(ENCRYPTED);
  });

  expect(result.toString()).toBe(INPUT_STRING);
  expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test("decrypt stream doesn't require sender public key", async () => {
  const stream = new DecryptStream(KEYPAIR_BOB);
  const result = [];

  await new Promise((rs, rj) => {
    stream.on("error", rj);
    stream.on("end", rs);
    stream.on("data", (chunk) => result.push(chunk));

    stream.end(ENCRYPTED);
  });

  expect(result.toString()).toBe(INPUT_STRING);
  expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test("decrypt with wrong keypair fails", async () => {
  await expect(async () => {
    await decrypt(ENCRYPTED, KEYPAIR_MALLORY);
  }).rejects.toThrow();
});
