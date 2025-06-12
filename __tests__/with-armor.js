const { armor, MessageType } = require("../dist/armor");
const {
  encryptAndArmor,
  dearmorAndDecrypt,
  EncryptAndArmorStream,
  DearmorAndDecryptStream,
  signAndArmor,
  verifyArmored,
  SignAndArmorStream,
  DearmorAndVerifyStream,
  signcryptAndArmor,
  dearmorAndDesigncrypt,
  SigncryptAndArmorStream,
  DearmorAndDesigncryptStream,
} = require("../dist/with-armor");
const enc = require("../dist/encryption");
const signc = require("../dist/signcryption");

const { INPUT_STRING } = require("./data/common.js");
const { ENCRYPTION_KEYPAIR, KEYPAIR_ALICE, KEYPAIR_BOB, KEYPAIR_MALLORY } = require("./data/encryption-keys");
const { ENCRYPTED } = require("./data/encryption-tests.js");
const { SIGNING_KEYPAIR, KEYPAIR_ALICE_S } = require("./data/signing-keys");
const { SIGNED } = require("./data/signing-tests");
const { SIGNCRYPTED } = require("./data/signcryption-tests");

enc.debugSetKey(Buffer.alloc(32).fill("\x00"));
enc.debugSetKeypair(ENCRYPTION_KEYPAIR);
signc.debugSetKey(Buffer.alloc(32).fill("\x00"));
signc.debugSetKeypair(ENCRYPTION_KEYPAIR);

describe("encryption", () => {
  test("encryption and armoring", async () => {
    const expected = armor(ENCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });

    const encrypted = await encryptAndArmor(INPUT_STRING, KEYPAIR_ALICE, [KEYPAIR_BOB.publicKey]);

    expect(encrypted).toBe(expected);
  });

  test("streaming encryption and armoring", async () => {
    const expected = armor(ENCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });
    const result = [];

    const stream = new EncryptAndArmorStream(KEYPAIR_ALICE, [KEYPAIR_BOB.publicKey]);

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk.toString()));

      stream.end(INPUT_STRING);
    });

    expect(result.join("")).toBe(expected);
  });

  test("dearmoring and decryption", async () => {
    const encrypted = armor(ENCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });

    const decrypted = await dearmorAndDecrypt(encrypted, KEYPAIR_BOB);

    expect(decrypted.toString()).toBe(INPUT_STRING);
    expect(decrypted.header_info.message_type).toBe(MessageType.ENCRYPTED_MESSAGE);
    expect(decrypted.header_info.app_name).toBe(null);
    expect(decrypted.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
  });

  test("streaming dearmoring and decryption", async () => {
    const armored = armor(ENCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });
    const result = [];

    const stream = new DearmorAndDecryptStream(KEYPAIR_BOB);

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk));

      stream.end(armored);
    });

    expect(result.join("")).toBe(INPUT_STRING);
    expect(stream.info.message_type).toBe(MessageType.ENCRYPTED_MESSAGE);
    expect(stream.info.app_name).toBe(null);
    expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
  });

  test("dearmor and decrypt with wrong keypair fails", async () => {
    await expect(async () => {
      const encrypted = armor(ENCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });

      await dearmorAndDecrypt(encrypted, KEYPAIR_MALLORY);
    }).rejects.toThrow();
  });
});

describe("signing", () => {
  test("signing and armoring", async () => {
    const expected = armor(SIGNED, { message_type: MessageType.SIGNED_MESSAGE });

    const signed = await signAndArmor(INPUT_STRING, SIGNING_KEYPAIR);

    expect(signed).toBe(expected);
  });

  test("streaming signing and armoring", async () => {
    const expected = armor(SIGNED, { message_type: MessageType.SIGNED_MESSAGE });
    const result = [];

    const stream = new SignAndArmorStream(SIGNING_KEYPAIR);

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk.toString()));

      stream.end(INPUT_STRING);
    });

    expect(result.join("")).toBe(expected);
  });

  test("dearmoring and verifying", async () => {
    const signed = armor(SIGNED, { message_type: MessageType.SIGNED_MESSAGE });

    const verified = await verifyArmored(signed, SIGNING_KEYPAIR.publicKey);

    expect(verified.toString()).toStrictEqual(INPUT_STRING);
    expect(verified.header_info.message_type).toBe(MessageType.SIGNED_MESSAGE);
    expect(verified.header_info.app_name).toBe(null);
  });

  test("streaming dearmoring and verifying", async () => {
    const armored = armor(SIGNED, { message_type: MessageType.SIGNED_MESSAGE });
    const result = [];

    const stream = new DearmorAndVerifyStream(SIGNING_KEYPAIR.publicKey);

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk.toString()));

      stream.end(armored);
    });

    expect(result.join("")).toBe(INPUT_STRING);
    expect(stream.info.message_type).toBe(MessageType.SIGNED_MESSAGE);
    expect(stream.info.app_name).toBe(null);
  });
});

describe("signcryption", () => {
  test("encryption and armoring", async () => {
    const expected = armor(SIGNCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });

    const encrypted = await signcryptAndArmor(INPUT_STRING, KEYPAIR_ALICE_S, [KEYPAIR_BOB.publicKey]);

    expect(encrypted).toBe(expected);
  });

  test("streaming encryption and armoring", async () => {
    const expected = armor(SIGNCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });
    const result = [];

    const stream = new SigncryptAndArmorStream(KEYPAIR_ALICE_S, [KEYPAIR_BOB.publicKey]);

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk.toString()));

      stream.end(INPUT_STRING);
    });

    expect(result.join("")).toBe(expected);
  });

  test("dearmoring and decryption", async () => {
    const encrypted = armor(SIGNCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });

    const decrypted = await dearmorAndDesigncrypt(encrypted, KEYPAIR_BOB);

    expect(decrypted.toString()).toBe(INPUT_STRING);
    expect(decrypted.header_info.message_type).toBe(MessageType.ENCRYPTED_MESSAGE);
    expect(decrypted.header_info.app_name).toBe(null);
    expect(decrypted.sender_public_key).toStrictEqual(KEYPAIR_ALICE_S.publicKey);
  });

  test("streaming dearmoring and decryption", async () => {
    const armored = armor(SIGNCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });
    const result = [];

    const stream = new DearmorAndDesigncryptStream(KEYPAIR_BOB);

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk));

      stream.end(armored);
    });

    expect(result.join("")).toBe(INPUT_STRING);
    expect(stream.info.message_type).toBe(MessageType.ENCRYPTED_MESSAGE);
    expect(stream.info.app_name).toBe(null);
    expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE_S.publicKey);
  });

  test("dearmor and decrypt with wrong keypair fails", async () => {
    await expect(async () => {
      const encrypted = armor(SIGNCRYPTED, { message_type: MessageType.ENCRYPTED_MESSAGE });

      await dearmorAndDecrypt(encrypted, KEYPAIR_MALLORY);
    }).rejects.toThrow();
  });
});
