const { sign, verify, SignStream, VerifyStream, signDetached, verifyDetached } = require("../dist/signing");

const { KEYPAIR } = require("./data/signing-keys.js");
const { SIGNED, DETACHED_SIGNATURE, SIGNED_HEX } = require("./data/signing-tests.js");
const { INPUT_STRING } = require("./data/common");

describe("attached signing", () => {
  test("sign", () => {
    const signed = sign(INPUT_STRING, KEYPAIR);

    expect(signed.toString("hex")).toStrictEqual(SIGNED_HEX);
  });

  test("sign stream", async () => {
    const stream = new SignStream(KEYPAIR);
    const result = [];

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk));

      stream.end(INPUT_STRING);
    });

    expect(Buffer.concat(result).toString("hex")).toStrictEqual(SIGNED_HEX);
  });

  test("verify", async () => {
    const data = await verify(SIGNED, KEYPAIR.publicKey);

    expect(data.toString()).toBe(INPUT_STRING);
  });

  test("verify doesn't require sender public key", async () => {
    const data = await verify(SIGNED);

    expect(data.toString()).toBe(INPUT_STRING);
    expect(data.public_key).toStrictEqual(KEYPAIR.publicKey);
  });

  test("verify stream", async () => {
    const stream = new VerifyStream(KEYPAIR.publicKey);
    const result = [];

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk));

      stream.end(SIGNED);
    });

    expect(Buffer.concat(result).toString()).toBe(INPUT_STRING);
  });

  test("verify stream doesn't require sender public key", async () => {
    const stream = new VerifyStream();
    const result = [];

    await new Promise((rs, rj) => {
      stream.on("error", rj);
      stream.on("end", rs);
      stream.on("data", (chunk) => result.push(chunk));

      stream.end(SIGNED);
    });

    expect(Buffer.concat(result).toString()).toBe(INPUT_STRING);
    expect(stream.public_key).toStrictEqual(KEYPAIR.publicKey);
  });

  test("verify with wrong public key fails", () => {
    const public_key = new Uint8Array(KEYPAIR.publicKey);
    public_key[0] = 0;

    expect(async () => {
      await verify(SIGNED, public_key);
    }).rejects.toThrow();
  });
});

describe("detached signing", () => {
  test("sign detached", () => {
    const signed = signDetached(INPUT_STRING, KEYPAIR);

    expect(signed).toStrictEqual(DETACHED_SIGNATURE);
  });

  test("verify detached", async () => {
    await verifyDetached(DETACHED_SIGNATURE, INPUT_STRING, KEYPAIR.publicKey);
  });

  test("verify detached doesn't require sender public key", async () => {
    const result = await verifyDetached(DETACHED_SIGNATURE, INPUT_STRING);

    expect(result.public_key).toStrictEqual(KEYPAIR.publicKey);
  });

  test("verify detached with wrong public key fails", () => {
    const public_key = KEYPAIR.publicKey;
    public_key[0] = 0;

    expect(async () => {
      await verifyDetached(DETACHED_SIGNATURE, INPUT_STRING, public_key);
    }).rejects.toThrow();
  });
});
