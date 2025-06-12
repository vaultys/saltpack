import SigncryptedMessageHeader from "./header";
import SigncryptedMessageRecipient, { SymmetricKeyRecipient } from "./recipient";
import SigncryptedMessagePayload from "./payload";
import { chunkBuffer } from "../util";
import { Readable, Transform, TransformCallback } from "stream";
import { BoxKeyPair, SignKeyPair, box, randomBytes } from "tweetnacl";
import { decodeMultiStream, Decoder } from "@msgpack/msgpack";

const CHUNK_LENGTH = 1024 * 1024;

let debug = false;
let debug_fix_key: Buffer | null = null;
let debug_fix_keypair: BoxKeyPair | null = null;

export function debugSetKey(key: Buffer) {
  debug_fix_key = key;
}
export function debugSetKeypair(keypair: BoxKeyPair) {
  debug_fix_keypair = keypair;
}

export async function signcrypt(data: Uint8Array | string, keypair: SignKeyPair | null, recipients_keys: (Uint8Array | SymmetricKeyRecipient)[]): Promise<Buffer> {
  const chunks = chunkBuffer(data, CHUNK_LENGTH);

  // 1. Generate a random 32-byte payload key.
  const payload_key = debug_fix_key ?? randomBytes(32);

  // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
  const ephemeral_keypair = debug_fix_keypair ?? box.keyPair();

  const recipients = recipients_keys.map((key, index) =>
    key instanceof SymmetricKeyRecipient
      ? SigncryptedMessageRecipient.createSymmetric(key.key, key.recipient_identifier, ephemeral_keypair.publicKey, payload_key, index)
      : SigncryptedMessageRecipient.create(key, ephemeral_keypair.secretKey, payload_key, index),
  );

  const header = SigncryptedMessageHeader.create(ephemeral_keypair.publicKey, payload_key, keypair?.publicKey ?? null, recipients);

  const payloads = [];

  for (const i in chunks) {
    const chunk = chunks[i];
    const final = chunks.length === parseInt(i) + 1;
    const payload = SigncryptedMessagePayload.create(header, payload_key, keypair?.secretKey ?? null, chunk, BigInt(i), final);

    payloads.push(payload);
  }

  return Buffer.concat([header.encoded, Buffer.concat(payloads.map((payload) => payload.encoded))]);
}

export class SigncryptStream extends Transform {
  readonly payload_key: Buffer;
  readonly ephemeral_keypair: BoxKeyPair;
  readonly keypair: SignKeyPair | null;
  readonly header: SigncryptedMessageHeader;
  private in_buffer = Buffer.alloc(0);
  private payload_index = BigInt(0);
  private i = 0;

  constructor(keypair: SignKeyPair | null, recipients_keys: (Uint8Array | SymmetricKeyRecipient)[]) {
    super();

    // 1. Generate a random 32-byte payload key.
    this.payload_key = debug_fix_key ?? Buffer.from(randomBytes(32));

    // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
    this.ephemeral_keypair = debug_fix_keypair ?? box.keyPair();

    this.keypair = keypair;

    const recipients = recipients_keys.map((key, index) =>
      key instanceof SymmetricKeyRecipient
        ? SigncryptedMessageRecipient.createSymmetric(key.key, key.recipient_identifier, this.ephemeral_keypair.publicKey, this.payload_key, index)
        : SigncryptedMessageRecipient.create(key, this.ephemeral_keypair.secretKey, this.payload_key, index),
    );

    this.header = SigncryptedMessageHeader.create(this.ephemeral_keypair.publicKey, this.payload_key, this.keypair?.publicKey ?? null, recipients);

    this.push(this.header.encoded);
  }

  _transform(data: Buffer, encoding: string, callback: TransformCallback) {
    if (debug) console.log("Processing chunk #%d: %s", this.i++, data);

    this.in_buffer = Buffer.concat([this.in_buffer, data]);

    while (this.in_buffer.length > CHUNK_LENGTH) {
      const chunk = this.in_buffer.slice(0, CHUNK_LENGTH);
      this.in_buffer = this.in_buffer.slice(CHUNK_LENGTH);

      // This is never the final payload as there must be additional data in `in_buffer`

      const payload = SigncryptedMessagePayload.create(this.header, this.payload_key, this.keypair?.secretKey ?? null, chunk, this.payload_index, /* final */ false);

      this.push(payload.encoded);
      this.payload_index++;
    }

    callback();
  }

  _flush(callback: TransformCallback) {
    while (this.in_buffer.length >= CHUNK_LENGTH) {
      const chunk = this.in_buffer.slice(0, CHUNK_LENGTH);
      this.in_buffer = this.in_buffer.slice(CHUNK_LENGTH);

      const final = !this.in_buffer.length;
      const payload = SigncryptedMessagePayload.create(this.header, this.payload_key, this.keypair?.secretKey ?? null, chunk, this.payload_index, final);

      this.push(payload.encoded);
      this.payload_index++;
    }

    if (this.in_buffer.length) {
      const chunk = this.in_buffer;
      this.in_buffer = Buffer.alloc(0);

      const final = !this.in_buffer.length;
      const payload = SigncryptedMessagePayload.create(this.header, this.payload_key, this.keypair?.secretKey ?? null, chunk, this.payload_index, final);

      this.push(payload.encoded);
      this.payload_index++;
    }

    callback();
  }
}

export interface DesigncryptResult extends Buffer {
  sender_public_key: Uint8Array | null;
}

export async function designcrypt(signcrypted: Uint8Array, recipient_keys: BoxKeyPair | SymmetricKeyRecipient, sender?: Uint8Array | null): Promise<DesigncryptResult> {
  const stream = new Readable();
  stream.push(signcrypted);
  stream.push(null);

  const items = [];

  for await (const item of decodeMultiStream(stream)) {
    items.push(item);
  }

  const header_data = items.shift() as any;
  const header = SigncryptedMessageHeader.decode(header_data, true);

  const payload_key_and_recipient =
    recipient_keys instanceof SymmetricKeyRecipient
      ? header.decryptPayloadKeyWithSymmetricKey(recipient_keys.key, recipient_keys.recipient_identifier)
      : header.decryptPayloadKeyWithCurve25519Keypair(recipient_keys.secretKey);
  if (!payload_key_and_recipient) throw new Error("keypair is not an intended recipient");

  const [payload_key] = payload_key_and_recipient;
  const sender_public_key = header.decryptSender(payload_key);

  if (sender && (!sender_public_key || !Buffer.from(sender_public_key).equals(Buffer.from(sender)))) {
    throw new Error("Sender public key doesn't match");
  }

  let output = Buffer.alloc(0);

  for (const i in items) {
    const message = items[i];
    const payload = SigncryptedMessagePayload.decode(message, true);

    const final = items.length === parseInt(i) + 1;
    if (payload.final && !final) {
      throw new Error("Found payload with invalid final flag, message extended?");
    }
    if (!payload.final && final) {
      throw new Error("Found payload with invalid final flag, message truncated?");
    }

    output = Buffer.concat([output, payload.decrypt(header, sender_public_key, payload_key, BigInt(i))]);
  }

  if (!items.length) {
    throw new Error("No signcrypted payloads, message truncated?");
  }

  return Object.assign(output, {
    sender_public_key,
  });
}

export class DesigncryptStream extends Transform {
  readonly sender: Uint8Array | null;
  private decoder = new Decoder();
  private header_data: [SigncryptedMessageHeader, Uint8Array, SigncryptedMessageRecipient, Uint8Array | null] | null = null;
  private last_payload: SigncryptedMessagePayload | null = null;
  private payload_index = BigInt(-1);
  private i = 0;

  constructor(
    readonly recipient_keys: BoxKeyPair | SymmetricKeyRecipient,
    sender?: Uint8Array | null,
  ) {
    super();

    this.sender = sender ?? null;
  }

  get header() {
    if (!this.header_data) throw new Error("Header hasn't been decoded yet");
    return this.header_data[0];
  }
  get payload_key() {
    if (!this.header_data) throw new Error("Header hasn't been decoded yet");
    return this.header_data[1];
  }
  get recipient() {
    if (!this.header_data) throw new Error("Header hasn't been decoded yet");
    return this.header_data[2];
  }
  get sender_public_key() {
    if (!this.header_data) throw new Error("Header hasn't been decoded yet");
    return this.header_data[3];
  }

  _transform(data: Buffer, encoding: string, callback: TransformCallback) {
    // @ts-ignore
    this.decoder.appendBuffer(data);

    try {
      let message;
      // @ts-ignore
      while ((message = this.decoder.doDecodeSync())) {
        // @ts-ignore
        const remaining = Buffer.from(this.decoder.bytes).slice(this.decoder.pos);
        // @ts-ignore
        this.decoder.setBuffer(remaining);

        this._handleMessage(message);
      }
    } catch (err) {}

    callback();
  }

  private _handleMessage(data: unknown) {
    if (debug) console.log("Processing chunk #%d: %s", this.i++, data);

    if (!this.header_data) {
      const header = SigncryptedMessageHeader.decode(data as any, true);

      const payload_key_and_recipient =
        this.recipient_keys instanceof SymmetricKeyRecipient
          ? header.decryptPayloadKeyWithSymmetricKey(this.recipient_keys.key, this.recipient_keys.recipient_identifier)
          : header.decryptPayloadKeyWithCurve25519Keypair(this.recipient_keys.secretKey);
      if (!payload_key_and_recipient) throw new Error("keypair is not an intended recipient");

      const [payload_key, recipient] = payload_key_and_recipient;
      const sender_public_key = header.decryptSender(payload_key);

      if (this.sender && (!sender_public_key || !Buffer.from(sender_public_key).equals(Buffer.from(this.sender)))) {
        throw new Error("Sender public key doesn't match");
      }

      this.header_data = [header, payload_key, recipient, sender_public_key];
    } else {
      this.payload_index++;

      if (this.last_payload) {
        if (this.last_payload.final) {
          throw new Error("Found payload with invalid final flag, message extended?");
        }

        this.push(this.last_payload.decrypt(this.header, this.sender_public_key, this.payload_key, this.payload_index - BigInt(1)));
      }

      const payload = SigncryptedMessagePayload.decode(data, true);
      this.last_payload = payload;
    }
  }

  _flush(callback: TransformCallback) {
    try {
      if (this.last_payload) {
        if (!this.last_payload.final) {
          throw new Error("Found payload with invalid final flag, message truncated?");
        }

        this.push(this.last_payload.decrypt(this.header, this.sender_public_key, this.payload_key, this.payload_index));
      }

      if (!this.last_payload) {
        throw new Error("No signcrypted payloads, message truncated?");
      }
    } catch (err) {
      return callback(err as Error);
    }

    callback();
  }
}
