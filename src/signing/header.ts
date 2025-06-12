import { encode } from "@msgpack/msgpack";
import { randomBytes, sign } from "tweetnacl";
import Header, { MessageType } from "../message-header";
import { isBufferOrUint8Array } from "../util";
import { sha512 } from "@noble/hashes/sha2";

// [
//     format name,
//     version,
//     mode,
//     sender public key,
//     nonce,
// ]

export default class SignedMessageHeader extends Header {
  static readonly DETACHED_SIGNATURE_PREFIX = Buffer.from("saltpack detached signature\0");

  static debug_fix_nonce = process.env.TEST ? Buffer.alloc(32).fill(0) : null;

  /** The sender's Ed25519 public key */
  readonly public_key: Uint8Array;
  /** Random data for this message */
  readonly nonce: Uint8Array;
  /** `true` if this is an attached signature header, `false` if this is a detached signature header */
  readonly attached: boolean;

  constructor(public_key: Uint8Array, nonce: Uint8Array, attached = true) {
    super();

    if (!isBufferOrUint8Array(public_key) || public_key.length !== 32) {
      throw new TypeError("public_key must be a 32 byte Uint8Array");
    }
    if (!isBufferOrUint8Array(nonce) || nonce.length !== 32) {
      throw new TypeError("nonce must be a 32 byte Uint8Array");
    }
    if (typeof attached !== "boolean") {
      throw new TypeError("attached must be a boolean");
    }

    this.public_key = public_key;
    this.nonce = nonce;
    this.attached = attached;
  }

  get encoded_data(): [Buffer, Buffer] {
    return Object.defineProperty(this, "encoded_data", {
      value: this.encode(),
    }).encoded_data;
  }

  /** The MessagePack encoded outer header data */
  get encoded() {
    return this.encoded_data[1];
  }
  /** The SHA512 hash of the MessagePack encoded inner header data */
  get hash() {
    return this.encoded_data[0];
  }

  static create(public_key: Uint8Array, attached = true): SignedMessageHeader {
    const nonce = this.debug_fix_nonce ?? randomBytes(32);

    return new this(public_key, nonce, attached);
  }

  encode() {
    return SignedMessageHeader.encodeHeader(this.public_key, this.nonce, this.attached);
  }

  static encodeHeader(public_key: Uint8Array, nonce: Uint8Array, attached: boolean) {
    const data = ["saltpack", [2, 0], attached ? MessageType.ATTACHED_SIGNING : MessageType.DETACHED_SIGNING, public_key, nonce];

    const encoded = encode(data);

    const header_hash = sha512.create().update(encoded).digest();

    return [header_hash, Buffer.from(encode(encoded))];
  }

  static decode(encoded: Uint8Array, unwrapped = false) {
    const [, data] = super.decode1(encoded, unwrapped);

    if (data[2] !== MessageType.ATTACHED_SIGNING && data[2] !== MessageType.DETACHED_SIGNING) throw new Error("Invalid data");

    const [, , , public_key, nonce] = data;

    return new this(public_key as Uint8Array, nonce as Uint8Array, data[2] === MessageType.ATTACHED_SIGNING);
  }

  signDetached(data: Uint8Array, private_key: Uint8Array): Buffer {
    if (this.attached) {
      throw new Error("Header attached is true");
    }

    const hash = sha512.create().update(this.hash).update(data).digest();

    const sign_data = Buffer.concat([SignedMessageHeader.DETACHED_SIGNATURE_PREFIX, hash]);

    return Buffer.from(sign.detached(Uint8Array.from(sign_data), Uint8Array.from(private_key)));
  }

  verifyDetached(signature: Uint8Array, data: Uint8Array, public_key: Uint8Array) {
    if (this.attached) {
      throw new Error("Header attached is true");
    }

    const hash = sha512.create().update(this.hash).update(data).digest();

    const sign_data = Buffer.concat([SignedMessageHeader.DETACHED_SIGNATURE_PREFIX, hash]);

    if (!sign.detached.verify(Uint8Array.from(sign_data), Uint8Array.from(signature), Uint8Array.from(public_key))) {
      throw new Error("Invalid signature");
    }
  }
}
