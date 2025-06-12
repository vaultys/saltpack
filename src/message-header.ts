import { decode } from "@msgpack/msgpack";
import { sha512 } from "@noble/hashes/sha2";

export enum MessageType {
  ENCRYPTION = 0,
  ATTACHED_SIGNING = 1,
  DETACHED_SIGNING = 2,
  SIGNCRYPTION = 3,
}

export default class Header {
  static decode1(encoded: Uint8Array, unwrapped = false) {
    // 1-3
    const data = unwrapped ? encoded : (decode(encoded) as Uint8Array);
    const header_hash = sha512.create().update(data).digest();
    const inner = decode(data);

    // 4
    if (!(inner instanceof Array) || inner.length < 3) {
      throw new Error("Invalid data");
    }

    const [format_name, version, mode] = inner as unknown[];

    if (format_name !== "saltpack") throw new Error("Invalid data");
    if (!(version instanceof Array) || version.length !== 2) {
      throw new Error("Invalid data");
    }

    if (version[0] !== 2) throw new Error("Unsupported version");
    if (version[1] !== 0) throw new Error("Unsupported version");

    if (typeof mode !== "number") throw new Error("Invalid data");

    return [header_hash, inner];
  }
}
