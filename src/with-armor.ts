import { encrypt, decrypt, EncryptStream, DecryptStream, DecryptResult } from "./encryption";
import { sign, verify, SignStream, VerifyStream, VerifyResult, signDetached, verifyDetached, VerifyDetachedResult } from "./signing";
import { signcrypt, designcrypt, SigncryptStream, DesigncryptStream, DesigncryptResult } from "./signcryption";
import { SymmetricKeyRecipient } from "./signcryption/recipient";
import { armor, dearmor, ArmorStream, DearmorStream, Options as ArmorOptions, MessageType, ArmorHeaderInfo, DearmorResult } from "./armor";
import Pumpify from "pumpify";
import { BoxKeyPair, SignKeyPair } from "tweetnacl";

export async function encryptAndArmor(data: Uint8Array | string, keypair: BoxKeyPair | null, recipients_keys: Uint8Array[]) {
  const encrypted = await encrypt(data, keypair, recipients_keys);
  return armor(encrypted, { message_type: MessageType.ENCRYPTED_MESSAGE });
}
export async function dearmorAndDecrypt(encrypted: string, keypair: BoxKeyPair, sender?: Uint8Array | null): Promise<DearmorAndDecryptResult> {
  const dearmored = dearmor(encrypted);
  return Object.assign(await decrypt(dearmored, keypair, sender), {
    remaining: dearmored.remaining,
    header_info: dearmored.header_info,
  });
}

export type DearmorAndDecryptResult = DearmorResult & DecryptResult;

export class EncryptAndArmorStream extends Pumpify {
  constructor(keypair: BoxKeyPair | null, recipients_keys: Uint8Array[], armor_options?: Partial<ArmorOptions>) {
    const encrypt = new EncryptStream(keypair, recipients_keys);
    const armor = new ArmorStream(
      Object.assign(
        {
          message_type: MessageType.ENCRYPTED_MESSAGE,
        },
        armor_options,
      ),
    );

    super(encrypt, armor);
  }
}
export class DearmorAndDecryptStream extends Pumpify {
  readonly dearmor: DearmorStream;
  readonly decrypt: DecryptStream;

  constructor(keypair: BoxKeyPair, sender?: Uint8Array | null, armor_options?: Partial<ArmorOptions>) {
    const dearmor = new DearmorStream(armor_options);
    const decrypt = new DecryptStream(keypair, sender);

    super(dearmor, decrypt);

    this.dearmor = dearmor;
    this.decrypt = decrypt;
  }

  get info(): ArmorHeaderInfo {
    return this.dearmor.info;
  }
  get sender_public_key(): Uint8Array {
    return this.decrypt.sender_public_key;
  }
}

export async function signAndArmor(data: Uint8Array | string, keypair: SignKeyPair) {
  const signed = sign(data, keypair);
  return armor(signed, { message_type: MessageType.SIGNED_MESSAGE });
}
export async function verifyArmored(signed: string, public_key?: Uint8Array | null): Promise<DearmorAndVerifyResult> {
  const dearmored = dearmor(signed);
  return Object.assign(await verify(dearmored, public_key), {
    remaining: dearmored.remaining,
    header_info: dearmored.header_info,
  });
}

export type DearmorAndVerifyResult = DearmorResult & VerifyResult;

export class SignAndArmorStream extends Pumpify {
  constructor(keypair: SignKeyPair, armor_options?: Partial<ArmorOptions>) {
    const sign = new SignStream(keypair);
    const armor = new ArmorStream(
      Object.assign(
        {
          message_type: MessageType.SIGNED_MESSAGE,
        },
        armor_options,
      ),
    );

    super(sign, armor);
  }
}
export class DearmorAndVerifyStream extends Pumpify {
  readonly dearmor: DearmorStream;
  readonly verify: VerifyStream;

  constructor(public_key?: Uint8Array | null, armor_options?: Partial<ArmorOptions>) {
    const dearmor = new DearmorStream(armor_options);
    const verify = new VerifyStream(public_key);

    super(dearmor, verify);

    this.dearmor = dearmor;
    this.verify = verify;
  }

  get info(): ArmorHeaderInfo {
    return this.dearmor.info;
  }
  get public_key(): Uint8Array {
    return this.verify.public_key;
  }
}

export async function signDetachedAndArmor(data: Uint8Array | string, keypair: SignKeyPair) {
  const signed = signDetached(data, keypair);
  return armor(signed, { message_type: MessageType.DETACHED_SIGNATURE });
}
export async function verifyDetachedArmored(signature: string, data: Uint8Array | string, public_key?: Uint8Array | null): Promise<DearmorAndVerifyDetachedResult> {
  const dearmored = dearmor(signature);
  const result = await verifyDetached(dearmored, data, public_key);

  return {
    remaining: dearmored.remaining,
    header_info: dearmored.header_info,
    public_key: result.public_key,
  };
}

export interface DearmorAndVerifyDetachedResult extends VerifyDetachedResult {
  remaining: Buffer;
  header_info: ArmorHeaderInfo;
}

export async function signcryptAndArmor(data: Uint8Array | string, keypair: SignKeyPair | null, recipients_keys: Uint8Array[]) {
  const encrypted = await signcrypt(data, keypair, recipients_keys);
  return armor(encrypted, { message_type: MessageType.ENCRYPTED_MESSAGE });
}
export async function dearmorAndDesigncrypt(signcrypted: string, keypair: BoxKeyPair, sender?: Uint8Array | null): Promise<DearmorAndDesigncryptResult> {
  const dearmored = dearmor(signcrypted);
  return Object.assign(await designcrypt(dearmored, keypair, sender), {
    remaining: dearmored.remaining,
    header_info: dearmored.header_info,
  });
}

export type DearmorAndDesigncryptResult = DearmorResult & DesigncryptResult;

export class SigncryptAndArmorStream extends Pumpify {
  constructor(keypair: SignKeyPair | null, recipients_keys: (Uint8Array | SymmetricKeyRecipient)[], armor_options?: Partial<ArmorOptions>) {
    const encrypt = new SigncryptStream(keypair, recipients_keys);
    const armor = new ArmorStream(
      Object.assign(
        {
          message_type: MessageType.ENCRYPTED_MESSAGE,
        },
        armor_options,
      ),
    );

    super(encrypt, armor);
  }
}
export class DearmorAndDesigncryptStream extends Pumpify {
  readonly dearmor: DearmorStream;
  readonly decrypt: DesigncryptStream;

  constructor(keys: BoxKeyPair | SymmetricKeyRecipient, armor_options?: Partial<ArmorOptions>) {
    const dearmor = new DearmorStream(armor_options);
    const decrypt = new DesigncryptStream(keys);

    super(dearmor, decrypt);

    this.dearmor = dearmor;
    this.decrypt = decrypt;
  }

  get info(): ArmorHeaderInfo {
    return this.dearmor.info;
  }
  get sender_public_key(): Uint8Array | null {
    return this.decrypt.sender_public_key;
  }
}
