import { KEY_BUNDLE_TYPE } from "../Defaults";
import { KeyPair } from "../Types";
import { gcm, ctr, cbc } from "@noble/ciphers/aes";
import { hkdf as HKDF } from "@noble/hashes/hkdf";
import { sha256 as SHA256, sha512 as SHA512 } from "@noble/hashes/sha2";
import { md5 as MD5 } from "./md5";
import { hmac as HMAC } from "@noble/hashes/hmac";
import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { curve } from "libsignal";

export const randomInt = (max: number) => {
  // Create a new Uint32Array to hold a random 32-bit integer
  const array = new Uint32Array(1);
  // Fill the array with cryptographically secure random values
  crypto.getRandomValues(array);
  // Scale the random number to the desired range
  return array[0] % max;
};

export const randomBytes = (size: number) =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(size)));

/** prefix version byte to the pub keys, required for some curve crypto functions */
export const generateSignalPubKey = (pubKey: Uint8Array | Buffer) =>
  pubKey.length === 33 ? pubKey : Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);

function scrubPubKeyFormat(pubKey: Uint8Array) {
  if (!(pubKey instanceof Uint8Array)) {
    throw new Error(`Invalid public key type`);
  }
  if (
    pubKey === undefined ||
    ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)
  ) {
    throw new Error("Invalid public key");
  }
  if (pubKey.byteLength == 33) {
    return pubKey.slice(1);
  } else {
    return pubKey;
  }
}

export const Curve = {
  generateKeyPair: (): KeyPair => {
    const { pubKey, privKey } = curve.generateKeyPair();
    return {
      private: Buffer.from(privKey),
      // remove version byte
      public: Buffer.from((pubKey as Uint8Array).slice(1)),
    };
  },
  sharedKey: (privateKey: Uint8Array, publicKey: Uint8Array) => {
    const shared = curve.calculateAgreement(
      generateSignalPubKey(publicKey),
      privateKey
    );
    return Buffer.from(shared);
  },
  sign: (privateKey: Uint8Array, buf: Uint8Array) =>
    curve.calculateSignature(privateKey, buf),
  verify: (pubKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => {
    try {
      curve.verifySignature(generateSignalPubKey(pubKey), message, signature);
      return true;
    } catch (error) {
      return false;
    }
  },
};

export const signedKeyPair = (identityKeyPair: KeyPair, keyId: number) => {
  const preKey = Curve.generateKeyPair();
  const pubKey = generateSignalPubKey(preKey.public);

  const signature = Curve.sign(identityKeyPair.private, pubKey);

  return { keyPair: preKey, signature, keyId };
};

/**
 * encrypt AES 256 GCM;
 * where the tag tag is suffixed to the ciphertext
 * */
export function aesEncryptGCM(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  additionalData: Uint8Array
) {
  const aes = gcm(key, iv, additionalData);
  return Buffer.from(aes.encrypt(plaintext));
}

/**
 * decrypt AES 256 GCM;
 * where the auth tag is suffixed to the ciphertext
 * */
export function aesDecryptGCM(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  additionalData: Uint8Array
) {
  const aes = gcm(key, iv, additionalData);

  const decrypted = aes.decrypt(ciphertext);

  return Buffer.from(decrypted);
}

export function aesEncryptCTR(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
) {
  const aes = ctr(key, iv);
  return Buffer.from(aes.encrypt(plaintext));
}

export function aesDecryptCTR(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
) {
  const aes = ctr(key, iv);
  return Buffer.from(aes.decrypt(ciphertext));
}

/** decrypt AES 256 CBC; where the IV is prefixed to the buffer */
export function aesDecrypt(buffer: Uint8Array, key: Uint8Array) {
  return aesDecryptWithIV(
    buffer.slice(16, buffer.length),
    key,
    buffer.slice(0, 16)
  );
}

/** decrypt AES 256 CBC */
export function aesDecryptWithIV(
  buffer: Uint8Array,
  key: Uint8Array,
  IV: Uint8Array
) {
  const aes = cbc(key, IV);
  return Buffer.from(aes.decrypt(buffer));
}

// encrypt AES 256 CBC; where a random IV is prefixed to the buffer
export function aesEncrypt(buffer: Uint8Array, key: Uint8Array) {
  const IV = randomBytes(16);

  const aes = cbc(key, IV);
  return Buffer.from(aes.encrypt(buffer));
}

// encrypt AES 256 CBC with a given IV
export function aesEncrypWithIV(
  buffer: Uint8Array,
  key: Uint8Array,
  IV: Uint8Array
) {
  const aes = cbc(key, IV);
  return Buffer.from(aes.encrypt(buffer));
}

const VARIANT_SHA_MAP = {
  sha256: SHA256,
  sha512: SHA512,
} as const;

// sign HMAC using SHA 256
export function hmacSign(
  buffer: Uint8Array,
  key: Uint8Array,
  variant: "sha256" | "sha512" = "sha256"
) {
  return Buffer.from(HMAC(VARIANT_SHA_MAP[variant], key, buffer));
}

export const md5 = (buffer: Buffer) => Buffer.from(MD5(buffer));

export const sha256 = (buffer: Buffer) => Buffer.from(SHA256(buffer));

// HKDF key expansion
export function hkdf(
  buffer: Uint8Array | Buffer,
  expandedLength: number,
  info: { salt?: Buffer; info?: string }
) {
  return Buffer.from(
    HKDF(SHA256, buffer, info.salt, info.info, expandedLength)
  );
}

export async function derivePairingCodeKey(pairingCode: string, salt: Buffer) {
  return pbkdf2(SHA256, pairingCode, salt, {
    c: 2 << 16,
    dkLen: 32,
  });
}
