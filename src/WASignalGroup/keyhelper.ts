import { randomBytes } from "@noble/hashes/utils";
import { randomInt, Curve } from "../Utils/crypto";

export const generateSenderKey = () => {
  return randomBytes(32);
};

export const generateSenderKeyId = () => {
  return randomInt(2147483647);
};

export const generateSenderSigningKey = (key?: any) => {
  if (!key) {
    key = Curve.generateKeyPair();
  }

  return {
    public: key.pubKey,
    private: key.privKey,
  };
};
