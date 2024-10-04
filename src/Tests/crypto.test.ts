import { Curve, generateSignalPubKey, signedKeyPair } from "../Utils/crypto";

describe("Curve", () => {
	test("generateKeyPair", () => {
		const keyPair = Curve.generateKeyPair();
		expect(keyPair).toHaveProperty("private");
		expect(keyPair).toHaveProperty("public");
		expect(keyPair.private).toBeInstanceOf(Uint8Array);
		expect(keyPair.public).toBeInstanceOf(Uint8Array);
		expect(keyPair.private.length).toBe(32);
		expect(keyPair.public.length).toBe(32);
	});

	test("sharedKey", () => {
		const keyPair1 = Curve.generateKeyPair();
		const keyPair2 = Curve.generateKeyPair();
		const sharedKey1 = Curve.sharedKey(keyPair1.private, keyPair2.public);
		const sharedKey2 = Curve.sharedKey(keyPair2.private, keyPair1.public);
		expect(sharedKey1).toBeInstanceOf(Uint8Array);
		expect(sharedKey2).toBeInstanceOf(Uint8Array);
		expect(sharedKey1).toEqual(sharedKey2);
	});

	test("sign and verify", () => {
		const keyPair = Curve.generateKeyPair();
		const message = new TextEncoder().encode("Hello, world!");
		const signature = Curve.sign(keyPair.private, message);
		const isValid = Curve.verify(keyPair.public, message, signature);
		expect(isValid).toBe(true);

		// Test with tampered message
		const tamperedMessage = new TextEncoder().encode("Hello, world");
		const isInvalid = Curve.verify(keyPair.public, tamperedMessage, signature);
		expect(isInvalid).toBe(false);
	});
});

describe("signedKeyPair", () => {
	test("generates signed key pair", () => {
		const identityKeyPair = Curve.generateKeyPair();
		const keyId = 1;
		const result = signedKeyPair(identityKeyPair, keyId);

		expect(result).toHaveProperty("keyPair");
		expect(result).toHaveProperty("signature");
		expect(result).toHaveProperty("keyId");
		expect(result.keyPair).toHaveProperty("private");
		expect(result.keyPair).toHaveProperty("public");
		expect(result.signature).toBeInstanceOf(Uint8Array);
		expect(result.keyId).toBe(keyId);

		// Verify the signature
		const pubKey = generateSignalPubKey(result.keyPair.public);
		const isValid = Curve.verify(
			identityKeyPair.public,
			pubKey,
			result.signature,
		);
		expect(isValid).toBe(true);
	});
});
