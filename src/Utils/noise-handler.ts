import { Boom } from "@hapi/boom";
import type { Logger } from "pino";
import { NOISE_MODE, WA_CERT_DETAILS } from "../Defaults";
import * as proto from "../Proto";
import type { KeyPair } from "../Types";
import { type BinaryNode, decodeBinaryNode } from "../WABinary";
import { aesDecryptGCM, aesEncryptGCM, Curve, hkdf, sha256 } from "./crypto";
import { readBinaryNode } from "./proto-utils";

const generateIV = (counter: number) => {
	const iv = new ArrayBuffer(12);
	new DataView(iv).setUint32(8, counter);

	return new Uint8Array(iv);
};

export const makeNoiseHandler = ({
	keyPair: { private: privateKey, public: publicKey },
	NOISE_HEADER,
	mobile,
	logger,
	routingInfo,
}: {
	keyPair: KeyPair;
	NOISE_HEADER: Uint8Array;
	mobile: boolean;
	logger: Logger;
	routingInfo?: Uint8Array | undefined;
}) => {
	logger = logger.child({ class: "ns" });

	const authenticate = (data: Uint8Array) => {
		if (!isFinished) {
			hash = sha256(new Uint8Array([...hash, ...data]));
		}
	};

	const encrypt = (plaintext: Uint8Array) => {
		const result = aesEncryptGCM(
			plaintext,
			encKey,
			generateIV(writeCounter),
			hash,
		);

		writeCounter += 1;

		authenticate(result);
		return result;
	};

	const decrypt = (ciphertext: Uint8Array) => {
		// before the handshake is finished, we use the same counter
		// after handshake, the counters are different
		const iv = generateIV(isFinished ? readCounter : writeCounter);
		const result = aesDecryptGCM(ciphertext, decKey, iv, hash);

		if (isFinished) {
			readCounter += 1;
		} else {
			writeCounter += 1;
		}

		authenticate(ciphertext);
		return result;
	};

	const localHKDF = (data: Uint8Array) => {
		const key = hkdf(data, 64, { salt, info: "" });

		return [key.slice(0, 32), key.slice(32)];
	};

	const mixIntoKey = (data: Uint8Array) => {
		const [write, read] = localHKDF(data);
		salt = write;
		encKey = read;
		decKey = read;
		readCounter = 0;
		writeCounter = 0;
	};

	const finishInit = () => {
		const [write, read] = localHKDF(new Uint8Array(0));
		encKey = write;
		decKey = read;
		hash = new Uint8Array();
		readCounter = 0;
		writeCounter = 0;
		isFinished = true;
	};

	const data = new TextEncoder().encode(NOISE_MODE);
	let hash = data.byteLength === 32 ? data : sha256(data);
	let salt = hash;
	let encKey = hash;
	let decKey = hash;
	let readCounter = 0;
	let writeCounter = 0;
	let isFinished = false;
	let sentIntro = false;

	let inBytes = new Uint8Array();

	authenticate(NOISE_HEADER);
	authenticate(publicKey);

	return {
		encrypt,
		decrypt,
		authenticate,
		mixIntoKey,
		finishInit,
		processHandshake: (
			{ serverHello }: proto.HandshakeMessage,
			noiseKey: KeyPair,
		) => {
			authenticate(serverHello?.ephemeral!);
			mixIntoKey(Curve.sharedKey(privateKey, serverHello?.ephemeral!));

			const decStaticContent = decrypt(serverHello?.static!);
			mixIntoKey(Curve.sharedKey(privateKey, decStaticContent));

			const certDecoded = decrypt(serverHello?.payload!);

			if (mobile) {
				readBinaryNode(proto.readCertChainNoiseCertificate, certDecoded);
			} else {
				const { intermediate: certIntermediate } = readBinaryNode(
					proto.readCertChain,
					certDecoded,
				);

				const { issuerSerial } = readBinaryNode(
					proto.readCertChainNoiseCertificateDetails,
					certIntermediate?.details!,
				);

				if (issuerSerial !== WA_CERT_DETAILS.SERIAL) {
					throw new Boom("certification match failed", { statusCode: 400 });
				}
			}

			const keyEnc = encrypt(noiseKey.public);
			mixIntoKey(Curve.sharedKey(noiseKey.private, serverHello?.ephemeral!));

			return keyEnc;
		},
		encodeFrame: (data: Uint8Array) => {
			if (isFinished) {
				data = encrypt(data);
			}

			let header: Uint8Array;

			if (routingInfo) {
				header = new Uint8Array(7);
				const headerView = new DataView(header.buffer);
				const encoder = new TextEncoder();
				encoder.encodeInto("ED", header);
				headerView.setUint8(2, 0);
				headerView.setUint8(3, 1);
				headerView.setUint8(4, routingInfo.byteLength >> 16);
				headerView.setUint16(5, routingInfo.byteLength & 65535);
				header = new Uint8Array([...header, ...routingInfo, ...NOISE_HEADER]);
			} else {
				header = new Uint8Array(NOISE_HEADER);
			}

			const introSize = sentIntro ? 0 : header.length;
			const frame = new Uint8Array(introSize + 3 + data.byteLength);
			const frameView = new DataView(frame.buffer);

			if (!sentIntro) {
				frame.set(header);
				sentIntro = true;
			}

			frameView.setUint8(introSize, data.byteLength >> 16);
			frameView.setUint16(introSize + 1, 65535 & data.byteLength);
			frame.set(data, introSize + 3);

			return frame;
		},
		decodeFrame: async (
			newData: Uint8Array,
			onFrame: (data: Uint8Array, binaryNode?: BinaryNode) => void,
		) => {
			// the binary protocol uses its own framing mechanism
			// on top of the WS frames
			// so we get this data and separate out the frames
			const getBytesSize = () => {
				if (inBytes.byteLength >= 3) {
					const view = new DataView(
						inBytes.buffer,
						inBytes.byteOffset,
						inBytes.byteLength,
					);
					return (view.getUint8(0) << 16) | view.getUint16(1);
				}
			};

			inBytes = new Uint8Array([...inBytes, ...newData]);

			logger.trace(
				`recv ${newData.length} bytes, total recv ${inBytes.length} bytes`,
			);

			let size = getBytesSize();
			while (size && inBytes.length >= size + 3) {
				const frame = inBytes.slice(3, size + 3);
				inBytes = inBytes.slice(size + 3);

				let binaryNode: BinaryNode | undefined;

				if (isFinished) {
					const result = decrypt(frame);
					binaryNode = await decodeBinaryNode(result);
				}

				logger.trace({ msg: (frame as any)?.attrs?.id }, "recv frame");

				onFrame(frame, binaryNode);
				size = getBytesSize();
			}
		},
	};
};
