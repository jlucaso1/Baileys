import { Boom } from "@hapi/boom";
import axios, { type AxiosRequestConfig } from "axios";
import { platform, release } from "node:os";
import type { Logger } from "pino";
import { version as baileysVersion } from "../Defaults/baileys-version";
import * as proto from "../Proto";
import {
	type BaileysEventEmitter,
	type BaileysEventMap,
	type BrowsersMap,
	DisconnectReason,
	type WACallUpdateType,
	type WAVersion,
} from "../Types";
import {
	type BinaryNode,
	getAllBinaryNodeChildren,
	jidDecode,
} from "../WABinary";
import { writeBinaryNode } from "./proto-utils";
import {
	base64ToUint8Array,
	isUint8Array,
	uint8ArrayToBase64,
	uint8ArrayToHex,
	utf8StringToUint8Array,
} from "./buffer";
import { randomBytes, sha256 } from "./crypto";
import type Long from "long";

const PLATFORM_MAP = {
	aix: "AIX",
	darwin: "Mac OS",
	win32: "Windows",
	android: "Android",
	freebsd: "FreeBSD",
	openbsd: "OpenBSD",
	sunos: "Solaris",
};

export const Browsers: BrowsersMap = {
	ubuntu: (browser) => ["Ubuntu", browser, "22.04.4"],
	macOS: (browser) => ["Mac OS", browser, "14.4.1"],
	baileys: (browser) => ["Baileys", browser, "6.5.0"],
	windows: (browser) => ["Windows", browser, "10.0.22631"],
	/** The appropriate browser based on your OS & release */
	appropriate: (browser) => [
		PLATFORM_MAP[platform()] || "Ubuntu",
		browser,
		release(),
	],
};

export const getPlatformId = (browser: string) => {
	const platformType = proto.DevicePropsPlatformType[browser.toUpperCase()];
	return platformType ? platformType.toString().charCodeAt(0).toString() : "49"; //chrome
};

export const BufferJSON = {
	replacer: (k: any, value: { type: string; data: any }) => {
		if (isUint8Array(value) || value?.type === "Buffer") {
			return { type: "Buffer", data: uint8ArrayToBase64(value?.data || value) };
		}

		return value;
	},
	reviver: (
		_: any,
		value: { buffer: boolean; type: string; data: any; value: any },
	) => {
		if (
			typeof value === "object" &&
			!!value &&
			(value.buffer === true || value.type === "Buffer")
		) {
			const val = value.data || value.value;
			return typeof val === "string"
				? base64ToUint8Array(val)
				: new Uint8Array(val || []);
		}

		return value;
	},
};

export const getKeyAuthor = (
	key: proto.MessageKey | undefined | null,
	meId = "me",
) => (key?.fromMe ? meId : key?.participant || key?.remoteJid) || "";

export const writeRandomPadMax16 = (msg: Uint8Array) => {
	const pad = randomBytes(1);
	pad[0] &= 0xf;
	if (!pad[0]) {
		pad[0] = 0xf;
	}

	// Create a padding array of length `pad[0]` filled with `pad[0]`
	const padArray = new Uint8Array(pad[0]).fill(pad[0]);

	// Create a new Uint8Array with combined length and set both arrays in it
	const result = new Uint8Array(msg.length + padArray.length);
	result.set(msg, 0); // Set the message at the start
	result.set(padArray, msg.length); // Append the padding after the message

	return result;
};

export const unpadRandomMax16 = (e: Uint8Array) => {
	const t = new Uint8Array(e);
	if (0 === t.length) {
		throw new Error("unpadPkcs7 given empty bytes");
	}

	const r = t[t.length - 1];
	if (r > t.length) {
		throw new Error(`unpad given ${t.length} bytes, but pad is ${r}`);
	}

	return new Uint8Array(t.buffer, t.byteOffset, t.length - r);
};

export const encodeWAMessage = (message: proto.Message) => {
	return writeRandomPadMax16(writeBinaryNode(proto.writeMessage, message));
};

export const generateRegistrationId = (): number => {
	return Uint16Array.from(randomBytes(2))[0] & 16383;
};

export const encodeBigEndian = (e: number, t = 4) => {
	let r = e;
	const a = new Uint8Array(t);
	for (let i = t - 1; i >= 0; i--) {
		a[i] = 255 & r;
		r >>>= 8;
	}

	return a;
};

export const toNumber = (t: Long | number | null | undefined): number =>
	typeof t === "object" && t
		? "toNumber" in t
			? t.toNumber()
			: (t as any).low
		: t;

/** unix timestamp of a date in seconds */
export const unixTimestampSeconds = (date: Date = new Date()) =>
	Math.floor(date.getTime() / 1000);

export type DebouncedTimeout = ReturnType<typeof debouncedTimeout>;

export const debouncedTimeout = (intervalMs = 1000, task?: () => void) => {
	let timeout: NodeJS.Timeout | undefined;
	return {
		start: (newIntervalMs?: number, newTask?: () => void) => {
			task = newTask || task;
			intervalMs = newIntervalMs || intervalMs;
			timeout && clearTimeout(timeout);
			timeout = setTimeout(() => task?.(), intervalMs);
		},
		cancel: () => {
			timeout && clearTimeout(timeout);
			timeout = undefined;
		},
		setTask: (newTask: () => void) => {
			task = newTask;
		},
		setInterval: (newInterval: number) => {
			intervalMs = newInterval;
		},
	};
};

export const delay = (ms: number) => delayCancellable(ms).delay;

export const delayCancellable = (ms: number) => {
	const stack = new Error().stack;
	let timeout: NodeJS.Timeout;
	let reject: (error) => void;
	const delay: Promise<void> = new Promise((resolve, _reject) => {
		timeout = setTimeout(resolve, ms);
		reject = _reject;
	});
	const cancel = () => {
		clearTimeout(timeout);
		reject(
			new Boom("Cancelled", {
				statusCode: 500,
				data: {
					stack,
				},
			}),
		);
	};

	return { delay, cancel };
};

export async function promiseTimeout<T>(
	ms: number | undefined,
	promise: (resolve: (v: T) => void, reject: (error) => void) => void,
) {
	if (!ms) {
		return new Promise(promise);
	}

	const stack = new Error().stack;
	// Create a promise that rejects in <ms> milliseconds
	const { delay, cancel } = delayCancellable(ms);
	const p = new Promise((resolve, reject) => {
		delay
			.then(() =>
				reject(
					new Boom("Timed Out", {
						statusCode: DisconnectReason.timedOut,
						data: {
							stack,
						},
					}),
				),
			)
			.catch((err) => reject(err));

		promise(resolve, reject);
	}).finally(cancel);
	return p as Promise<T>;
}

// inspired from whatsmeow code
// https://github.com/tulir/whatsmeow/blob/64bc969fbe78d31ae0dd443b8d4c80a5d026d07a/send.go#L42
export const generateMessageIDV2 = (userId?: string): string => {
	const data = new Uint8Array(8 + 20 + 16);
	const view = new DataView(data.buffer);
	view.setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)), false);

	if (userId) {
		const id = jidDecode(userId);
		if (id?.user) {
			const userBytes = utf8StringToUint8Array(id.user);
			const suffixBytes = utf8StringToUint8Array("@c.us");
			data.set(userBytes, 8);
			data.set(suffixBytes, 8 + userBytes.length);
		}
	}

	const random = randomBytes(16);
	data.set(random, 28);

	const hash = sha256(data);
	return `3EB0${uint8ArrayToHex(hash).toUpperCase().substring(0, 18)}`;
};

// generate a random ID to attach to a message
export const generateMessageID = () =>
	`3EB0${uint8ArrayToHex(randomBytes(18)).toUpperCase()}`;

export function bindWaitForEvent<T extends keyof BaileysEventMap>(
	ev: BaileysEventEmitter,
	event: T,
) {
	return async (
		check: (u: BaileysEventMap[T]) => boolean | undefined,
		timeoutMs?: number,
	) => {
		let listener: (item: BaileysEventMap[T]) => void;
		let closeListener: any;
		await promiseTimeout<void>(timeoutMs, (resolve, reject) => {
			closeListener = ({ connection, lastDisconnect }) => {
				if (connection === "close") {
					reject(
						lastDisconnect?.error ||
							new Boom("Connection Closed", {
								statusCode: DisconnectReason.connectionClosed,
							}),
					);
				}
			};

			ev.on("connection.update", closeListener);
			listener = (update) => {
				if (check(update)) {
					resolve();
				}
			};

			ev.on(event, listener);
		}).finally(() => {
			ev.off(event, listener);
			ev.off("connection.update", closeListener);
		});
	};
}

export const bindWaitForConnectionUpdate = (ev: BaileysEventEmitter) =>
	bindWaitForEvent(ev, "connection.update");

export const printQRIfNecessaryListener = (
	ev: BaileysEventEmitter,
	logger: Logger,
) => {
	ev.on("connection.update", async ({ qr }) => {
		if (qr) {
			const QR = await import("qrcode-terminal")
				.then((m) => m.default || m)
				.catch(() => {
					logger.error("QR code terminal not added as dependency");
				});
			QR?.generate(qr, { small: true });
		}
	});
};

/**
 * utility that fetches latest baileys version from the master branch.
 * Use to ensure your WA connection is always on the latest version
 */
export const fetchLatestBaileysVersion = async (
	options: AxiosRequestConfig<any> = {},
) => {
	const URL =
		"https://raw.githubusercontent.com/WhiskeySockets/Baileys/master/src/Defaults/baileys-version.json";
	try {
		const result = await axios.get<{ version: WAVersion }>(URL, {
			...options,
			responseType: "json",
		});
		return {
			version: result.data.version,
			isLatest: true,
		};
	} catch (error) {
		return {
			version: baileysVersion as WAVersion,
			isLatest: false,
			error,
		};
	}
};

/**
 * A utility that fetches the latest web version of whatsapp.
 * Use to ensure your WA connection is always on the latest version
 */
export const fetchLatestWaWebVersion = async (
	options: AxiosRequestConfig<any>,
) => {
	try {
		const result = await axios.get(
			"https://web.whatsapp.com/check-update?version=1&platform=web",
			{
				...options,
				responseType: "json",
			},
		);
		const version = result.data.currentVersion.split(".");
		return {
			version: [+version[0], +version[1], +version[2]] as WAVersion,
			isLatest: true,
		};
	} catch (error) {
		return {
			version: baileysVersion as WAVersion,
			isLatest: false,
			error,
		};
	}
};

/** unique message tag prefix for MD clients */
export const generateMdTagPrefix = () => {
	const bytes = randomBytes(4);
	const view = new DataView(bytes.buffer);

	return `${view.getUint16(0)}.${view.getUint16(2)}-`;
};

const STATUS_MAP: { [_: string]: proto.WebMessageInfoStatus } = {
	played: proto.WebMessageInfoStatus.PLAYED,
	read: proto.WebMessageInfoStatus.READ,
	"read-self": proto.WebMessageInfoStatus.READ,
};
/**
 * Given a type of receipt, returns what the new status of the message should be
 * @param type type from receipt
 */
export const getStatusFromReceiptType = (type: string | undefined) => {
	const status = STATUS_MAP[type!];
	if (typeof type === "undefined") {
		return proto.WebMessageInfoStatus.DELIVERY_ACK;
	}

	return status;
};

const CODE_MAP: { [_: string]: DisconnectReason } = {
	conflict: DisconnectReason.connectionReplaced,
};

/**
 * Stream errors generally provide a reason, map that to a baileys DisconnectReason
 * @param reason the string reason given, eg. "conflict"
 */
export const getErrorCodeFromStreamError = (node: BinaryNode) => {
	const [reasonNode] = getAllBinaryNodeChildren(node);
	let reason = reasonNode?.tag || "unknown";
	const statusCode = +(
		node.attrs.code ||
		CODE_MAP[reason] ||
		DisconnectReason.badSession
	);

	if (statusCode === DisconnectReason.restartRequired) {
		reason = "restart required";
	}

	return {
		reason,
		statusCode,
	};
};

export const getCallStatusFromNode = ({ tag, attrs }: BinaryNode) => {
	let status: WACallUpdateType;
	switch (tag) {
		case "offer":
		case "offer_notice":
			status = "offer";
			break;
		case "terminate":
			if (attrs.reason === "timeout") {
				status = "timeout";
			} else {
				//fired when accepted/rejected/timeout/caller hangs up
				status = "terminate";
			}

			break;
		case "reject":
			status = "reject";
			break;
		case "accept":
			status = "accept";
			break;
		default:
			status = "ringing";
			break;
	}

	return status;
};

const UNEXPECTED_SERVER_CODE_TEXT = "Unexpected server response: ";

export const getCodeFromWSError = (error: Error) => {
	let statusCode = 500;
	if (error?.message?.includes(UNEXPECTED_SERVER_CODE_TEXT)) {
		const code = +error?.message.slice(UNEXPECTED_SERVER_CODE_TEXT.length);
		if (!Number.isNaN(code) && code >= 400) {
			statusCode = code;
		}
	} else if (
		(error as any)?.code?.startsWith("E") ||
		error?.message?.includes("timed out")
	) {
		// handle ETIMEOUT, ENOTFOUND etc
		statusCode = 408;
	}

	return statusCode;
};

/**
 * Is the given platform WA business
 * @param platform AuthenticationCreds.platform
 */
export const isWABusinessPlatform = (platform: string) => {
	return platform === "smbi" || platform === "smba";
};

export function trimUndefined(obj: any) {
	for (const key in obj) {
		if (typeof obj[key] === "undefined") {
			delete obj[key];
		}
	}

	return obj;
}

const CROCKFORD_CHARACTERS = "123456789ABCDEFGHJKLMNPQRSTVWXYZ";

export function bytesToCrockford(buffer: Uint8Array): string {
	let value = 0;
	let bitCount = 0;
	const crockford: string[] = [];

	for (const element of buffer) {
		value = (value << 8) | (element & 0xff);
		bitCount += 8;

		while (bitCount >= 5) {
			crockford.push(
				CROCKFORD_CHARACTERS.charAt((value >>> (bitCount - 5)) & 31),
			);
			bitCount -= 5;
		}
	}

	if (bitCount > 0) {
		crockford.push(CROCKFORD_CHARACTERS.charAt((value << (5 - bitCount)) & 31));
	}

	return crockford.join("");
}
