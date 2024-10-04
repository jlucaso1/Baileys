import axios, { type AxiosRequestConfig } from "axios";
import {
	MOBILE_REGISTRATION_ENDPOINT,
	MOBILE_TOKEN,
	MOBILE_USERAGENT,
	REGISTRATION_PUBLIC_KEY,
} from "../Defaults";
import type { KeyPair, SignedKeyPair, SocketConfig } from "../Types";
import { aesEncryptGCM, Curve, md5 } from "../Utils/crypto";
import { jidEncode } from "../WABinary";
import { makeBusinessSocket } from "./business";
import {
	uint8ArrayToBase64url,
	uint8ArrayToHex,
	utf8StringToUint8Array,
} from "../Utils/buffer";

function urlencode(str: string) {
	return str.replace(/-/g, "%2d").replace(/_/g, "%5f").replace(/~/g, "%7e");
}

const validRegistrationOptions = (config: RegistrationOptions) =>
	config?.phoneNumberCountryCode &&
	config.phoneNumberNationalNumber &&
	config.phoneNumberMobileCountryCode;

export const makeRegistrationSocket = (config: SocketConfig) => {
	const sock = makeBusinessSocket(config);

	const register = async (code: string) => {
		if (!validRegistrationOptions(config.auth.creds.registration)) {
			throw new Error("please specify the registration options");
		}

		const result = await mobileRegister(
			{ ...sock.authState.creds, ...sock.authState.creds.registration, code },
			config.options,
		);

		if (!result.login) {
			throw new Error("registration failed");
		}

		sock.authState.creds.me = {
			id: jidEncode(result.login, "s.whatsapp.net"),
			name: "~",
		};

		sock.authState.creds.registered = true;
		sock.ev.emit("creds.update", sock.authState.creds);

		return result;
	};

	const requestRegistrationCode = async (
		_registrationOptions?: RegistrationOptions,
	) => {
		const registrationOptions =
			_registrationOptions || config.auth.creds.registration;
		if (!validRegistrationOptions(registrationOptions)) {
			throw new Error("Invalid registration options");
		}

		sock.authState.creds.registration = registrationOptions;

		sock.ev.emit("creds.update", sock.authState.creds);

		return mobileRegisterCode(
			{ ...config.auth.creds, ...registrationOptions },
			config.options,
		);
	};

	return {
		...sock,
		register,
		requestRegistrationCode,
	};
};

// Backup_token: Base64.getEncoder().encodeToString(Arrays.copyOfRange(Base64.getDecoder().decode(UUID.randomUUID().toString().replace('-','')),0,15))

export interface RegistrationData {
	registrationId: number;
	signedPreKey: SignedKeyPair;
	noiseKey: KeyPair;
	signedIdentityKey: KeyPair;
	identityId: Uint8Array;
	phoneId: string;
	deviceId: string;
	backupToken: Uint8Array;
}

export interface RegistrationOptions {
	/** your phone number */
	phoneNumber?: string;
	/** the country code of your phone number */
	phoneNumberCountryCode: string;
	/** your phone number without country code */
	phoneNumberNationalNumber: string;
	/** the country code of your mobile network
	 * @see {@link https://de.wikipedia.org/wiki/Mobile_Country_Code}
	 */
	phoneNumberMobileCountryCode: string;
	/** the network code of your mobile network
	 * @see {@link https://de.wikipedia.org/wiki/Mobile_Network_Code}
	 */
	phoneNumberMobileNetworkCode: string;
	/**
	 * How to send the one time code
	 */
	method?: "sms" | "voice" | "captcha";
	/**
	 * The captcha code if it was requested
	 */
	captcha?: string;
}

export type RegistrationParams = RegistrationData & RegistrationOptions;

function convertBufferToUrlHex(buffer: Uint8Array) {
	let id = "";

	for (const x of buffer) {
		// encode random identity_id buffer as percentage url encoding
		id += `%${x.toString(16).padStart(2, "0").toLowerCase()}`;
	}

	return id;
}

export function registrationParams(params: RegistrationParams) {
	const e_regid = new Uint8Array(4);
	e_regid.set(new Uint32Array([params.registrationId]), 0);

	const e_skey_id = new Uint8Array(3);
	e_skey_id.set(new Uint16Array([params.signedPreKey.keyId]), 0);

	params.phoneNumberCountryCode = params.phoneNumberCountryCode
		.replace("+", "")
		.trim();
	params.phoneNumberNationalNumber = params.phoneNumberNationalNumber
		.replace(/[/-\s)(]/g, "")
		.trim();

	return {
		cc: params.phoneNumberCountryCode,
		in: params.phoneNumberNationalNumber,
		Rc: "0",
		lg: "en",
		lc: "GB",
		mistyped: "6",
		authkey: uint8ArrayToBase64url(params.noiseKey.public),
		e_regid: uint8ArrayToBase64url(e_regid),
		e_keytype: "BQ",
		e_ident: uint8ArrayToBase64url(params.signedIdentityKey.public),
		// e_skey_id: e_skey_id.toString('base64url'),
		e_skey_id: "AAAA",
		e_skey_val: uint8ArrayToBase64url(params.signedPreKey.keyPair.public),
		e_skey_sig: uint8ArrayToBase64url(params.signedPreKey.signature),
		fdid: params.phoneId,
		network_ratio_type: "1",
		expid: params.deviceId,
		simnum: "1",
		hasinrc: "1",
		pid: Math.floor(Math.random() * 1000).toString(),
		id: convertBufferToUrlHex(params.identityId),
		backup_token: convertBufferToUrlHex(params.backupToken),
		token: uint8ArrayToHex(
			md5(
				new Uint8Array([
					...MOBILE_TOKEN,
					...utf8StringToUint8Array(params.phoneNumberNationalNumber),
				]),
			),
		),
		fraud_checkpoint_code: params.captcha,
	};
}

/**
 * Requests a registration code for the given phone number.
 */
export function mobileRegisterCode(
	params: RegistrationParams,
	fetchOptions?: AxiosRequestConfig,
) {
	return mobileRegisterFetch("/code", {
		params: {
			...registrationParams(params),
			mcc: `${params.phoneNumberMobileCountryCode}`.padStart(3, "0"),
			mnc: `${params.phoneNumberMobileNetworkCode || "001"}`.padStart(3, "0"),
			sim_mcc: "000",
			sim_mnc: "000",
			method: params?.method || "sms",
			reason: "",
			hasav: "1",
		},
		...fetchOptions,
	});
}

export function mobileRegisterExists(
	params: RegistrationParams,
	fetchOptions?: AxiosRequestConfig,
) {
	return mobileRegisterFetch("/exist", {
		params: registrationParams(params),
		...fetchOptions,
	});
}

/**
 * Registers the phone number on whatsapp with the received OTP code.
 */
export async function mobileRegister(
	params: RegistrationParams & { code: string },
	fetchOptions?: AxiosRequestConfig,
) {
	//const result = await mobileRegisterFetch(`/reg_onboard_abprop?cc=${params.phoneNumberCountryCode}&in=${params.phoneNumberNationalNumber}&rc=0`)

	return mobileRegisterFetch("/register", {
		params: {
			...registrationParams(params),
			code: params.code.replace("-", ""),
		},
		...fetchOptions,
	});
}

/**
 * Encrypts the given string as AEAD aes-256-gcm with the public whatsapp key and a random keypair.
 */
export function mobileRegisterEncrypt(data: string) {
	const keypair = Curve.generateKeyPair();
	const key = Curve.sharedKey(keypair.private, REGISTRATION_PUBLIC_KEY);

	const buffer = aesEncryptGCM(
		utf8StringToUint8Array(data),
		key,
		new Uint8Array(12),
		new Uint8Array(0),
	);

	return uint8ArrayToBase64url(new Uint8Array([...keypair.public, ...buffer]));
}

export async function mobileRegisterFetch(
	path: string,
	opts: AxiosRequestConfig = {},
) {
	let url = `${MOBILE_REGISTRATION_ENDPOINT}${path}`;

	if (opts.params) {
		const parameter = [] as string[];

		for (const param in opts.params) {
			if (opts.params[param] !== null && opts.params[param] !== undefined) {
				parameter.push(`${param}=${urlencode(opts.params[param])}`);
			}
		}

		url += `?${parameter.join("&")}`;
		opts.params = undefined;
	}

	if (!opts.headers) {
		opts.headers = {};
	}

	opts.headers["User-Agent"] = MOBILE_USERAGENT;

	const response = await axios(url, opts);

	const json = response.data;

	if (response.status > 300 || json.reason) {
		throw json;
	}

	if (json.status && !["ok", "sent"].includes(json.status)) {
		throw json;
	}

	return json as ExistsResponse;
}

export interface ExistsResponse {
	status: "fail" | "sent";
	voice_length?: number;
	voice_wait?: number;
	sms_length?: number;
	sms_wait?: number;
	reason?: "incorrect" | "missing_param" | "code_checkpoint";
	login?: string;
	flash_type?: number;
	ab_hash?: string;
	ab_key?: string;
	exp_cfg?: string;
	lid?: string;
	image_blob?: string;
	audio_blob?: string;
}
