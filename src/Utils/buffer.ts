import { Readable } from "node:stream";

/**
 * Converts a Uint8Array to a base64 string.
 * @param array The Uint8Array to convert.
 * @returns The base64 encoded string.
 */
export function uint8ArrayToBase64(array: Uint8Array): string {
	return btoa(String.fromCharCode.apply(null, array));
}

export function base64ToUint8Array(base64: string): Uint8Array {
	const binaryString = atob(base64); // Decode base64 to a binary string
	const length = binaryString.length;
	const array = new Uint8Array(length);

	// Convert the binary string into a Uint8Array
	for (let i = 0; i < length; i++) {
		array[i] = binaryString.charCodeAt(i);
	}

	return array;
}

/**
 * Converts a Uint8Array to a base64url string.
 * @param array The Uint8Array to convert.
 * @returns The base64url encoded string.
 */
export function uint8ArrayToBase64url(array: Uint8Array): string {
	// Step 1: Convert Uint8Array to a regular base64 string
	const base64 = uint8ArrayToBase64(array);

	// Step 2: Convert base64 to base64url
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Converts a Uint8Array to a UTF-8 string.
 * @param array The Uint8Array to convert.
 * @returns The UTF-8 encoded string.
 */
export function uint8ArrayToUtf8String(array: Uint8Array): string {
	return new TextDecoder("utf-8").decode(array);
}

export function utf8StringToUint8Array(str: string): Uint8Array {
	return new TextEncoder().encode(str);
}

export function isUint8Array(item: any): item is Uint8Array {
	return item instanceof Uint8Array;
}

// Utility function to convert Uint8Array to Readable stream
export function bufferToReadable(array: Uint8Array): Readable {
	return Readable.from(array);
}

export const readableToBuffer = async (
	stream: Readable,
): Promise<Uint8Array> => {
	const chunks: Uint8Array[] = [];
	for await (const chunk of stream) {
		chunks.push(new Uint8Array(chunk));
	}

	stream.destroy();

	// Calculate the total length of the final Uint8Array
	const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);

	// Create a new Uint8Array with the total length
	const result = new Uint8Array(totalLength);

	// Copy all chunks into the result array
	let offset = 0;
	for (const chunk of chunks) {
		result.set(chunk, offset);
		offset += chunk.length;
	}

	return result;
};

export function uint8ArrayToHex(array: Uint8Array): string {
	return Array.from(array)
		.map((byte) => byte.toString(16).padStart(2, "0")) // Convert byte to hex and pad with 0 if necessary
		.join(""); // Join all hex values into a single string
}
