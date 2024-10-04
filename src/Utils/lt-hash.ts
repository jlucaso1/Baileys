import { hkdf } from "./crypto";

/**
 * LT Hash is a summation based hash algorithm that maintains the integrity of a piece of data
 * over a series of mutations. You can add/remove mutations and it'll return a hash equal to
 * if the same series of mutations was made sequentially.
 */

const o = 128;

class d {
	salt: string;

	constructor(e: string) {
		this.salt = e;
	}
	add(e, t) {
		for (const item of t) {
			e = this._addSingle(e, item);
		}

		return e;
	}
	subtract(e, t) {
		for (const item of t) {
			e = this._subtractSingle(e, item);
		}

		return e;
	}
	subtractThenAdd(e, t, r) {
		return this.add(this.subtract(e, r), t);
	}
	_addSingle(e, t) {
		const n = new Uint8Array(hkdf(Buffer.from(t), o, { info: this.salt }))
			.buffer;
		return this.performPointwiseWithOverflow(e, n, (e, t) => e + t);
	}
	_subtractSingle(e, t) {
		const n = new Uint8Array(hkdf(Buffer.from(t), o, { info: this.salt }))
			.buffer;
		return this.performPointwiseWithOverflow(e, n, (e, t) => e - t);
	}
	performPointwiseWithOverflow(e, t, r) {
		const n = new DataView(e);
		const i = new DataView(t);
		const a = new ArrayBuffer(n.byteLength);
		const s = new DataView(a);
		for (let e = 0; e < n.byteLength; e += 2) {
			s.setUint16(e, r(n.getUint16(e, !0), i.getUint16(e, !0)), !0);
		}

		return a;
	}
}
export const LT_HASH_ANTI_TAMPERING = new d("WhatsApp Patch Integrity");
