import {
	ProtocolAddress,
	SessionBuilder,
	SessionCipher,
	SessionRecord,
} from "libsignal";
import type { SignalAuthState } from "../Types";
import type { SignalRepository } from "../Types/Signal";
import { generateSignalPubKey } from "../Utils";
import { jidDecode } from "../WABinary";
import {
	GroupCipher,
	GroupSessionBuilder,
	SenderKeyDistributionMessage,
	SenderKeyName,
	SenderKeyRecord,
} from "../WASignalGroup";

export function makeLibSignalRepository(
	auth: SignalAuthState,
): SignalRepository {
	const storage = signalStorage(auth);
	return {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderName = jidToSignalSenderKeyName(group, authorJid);
			const cipher = new GroupCipher(storage, senderName);

			return cipher.decrypt(msg);
		},
		async processSenderKeyDistributionMessage({ item, authorJid }) {
			const builder = new GroupSessionBuilder(storage);
			const senderName = jidToSignalSenderKeyName(item.groupId!, authorJid);

			const senderMsg = new SenderKeyDistributionMessage(
				undefined,
				undefined,
				undefined,
				undefined,
				item.axolotlSenderKeyDistributionMessage,
			);
			const { [senderName]: senderKey } = await auth.keys.get("sender-key", [
				senderName,
			]);
			if (!senderKey) {
				await storage.storeSenderKey(senderName, new SenderKeyRecord());
			}

			await builder.process(senderName, senderMsg);
		},
		async decryptMessage({ jid, type, ciphertext }) {
			const addr = jidToSignalProtocolAddress(jid);
			const session = new SessionCipher(storage, addr);
			let result: Uint8Array;
			switch (type) {
				case "pkmsg":
					result = await session.decryptPreKeyWhisperMessage(ciphertext);
					break;
				case "msg":
					result = await session.decryptWhisperMessage(ciphertext);
					break;
			}

			return result;
		},
		async encryptMessage({ jid, data }) {
			const addr = jidToSignalProtocolAddress(jid);
			const cipher = new SessionCipher(storage, addr);

			const { type: sigType, body } = await cipher.encrypt(data);
			const type = sigType === 3 ? "pkmsg" : "msg";
			return { type, ciphertext: body };
		},
		async encryptGroupMessage({ group, meId, data }) {
			const senderName = jidToSignalSenderKeyName(group, meId);
			const builder = new GroupSessionBuilder(storage);

			const { [senderName]: senderKey } = await auth.keys.get("sender-key", [
				senderName,
			]);
			if (!senderKey) {
				await storage.storeSenderKey(senderName, new SenderKeyRecord());
			}

			const senderKeyDistributionMessage = await builder.create(senderName);
			const session = new GroupCipher(storage, senderName);
			const ciphertext = await session.encrypt(data);

			return {
				ciphertext,
				senderKeyDistributionMessage: senderKeyDistributionMessage.serialize(),
			};
		},
		async injectE2ESession({ jid, session }) {
			const cipher = new SessionBuilder(
				storage,
				jidToSignalProtocolAddress(jid),
			);
			await cipher.initOutgoing(session);
		},
		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString();
		},
	};
}

const jidToSignalProtocolAddress = (jid: string) => {
	const { user, device } = jidDecode(jid)!;
	return new ProtocolAddress(user, device || 0);
};

const jidToSignalSenderKeyName = (group: string, user: string): string => {
	return new SenderKeyName(group, jidToSignalProtocolAddress(user)).toString();
};

function signalStorage({ creds, keys }: SignalAuthState) {
	return {
		loadSession: async (id: string) => {
			const { [id]: sess } = await keys.get("session", [id]);
			if (sess) {
				return SessionRecord.deserialize(sess);
			}
		},
		storeSession: async (id, session) => {
			await keys.set({ session: { [id]: session.serialize() } });
		},
		isTrustedIdentity: () => {
			return true;
		},
		loadPreKey: async (id: number | string) => {
			const keyId = id.toString();
			const { [keyId]: key } = await keys.get("pre-key", [keyId]);
			if (key) {
				return {
					privKey: key.private,
					pubKey: key.public,
				};
			}
		},
		removePreKey: (id: number) => keys.set({ "pre-key": { [id]: null } }),
		loadSignedPreKey: () => {
			const key = creds.signedPreKey;
			return {
				privKey: key.keyPair.private,
				pubKey: key.keyPair.public,
			};
		},
		loadSenderKey: async (keyId: string) => {
			const { [keyId]: key } = await keys.get("sender-key", [keyId]);
			if (key) {
				return new SenderKeyRecord(key);
			}
		},
		storeSenderKey: async (keyId, key) => {
			await keys.set({ "sender-key": { [keyId]: key.serialize() } });
		},
		getOurRegistrationId: () => creds.registrationId,
		getOurIdentity: () => {
			const { signedIdentityKey } = creds;
			return {
				privKey: signedIdentityKey.private,
				pubKey: generateSignalPubKey(signedIdentityKey.public),
			};
		},
	};
}
