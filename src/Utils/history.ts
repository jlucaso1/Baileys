import type { AxiosRequestConfig } from "axios";
import { promisify } from "node:util";
import { inflate } from "node:zlib";
import * as proto from "../Proto";
import { type Chat, type Contact, WAMessageStubType } from "../Types";
import { isJidUser } from "../WABinary";
import { toNumber } from "./generics";
import { normalizeMessageContent } from "./messages";
import { downloadContentFromMessage } from "./messages-media";
import { readBinaryNode } from "./proto-utils";

const inflatePromise = promisify(inflate);

export const downloadHistory = async (
	msg: proto.MessageHistorySyncNotification,
	options: AxiosRequestConfig<any>,
) => {
	const stream = await downloadContentFromMessage(msg, "md-msg-hist", {
		options,
	});
	const bufferArray: Buffer[] = [];
	for await (const chunk of stream) {
		bufferArray.push(chunk);
	}

	let buffer = Buffer.concat(bufferArray);

	// decompress buffer
	buffer = await inflatePromise(buffer);

	const syncData = readBinaryNode(proto.readHistorySync, buffer);
	return syncData;
};

export const processHistoryMessage = (item: proto.HistorySync) => {
	const messages: proto.WebMessageInfo[] = [];
	const contacts: Contact[] = [];
	const chats: Chat[] = [];

	switch (item.syncType) {
		case proto.HistorySyncHistorySyncType.INITIAL_BOOTSTRAP:
		case proto.HistorySyncHistorySyncType.RECENT:
		case proto.HistorySyncHistorySyncType.FULL:
		case proto.HistorySyncHistorySyncType.ON_DEMAND:
			for (const chat of item.conversations! as Chat[]) {
				contacts.push({ id: chat.id, name: chat.name || undefined });

				const msgs = chat.messages || [];
				chat.messages = undefined;
				chat.archived = undefined;
				chat.muteEndTime = undefined;
				chat.pinned = undefined;

				for (const item of msgs) {
					const message = item.message!;
					messages.push(message);

					if (!chat.messages?.length) {
						// keep only the most recent message in the chat array
						chat.messages = [{ message }];
					}

					if (!message.key.fromMe && !chat.lastMessageRecvTimestamp) {
						chat.lastMessageRecvTimestamp = toNumber(message.messageTimestamp);
					}

					if (
						(message.messageStubType ===
							WAMessageStubType.BIZ_PRIVACY_MODE_TO_BSP ||
							message.messageStubType ===
								WAMessageStubType.BIZ_PRIVACY_MODE_TO_FB) &&
						message.messageStubParameters?.[0]
					) {
						contacts.push({
							id: message.key.participant || message.key.remoteJid!,
							verifiedName: message.messageStubParameters?.[0],
						});
					}
				}

				if (isJidUser(chat.id) && chat.readOnly && chat.archived) {
					chat.readOnly = undefined;
				}

				chats.push({ ...chat });
			}

			break;
		case proto.HistorySyncHistorySyncType.PUSH_NAME:
			for (const c of item.pushnames!) {
				contacts.push({ id: c.id!, notify: c.pushname! });
			}

			break;
	}

	return {
		chats,
		contacts,
		messages,
		syncType: item.syncType,
		progress: item.progress,
	};
};

export const downloadAndProcessHistorySyncNotification = async (
	msg: proto.MessageHistorySyncNotification,
	options: AxiosRequestConfig<any>,
) => {
	const historyMsg = await downloadHistory(msg, options);
	return processHistoryMessage(historyMsg);
};

export const getHistoryMsg = (message: proto.Message) => {
	const normalizedContent = message
		? normalizeMessageContent(message)
		: undefined;
	const anyHistoryMsg =
		normalizedContent?.protocolMessage?.historySyncNotification;

	return anyHistoryMsg;
};
