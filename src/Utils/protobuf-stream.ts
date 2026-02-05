import { Readable } from 'stream'
import { proto } from '../../WAProto/index.js'

/**
 * A helper class to read Protobuf fields from a stream of buffers.
 * It handles partial reads and buffering.
 */
export class ProtobufChunkStream {
	private iterator: AsyncIterator<Buffer>
	private currentBuffer: Buffer | null = null
	private position = 0
	private ended = false

	constructor(stream: Readable | AsyncIterable<Buffer>) {
		if (Symbol.asyncIterator in stream) {
			this.iterator = (stream as AsyncIterable<Buffer>)[Symbol.asyncIterator]()
		} else if ('iterator' in stream) {
			// Readable in Node < 10 or generic iterator?
			// Readable should have Symbol.asyncIterator in modern node.
			this.iterator = (stream as any)[Symbol.asyncIterator]()
		} else {
			// Fallback for some streams
			this.iterator = (Readable.toWeb(stream as Readable) as any)[Symbol.asyncIterator]()
		}
	}

	private async ensureData(minBytes = 1): Promise<boolean> {
		if (this.currentBuffer && this.position + minBytes <= this.currentBuffer.length) {
			return true
		}

		if (!this.currentBuffer || this.position >= this.currentBuffer.length) {
			const result = await this.iterator.next()
			if (result.done) {
				this.ended = true
				return false
			}

			this.currentBuffer = result.value
			this.position = 0
		}

		while (this.currentBuffer.length - this.position < minBytes) {
			const result = await this.iterator.next()
			if (result.done) {
				this.ended = true
				return false
			}

			const remaining = this.currentBuffer.subarray(this.position)
			this.currentBuffer = Buffer.concat([remaining, result.value])
			this.position = 0
		}

		return true
	}

	async readVarint(): Promise<number> {
		let count = 0
		let result = 0
		let shift = 0

		while (true) {
			if (!(await this.ensureData(1))) {
				throw new Error('Unexpected end of stream while reading varint')
			}

			if (!this.currentBuffer) {
				throw new Error('Buffer is null despite ensureData returning true')
			}

			const byte = this.currentBuffer[this.position++]
			if (byte === undefined) {
				throw new Error('Unexpected undefined byte')
			}

			result |= (byte & 0x7f) << shift
			shift += 7
			count++

			if ((byte & 0x80) === 0) {
				return result
			}

			if (count >= 10) {
				throw new Error('Varint too long')
			}
		}
	}

	async readBuffer(length: number): Promise<Buffer> {
		if (!(await this.ensureData(length))) {
			throw new Error(`Unexpected end of stream while reading ${length} bytes`)
		}

		if (!this.currentBuffer) {
			throw new Error('Buffer is null despite ensureData returning true')
		}

		const buf = this.currentBuffer.subarray(this.position, this.position + length)
		this.position += length
		return buf
	}

	async hasData(): Promise<boolean> {
		return this.ensureData(1)
	}
}

export async function* decodeSyncdMutationsStream(
	stream: Readable | AsyncIterable<Buffer>
): AsyncIterable<proto.ISyncdMutation> {
	const reader = new ProtobufChunkStream(stream)

	while (await reader.hasData()) {
		const key = await reader.readVarint()
		const wireType = key & 0x07
		const fieldNumber = key >>> 3

		if (wireType === 2) {
			const length = await reader.readVarint()
			const buffer = await reader.readBuffer(length)

			if (fieldNumber === 1) {
				// mutations
				yield proto.SyncdMutation.decode(buffer)
			}
		} else {
			await skipField(reader, wireType)
		}
	}
}

export type SnapshotStreamPart =
	| { type: 'version'; value: proto.ISyncdVersion }
	| { type: 'record'; value: proto.ISyncdRecord }
	| { type: 'mac'; value: Uint8Array }
	| { type: 'keyId'; value: proto.IKeyId }

export async function* decodeSyncdSnapshotStream(
	stream: Readable | AsyncIterable<Buffer>
): AsyncIterable<SnapshotStreamPart> {
	const reader = new ProtobufChunkStream(stream)

	while (await reader.hasData()) {
		const key = await reader.readVarint()
		const wireType = key & 0x07
		const fieldNumber = key >>> 3

		if (wireType === 2) {
			const length = await reader.readVarint()
			const buffer = await reader.readBuffer(length)

			switch (fieldNumber) {
				case 1:
					yield { type: 'version', value: proto.SyncdVersion.decode(buffer) }
					break
				case 2:
					yield { type: 'record', value: proto.SyncdRecord.decode(buffer) }
					break
				case 3:
					yield { type: 'mac', value: buffer }
					break
				case 4:
					yield { type: 'keyId', value: proto.KeyId.decode(buffer) }
					break
			}
		} else {
			await skipField(reader, wireType)
		}
	}
}

// Helper to skip fields
async function skipField(reader: ProtobufChunkStream, wireType: number) {
	switch (wireType) {
		case 0: // Varint
			await reader.readVarint()
			break
		case 1: // 64-bit
			await reader.readBuffer(8)
			break
		case 2: // Length-delimited
			const len = await reader.readVarint()
			await reader.readBuffer(len)
			break
		case 5: // 32-bit
			await reader.readBuffer(4)
			break
		default:
			throw new Error(`Unsupported wire type ${wireType} for skipping`)
	}
}
