import { Boom } from '@hapi/boom'
import EventEmitter from 'events'
import { promisify } from "util"
import WebSocket from "ws"
import { randomBytes } from 'crypto'
import { proto } from '../../WAProto'
import { DisconnectReason, SocketConfig, BaileysEventEmitter, ConnectionState } from "../Types"
import { Curve, initAuthState, generateRegistrationNode, configureSuccessfulPairing, generateLoginNode, encodeBigEndian, promiseTimeout, generateOrGetPreKeys, xmppSignedPreKey, xmppPreKey, getPreKeys, makeNoiseHandler } from "../Utils"
import { DEFAULT_ORIGIN, DEF_TAG_PREFIX, DEF_CALLBACK_PREFIX, KEY_BUNDLE_TYPE } from "../Defaults"
import { assertNodeErrorFree, BinaryNode, encodeBinaryNode, S_WHATSAPP_NET } from '../WABinary'
/**
 * Connects to WA servers and performs:
 * - simple queries (no retry mechanism, wait for connection establishment)
 * - listen to messages and emit events
 * - query phone connection
 */
export const makeSocket = ({
    waWebSocketUrl, 
    connectTimeoutMs, 
    logger, 
    agent, 
    keepAliveIntervalMs,
    version,
    browser,
    auth: initialAuthState,
    printQRInTerminal,
}: SocketConfig) => {
	const ws = new WebSocket(waWebSocketUrl, undefined, {
		origin: DEFAULT_ORIGIN,
		timeout: connectTimeoutMs,
		agent,
		headers: {
			'Accept-Encoding': 'gzip, deflate, br',
			'Accept-Language': 'en-US,en;q=0.9',
			'Cache-Control': 'no-cache',
			'Host': 'web.whatsapp.com',
			'Pragma': 'no-cache',
			'Sec-WebSocket-Extensions': 'permessage-deflate; client_max_window_bits'
		}
	})
    ws.setMaxListeners(0)
    /** ephemeral key pair used to encrypt/decrypt communication. Unique for each connection */
    const ephemeralKeyPair = Curve.generateKeyPair()
    /** WA noise protocol wrapper */
    const noise = makeNoiseHandler(ephemeralKeyPair)
    const authState = initialAuthState || initAuthState()
    const { creds } = authState
    const ev = new EventEmitter() as BaileysEventEmitter
	
    let lastDateRecv: Date
	let epoch = 0
	let keepAliveReq: NodeJS.Timeout

    const uqTagId = `${randomBytes(1).toString('hex')[0]}.${randomBytes(1).toString('hex')[0]}-`
    const generateMessageTag = () => `${uqTagId}${epoch++}`

	const sendPromise = promisify<void>(ws.send)
	/** send a raw buffer */
	const sendRawMessage = (data: Buffer | Uint8Array) => {
        const bytes = noise.encodeFrame(data)
        return sendPromise.call(ws, bytes) as Promise<void>
    }
    /** send a binary node */
    const sendNode = (node: BinaryNode) => {
        let buff = encodeBinaryNode(node)
        return sendRawMessage(buff)
    }
    /** await the next incoming message */
    const awaitNextMessage = async(sendMsg?: Uint8Array) => {
        if(ws.readyState !== ws.OPEN) {
            throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
        }
        let onOpen: (data: any) => void
        let onClose: (err: Error) => void

        const result = new Promise<any>((resolve, reject) => {
            onOpen = (data: any) => resolve(data)
            onClose = reject
            ws.on('frame', onOpen)
            ws.on('close', onClose)
            ws.on('error', onClose)
        })
        .finally(() => {
            ws.off('frame', onOpen)
            ws.off('close', onClose)
            ws.off('error', onClose)
        })

        if(sendMsg) {
            sendRawMessage(sendMsg).catch(onClose)
        }

        return result
    }

    /**
     * Wait for a message with a certain tag to be received
     * @param tag the message tag to await
     * @param json query that was sent
     * @param timeoutMs timeout after which the promise will reject
     */
	 const waitForMessage = async(msgId: string, timeoutMs?: number) => {
        let onRecv: (json) => void
        let onErr: (err) => void
        try {
            const result = await promiseTimeout(timeoutMs,
                (resolve, reject) => {
                    onRecv = resolve
                    onErr = err => {
                        reject(err || new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed }))
                    }
                    
                    ws.on(`TAG:${msgId}`, onRecv)
                    ws.on('close', onErr) // if the socket closes, you'll never receive the message
                },
            )
            return result as any
        } finally {
            ws.off(`TAG:${msgId}`, onRecv)
            ws.off('close', onErr) // if the socket closes, you'll never receive the message
        }
    }
    /** send a query, and wait for its response. auto-generates message ID if not provided */
    const query = async(node: BinaryNode, timeoutMs?: number) => {
        if(!node.attrs.id) node.attrs.id = generateMessageTag()

        const msgId = node.attrs.id
        const wait = waitForMessage(msgId, timeoutMs)

        await sendNode(node)

        const result = await (wait as Promise<BinaryNode>)
        if('tag' in result) {
            assertNodeErrorFree(result)
        }
        return result
    }
    /** connection handshake */
    const validateConnection = async () => {
        logger.info('connected to WA Web')

        const init = proto.HandshakeMessage.encode({
            clientHello: { ephemeral: ephemeralKeyPair.public }
        }).finish()

        const result = await awaitNextMessage(init)
        const handshake = proto.HandshakeMessage.decode(result)

        logger.debug('handshake recv from WA Web')

        const keyEnc = noise.processHandshake(handshake, creds.noiseKey)
        logger.info('handshake complete')

        let node: Uint8Array
        if(!creds.me) {
            logger.info('not logged in, attempting registration...')
            node = generateRegistrationNode(creds, { version, browser })
        } else {
            logger.info('logging in...')
            node = generateLoginNode(creds.me!.id, { version, browser })
        }
        const payloadEnc = noise.encrypt(node)
        await sendRawMessage(
            proto.HandshakeMessage.encode({
                clientFinish: {
                    static: new Uint8Array(keyEnc),
                    payload: new Uint8Array(payloadEnc),
                },
            }).finish()
        )
        noise.finishInit()
        startKeepAliveRequest()
    }
    /** get some pre-keys and do something with them */
    const assertingPreKeys = async(range: number, execute: (keys: { [_: number]: any }) => Promise<void>) => {
        const { newPreKeys, lastPreKeyId, preKeysRange } = generateOrGetPreKeys(authState, range)
        const preKeys = await getPreKeys(authState.keys, preKeysRange[0], preKeysRange[1])

        await execute(preKeys)
        
        creds.serverHasPreKeys = true
        creds.nextPreKeyId = Math.max(lastPreKeyId+1, creds.nextPreKeyId)
        creds.firstUnuploadedPreKeyId = Math.max(creds.firstUnuploadedPreKeyId, lastPreKeyId+1)
        await Promise.all(
            Object.keys(newPreKeys).map(k => authState.keys.setPreKey(+k, newPreKeys[+k]))
        )

        ev.emit('auth-state.update', authState)
    }
    /** generates and uploads a set of pre-keys */
    const uploadPreKeys = async() => {
        await assertingPreKeys(50, async preKeys => {
            const node: BinaryNode = {
                tag: 'iq',
                attrs: {
                    id: generateMessageTag(),
                    xmlns: 'encrypt',
                    type: 'set',
                    to: S_WHATSAPP_NET,
                },
                content: [
                    { tag: 'registration', attrs: { }, content: encodeBigEndian(creds.registrationId) },
                    { tag: 'type', attrs: { }, content: KEY_BUNDLE_TYPE },
                    { tag: 'identity', attrs: { }, content: creds.signedIdentityKey.public },
                    { tag: 'list', attrs: { }, content: Object.keys(preKeys).map(k => xmppPreKey(preKeys[+k], +k)) },
                    xmppSignedPreKey(creds.signedPreKey)
                ]
            }
            await sendNode(node)

            logger.info('uploaded pre-keys')
        })
    }

    const onMessageRecieved = (data: Buffer) => {
        noise.decodeFrame(data, frame => {
            ws.emit('frame', frame)
            // if it's a binary node
            if(!(frame instanceof Uint8Array)) {
                const msgId = frame.attrs.id

                if(logger.level === 'trace') {
                    logger.trace({ msgId, fromMe: false, frame }, 'communication')
                }
    
                let anyTriggered = false
                /* Check if this is a response to a message we sent */
                anyTriggered = ws.emit(`${DEF_TAG_PREFIX}${msgId}`, frame)
                /* Check if this is a response to a message we are expecting */
                const l0 = frame.tag
                const l1 = frame.attrs || { }
                const l2 = Array.isArray(frame.content) ? frame.content[0]?.tag : ''
    
                Object.keys(l1).forEach(key => {
                    anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]},${l2}`, frame) || anyTriggered
                    anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]}`, frame) || anyTriggered
                    anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}`, frame) || anyTriggered
                })
                anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},,${l2}`, frame) || anyTriggered
                anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0}`, frame) || anyTriggered
                anyTriggered = ws.emit('frame', frame) || anyTriggered
    
                if (!anyTriggered && logger.level === 'debug') {
                    logger.debug({ unhandled: true, msgId, fromMe: false, frame }, 'communication recv')
                }
            }
        })
    }

    const end = (error: Error | undefined) => {
        logger.info({ error }, 'connection closed')

        clearInterval(keepAliveReq)

        ws.removeAllListeners('close')
        ws.removeAllListeners('error')
        ws.removeAllListeners('open')
        ws.removeAllListeners('message')

        if(ws.readyState !== ws.CLOSED && ws.readyState !== ws.CLOSING) {
            try { ws.close() } catch { }
        }

        ev.emit('connection.update', { 
            connection: 'close', 
            lastDisconnect: {
                error,
                date: new Date()
            } 
        })
        ws.removeAllListeners('connection.update')
	}

    const waitForSocketOpen = async() => {
        if(ws.readyState === ws.OPEN) return
        if(ws.readyState === ws.CLOSED || ws.readyState === ws.CLOSING) {
            throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
        }
        let onOpen: () => void
        let onClose: (err: Error) => void
        await new Promise((resolve, reject) => {
            onOpen = () => resolve(undefined)
            onClose = reject
            ws.on('open', onOpen)
            ws.on('close', onClose)
            ws.on('error', onClose)
        })
        .finally(() => {
            ws.off('open', onOpen)
            ws.off('close', onClose)
            ws.off('error', onClose)
        })
    }

    const startKeepAliveRequest = () => (
        keepAliveReq = setInterval(() => {
            if (!lastDateRecv) lastDateRecv = new Date()
            const diff = Date.now() - lastDateRecv.getTime()
            /*
                check if it's been a suspicious amount of time since the server responded with our last seen
                it could be that the network is down
            */
            if (diff > keepAliveIntervalMs+5000) {
                end(new Boom('Connection was lost', { statusCode: DisconnectReason.connectionLost }))
            } else if(ws.readyState === ws.OPEN) {
                // if its all good, send a keep alive request
                query(
                    {
                        tag: 'iq',
                        attrs: {
                            id: generateMessageTag(),
                            to: S_WHATSAPP_NET,
                            type: 'get',
                            xmlns: 'w:p',
                        },
                        content: [{ tag: 'ping', attrs: { } }]
                    },
                    keepAliveIntervalMs
                )
                .then(() => {
                    lastDateRecv = new Date()
                    logger.trace('recv keep alive')
                })
                .catch(err => end(err))
            } else {
                logger.warn('keep alive called when WS not open')
            }
        }, keepAliveIntervalMs)
    )
    /** i have no idea why this exists. pls enlighten me */
    const sendPassiveIq = (tag: 'passive' | 'active') => (
        sendNode({
            tag: 'iq',
            attrs: {
                to: S_WHATSAPP_NET,
                xmlns: 'passive',
                type: 'set',
                id: generateMessageTag(),
            },
            content: [
                { tag, attrs: { } }
            ]
        })
    )
    /** logout & invalidate connection */
    const logout = async() => {
        await sendNode({
            tag: 'iq',
            attrs: {
                to: S_WHATSAPP_NET,
                type: 'set',
                id: generateMessageTag(),
                xmlns: 'md'
            },
            content: [
                {
                    tag: 'remove-companion-device',
                    attrs: {
                        jid: authState.creds.me!.id,
                        reason: 'user_initiated'
                    }
                }
            ]
        })
        end(new Boom('Intentional Logout', { statusCode: DisconnectReason.loggedOut }))
    }
    /** Waits for the connection to WA to reach a state */
	const waitForConnectionUpdate = async(check: (u: Partial<ConnectionState>) => boolean, timeoutMs?: number) => {
        let listener: (item: Partial<ConnectionState>) => void
        await (
            promiseTimeout(
                timeoutMs, 
                (resolve, reject) => {
                    listener = (update) => {
                        if(check(update)) {
                            resolve()
                        } else if(update.connection == 'close') {
							reject(update.lastDisconnect?.error || new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed }))
						}
					}
                    ev.on('connection.update', listener)
                }
            )
            .finally(() => (
				ev.off('connection.update', listener)
			))
        )
    }

	ws.on('message', onMessageRecieved)
	ws.on('open', validateConnection)
	ws.on('error', end)
	ws.on('close', () => end(new Boom('Connection Terminated', { statusCode: DisconnectReason.connectionClosed })))
    // the server terminated the connection
    ws.on('CB:xmlstreamend', () => {
        end(new Boom('Connection Terminated by Server', { statusCode: DisconnectReason.connectionClosed }))
    })
    // QR gen
    ws.on('CB:iq,type:set,pair-device', async (stanza: BinaryNode) => {
        const postQR = async() => {
            if(printQRInTerminal) {
                const QR = await import('qrcode-terminal').catch(err => {
                    logger.error('add `qrcode-terminal` as a dependency to auto-print QR')
                })
                QR?.generate(qr, { small: true })
            }
        }
        
        const refs = ((stanza.content[0] as BinaryNode).content as BinaryNode[]).map(n => n.content as string)
        const iq: BinaryNode = { 
            tag: 'iq', 
            attrs: {
                to: S_WHATSAPP_NET,
                type: 'result',
                id: stanza.attrs.id,
            }
        }
        const noiseKeyB64 = Buffer.from(creds.noiseKey.public).toString('base64');
        const identityKeyB64 = Buffer.from(creds.signedIdentityKey.public).toString('base64')
        const advB64 = creds.advSecretKey
        const qr = [refs[0], noiseKeyB64, identityKeyB64, advB64].join(',');

        ev.emit('connection.update', { qr })
        await postQR()
        await sendNode(iq)
    })
    // device paired for the first time
    // if device pairs successfully, the server asks to restart the connection
    ws.on('CB:iq,,pair-success', async(stanza: BinaryNode) => {
        logger.debug('pair success recv')
        try {
            const { reply, creds: updatedCreds } = configureSuccessfulPairing(stanza, creds)

            logger.debug('pairing configured successfully')

            const waiting = awaitNextMessage()
            await sendNode(reply)

            const value = (await waiting) as BinaryNode
            if(value.tag === 'stream:error') {
                if(value.attrs?.code !== '515') {
                    throw new Boom('Authentication failed', { statusCode: +(value.attrs.code || 500) })
                }
            }
            Object.assign(creds, updatedCreds)
            logger.info({ jid: creds.me!.id }, 'registered connection, restart server')

            ev.emit('auth-state.update', authState)
            ev.emit('connection.update', { isNewLogin: true, qr: undefined })

            end(new Boom('Restart Required', { statusCode: DisconnectReason.restartRequired }))
        } catch(error) {
            logger.info({ trace: error.stack }, 'error in pairing')
            end(error)
        }
    })
    // login complete
    ws.on('CB:success', async() => {
        if(!creds.serverHasPreKeys) {
            await uploadPreKeys()
        }
        await sendPassiveIq('active')

        logger.info('opened connection to WA')

        ev.emit('connection.update', { connection: 'open' })
    })
    // logged out
    ws.on('CB:failure,reason:401', () => {
        end(new Boom('Logged Out', { statusCode: DisconnectReason.loggedOut }))
    })
    process.nextTick(() => {
        ev.emit('connection.update', { connection: 'connecting', receivedPendingNotifications: false, qr: undefined })
    })

	return {
        ws,
        ev,
        authState,
        get user () {
            return authState.creds.me
        },
        assertingPreKeys,
        generateMessageTag,
        query,
        waitForMessage,
        waitForSocketOpen,
		sendRawMessage,
        sendNode,
        logout,
        end,
        waitForConnectionUpdate
	}
}
export type Socket = ReturnType<typeof makeSocket>