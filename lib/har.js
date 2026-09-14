// HAR (HTTP Archive) recorder. Attaches to the observability event stream, buffers one
// entry per completed request in memory, and writes a HAR 1.2 file on flush() / process
// exit / SIGINT. Handles H1 and H2 (H3 doesn't fire request-lifecycle events yet).
//
// Usage:
//   const request = require('@unreleased/hellojs')
//   request.har.record('./capture.har')          // start; auto-writes on exit
//   // ... make requests ...
//   request.har.flush()                          // explicit write (idempotent within a session)
//   request.har.stop()                           // cancel recording, no auto-write
//
// Design notes:
// - HAR entries are held in memory, not streamed to disk, because HAR is a single JSON
//   document whose top-level `log.entries` array is closed only at write time. For very
//   long-running captures use rotate(newPath) to close the current file and start fresh.
// - Bodies larger than `maxBodyBytes` are truncated (headersOnly-style) and a `_truncated`
//   marker is set on the entry so the reader knows it's not a full capture.
// - The writer is synchronous on process 'exit' so short-lived scripts still emit the file.
//   SIGINT/SIGTERM handlers write asynchronously — Node has time to flush before the
//   default handler kills the process.

const fs = require('node:fs')
const { URL } = require('node:url')
const { observability } = require('./observability')

const HAR_VERSION = '1.2'
const CREATOR = { name: 'hellojs', version: require('../package.json').version || '0.0.0' }

class HarRecorder {
	constructor() {
		this.reset()
	}

	reset() {
		this.entries = []           // completed HAR entries
		this.inflight = new Map()   // reqId → { startedAt, url, method, requestHeaders, requestBody, tHeadersSent, tFirstByte }
		this.path = null
		this.maxBodyBytes = 5 * 1024 * 1024      // 5 MiB per body cap by default
		this.writeOnExit = true
		this._attached = false
		this._exitHandlersInstalled = false
		this._flushed = false
	}

	// Start recording to `path`. Call once at process start; subsequent calls before stop()
	// change only the destination path.
	record(path, opts = {}) {
		if (!path || typeof path !== 'string') throw new TypeError('har.record: path is required')
		this.path = path
		if (typeof opts.maxBodyBytes === 'number') this.maxBodyBytes = opts.maxBodyBytes
		if (opts.writeOnExit === false) this.writeOnExit = false
		if (!this._attached) this._attach()
		if (this.writeOnExit && !this._exitHandlersInstalled) this._installExitHandlers()
		return this
	}

	stop() {
		if (!this._attached) return
		observability.off('request:start', this._onStart)
		observability.off('request:headersSent', this._onHeadersSent)
		observability.off('request:firstByte', this._onFirstByte)
		observability.off('request:end', this._onEnd)
		observability.off('request:error', this._onError)
		this._attached = false
	}

	// Serialize + write. Idempotent within a single recording session (subsequent calls
	// re-write the same file with any additional entries captured meanwhile).
	flush() {
		if (!this.path) return null
		const har = this.build()
		fs.writeFileSync(this.path, JSON.stringify(har, null, 2))
		this._flushed = true
		return this.path
	}

	// Close current file and start a fresh capture (entries in-memory are cleared).
	rotate(newPath) {
		this.flush()
		this.entries = []
		this.inflight = new Map()
		this.path = newPath || this.path
		this._flushed = false
	}

	// Build the HAR document without writing it (useful for tests / custom sinks).
	build() {
		return {
			log: {
				version: HAR_VERSION,
				creator: CREATOR,
				entries: this.entries.slice(),
			},
		}
	}

	_attach() {
		this._onStart = (ev) => {
			this.inflight.set(ev.id, {
				startedAt: Date.now(),
				startedISO: new Date().toISOString(),
				url: ev.url,
				method: ev.method,
				requestHeaders: ev.headers || {},
				requestBody: ev.requestBody || null,
			})
		}
		this._onHeadersSent = (ev) => {
			const rec = this.inflight.get(ev.id); if (!rec) return
			rec.tHeadersSent = Date.now()
		}
		this._onFirstByte = (ev) => {
			const rec = this.inflight.get(ev.id); if (!rec) return
			rec.tFirstByte = Date.now()
		}
		this._onEnd = (ev) => {
			const rec = this.inflight.get(ev.id); if (!rec) return
			this.inflight.delete(ev.id)
			const now = Date.now()
			const send    = rec.tHeadersSent != null ? Math.max(0, rec.tHeadersSent - rec.startedAt) : -1
			const wait    = (rec.tFirstByte != null && rec.tHeadersSent != null) ? Math.max(0, rec.tFirstByte - rec.tHeadersSent) : -1
			const receive = rec.tFirstByte != null ? Math.max(0, now - rec.tFirstByte) : -1
			this.entries.push(this._makeEntry(rec, {
				status: ev.status,
				responseHeaders: ev.headers || {},
				responseBody: ev.responseBody || null,
				totalBytes: ev.totalBytes || 0,
				timings: { send, wait, receive },
				totalMs: ev.durationMs != null ? ev.durationMs : (now - rec.startedAt),
			}))
		}
		this._onError = (ev) => {
			const rec = this.inflight.get(ev.id); if (!rec) return
			this.inflight.delete(ev.id)
			this.entries.push(this._makeEntry(rec, {
				status: 0,
				responseHeaders: {},
				responseBody: null,
				totalBytes: 0,
				timings: { send: -1, wait: -1, receive: -1 },
				totalMs: ev.durationMs || 0,
				error: { code: ev.code || 'ERROR', message: ev.message || '' },
			}))
		}
		observability.on('request:start', this._onStart)
		observability.on('request:headersSent', this._onHeadersSent)
		observability.on('request:firstByte', this._onFirstByte)
		observability.on('request:end', this._onEnd)
		observability.on('request:error', this._onError)
		this._attached = true
	}

	_installExitHandlers() {
		const writeSync = () => { try { this.flush() } catch (_) {} }
		// 'exit' runs synchronously — only sync work permitted. We already use writeFileSync
		// in flush(), so this is safe.
		process.on('exit', writeSync)
		// SIGINT/SIGTERM: flush then re-throw the default behaviour so Node exits with the
		// conventional 128+signal code. Attaching a listener suppresses default exit, so
		// we call process.exit ourselves.
		const onSignal = (sig) => { writeSync(); process.exit(128 + (sig === 'SIGINT' ? 2 : 15)) }
		process.on('SIGINT', () => onSignal('SIGINT'))
		process.on('SIGTERM', () => onSignal('SIGTERM'))
		// Best-effort on an uncaught error: still emit what we have, then let the crash
		// propagate naturally.
		process.on('uncaughtException', (e) => { writeSync(); throw e })
		this._exitHandlersInstalled = true
	}

	_makeEntry(rec, res) {
		const url = safeParseUrl(rec.url)
		const reqHeaders = headersToHar(rec.requestHeaders)
		const respHeaders = headersToHar(res.responseHeaders)
		const cookies = extractCookiesFromHeaders(reqHeaders)
		const setCookies = extractSetCookiesFromHeaders(respHeaders)
		const reqBodyText = bodyToText(rec.requestBody, this.maxBodyBytes)
		const respBodyText = bodyToText(res.responseBody, this.maxBodyBytes)
		const reqMime = pickHeader(reqHeaders, 'content-type') || ''
		const respMime = pickHeader(respHeaders, 'content-type') || ''

		const entry = {
			startedDateTime: rec.startedISO,
			time: res.totalMs,
			request: {
				method: rec.method || 'GET',
				url: rec.url,
				httpVersion: 'HTTP/2',
				cookies,
				headers: reqHeaders,
				queryString: url ? [...url.searchParams].map(([name, value]) => ({ name, value })) : [],
				headersSize: -1,
				bodySize: rec.requestBody ? rec.requestBody.length : 0,
				...(reqBodyText.text != null ? {
					postData: {
						mimeType: reqMime || 'application/octet-stream',
						text: reqBodyText.text,
						...(reqBodyText.encoding ? { encoding: reqBodyText.encoding } : {}),
					},
				} : {}),
			},
			response: {
				status: res.status || 0,
				statusText: '',
				httpVersion: 'HTTP/2',
				cookies: setCookies,
				headers: respHeaders,
				content: {
					size: res.totalBytes || (res.responseBody ? res.responseBody.length : 0),
					mimeType: respMime || 'application/octet-stream',
					...(respBodyText.text != null ? { text: respBodyText.text } : {}),
					...(respBodyText.encoding ? { encoding: respBodyText.encoding } : {}),
				},
				redirectURL: pickHeader(respHeaders, 'location') || '',
				headersSize: -1,
				bodySize: res.totalBytes || 0,
			},
			cache: {},
			timings: {
				send: res.timings.send,
				wait: res.timings.wait,
				receive: res.timings.receive,
			},
			_hellojs: { id: rec.id },
			...(res.error ? { _error: res.error } : {}),
			...(reqBodyText.truncated || respBodyText.truncated ? { _truncated: true } : {}),
		}
		return entry
	}
}

function safeParseUrl(u) { try { return new URL(u) } catch { return null } }

function headersToHar(headers) {
	if (!headers) return []
	const out = []
	for (const [k, v] of Object.entries(headers)) {
		if (Array.isArray(v)) for (const vv of v) out.push({ name: k, value: String(vv) })
		else out.push({ name: k, value: String(v) })
	}
	return out
}

function pickHeader(harHeaders, name) {
	const lc = name.toLowerCase()
	const h = harHeaders.find(x => x.name.toLowerCase() === lc)
	return h ? h.value : null
}

function extractCookiesFromHeaders(harHeaders) {
	const cookieHdr = harHeaders.filter(h => h.name.toLowerCase() === 'cookie').map(h => h.value).join('; ')
	if (!cookieHdr) return []
	return cookieHdr.split(/;\s*/).filter(Boolean).map(pair => {
		const eq = pair.indexOf('=')
		return eq >= 0
			? { name: pair.slice(0, eq), value: pair.slice(eq + 1) }
			: { name: pair, value: '' }
	})
}

function extractSetCookiesFromHeaders(harHeaders) {
	const out = []
	for (const h of harHeaders) {
		if (h.name.toLowerCase() !== 'set-cookie') continue
		const parts = String(h.value).split(/;\s*/)
		const [nameValue, ...attrs] = parts
		const eq = nameValue.indexOf('=')
		const c = eq >= 0
			? { name: nameValue.slice(0, eq), value: nameValue.slice(eq + 1) }
			: { name: nameValue, value: '' }
		for (const a of attrs) {
			const [k, v] = a.split('=').map(s => s.trim())
			const lc = k.toLowerCase()
			if (lc === 'path') c.path = v || '/'
			else if (lc === 'domain') c.domain = v || ''
			else if (lc === 'expires') c.expires = v
			else if (lc === 'httponly') c.httpOnly = true
			else if (lc === 'secure') c.secure = true
			else if (lc === 'samesite') c.sameSite = v
		}
		out.push(c)
	}
	return out
}

// Convert a Buffer body to HAR content.text. Text-ish (utf8-decodable) bodies go as-is;
// binary bodies are base64-encoded with encoding='base64'. Truncated flag returned for
// bodies larger than `max`.
function bodyToText(buf, max) {
	if (!buf || !buf.length) return { text: null }
	let truncated = false
	let b = buf
	if (b.length > max) { b = b.subarray(0, max); truncated = true }
	// Heuristic: treat as text if it decodes cleanly and contains no NULs.
	const str = b.toString('utf8')
	const looksText = !str.includes('\0') && Buffer.byteLength(str, 'utf8') === b.length
	if (looksText) return { text: str, truncated }
	return { text: b.toString('base64'), encoding: 'base64', truncated }
}

const har = new HarRecorder()
module.exports = { har, HarRecorder }
