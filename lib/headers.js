// Default Chrome 147 request header set + ordering, plus the profile-driven builders that
// the client uses to assemble outgoing requests. HTTP/2 sends headers in the order keys are
// inserted into the JS object, so order is controllable from JS.

const CHROME_147_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36'

const CHROME_147_DEFAULT_HEADERS = Object.freeze({
	'sec-ch-ua': '"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
	'sec-ch-ua-mobile': '?0',
	'sec-ch-ua-platform': '"macOS"',
	'upgrade-insecure-requests': '1',
	'user-agent': CHROME_147_UA,
	'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	'sec-fetch-site': 'none',
	'sec-fetch-mode': 'navigate',
	'sec-fetch-user': '?1',
	'sec-fetch-dest': 'document',
	'accept-encoding': 'gzip, deflate, br, zstd',
	'accept-language': 'en-US,en;q=0.9,es;q=0.8',
	'priority': 'u=0, i',
})

const DEFAULT_PSEUDO_ORDER = [':method', ':authority', ':scheme', ':path']

function defaultsFromProfile(profile) {
	if (profile && profile.headers) return profile.headers
	return CHROME_147_DEFAULT_HEADERS
}

function pseudoOrderFromProfile(profile) {
	const o = profile?.http2?.pseudoHeaderOrder
	return Array.isArray(o) && o.length ? o : DEFAULT_PSEUDO_ORDER
}

// Build the H/2 headers map for an outgoing request. Pseudo-headers come first in the
// profile-defined order; the profile-default header block follows in its declared order;
// caller overrides win on conflict.
function buildH2Headers({ method, host, path, userHeaders, profile }) {
	const order = pseudoOrderFromProfile(profile)
	// A caller-supplied Host header overrides :authority and is NEVER emitted as a regular h2
	// header — Chrome carries the origin only in :authority, so a stray `host` header is a tell.
	let hostOverride
	if (userHeaders) for (const k of Object.keys(userHeaders)) if (k.toLowerCase() === 'host') hostOverride = userHeaders[k]
	const pseudoVals = { ':method': method, ':authority': hostOverride != null ? hostOverride : host, ':scheme': 'https', ':path': path }
	const h = {}
	for (const k of order) {
		if (pseudoVals[k] != null) h[k] = pseudoVals[k]
	}
	// Any pseudo we know about but isn't in the profile's order — append for safety.
	for (const [k, v] of Object.entries(pseudoVals)) {
		if (h[k] == null) h[k] = v
	}
	// Caller-order wins. The wire order is: (1) whatever the caller placed in `headers` in
	// its exact insertion order, then (2) profile defaults filling any gaps at the tail in
	// their declared Chrome order. Fingerprint-conscious callers who capture a full Chrome
	// header block get byte-exact position control; casual callers who override just a few
	// get the rest of Chrome's block appended after. Connection-specific headers are illegal
	// in H2 (RFC 7540 §8.1.2.2) and dropped from either source.
	const FORBIDDEN_H2 = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'proxy-connection'])
	const emitted = new Set()
	if (userHeaders) for (const [k, v] of Object.entries(userHeaders)) {
		const lk = k.toLowerCase()
		if (lk === 'host' || FORBIDDEN_H2.has(lk)) continue
		h[lk] = v
		emitted.add(lk)
	}
	for (const [k, v] of Object.entries(defaultsFromProfile(profile))) {
		const lk = k.toLowerCase()
		if (lk === 'host' || FORBIDDEN_H2.has(lk) || emitted.has(lk)) continue
		h[lk] = v
	}
	return h
}

// HTTP/1.1 header block builder. Returns a CRLF-joined header section (no leading request line).
function buildH1Headers({ host, userHeaders, profile }) {
	// Caller-order wins (same policy as buildH2Headers). Wire order:
	//   1. Host (builder-managed, always first — RFC 7230 §5.4)
	//   2. Caller headers in caller's exact insertion order, with caller's exact casing
	//      (Chrome mixes Title-Case standard headers with lowercase sec-ch-ua* and that
	//      casing is a fingerprint tell — we send back what the caller wrote).
	//   3. Any profile defaults the caller didn't provide, appended in Chrome default order
	//      with the existing Title-Case transform.
	let hostOverride
	if (userHeaders) for (const [k, v] of Object.entries(userHeaders)) {
		if (k.toLowerCase() === 'host') { hostOverride = v; break }
	}
	const hostValue = hostOverride != null ? hostOverride : host
	const lines = [`Host: ${hostValue}`]
	const emitted = new Set(['host'])
	if (userHeaders) for (const [k, v] of Object.entries(userHeaders)) {
		const lk = k.toLowerCase()
		if (lk === 'host') continue
		lines.push(`${k}: ${v}`)
		emitted.add(lk)
	}
	for (const [dk, dv] of Object.entries(defaultsFromProfile(profile))) {
		const lk = dk.toLowerCase()
		if (emitted.has(lk)) continue
		lines.push(`${dk.replace(/(^|-)([a-z])/g, (_, p, c) => p + c.toUpperCase())}: ${dv}`)
	}
	return lines.join('\r\n')
}

module.exports = { CHROME_147_DEFAULT_HEADERS, CHROME_147_UA, buildH2Headers, buildH1Headers }
