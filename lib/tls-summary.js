// Extract a compact, HAR-friendly summary of the TLS state on a pooled connection.
// Called at request:end time so the HAR entry can carry _securityDetails (Chrome
// DevTools extension format), serverIPAddress, and the connection identifier.
//
// Everything is best-effort — a field missing on the conn produces null in the
// summary, never a throw. Any consumer that wants full fidelity should ask the
// underlying TLS instance directly.

const crypto = require('node:crypto')

// TLS 1.3 cipher-suite code → RFC name. Extracted from lib/utils/config.js CIPHERS.
const CIPHER_NAMES = {
	0x1301: 'TLS_AES_128_GCM_SHA256',
	0x1302: 'TLS_AES_256_GCM_SHA384',
	0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
	0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
	0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
	0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
	0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
	0xCCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
	0xCCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
}

// IANA named-group codepoints for the key_share echo.
const GROUP_NAMES = {
	0x0017: 'secp256r1',
	0x0018: 'secp384r1',
	0x0019: 'secp521r1',
	0x001D: 'X25519',
	0x001E: 'X448',
	0x11EC: 'X25519MLKEM768',
}

// TLS legacy-version → text name for the response.
const PROTOCOL_NAMES = {
	0x0304: 'TLS 1.3',
	0x0303: 'TLS 1.2',
	0x0302: 'TLS 1.1',
	0x0301: 'TLS 1.0',
}

function summarizeConn(conn) {
	if (!conn) return null
	const tls = conn.tls || null
	const socket = tls?.socket || null

	const cipherCode = tls?.server?.cipherSuite ?? null
	const versionCode = tls?.server?.selVersion ?? null
	const groupCode = tls?.server?.serverKShare?.group ?? null

	// Leaf cert (best-effort — we only try to parse if we have chain bytes).
	let cert = null
	const leaf = tls?.serverCertChain?.[0]
	if (leaf) {
		try {
			const x = leaf instanceof crypto.X509Certificate ? leaf : new crypto.X509Certificate(leaf)
			const sanList = String(x.subjectAltName || '').split(',').map(s => {
				const t = s.trim()
				if (t.startsWith('DNS:')) return t.slice(4)
				if (t.startsWith('IP Address:')) return t.slice(11).trim()
				return t
			}).filter(Boolean)
			cert = {
				subject: x.subject,
				issuer: x.issuer,
				validFrom: x.validFrom,     // e.g. "Aug  1 00:00:00 2026 GMT"
				validTo: x.validTo,
				sanList,
				fingerprint256: x.fingerprint256,
			}
		} catch (_) { /* leave cert null */ }
	}

	return {
		alpn: conn.alpn || null,
		protocol: versionCode != null ? (PROTOCOL_NAMES[versionCode] || `0x${versionCode.toString(16)}`) : null,
		cipher: cipherCode != null ? (CIPHER_NAMES[cipherCode] || `0x${cipherCode.toString(16)}`) : null,
		cipherCode,
		keyExchange: groupCode != null ? (GROUP_NAMES[groupCode] || `0x${groupCode.toString(16)}`) : null,
		serverIPAddress: socket?.remoteAddress || null,
		serverPort: socket?.remotePort || null,
		connectionId: conn.key || null,
		ja3: tls?.actualFingerprint?.ja3 || null,
		ja3_str: tls?.actualFingerprint?.ja3_str || null,
		ja4: tls?.actualFingerprint?.ja4 || null,
		usedSession: !!conn.usedSession,
		usedEarlyData: !!conn.usedEarlyData,
		cert,
	}
}

module.exports = { summarizeConn }
