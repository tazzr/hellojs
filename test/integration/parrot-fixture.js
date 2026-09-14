// Verify a captured parrot.json still round-trips against tls.peet.ws.
//
// Unlike test/integration/parrot.js which captures a FRESH baseline each run, this script
// uses a pre-captured fixture — the JSON you originally used to build the profile — and
// checks that a live request through hellojs still produces the same JA4 / peetprint /
// akamai_fingerprint. This is the regression test for "it matched before, does it still".
//
// Usage:
//   node test/integration/parrot-fixture.js <path-to-parrot.json>
//
// Exit code: 0 = all non-JA3 fingerprints match, 1 = at least one mismatch.
//
// Why not JA3: Chrome (and our impl mirroring it) shuffles the middle of the extension
// block per TLS instance, so JA3 hash — computed over extensions in wire order — varies
// run to run. JA4, peetprint, and akamai_fingerprint are all extension-order-invariant.

const fs = require('fs')
const request = require('../..')
const profiles = require('../../lib/profiles')

const fixturePath = process.argv[2]
if (!fixturePath) {
	console.error('Usage: node test/integration/parrot-fixture.js <path-to-parrot.json>')
	process.exit(2)
}
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'))

const expected = {
	ja4:       fixture.tls?.ja4,
	peetprint: fixture.tls?.peetprint_hash,
	akamai:    fixture.http2?.akamai_fingerprint_hash,
}
if (!expected.ja4 || !expected.peetprint || !expected.akamai) {
	console.error('Fixture is missing tls.ja4 / tls.peetprint_hash / http2.akamai_fingerprint_hash')
	process.exit(2)
}

console.log(`Fixture: ${fixturePath}`)
console.log(`  ja4       ${expected.ja4}`)
console.log(`  peetprint ${expected.peetprint}`)
console.log(`  akamai    ${expected.akamai}`)

;(async () => {
	// Register the profile from the captured JSON.
	profiles.registerFromPeet('parrot-fixture', fixture)

	// Force a fresh connection AND clear the session cache so a stale PSK doesn't add a
	// pre_shared_key extension that bumps the JA4 extension count.
	request.pool.closeAll()
	require('../../lib/tls/session-cache').clear()

	const res = await request({
		url: 'https://tls.peet.ws/api/all',
		json: true,
		profile: 'parrot-fixture',
		forever: false,
		resolveWithFullResponse: true,
		timeouts: { tlsHandshake: 15_000, response: 15_000 },
	})

	const got = {
		ja4:       res.body.tls?.ja4,
		peetprint: res.body.tls?.peetprint_hash,
		akamai:    res.body.http2?.akamai_fingerprint_hash,
	}
	console.log(`\nLive response from tls.peet.ws:`)
	console.log(`  ja4       ${got.ja4}`)
	console.log(`  peetprint ${got.peetprint}`)
	console.log(`  akamai    ${got.akamai}`)

	console.log('')
	let fail = 0
	for (const k of ['ja4', 'peetprint', 'akamai']) {
		if (expected[k] === got[k]) {
			console.log(`\x1b[32mMATCH\x1b[0m ${k}`)
		} else {
			console.log(`\x1b[31mDIFF \x1b[0m ${k}\n  expected: ${expected[k]}\n  got:      ${got[k]}`)
			fail++
		}
	}

	// Also verify the two unknown-extension IDs the fixture asked for actually round-tripped.
	// tls.peet.ws lists them in tls.extensions with the same "Unknown extension N" labels
	// (or their proper names if peet learned about them since capture).
	const fixtureUnknowns = (fixture.tls?.extensions || [])
		.map(e => {
			const m = String(e.name).match(/^Unknown extension\s+(?:0x([0-9a-fA-F]+)|(\d+))$/)
			return m ? (m[1] ? parseInt(m[1], 16) : parseInt(m[2], 10)) : null
		})
		.filter(id => id != null)
	if (fixtureUnknowns.length) {
		console.log('')
		const gotExtIds = new Set(
			(res.body.tls?.extensions || []).map(e => {
				const m = String(e.name).match(/\((?:0x([0-9a-fA-F]+)|(\d+))\)\s*$/)
					|| String(e.name).match(/^Unknown extension\s+(?:0x([0-9a-fA-F]+)|(\d+))$/)
				return m ? (m[1] ? parseInt(m[1], 16) : parseInt(m[2], 10)) : null
			}).filter(id => id != null),
		)
		for (const id of fixtureUnknowns) {
			if (gotExtIds.has(id)) console.log(`\x1b[32mMATCH\x1b[0m unknown ext ${id} (0x${id.toString(16)}) present on wire`)
			else { console.log(`\x1b[31mDIFF \x1b[0m unknown ext ${id} (0x${id.toString(16)}) MISSING from live CH`); fail++ }
		}
	}

	console.log(`\n${fail === 0 ? '\x1b[32mALL PASS\x1b[0m' : `\x1b[31m${fail} FAILURE(S)\x1b[0m`}`)
	request.pool.closeAll()
	process.exit(fail ? 1 : 0)
})().catch((e) => {
	console.error('\nRequest failed:', e.code || '', e.message)
	request.pool.closeAll()
	process.exit(1)
})
