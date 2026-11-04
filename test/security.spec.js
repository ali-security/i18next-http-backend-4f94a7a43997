import expect from 'expect.js'
import {
  interpolate,
  interpolateUrl,
  getInterpolationRegexp,
  isSafeLangUrlSegment,
  isSafeNsUrlSegment,
  isSafeUrlSegment,
  sanitizeLogValue,
  redactUrlCredentials,
  hasXMLHttpRequest
} from '../lib/utils.js'
import Backend from '../lib/index.js'
import request from '../lib/request.js'
import server from './fixtures/server.js'

// Security tests for CVE-2026-41691 (GHSA-q89c-q3h5-w34g): path traversal and
// URL injection through unsanitised `lng` / `ns` values in loadPath/addPath.
// Nested namespaces with `/` stay allowed, as long as the value does not
// change the scheme or authority of the URL (GHSA-qh2f-jh77-hfwf).

describe('security', () => {
  describe('isSafeLangUrlSegment (strict — for `lng`)', () => {
    it('accepts arbitrary language-code shapes (i18next permits any shape)', () => {
      expect(isSafeLangUrlSegment('en')).to.be(true)
      expect(isSafeLangUrlSegment('de-DE')).to.be(true)
      expect(isSafeLangUrlSegment('en_US')).to.be(true)
      expect(isSafeLangUrlSegment('zh-Hant-HK')).to.be(true)
      expect(isSafeLangUrlSegment('pirate-speak')).to.be(true)
      expect(isSafeLangUrlSegment('my-custom.ns')).to.be(true)
    })

    it('rejects path-traversal / URL-structure / control-char payloads', () => {
      expect(isSafeLangUrlSegment('../etc/passwd')).to.be(false)
      expect(isSafeLangUrlSegment('..')).to.be(false)
      expect(isSafeLangUrlSegment('foo/bar')).to.be(false)
      expect(isSafeLangUrlSegment('foo\\bar')).to.be(false)
      expect(isSafeLangUrlSegment('en?admin=true')).to.be(false)
      expect(isSafeLangUrlSegment('en#frag')).to.be(false)
      expect(isSafeLangUrlSegment('en%2F..')).to.be(false)
      expect(isSafeLangUrlSegment('en user')).to.be(false)
      expect(isSafeLangUrlSegment('en@evil.com')).to.be(false)
      expect(isSafeLangUrlSegment('http:127.0.0.1:8080')).to.be(false)
      expect(isSafeLangUrlSegment('__proto__')).to.be(false)
      expect(isSafeLangUrlSegment('en\r\nX-Injected: bad')).to.be(false)
      expect(isSafeLangUrlSegment('')).to.be(false)
      expect(isSafeLangUrlSegment('a'.repeat(200))).to.be(false)
    })

    it('is still exported as `isSafeUrlSegment` for 3.0.5 backwards compat', () => {
      expect(isSafeUrlSegment).to.be(isSafeLangUrlSegment)
    })
  })

  describe('isSafeNsUrlSegment (loose — for `ns`, allows `/`)', () => {
    it('accepts nested namespace names with forward slashes', () => {
      expect(isSafeNsUrlSegment('a/b')).to.be(true)
      expect(isSafeNsUrlSegment('foo/bar/baz')).to.be(true)
      expect(isSafeNsUrlSegment('common')).to.be(true)
    })

    it('still rejects every concrete attack pattern from the 3.0.5 advisory', () => {
      expect(isSafeNsUrlSegment('..')).to.be(false)
      expect(isSafeNsUrlSegment('../etc/passwd')).to.be(false)
      expect(isSafeNsUrlSegment('a/../b')).to.be(false)
      expect(isSafeNsUrlSegment('foo\\bar')).to.be(false)
      expect(isSafeNsUrlSegment('ns?admin=true')).to.be(false)
      expect(isSafeNsUrlSegment('ns#frag')).to.be(false)
      expect(isSafeNsUrlSegment('ns%2F..')).to.be(false)
      expect(isSafeNsUrlSegment('http:127.0.0.1:8080/x')).to.be(false)
      expect(isSafeNsUrlSegment('//evil.example/x')).to.be(false)
      expect(isSafeNsUrlSegment('a//b')).to.be(false)
      expect(isSafeNsUrlSegment('ns@evil')).to.be(false)
      expect(isSafeNsUrlSegment('__proto__')).to.be(false)
      expect(isSafeNsUrlSegment('ns\r\n')).to.be(false)
      expect(isSafeNsUrlSegment('')).to.be(false)
      expect(isSafeNsUrlSegment('a'.repeat(200))).to.be(false)
    })
  })

  describe('interpolate', () => {
    it('does not pollute Object.prototype via __proto__ key in data', () => {
      // interpolate is not a mutation API (it just reads data[key]) but we
      // still guard the key name to prevent surprising behaviour from a
      // polluted template.
      const out = interpolate('x {{__proto__}} y', { __proto__: { polluted: true } })
      // The placeholder is returned unchanged (no substitution for unsafe keys)
      expect(out).to.equal('x {{__proto__}} y')
      expect(({}).polluted).to.be(undefined)
    })

    it('still substitutes safe keys', () => {
      expect(interpolate('hi {{name}}', { name: 'world' })).to.equal('hi world')
    })
  })

  describe('interpolateUrl', () => {
    it('accepts plain codes and multi-lang + joins', () => {
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: 'common' }))
        .to.equal('/locales/en/common.json')
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en+de', ns: 'a+b' }))
        .to.equal('/locales/en+de/a+b.json')
    })

    it('returns null for path-traversal values', () => {
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: '../etc/passwd', ns: 'x' }))
        .to.equal(null)
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: '..' }))
        .to.equal(null)
    })

    it('returns null for URL-structure injection (query-string, fragment)', () => {
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en?admin=true', ns: 'x' }))
        .to.equal(null)
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en#frag', ns: 'x' }))
        .to.equal(null)
    })

    it('accepts nested ns with `/` (3.0.6 regression fix)', () => {
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: 'a/b' }))
        .to.equal('/locales/en/a/b.json')
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: 'foo/bar/baz' }))
        .to.equal('/locales/en/foo/bar/baz.json')
    })

    it('still returns null for ns with `..` or `\\` — nested ns does not weaken the fix', () => {
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: 'a/../b' }))
        .to.equal(null)
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: '..' }))
        .to.equal(null)
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: 'a\\b' }))
        .to.equal(null)
    })

    it('still rejects `/` in lng (strict)', () => {
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en/foo', ns: 'x' }))
        .to.equal(null)
    })

    it('returns null when any segment of a multi-lang + join is unsafe', () => {
      expect(interpolateUrl('/locales/{{lng}}.json', { lng: 'en+../etc/passwd' }))
        .to.equal(null)
    })

    it('returns null for the advisory payloads (traversal, query, fragment, encoded bypass)', () => {
      const t = '/locales/{{lng}}/{{ns}}.json'
      expect(interpolateUrl(t, { lng: '../../config', ns: 'translation' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en?admin=true', ns: 'translation' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en#anything', ns: 'translation' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en%2F..', ns: 'translation' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en', ns: '%2E%2E%2Fconfig' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en', ns: '..\\..\\config' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en', ns: 'a' + String.fromCharCode(0) + 'b' })).to.equal(null)
    })

    // GHSA-qh2f-jh77-hfwf: with a template that puts the placeholder in the
    // host, `@` (userinfo delimiter) or `/` (end of the authority) in the
    // value sends the request to another host.
    it('returns null when a value changes the host of the template', () => {
      const t = 'https://{{ns}}.cdn.example.com/{{lng}}.json'
      expect(interpolateUrl(t, { lng: 'en', ns: '@evil.example/x' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en', ns: 'evil.example/x' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en', ns: 'evil.example@x' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en', ns: 'common+@evil.example/x' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'en', ns: 'common+evil.example/x' })).to.equal(null)
      expect(interpolateUrl('//{{ns}}.cdn.example.com/{{lng}}.json', { lng: 'en', ns: '@evil.example/x' })).to.equal(null)
      expect(interpolateUrl('//{{ns}}.cdn.example.com/{{lng}}.json', { lng: 'en', ns: 'evil.example/x' })).to.equal(null)
    })

    // GHSA-9jhj-wvmw-cfx5: a nested-ns value starting with `/` turns a
    // root-relative template into a protocol-relative URL to another origin.
    it('returns null when a value makes the URL protocol-relative or adds a scheme', () => {
      expect(interpolateUrl('/{{ns}}/{{lng}}.json', { lng: 'en', ns: '/evil.example' })).to.equal(null)
      expect(interpolateUrl('{{ns}}/{{lng}}.json', { lng: 'en', ns: 'file:/etc/passwd' })).to.equal(null)
      expect(interpolateUrl('{{ns}}/{{lng}}.json', { lng: 'en', ns: 'http://evil.example/x' })).to.equal(null)
      expect(interpolateUrl('{{lng}}/{{ns}}.json', { lng: 'javascript:alert(1)', ns: 'x' })).to.equal(null)
    })

    it('returns null (does not throw) for values that cannot be percent-encoded', () => {
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: String.fromCharCode(0xD800) }))
        .to.equal(null)
    })

    it('still allows plain values in the host and `/` in the path', () => {
      expect(interpolateUrl('https://{{ns}}.cdn.example.com/{{lng}}.json', { lng: 'en', ns: 'common' }))
        .to.equal('https://common.cdn.example.com/en.json')
      expect(interpolateUrl('https://{{lng}}.cdn.example.com/{{ns}}.json', { lng: 'de-CH', ns: 'org/pkg' }))
        .to.equal('https://de-CH.cdn.example.com/org/pkg.json')
      expect(interpolateUrl('https://cdn.example.com/{{lng}}/{{ns}}.json', { lng: 'en', ns: 'org/pkg' }))
        .to.equal('https://cdn.example.com/en/org/pkg.json')
      expect(interpolateUrl('/locales/{{lng}}/{{ns}}.json', { lng: 'en', ns: 'org/pkg' }))
        .to.equal('/locales/en/org/pkg.json')
      expect(interpolateUrl('{{ns}}/{{lng}}.json', { lng: 'en', ns: 'org/pkg' }))
        .to.equal('org/pkg/en.json')
      expect(interpolateUrl('/locales/resources.json?lng={{lng}}&ns={{ns}}', { lng: 'de+en', ns: 'ns1+ns2' }))
        .to.equal('/locales/resources.json?lng=de+en&ns=ns1+ns2')
    })

    it('honours a custom placeholder regexp (i18next interpolation prefix/suffix)', () => {
      const re = getInterpolationRegexp({ prefix: '__', suffix: '__' })
      expect(interpolateUrl('/locales/__lng__/__ns__.json', { lng: 'en', ns: 'common' }, re))
        .to.equal('/locales/en/common.json')
      expect(interpolateUrl('/locales/__lng__/__ns__.json', { lng: '../../config', ns: 'common' }, re))
        .to.equal(null)
      expect(interpolateUrl('/{{lng}}/__ns__.json', { lng: 'en', ns: 'common' }, re))
        .to.equal('/{{lng}}/common.json')
    })

    // GHSA-xvq9-wjp8-hwqf: with a template that starts with the placeholder
    // (no origin / leading path), a `scheme:` or `//` prefix in the value
    // turns the interpolated string into an absolute / protocol-relative URL.
    it('returns null for scheme or protocol-relative injection when the placeholder leads the template', () => {
      expect(interpolateUrl('{{lng}}/{{ns}}.json', { lng: 'http:127.0.0.1:8080', ns: 'common' }))
        .to.equal(null)
      expect(interpolateUrl('{{ns}}/{{lng}}.json', { lng: 'en', ns: 'http:127.0.0.1:8080/x' }))
        .to.equal(null)
      expect(interpolateUrl('{{ns}}/{{lng}}.json', { lng: 'en', ns: '//evil.example/x' }))
        .to.equal(null)
      expect(interpolateUrl('{{lng}}/{{ns}}.json', { lng: 'en+http:127.0.0.1:8080', ns: 'common' }))
        .to.equal(null)
    })

    // GHSA-3cmx-xjww-583x: with a query-shaped template, `&` / `=` / `;` in
    // a value add or override query parameters.
    it('returns null for query-parameter injection in a query-shaped template', () => {
      const t = '/locales/resources.json?lng={{lng}}&ns={{ns}}'
      expect(interpolateUrl(t, { lng: 'de&ns=private&admin=true', ns: 'common' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'de', ns: 'common&admin=true' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'de;admin=true', ns: 'common' })).to.equal(null)
      expect(interpolateUrl(t, { lng: 'de+en=x', ns: 'common' })).to.equal(null)
      // the documented multiload shape keeps working
      expect(interpolateUrl(t, { lng: 'de+en', ns: 'ns1+ns2' }))
        .to.equal('/locales/resources.json?lng=de+en&ns=ns1+ns2')
    })

    it('ignores __proto__ placeholder', () => {
      expect(interpolateUrl('/{{__proto__}}/x', { __proto__: { a: 1 } }))
        .to.equal('/{{__proto__}}/x')
    })
  })

  describe('Backend.read with a leading-placeholder loadPath (GHSA-xvq9-wjp8-hwqf)', () => {
    it('refuses to issue the request for a scheme-injecting lng', (done) => {
      let fetched = false
      const backend = new Backend(null, {
        loadPath: '{{lng}}/{{ns}}.json',
        alternateFetch: (url) => { fetched = true; return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve('{}') }) }
      })
      backend.read('http:127.0.0.1:8080', 'common', (err, data) => {
        expect(fetched).to.be(false)
        expect(err).to.be.an(Error)
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        done()
      })
    })

    const requestInto = (urls) => (options, url, payload, callback) => {
      urls.push(url)
      callback(null, { status: 200, data: '{}' })
    }

    it('refuses a scheme-injecting or protocol-relative ns', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '{{ns}}/{{lng}}.json', request: requestInto(urls) })
      backend.read('en', 'http:127.0.0.1:8080/x', (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        backend.read('en', '//evil.example/x', (err, data) => {
          expect(err.message).to.contain('unsafe lng/ns value')
          expect(data).to.be(false)
          expect(urls).to.eql([])
          done()
        })
      })
    })

    it('readMulti refuses when any language injects a scheme', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '{{lng}}/{{ns}}.json', request: requestInto(urls) })
      backend.readMulti(['en', 'http:127.0.0.1:8080'], ['common'], (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        expect(urls).to.eql([])
        done()
      })
    })

    it('create skips a scheme-injecting lng with a leading-placeholder addPath', (done) => {
      const urls = []
      const backend = new Backend(null, { addPath: '{{lng}}/add/{{ns}}', request: requestInto(urls) })
      backend.create(['http:127.0.0.1:8080', 'en'], 'common', 'key', 'value', () => {
        expect(urls).to.eql(['en/add/common'])
        done()
      })
    })

    it('still loads plain and nested namespaces with a leading-placeholder loadPath', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '{{lng}}/{{ns}}.json', request: requestInto(urls) })
      backend.read('en', 'org/pkg', (err) => {
        expect(err).to.be(null)
        expect(urls).to.eql(['en/org/pkg.json'])
        done()
      })
    })
  })

  describe('getInterpolationRegexp', () => {
    it('defaults to {{ }} and matches the i18next defaults', () => {
      const t = '/locales/{{lng}}/{{ns}}.json'
      const data = { lng: 'en', ns: 'common' }
      expect(interpolateUrl(t, data, getInterpolationRegexp())).to.equal('/locales/en/common.json')
      expect(interpolateUrl(t, data, getInterpolationRegexp({ prefix: '{{', suffix: '}}' }))).to.equal('/locales/en/common.json')
    })

    it('supports pre-escaped prefix/suffix', () => {
      const re = getInterpolationRegexp({ prefixEscaped: '\\[\\[', suffixEscaped: '\\]\\]' })
      expect(interpolateUrl('/locales/[[lng]]/[[ns]].json', { lng: 'en', ns: 'common' }, re))
        .to.equal('/locales/en/common.json')
    })
  })

  describe('Backend refuses unsafe lng/ns values (GHSA-q89c-q3h5-w34g)', () => {
    const requestInto = (urls) => (options, url, payload, callback) => {
      urls.push(url)
      callback(null, { status: 200, data: '{}' })
    }

    const payloads = ['../../config', 'en?admin=true', 'en#anything', 'en%2F..', '..', 'en\\..\\..']

    payloads.forEach((lng) => {
      it('read refuses lng ' + JSON.stringify(lng) + ' without issuing a request', (done) => {
        const urls = []
        const backend = new Backend(null, { loadPath: '/locales/{{lng}}/{{ns}}.json', request: requestInto(urls) })
        backend.read(lng, 'translation', (err, data) => {
          expect(err).to.be.an(Error)
          expect(err.message).to.contain('unsafe lng/ns value')
          expect(data).to.be(false)
          expect(urls).to.eql([])
          done()
        })
      })
    })

    it('read refuses a path-traversal ns, also for a function loadPath', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: () => '/locales/{{lng}}/{{ns}}.json', request: requestInto(urls) })
      backend.read('en', '../../../secrets', (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        expect(urls).to.eql([])
        done()
      })
    })

    it('readMulti refuses when any language is unsafe', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '/locales/resources.json?lng={{lng}}&ns={{ns}}', request: requestInto(urls) })
      backend.readMulti(['en', '../admin'], ['translation'], (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        expect(urls).to.eql([])
        done()
      })
    })

    it('does not forge log lines through the refusal message', (done) => {
      const backend = new Backend(null, { request: requestInto([]) })
      backend.read('en\r\n2026-04-18 admin login', 'translation', (err) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(/[\r\n]/.test(err.message)).to.be(false)
        done()
      })
    })

    it('create skips unsafe languages and still calls back', (done) => {
      const urls = []
      const backend = new Backend(null, { addPath: '/locales/add/{{lng}}/{{ns}}', request: requestInto(urls) })
      backend.create(['../../admin', 'en'], 'translation', 'key', 'value', () => {
        expect(urls).to.eql(['/locales/add/en/translation'])
        done()
      })
    })

    it('create refuses a path-traversal ns', (done) => {
      const urls = []
      const backend = new Backend(null, { addPath: '/locales/add/{{lng}}/{{ns}}', request: requestInto(urls) })
      backend.create(['en'], '../../admin', 'key', 'value', () => {
        expect(urls).to.eql([])
        done()
      })
    })

    // GHSA-3cmx-xjww-583x: query-parameter injection through a query-shaped
    // loadPath / addPath.
    it('read refuses query-parameter injection in a query-shaped loadPath', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '/locales/resources.json?lng={{lng}}&ns={{ns}}', request: requestInto(urls) })
      backend.read('de&ns=private&admin=true', 'common', (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        backend.read('de;admin=true', 'common', (err, data) => {
          expect(err.message).to.contain('unsafe lng/ns value')
          expect(data).to.be(false)
          expect(urls).to.eql([])
          done()
        })
      })
    })

    it('readMulti refuses query-parameter injection in ns and keeps the multiload shape', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '/locales/resources.json?lng={{lng}}&ns={{ns}}', request: requestInto(urls) })
      backend.readMulti(['de'], ['common&admin=true'], (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        expect(urls).to.eql([])
        backend.readMulti(['de', 'en'], ['ns1', 'ns2'], (err) => {
          expect(err).to.be(null)
          expect(urls).to.eql(['/locales/resources.json?lng=de+en&ns=ns1+ns2'])
          done()
        })
      })
    })

    it('create refuses query-parameter injection in a query-shaped addPath', (done) => {
      const urls = []
      const backend = new Backend(null, { addPath: '/locales/add?lng={{lng}}&ns={{ns}}', request: requestInto(urls) })
      backend.create(['de&ns=private', 'en'], 'common', 'key', 'value', () => {
        expect(urls).to.eql(['/locales/add?lng=en&ns=common'])
        backend.create(['en'], 'common=x', 'key', 'value', () => {
          expect(urls).to.eql(['/locales/add?lng=en&ns=common'])
          done()
        })
      })
    })

    it('still loads plain and nested namespaces', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '/locales/{{lng}}/{{ns}}.json', request: requestInto(urls) })
      backend.read('de-CH', 'translation', (err, data) => {
        expect(err).to.be(null)
        expect(data).to.eql({})
        backend.readMulti(['en', 'de'], ['a/b', 'common'], (err) => {
          expect(err).to.be(null)
          expect(urls).to.eql(['/locales/de-CH/translation.json', '/locales/en+de/a/b+common.json'])
          done()
        })
      })
    })

    it('uses the interpolation prefix/suffix configured on i18next', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '/locales/__lng__/__ns__.json', request: requestInto(urls) }, { interpolation: { prefix: '__', suffix: '__' } })
      backend.read('en', 'common', (err) => {
        expect(err).to.be(null)
        expect(urls).to.eql(['/locales/en/common.json'])
        backend.read('../../config', 'common', (err, data) => {
          expect(err.message).to.contain('unsafe lng/ns value')
          expect(data).to.be(false)
          expect(urls).to.eql(['/locales/en/common.json'])
          done()
        })
      })
    })

    it('redacts credentials from loadPath in error messages', (done) => {
      const backend = new Backend(null, {
        loadPath: 'https://user:s3cret@example.com/locales/{{lng}}/{{ns}}.json',
        request: (options, url, payload, callback) => callback(null, { status: 404 })
      })
      backend.read('en', 'translation', (err) => {
        expect(err).to.contain('failed loading https://example.com/locales/en/translation.json')
        expect(err.indexOf('s3cret')).to.equal(-1)
        done()
      })
    })
  })

  describe('Backend with {{ns}} in the host of loadPath / addPath (GHSA-qh2f-jh77-hfwf)', () => {
    const requestInto = (urls) => (options, url, payload, callback) => {
      urls.push(url)
      callback(null, { status: 200, data: '{}' })
    }

    it('read refuses an ns that moves the request to another host, for string and function loadPath', (done) => {
      const urls = []
      const options = { request: requestInto(urls) }
      const backend = new Backend(null, { ...options, loadPath: 'https://{{ns}}.cdn.example.com/{{lng}}.json' })
      const fnBackend = new Backend(null, { ...options, loadPath: () => 'https://{{ns}}.cdn.example.com/{{lng}}.json' })
      backend.read('en', '@evil.example/x', (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        fnBackend.read('en', 'evil.example/x', (err, data) => {
          expect(err.message).to.contain('unsafe lng/ns value')
          expect(data).to.be(false)
          expect(urls).to.eql([])
          done()
        })
      })
    })

    it('read refuses an ns that makes a root-relative loadPath protocol-relative', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: '/{{ns}}/{{lng}}.json', request: requestInto(urls) })
      backend.read('en', '/evil.example', (err, data) => {
        expect(err.message).to.contain('unsafe lng/ns value')
        expect(data).to.be(false)
        expect(urls).to.eql([])
        done()
      })
    })

    it('create refuses it too', (done) => {
      const urls = []
      const backend = new Backend(null, { addPath: 'https://{{ns}}.cdn.example.com/add/{{lng}}', request: requestInto(urls) })
      backend.create(['en'], 'evil.example/x', 'key', 'value', () => {
        expect(urls).to.eql([])
        done()
      })
    })

    it('still loads a nested namespace from the path', (done) => {
      const urls = []
      const backend = new Backend(null, { loadPath: 'https://cdn.example.com/{{lng}}/{{ns}}.json', request: requestInto(urls) })
      backend.read('en', 'org/pkg', (err) => {
        expect(err).to.be(null)
        expect(urls).to.eql(['https://cdn.example.com/en/org/pkg.json'])
        done()
      })
    })
  })

  describe('request hardening', () => {
    before(server)

    it('does not leak inherited (prototype-chain) queryStringParams into the URL', (done) => {
      const params = Object.create({ injected: 'evil' })
      params.version = '1.2.3'
      request({ queryStringParams: params }, 'http://localhost:5001/locales/en/testqs', null, (err, ret) => {
        expect(err).not.to.be.ok()
        expect(JSON.parse(ret.data)).to.eql({ version: '1.2.3' })
        done()
      })
    })

    if (!hasXMLHttpRequest()) {
      it('keeps the "not implemented" fetch-options fallback per backend instance', (done) => {
        const seen = []
        const okResponse = () => Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve('{}') })
        const failing = {
          requestOptions: { mode: 'cors' },
          alternateFetch: (url, init) => {
            if (init.mode) throw new Error('mode is not implemented')
            seen.push(['failing', init.mode])
            return okResponse()
          }
        }
        const healthy = {
          requestOptions: { mode: 'cors' },
          alternateFetch: (url, init) => {
            seen.push(['healthy', init.mode])
            return okResponse()
          }
        }
        request(failing, 'http://localhost:5001/locales/en/test', (err) => {
          expect(err).not.to.be.ok()
          request(healthy, 'http://localhost:5001/locales/en/test', (err) => {
            expect(err).not.to.be.ok()
            expect(seen).to.eql([['failing', undefined], ['healthy', 'cors']])
            expect(failing._omitFetchOptions).to.be(true)
            expect(healthy._omitFetchOptions).to.be(undefined)
            done()
          })
        })
      })
    }
  })

  describe('sanitizeLogValue', () => {
    it('strips CR, LF, NUL and other control chars', () => {
      expect(sanitizeLogValue('en\r\n2026-04-18 admin login'))
        .to.equal('en  2026-04-18 admin login')
      expect(sanitizeLogValue('en\u0000')).to.equal('en ')
    })
    it('passes non-strings through unchanged', () => {
      expect(sanitizeLogValue(undefined)).to.equal(undefined)
      expect(sanitizeLogValue(42)).to.equal(42)
    })
  })

  describe('redactUrlCredentials', () => {
    it('strips user:password from URLs', () => {
      expect(redactUrlCredentials('https://user:pass@example.com/locales/en.json'))
        .to.equal('https://example.com/locales/en.json')
      expect(redactUrlCredentials('https://example.com/locales/en.json'))
        .to.equal('https://example.com/locales/en.json')
    })
    it('handles malformed URLs (regex fallback)', () => {
      const out = redactUrlCredentials('//user:pass@example.com/path')
      expect(out.indexOf('user:pass@')).to.equal(-1)
    })
    it('passes non-strings / empty through', () => {
      expect(redactUrlCredentials(null)).to.equal(null)
      expect(redactUrlCredentials('')).to.equal('')
    })
  })
})
