const arr = []
const each = arr.forEach
const slice = arr.slice

const UNSAFE_KEYS = ['__proto__', 'constructor', 'prototype']

export function defaults (obj) {
  each.call(slice.call(arguments, 1), (source) => {
    if (source) {
      for (const prop of Object.keys(source)) {
        if (UNSAFE_KEYS.indexOf(prop) > -1) continue
        if (obj[prop] === undefined) obj[prop] = source[prop]
      }
    }
  })
  return obj
}

// Shared denylist: the patterns that are always unsafe to interpolate into a
// URL, regardless of whether the value is a language code or a namespace
// name. Blocks directory escape (`..`), Windows path separators (`\`),
// URL-structure characters that would terminate the path (`?`, `#`, `%`,
// whitespace, `@`), control characters, prototype keys, empty strings, and
// oversized inputs. The one dimension that differs per-key is whether `/`
// is allowed — see the two per-key helpers below.
function isSafeUrlSegmentBase (v) {
  if (typeof v !== 'string') return false
  if (v.length === 0 || v.length > 128) return false
  if (UNSAFE_KEYS.indexOf(v) > -1) return false
  if (v.indexOf('..') > -1) return false
  if (v.indexOf('\\') > -1) return false
  // Block characters that would terminate/restructure the URL:
  // `?` (starts query), `#` (starts fragment), `%` (percent-encoded bypass
  // of `..`/`/` via `%2E%2E`/`%2F`), space (ambiguous), `@` (authority
  // boundary in userinfo-containing URLs).
  if (/[?#%\s@]/.test(v)) return false
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(v)) return false
  return true
}

// Strict — also rejects `/`. Applied to `lng`:
// no legitimate BCP-47 / i18next language-code shape
// (https://www.i18next.com/how-to/faq#how-should-the-language-codes-be-formatted)
// contains `/`, so allowing it would only enable attacks.
export function isSafeLangUrlSegment (v) {
  if (!isSafeUrlSegmentBase(v)) return false
  if (v.indexOf('/') > -1) return false
  return true
}

// Loose — allows `/`. Applied to `ns`:
// nested namespace names like `a/b` that map to subfolder URL layouts
// (`/locales/en/a/b.json`) are a documented i18next pattern. In the URL path
// position `/` is a plain path separator; a template that puts `{{ns}}` in
// the host is covered by `interpolateUrl`, which refuses a value that changes
// the scheme or authority. Directory escape is still prevented — `..` is
// still blocked, `\` is still blocked, URL-structure characters are still
// blocked — so the security fix remains in force for every concrete attack
// pattern (path traversal, query/fragment injection, encoded bypass).
export function isSafeNsUrlSegment (v) {
  return isSafeUrlSegmentBase(v)
}

// Alias for the strict check.
export const isSafeUrlSegment = isSafeLangUrlSegment

// Per-interpolation-key routing: `lng` gets strict, `ns` gets loose.
// Unknown keys fall back to strict (fail-closed).
const SAFETY_CHECK_BY_KEY = {
  lng: isSafeLangUrlSegment,
  ns: isSafeNsUrlSegment
}

// Strip control characters (CR/LF/NUL/C0/C1) from a string so it cannot
// inject fake log lines when concatenated into an error message (CWE-117).
export function sanitizeLogValue (v) {
  if (typeof v !== 'string') return v
  // eslint-disable-next-line no-control-regex
  return v.replace(/[\r\n\x00-\x1F\x7F]/g, ' ')
}

// Redact user:password credentials from a URL-like string before logging.
// Handles both full URLs and malformed ones — on parse failure, falls back
// to a regex that matches the userinfo portion of the authority.
export function redactUrlCredentials (u) {
  if (typeof u !== 'string' || u.length === 0) return u
  try {
    const parsed = new URL(u)
    if (parsed.username || parsed.password) {
      parsed.username = ''
      parsed.password = ''
      return parsed.toString()
    }
    return u
  } catch (e) {
    return u.replace(/(\/\/)[^/@\s]+@/g, '$1')
  }
}

export function hasXMLHttpRequest () {
  return (typeof XMLHttpRequest === 'function' || typeof XMLHttpRequest === 'object')
}

/**
 * Determine whether the given `maybePromise` is a Promise.
 *
 * @param {*} maybePromise
 *
 * @returns {Boolean}
 */
function isPromise (maybePromise) {
  return !!maybePromise && typeof maybePromise.then === 'function'
}

/**
 * Convert any value to a Promise than will resolve to this value.
 *
 * @param {*} maybePromise
 *
 * @returns {Promise}
 */
export function makePromise (maybePromise) {
  if (isPromise(maybePromise)) {
    return maybePromise
  }

  return Promise.resolve(maybePromise)
}

const interpolationRegexp = /\{\{(.+?)\}\}/g

const regexEscape = (str) => str.replace(/[-[\]/{}()*+?.\\^$|]/g, '\\$&')

// Placeholder regexp for `loadPath` / `addPath`. Honours the interpolation
// prefix/suffix configured on i18next (`interpolation.prefix`/`.suffix`, or
// the pre-escaped `prefixEscaped`/`suffixEscaped`), the same delimiters the
// i18next interpolator applies; defaults to `{{` / `}}`.
export function getInterpolationRegexp (interpolationOptions) {
  const o = interpolationOptions || {}
  const prefix = (o.prefix ? regexEscape(o.prefix) : o.prefixEscaped) || '\\{\\{'
  const suffix = (o.suffix ? regexEscape(o.suffix) : o.suffixEscaped) || '\\}\\}'
  if (prefix === '\\{\\{' && suffix === '\\}\\}') return interpolationRegexp
  return new RegExp(prefix + '(.+?)' + suffix, 'g')
}

export function interpolate (str, data) {
  return str.replace(interpolationRegexp, (match, key) => {
    const k = key.trim()
    if (UNSAFE_KEYS.indexOf(k) > -1) return match
    const value = data[k]
    return value != null ? value : match
  })
}

// The scheme and authority (`https://user@host:port`) at the start of a URL
// or relative reference (RFC 3986, appendix B), with `\` counted as `/` as
// browsers do for http(s) URLs. This part decides where the request goes.
const URL_SCHEME_AND_AUTHORITY = /^([^:/\\?#]+:)?([/\\]{2}[^/\\?#]*)?/

// URL-specific variant: reject values that fail the URL-segment safety
// check. Returns `null` if any substitution is unsafe — callers should bail
// out cleanly rather than issue the request. For multi-value joins
// (`en+de`), validates each `+`-separated segment independently.
export function interpolateUrl (str, data, regexp) {
  const placeholder = regexp || interpolationRegexp
  let unsafe = false
  const fill = (encode) => str.replace(placeholder, (match, key) => {
    const k = key.trim()
    if (UNSAFE_KEYS.indexOf(k) > -1) return match
    const value = data[k]
    if (value == null) return match
    // fail-closed on unknown keys
    const check = Object.prototype.hasOwnProperty.call(SAFETY_CHECK_BY_KEY, k) ? SAFETY_CHECK_BY_KEY[k] : isSafeLangUrlSegment
    const segments = String(value).split('+')
    for (const seg of segments) {
      if (!check(seg)) {
        unsafe = true
        return match
      }
    }
    return encode(segments.join('+'))
  })
  const result = fill(v => v)
  if (unsafe) return null
  // The per-value checks cannot see where the template puts the value. In
  // the path, `/` is a plain character (nested namespaces such as `a/b`),
  // but in the host it moves the request elsewhere: with
  // `https://{{ns}}.cdn.example.com/{{lng}}.json`, an ns of `evil.example/x`
  // sends it to `evil.example`, and with `/{{ns}}/{{lng}}.json`, an ns of
  // `/evil.example` yields the protocol-relative `//evil.example/en.json`.
  // So the result must keep the scheme and authority the template gets with
  // the same values percent-encoded, i.e. as plain data.
  // A value in the host may therefore only hold letters, digits and `-._~!*'()`.
  let asData
  try {
    asData = fill(encodeURIComponent)
  } catch (e) {
    // encodeURIComponent throws (URIError) on lone surrogates — such a value
    // cannot be part of a well-formed URL.
    return null
  }
  if (result.match(URL_SCHEME_AND_AUTHORITY)[0] !== asData.match(URL_SCHEME_AND_AUTHORITY)[0]) return null
  return result
}
