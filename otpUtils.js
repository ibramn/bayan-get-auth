const log = (...args) => console.log('[OTPUtils]', ...args);

function normalizeDigits(input) {
  if (input == null) return '';
  const s = typeof input === 'string' ? input : String(input);
  if (!s) return '';
  return s
    .replace(/[٠-٩]/g, (d) => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
    .replace(/[۰-۹]/g, (d) => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)));
}

/**
 * Extract OTP code from text. Safe for null/undefined/non-string input.
 */
export function extractOtp(text, opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const minLen = Math.max(1, Math.min(20, Number(options.minLen) || 4));
  const maxLen = Math.max(minLen, Math.min(20, Number(options.maxLen) || 8));
  const t = normalizeDigits(text);
  if (!t) {
    log('extractOtp: empty input');
    return null;
  }

  try {
    const keywordRegex = /(otp|code|verification|verify|login|رمز|تحقق|تأكيد|التحقق)/i;
    const keywordMatch = t.match(keywordRegex);
    if (keywordMatch?.index != null) {
      const start = Math.max(0, keywordMatch.index - 80);
      const end = Math.min(t.length, keywordMatch.index + 160);
      const windowText = t.slice(start, end);
      const m = windowText.match(new RegExp(`\\b(\\d{${minLen},${maxLen}})\\b`));
      if (m?.[1]) {
        log('extractOtp: found via keyword', { len: m[1].length });
        return m[1];
      }
    }

    const m = t.match(new RegExp(`\\b(\\d{${minLen},${maxLen}})\\b`));
    const result = m?.[1] ?? null;
    if (result) log('extractOtp: found via digit run', { len: result.length });
    else log('extractOtp: no match');
    return result;
  } catch (e) {
    log('extractOtp: error', e?.message);
    return null;
  }
}
