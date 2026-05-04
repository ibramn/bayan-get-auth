const log = (...args) => console.log('[OTPUtils]', ...args);

function normalizeDigits(input) {
  if (input == null) return '';
  const s = typeof input === 'string' ? input : String(input);
  if (!s) return '';
  return s
    .replace(/[٠-٩]/g, (d) => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
    .replace(/[۰-۹]/g, (d) => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)));
}

function stripHtmlToText(html) {
  if (html == null) return '';
  const s = typeof html === 'string' ? html : String(html);
  return s
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Extract OTP code from text. Safe for null/undefined/non-string input.
 */
export function extractOtp(text, opts = {}) {
  const options = opts && typeof opts === 'object' ? opts : {};
  const minLen = Math.max(1, Math.min(20, Number(options.minLen) || 4));
  const maxLen = Math.max(minLen, Math.min(20, Number(options.maxLen) || 8));
  let work = typeof text === 'string' ? text : text == null ? '' : String(text);
  if (work.includes('<') && work.includes('>')) work = stripHtmlToText(work);
  const t = normalizeDigits(work);
  if (!t) {
    log('extractOtp: empty input');
    return null;
  }

  try {
    const digitRange = `{${minLen},${maxLen}}`;

    // Logisti / IAM style: "Login verification code: 2207 :رمز تحقق تسجيل الدخول"
    const explicitPatterns = [
      new RegExp(`verification\\s+code\\s*[:\\s]\\s*(\\d${digitRange})`, 'i'),
      new RegExp(`login\\s+verification\\s+code\\s*[:\\s]\\s*(\\d${digitRange})`, 'i'),
      new RegExp(`(?:رمز\\s*تحقق|تحقق\\s*تسجيل\\s*الدخول)[^\\d]{0,30}(\\d${digitRange})`, 'i'),
      new RegExp(`(?:code|رمز)\\s*[:\\s：]\\s*(\\d${digitRange})`, 'i'),
    ];
    for (const re of explicitPatterns) {
      const m = t.match(re);
      if (m?.[1]) {
        log('extractOtp: found via phrase pattern', { len: m[1].length });
        return m[1];
      }
    }

    const keywordRegex = /(otp|code|verification|verify|login|رمز|تحقق|تأكيد|التحقق)/i;
    const keywordMatch = t.match(keywordRegex);
    if (keywordMatch?.index != null) {
      const start = Math.max(0, keywordMatch.index - 80);
      const end = Math.min(t.length, keywordMatch.index + 200);
      const windowText = t.slice(start, end);
      const colonDigits = windowText.match(
        new RegExp(`[:：]\\s*(\\d${digitRange})(?:\\s*[:：]|\\s|$)`, 'i')
      );
      if (colonDigits?.[1]) {
        log('extractOtp: found via keyword + colon digits', { len: colonDigits[1].length });
        return colonDigits[1];
      }
      const m = windowText.match(new RegExp(`\\b(\\d${digitRange})\\b`));
      if (m?.[1]) {
        log('extractOtp: found via keyword', { len: m[1].length });
        return m[1];
      }
    }

    const m = t.match(new RegExp(`\\b(\\d${digitRange})\\b`));
    const result = m?.[1] ?? null;
    if (result) log('extractOtp: found via digit run', { len: result.length });
    else log('extractOtp: no match');
    return result;
  } catch (e) {
    log('extractOtp: error', e?.message);
    return null;
  }
}
