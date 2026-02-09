function normalizeDigits(input) {
  if (!input) return '';
  return input
    .replace(/[٠-٩]/g, (d) => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
    .replace(/[۰-۹]/g, (d) => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)));
}

/**
 * Extract OTP code from text.
 */
export function extractOtp(text, { minLen = 4, maxLen = 8 } = {}) {
  const t = normalizeDigits(text);
  if (!t) return null;

  const keywordRegex = /(otp|code|verification|verify|login|رمز|تحقق|تأكيد|التحقق)/i;
  const keywordMatch = t.match(keywordRegex);
  if (keywordMatch?.index != null) {
    const start = Math.max(0, keywordMatch.index - 80);
    const end = Math.min(t.length, keywordMatch.index + 160);
    const windowText = t.slice(start, end);
    const m = windowText.match(new RegExp(`\\b(\\d{${minLen},${maxLen}})\\b`));
    if (m?.[1]) return m[1];
  }

  const m = t.match(new RegExp(`\\b(\\d{${minLen},${maxLen}})\\b`));
  return m?.[1] ?? null;
}
