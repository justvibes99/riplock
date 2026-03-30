export function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

const PLACEHOLDER_PATTERNS = [
  /example/i,
  /placeholder/i,
  /your[-_]/i,
  /xxx/i,
  /TODO/i,
  /CHANGE_ME/i,
  /INSERT_/i,
  /<your/i,
  /fake/i,
  /mock/i,
  /dummy/i,
  /test[-_]?key/i,
  /sample/i,
  /replace[-_]?me/i,
  /put[-_]?your/i,
  /env\([A-Za-z0-9_]+\)/i,   // Supabase/config template: env(SECRET_NAME)
  /\$\{[A-Za-z0-9_]+\}/,     // Shell/config variable: ${SECRET_NAME}
  /process\.env\.\w+/,       // Node env reference: process.env.SECRET
];

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(value));
}
