/**
 * A user name from a display name, as a suggestion: "Mia Müller" → "mia.mueller". The server's
 * rule is lower case letters, digits, `.`, `_` and `-`, starting with a letter or digit.
 */
export function suggestUsername(displayName: string): string {
  return displayName
    .trim()
    .toLowerCase()
    .replace(/ä/g, 'ae')
    .replace(/ö/g, 'oe')
    .replace(/ü/g, 'ue')
    .replace(/ß/g, 'ss')
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/\s+/g, '.')
    .replace(/[^a-z0-9._-]/g, '')
    .replace(/[._-]{2,}/g, '.')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/[._-]+$/, '')
    .slice(0, 64);
}

/** Whether the server will take `name` as a user name. */
export function validUsername(name: string): boolean {
  return /^[a-z0-9][a-z0-9._-]{0,63}$/.test(name);
}
