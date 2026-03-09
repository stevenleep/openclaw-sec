/**
 * Encoding bypass defense.
 *
 * Decodes Base64, URL-encoded, and Hex-encoded strings before scanning,
 * preventing attackers from evading detection by encoding secrets.
 */

export interface DecodedLayer {
  encoding: 'base64' | 'url' | 'hex' | 'unicode_escape';
  original: string;
  decoded: string;
  position?: { start: number; end: number };
}

export interface DecodingResult {
  decodedLayers: DecodedLayer[];
  allDecodedTexts: string[];
}

const BASE64_REGEX = /(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/=])/g;

const URL_ENCODED_REGEX = /(?:%[0-9A-Fa-f]{2}[^%]*){2,}/g;

const HEX_REGEX = /(?:0x)?(?:[0-9A-Fa-f]{2}){8,}/g;

const UNICODE_ESCAPE_REGEX = /(?:\\u[0-9A-Fa-f]{4}){3,}/g;

const isLikelyText = (s: string): boolean => {
  if (s.length < 4) return false;
  const printable = s.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
  return printable / s.length > 0.7;
};

const tryDecodeBase64 = (text: string): DecodedLayer[] => {
  const layers: DecodedLayer[] = [];
  const regex = new RegExp(BASE64_REGEX.source, BASE64_REGEX.flags);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(match[0], 'base64').toString('utf-8');
      if (isLikelyText(decoded)) {
        layers.push({
          encoding: 'base64',
          original: match[0],
          decoded,
          position: { start: match.index, end: match.index + match[0].length },
        });
      }
    } catch { /* invalid base64, skip */ }
  }

  return layers;
};

const tryDecodeURL = (text: string): DecodedLayer[] => {
  const layers: DecodedLayer[] = [];
  const regex = new RegExp(URL_ENCODED_REGEX.source, URL_ENCODED_REGEX.flags);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    try {
      const decoded = decodeURIComponent(match[0]);
      if (decoded !== match[0] && isLikelyText(decoded)) {
        layers.push({
          encoding: 'url',
          original: match[0],
          decoded,
          position: { start: match.index, end: match.index + match[0].length },
        });
      }
    } catch { /* invalid encoding, skip */ }
  }

  return layers;
};

const tryDecodeHex = (text: string): DecodedLayer[] => {
  const layers: DecodedLayer[] = [];
  const regex = new RegExp(HEX_REGEX.source, HEX_REGEX.flags);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    try {
      const hexStr = match[0].startsWith('0x') ? match[0].slice(2) : match[0];
      if (hexStr.length % 2 !== 0) continue;

      const bytes = Buffer.from(hexStr, 'hex');
      const decoded = bytes.toString('utf-8');

      if (isLikelyText(decoded)) {
        layers.push({
          encoding: 'hex',
          original: match[0],
          decoded,
          position: { start: match.index, end: match.index + match[0].length },
        });
      }
    } catch { /* invalid hex, skip */ }
  }

  return layers;
};

const tryDecodeUnicodeEscape = (text: string): DecodedLayer[] => {
  const layers: DecodedLayer[] = [];
  const regex = new RegExp(UNICODE_ESCAPE_REGEX.source, UNICODE_ESCAPE_REGEX.flags);
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    try {
      const decoded = match[0].replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
      if (decoded !== match[0] && isLikelyText(decoded)) {
        layers.push({
          encoding: 'unicode_escape',
          original: match[0],
          decoded,
          position: { start: match.index, end: match.index + match[0].length },
        });
      }
    } catch { /* invalid escape, skip */ }
  }

  return layers;
};

export class EncodingDecoder {
  decode(text: string): DecodingResult {
    const decodedLayers: DecodedLayer[] = [
      ...tryDecodeBase64(text),
      ...tryDecodeURL(text),
      ...tryDecodeHex(text),
      ...tryDecodeUnicodeEscape(text),
    ];

    const allDecodedTexts = decodedLayers.map(l => l.decoded);

    return { decodedLayers, allDecodedTexts };
  }
}

export const decodeEncodings = (text: string): DecodingResult => {
  const decoder = new EncodingDecoder();
  return decoder.decode(text);
};
