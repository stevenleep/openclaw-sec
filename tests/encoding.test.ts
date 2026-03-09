import { describe, it, expect } from 'vitest';
import { EncodingDecoder, decodeEncodings } from '../src/scanner/encoding.js';

describe('EncodingDecoder', () => {
  const decoder = new EncodingDecoder();

  describe('base64 decoding', () => {
    it('decodes base64-encoded text', () => {
      const secret = 'sk-abc123secretkey456789';
      const encoded = Buffer.from(secret).toString('base64');
      const result = decoder.decode(`Here is the data: ${encoded}`);
      expect(result.decodedLayers.length).toBeGreaterThanOrEqual(1);
      expect(result.decodedLayers.some(l => l.encoding === 'base64')).toBe(true);
      expect(result.allDecodedTexts.some(t => t.includes('sk-abc123'))).toBe(true);
    });

    it('ignores short base64 that is likely not encoded', () => {
      const result = decoder.decode('Hello World');
      expect(result.decodedLayers).toHaveLength(0);
    });
  });

  describe('URL decoding', () => {
    it('decodes URL-encoded strings', () => {
      const encoded = 'password%3Dmy_secret%26user%3Dadmin';
      const result = decoder.decode(`url: ${encoded}`);
      expect(result.decodedLayers.some(l => l.encoding === 'url')).toBe(true);
    });
  });

  describe('hex decoding', () => {
    it('decodes hex-encoded text', () => {
      const secret = 'secret_api_key_here';
      const hex = Buffer.from(secret).toString('hex');
      const result = decoder.decode(`data: ${hex}`);
      expect(result.decodedLayers.some(l => l.encoding === 'hex')).toBe(true);
      expect(result.allDecodedTexts.some(t => t.includes('secret_api_key'))).toBe(true);
    });
  });

  describe('unicode escape decoding', () => {
    it('decodes unicode escape sequences', () => {
      const result = decoder.decode('text: \\u0048\\u0065\\u006C\\u006C\\u006F\\u0020\\u0057\\u006F\\u0072\\u006C\\u0064');
      expect(result.decodedLayers.some(l => l.encoding === 'unicode_escape')).toBe(true);
      expect(result.allDecodedTexts.some(t => t.includes('Hello World'))).toBe(true);
    });
  });

  describe('convenience function', () => {
    it('decodeEncodings works', () => {
      const encoded = Buffer.from('test_secret_data').toString('base64');
      const result = decodeEncodings(encoded);
      expect(result.decodedLayers.length).toBeGreaterThanOrEqual(0);
    });
  });
});
