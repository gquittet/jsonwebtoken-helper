import * as jwt from 'jsonwebtoken';

/**
 * List of authorized algorithm. I exclude none to be sure that the payload is
 * encrypted.
 */
enum AuthorizedAlgorithms {
  'HS256' = 'HS256',
  'HS384' = 'HS384',
  'HS512' = 'HS512',
  'RS256' = 'RS256',
  'RS384' = 'RS384',
  'RS512' = 'RS512',
  'ES256' = 'ES256',
  'ES384' = 'ES384',
  'ES512' = 'ES512',
}

/**
 * An helper for managing multiple secrets with JWT.
 * This helper is compliant with RFC 7515 and draft-ietf-oauth-jwt-bcp-02
 *
 * @author Guillaume Quittet
 * @date 16th July 2019
 *
 * Sources:
 * https://tools.ietf.org/html/rfc7515
 * https://tools.ietf.org/id/draft-ietf-oauth-jwt-bcp-02.html
 */
class JwtHelper {
  private static _HEADER: jwt.SignOptions[];
  private static _SECRET: any;
  private static _HAS_PARSED: boolean;
  private static readonly _DEFAULT_NO_KEY_ID = 'noKeyId';

  /**
   * Parse the secrets and key ids from environment variables.
   */
  private static parseFromEnv(): void {
    const {
      JWT_ALGORITHM,
      JWT_DEFAULT_EXPIRES,
      JWT_ISSUER,
      JWT_KEY_IDS,
      JWT_SECRET_SEPARATOR,
      JWT_SECRET_TOKEN,
    } = process.env;

    if (!JWT_KEY_IDS || !JWT_ISSUER || !JWT_SECRET_SEPARATOR || !JWT_SECRET_TOKEN) {
      throw new Error(
        'You must be provide these environement variables: ' +
          'JWT_SECRET_SEPARATOR, JWT_SECRET_TOKEN, JWT_KEY_IDS, JWT_ISSUER',
      );
    }

    /* Add an expire value if JWT_DEFAULT_EXPIRES is set. jsonwebtoken use 'ms'
       to parse the time value. So I need to check if I have a number or not
       because 1 = 1s and '1' = 1ms.
    */
    let defaultExpire: number | string | undefined = undefined;
    if (JWT_DEFAULT_EXPIRES) {
      if (/^\d+$/.test(JWT_DEFAULT_EXPIRES)) {
        defaultExpire = parseInt(JWT_DEFAULT_EXPIRES, 10);
      } else {
        defaultExpire = JWT_DEFAULT_EXPIRES;
      }
    }

    this._HEADER = [];
    this._SECRET = {};

    const keyIds = JWT_KEY_IDS.split(JWT_SECRET_SEPARATOR);
    const secrets = JWT_SECRET_TOKEN.split(JWT_SECRET_SEPARATOR);

    if (secrets.length !== keyIds.length) {
      throw new Error('Please provide the same .');
    }

    for (let i = 0; i < keyIds.length; i += 1) {
      const keyId = keyIds[i] || this._DEFAULT_NO_KEY_ID;
      this._SECRET[keyId] = secrets[i];

      const header = {
        algorithm: JWT_ALGORITHM,
        expiresIn: defaultExpire,
        issuer: JWT_ISSUER,
        keyid: keyId,
      };

      if (!JWT_ALGORITHM) {
        delete header.algorithm;
      }

      if (!JWT_DEFAULT_EXPIRES) {
        delete header.expiresIn;
      }

      this._HEADER.push(header);
    }
  }

  /**
   * Sign a payload with the latest secret.
   * @param payload The payload to sign.
   * @returns The encrypted payload.
   */
  static sign(payload: string | object | Buffer): string {
    this.init();
    const keys = Object.keys(this._SECRET);
    const lastKey = keys[keys.length - 1];
    return jwt.sign(payload, this._SECRET[lastKey || this.NO_KEY_ID], this.getHeader(lastKey));
  }

  /**
   * Verify and decrypt an encrypted payload with its matching secret.
   * @param payload The payload to verify.
   * @returns The payload decrypted.
   */
  static verify(payload: string) {
    this.init();
    const payloadKeyId = this.getKeyId(payload);
    const options = this.getHeader(payloadKeyId) || {};
    const opts = { ...options, complete: true };
    return jwt.verify(payload, this._SECRET[payloadKeyId], opts, (error: Error, decrypted: any) => {
      if (error) {
        throw error;
      }

      const { header, payload: toReturn } = decrypted;
      if (header) {
        if (header.kid && header.kid === opts.keyid) {
          return toReturn;
        }
        if (!header.kid) {
          return toReturn;
        }
        throw new jwt.JsonWebTokenError(`jwt keyid invalid. expected: ${opts.keyid}`);
      }
      return undefined;
    });
  }

  /**
   * Extract the key id from a payload.
   * @param payload The payload to extract the key id.
   * @returns The key id.
   */
  static getKeyId(payload: string): string {
    const decrypted: any = jwt.decode(payload, { complete: true });
    if (decrypted && decrypted.header && decrypted.header.kid) {
      return decrypted.header.kid;
    }
    return this._DEFAULT_NO_KEY_ID;
  }

  /**
   * Return the header matching a key id.
   * @param keyId The key id.
   * @returns The header matching the key id.
   */
  static getHeader(keyId: string): jwt.SignOptions | undefined {
    this.init();
    return this._HEADER.find(({ keyid: kid }) => kid === keyId);
  }

  /**
   * Initialize the headers and secrets from environment variables.
   */
  static init(): void {
    if (!this._HAS_PARSED) {
      this.parseFromEnv();
    }
    this._HAS_PARSED = true;
  }

  /**
   * Return all the headers.
   * @returns All the headers.
   */
  static getHeaders(): jwt.SignOptions[] {
    this.init();
    return this._HEADER;
  }

  /**
   * Return all the secrets.
   * @returns All the secrets.
   */
  static getSecrets(): any {
    this.init();
    return this._SECRET;
  }

  /**
   * Return the default key id.
   * @returns The default key id.
   */
  static get NO_KEY_ID() {
    return this._DEFAULT_NO_KEY_ID;
  }
}

export default JwtHelper;
