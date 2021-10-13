import * as Jwks from 'jwks-rsa';
import { logger } from './logger';
export class JwksResolver {
  _jwksClient: Jwks.JwksClient;
  constructor(options: Jwks.Options) {
    this._jwksClient = new Jwks.JwksClient(options);
  }

  getKeys() {
    return this._jwksClient.getKeys();
  }

  getSigningKeys() {
    return this._jwksClient.getSigningKeys();
  }

  getSigningKey(kid: string) {
    logger.info('Inside JWKS Key resolver');
    return this._jwksClient.getSigningKey(kid).then((response) => {
      logger.debug('Key Response: ' + JSON.stringify(response));
      return response;
    });
  }
}
