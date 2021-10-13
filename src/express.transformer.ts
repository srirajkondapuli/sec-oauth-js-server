import { JwtTokenOptions } from './jwttokenhandler';
import { AuthTokenType } from './models/auth.request';
/* tslint:disable:no-string-literal */
import { AuthRequestJson, AuthRequest } from './models/auth.request';
import { Request } from 'express';

import { logger } from './logger';
import { Base64, fromBase64 } from 'js-base64';
import { AuthTypeEnum } from './models/auth.request';
import { AuthInfo } from './models/auth.request';
export class ExpressTransformer {
  transform(req: Request): AuthRequest {
    logger.debug('Inside Transformer filter function');

    const authRequest = new AuthRequest({
      method: req.method,
      body: req.body,
      ip: req.ip,
      origin: req.originalUrl,
      path: req.path,
      req_params: req.params,
      query_params: req.query,
      protocol: req.protocol,
      host_name: req.hostname,
      cookies: req.cookies,
      status: req.statusCode,
      base_url: req.baseUrl,
      headers: req.headers,
    });
    logger.debug(JSON.stringify(authRequest.headers));
    const authHeader = String(authRequest.headers['authorization']);
    if (authHeader) {
      logger.debug('Authentication Header Found!!');
      logger.debug('Authorization Header Value 1 : ' + authHeader);
      const basicAuthValue = authHeader.split(' ')[1].trim();
      const authType = authHeader.split(' ')[0].trim();
      logger.debug('Authorization Header Type 2 : ' + authType);
      logger.debug('Authorization Header Value 2 : ' + basicAuthValue);

      if (authType === AuthTypeEnum.basic) {
        const authHeaderValue = fromBase64(basicAuthValue);
        logger.debug(`Authorization Header Value : ${authHeaderValue}`);
        const authHeaderArray = authHeaderValue.split(':');
        const authInfo = new AuthInfo({
          token_type: AuthTypeEnum.basic,
          user: authHeaderArray[0].trim(),
          password: authHeaderArray[1].trim(),
        });
        authRequest.authInfo = authInfo;
      } else if (authType === AuthTypeEnum.bearer) {
        const authInfo = new AuthInfo({
          token_type: AuthTypeEnum.bearer,
          token: basicAuthValue,
        });
        authRequest.authInfo = authInfo;
      }
    }

    return authRequest;
  }
}

export default new ExpressTransformer();
