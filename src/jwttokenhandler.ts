// import { ErrorParams } from './../lib/bearertoken.error.d';
// @ts-ignore: Object is possibly 'null'.
'use strict';

//  const _ = require('lodash');
import * as _ from 'lodash';
// const BearerTokenError = require('./errors/bearer-token-error')
import * as JWT from 'jsonwebtoken';
import * as JWKS from 'jwks-rsa';
import { BearerTokenError } from './bearertoken.error';
import { JwksResolver } from './jwksresolver';
// import { BearerTokenError,ErrorParams } from "./bearertoken.error";
import { ErrorParams } from './bearertoken.error';
import { logger } from './logger';
import { AuthenticatedPrincipal } from './models/authenticated.principal';
const methods = {
  HEADER: 'HEADER',
  QUERY: 'QUERY',
  FORM_BODY: 'FORM_BODY',
};
export interface JwtTokenOptionsJson {
  realm: string;
  audience: string;
  scopes_claim_name: string;
  issuer: string;
  clock_tolerance: number;
  algorithms: string[];
  methods: string[];
  scopes: string[];
  jwks_options: JWKS.Options;
}

export class JwtTokenOptions {
  realm: string;
  audience: string;
  scopesClaimName: string;
  issuer: string;
  clockTolerance: number;
  algorithms: string[];
  methods: string[];
  scopes: string[];
  jwksOptions: JWKS.Options;
  constructor(data: JwtTokenOptionsJson) {
    (this.realm = data.realm),
      (this.scopes = data.scopes),
      (this.algorithms = data.algorithms),
      (this.audience = data.audience),
      (this.clockTolerance = data.clock_tolerance),
      (this.methods = data.methods),
      (this.jwksOptions = data.jwks_options),
      (this.issuer = data.issuer),
      (this.scopesClaimName = data.scopes_claim_name);
  }
}
export class JwtTokenHandler {
  _tokenOptions: JwtTokenOptions;
  _tokenResolver: JwksResolver;
  constructor(options: JwtTokenOptions) {
    this._tokenOptions = options;
    if (!options) {
      throw new TypeError('options is a required argument to verify a token');
    }
    if (!options.issuer) {
      throw new TypeError('options.issuer is a required argument to verify a token');
    }
    if (!options.audience) {
      throw new TypeError('options.audience is a required argument to verify a token');
    }

    if (!options.jwksOptions) {
      throw new TypeError('options.jwks or options.jwksUrl is a required argument to verify a token');
    }

    this._tokenResolver = new JwksResolver(options.jwksOptions);
  }
  get issuer() {
    return this._tokenOptions.issuer;
  }

  get audience() {
    return this._tokenOptions.audience;
  }

  get realm() {
    return this._tokenOptions.realm;
  }

  get scopes() {
    return this._tokenOptions.scopes;
  }

  get scopesClaimName() {
    return this._tokenOptions.scopesClaimName;
  }

  async verifyToken(
    token: string,
    callback: (error: ErrorParams, decoded?: any) => void,
  ): Promise<AuthenticatedPrincipal | undefined> {
    const decodedJwt: JWT.Jwt | null = JWT.decode(token, { complete: true });
    // let authenticatedPrincipal: AuthenticatedPrincipal | undefined;
    logger.info('Inside VerifyToken Method!!');
    if (!_.isObject(decodedJwt)) {
      callback({
        realm: '',
        errorCode: 'invalid_token',
        description: 'The token is not a valid JSON Web Token (JWT)',
        uri: 'https://tools.ietf.org/html/rfc7519',
      });
    }

    logger.info('Verifying JWT bearer token => %j', decodedJwt);
    if (decodedJwt && decodedJwt.header === null) {
      callback({
        realm: '',
        errorCode: 'invalid_token',
        description: 'The token must specify a JOSE header',
        uri: 'https://tools.ietf.org/html/rfc7519',
      });
    }
    logger.info('JOSE Header check successful!!');
    if (decodedJwt && decodedJwt.header.alg !== 'RS256') {
      callback({
        realm: '',
        errorCode: 'invalid_token',
        description: 'The token must specify a valid signature algorithm',
        uri: 'https://tools.ietf.org/html/rfc7519',
      });
    }
    logger.info('RSA Algorithm check successful!!');
    if (decodedJwt && !this._tokenOptions.algorithms.includes(decodedJwt.header.alg)) {
      callback({
        realm: '',
        errorCode: 'invalid_token',
        description: 'The token must specify a valid signature algorithm',
        uri: 'https://tools.ietf.org/html/rfc7519',
      });
    }
    logger.info('Header Algorighm check successful!!');
    if (decodedJwt && decodedJwt.header.kid?.length === 0) {
      callback({
        realm: '',
        errorCode: 'invalid_token',
        description: 'The token must specify a "kid" (key ID) header parameter',
        uri: 'https://tools.ietf.org/html/rfc7519',
      });
    }
    logger.info('KID check successful!!');

    const result = await this.getSigningKey(decodedJwt!.header.kid!);

    logger.info('Signing Key Returned Successful!!!');
    //const jwtDecoded = this.verify(token, result, callback);

    const authenticatedPrincipal = this.verify(token, result, callback);
    // logger.info('Verification Successful!!!');
   

    // logger.info('Returning decoded JWT Successful!!!');
    // logger.info('Decoded JWT = ' + JSON.stringify(jwtDecoded));
    // const authenticatedPrincipal = new AuthenticatedPrincipal({
    //   subject: jwtDecoded.sub!,
    //   given_name: jwtDecoded.cn,
    //   family_name: jwtDecoded.client_id,
    //   access_token: token,
    //   email: jwtDecoded.email,
    //   groups: jwtDecoded.groups,
    //   is_authenticated: true,
    //   attributes: {},
    // });

    logger.info('Decoded Principal  = ' + JSON.stringify(authenticatedPrincipal));
    return authenticatedPrincipal;
  }

  async getSigningKey(kid: string): Promise<JWKS.CertSigningKey | JWKS.RsaSigningKey> {
    logger.info('Signing Key Kid: ' + kid);
    const value = await this._tokenResolver.getSigningKey(kid).then((result) => {
      logger.info('Key Result:' + JSON.stringify(result));
      return result;
    });
    logger.info('Signing Key : ' + JSON.stringify(value));
    return value;
  }
  verify(token: string, key: any, callback: (error: ErrorParams) => void): any {
    let invalidToken:any = false;
    let errorParams: ErrorParams = {};
    let decod: JWT.JwtPayload|any = {};
    let principal:AuthenticatedPrincipal = {};
    JWT.verify(token, key.getPublicKey(), (err: any, decoded: any) => {
      if (err) {
        logger.error('Unable to verify token due to error %s', err.message);
        
        if (err instanceof JWT.TokenExpiredError) {
          invalidToken = true;
          errorParams = {
            realm: '',
            errorCode: 'invalid_token',
            description: 'The token is expired',
            uri: 'https://tools.ietf.org/html/rfc7519',
          };
          callback(errorParams);

          // callback({
          //   realm: '',
          //   errorCode: 'invalid_token',
          //   description: 'The token is expired',
          //   uri: 'https://tools.ietf.org/html/rfc7519',
          // });
        } else if (err instanceof JWT.NotBeforeError) {
          callback({
            realm: '',
            errorCode: 'invalid_token',
            description: 'The token is valid in the future',
            uri: 'https://tools.ietf.org/html/rfc7519',
          });
        } else {
          callback({
            realm: '',
            errorCode: 'invalid_token',
            description: 'The token is not valid',
            uri: 'https://tools.ietf.org/html/rfc7519',
          });
        }
      }

      logger.info('Invalid Token : ' + invalidToken);

      logger.info('Error Params : ' + JSON.stringify(errorParams));

      decod = decoded;
      logger.info('Claims Json: ' + JSON.stringify(decoded));

      logger.info('Claims Json: ' + JSON.stringify(decod));
    });

    logger.info('Invalid Token A : ' + invalidToken);

    logger.info('Error Params A : ' + JSON.stringify(errorParams));

    // logger.info('Authenticated JWT : ' + JSON.stringify(JWT.decode(token)));
    logger.info('Authenticated JWT : ' + JSON.stringify(decod));
    logger.info('Authenticated JWT : ' + JSON.stringify(errorParams));


    
    //return JWT.decode(token);
    decod = JWT.decode(token);
    logger.info('Decod After JWT : ' + JSON.stringify(decod));
    if(errorParams.errorCode ==='invalid_token'){
      principal = new AuthenticatedPrincipal({
        subject: decod.sub!,
        given_name: decod.cn,
        family_name: decod.client_id,
        access_token: token,
        email: decod.email,
        groups: decod.groups,
        is_authenticated: false,
        attributes: {},
      });
    }else{
      principal = new AuthenticatedPrincipal({
        subject: decod.sub!,
        given_name: decod.cn,
        family_name: decod.client_id,
        access_token: token,
        email: decod.email,
        groups: decod.groups,
        is_authenticated: true,
        attributes: {},
      });

    }

    // return decod;
    return principal;
  }
}
