import { AuthorizationHandler } from './authorizationhandler';
import {AuthenticationHandler} from './authenticationhandler';
import { AuthenticatedPrincipal } from './models/authenticated.principal';
import { Request, Response, NextFunction } from 'express';


import { logger } from './logger';

import { JwtTokenOptions } from './jwttokenhandler';

import { Rbac } from './rbac';
export class AppAuthMiddleware {


  
  async authenticate(req: Request, res: Response, next: NextFunction) {
    const issuerUrl = process.env.ISSUER;
    const audience = process.env.AUDIENCE;
    const jwks = process.env.JWKSURI;

    logger.info(`Issuer URl: ${issuerUrl}, Audience: ${audience}, JWKS URI: ${jwks}`);
    const tokenOptions = new JwtTokenOptions({
      issuer: issuerUrl!,
      scopes: ['email', 'openid'],
      scopes_claim_name: 'scope',
      audience: audience!,
      clock_tolerance: 1000,
      methods: ['GET', 'POST'],
      algorithms: ['RS256', 'DSA', 'RSASHA256'],
      realm: '',
      jwks_options: {
        jwksUri: jwks!,
        cache: false,
        timeout: 5000,
      },
    });
    logger.debug('Inside Authenticate filter function');



    const authenticationHandler = new AuthenticationHandler();

    const principal:AuthenticatedPrincipal = await authenticationHandler.authenticate(req,tokenOptions);
    if(!principal.isAuthenticated){
      return res.status(403).json({
        error: "You are not Authenticated!!"
       });
    }
    logger.info('Setting Authentication Principal ' + JSON.stringify(principal));
    res.locals.user = principal;
    next();
  }
  async authorize(req: Request, res: Response, next: NextFunction) {
    const rbac = new Rbac();
    logger.debug('Inside Authorize filter function');
    const authenticatedPrincipal: AuthenticatedPrincipal = res.locals.user;
    logger.info('Authorized Principal : ' + JSON.stringify(authenticatedPrincipal,null,1));
    logger.info('Role Based Access Control: ' + JSON.stringify(rbac));

    const authorizationHandler = new AuthorizationHandler();

    const permission = authorizationHandler.authorize(res);

    logger.info("Did Grant Permission : " + JSON.stringify(permission));

    if (!permission.granted) {
      return res.status(401).json({
       error: "You don't have enough permission to perform this action"
      });
     }
    next();
  }
}


