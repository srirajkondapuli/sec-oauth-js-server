
import { AuthenticatedPrincipal } from './models/authenticated.principal';
import { Request, Response, NextFunction } from 'express';

import { logger } from './logger';
import { Transformer } from './transformer';
import { JwtTokenOptions } from './jwttokenhandler';

export class AuthenticationHandler{

    authenticate = async (req: Request, tokenOptions: JwtTokenOptions) : Promise<AuthenticatedPrincipal | any> => {
        const issuerUrl = process.env.ISSUER;
        const audience = process.env.AUDIENCE;
        const jwks = process.env.JWKSURI;
    
        logger.info(`Issuer URl: ${issuerUrl}, Audience: ${audience}, JWKS URI: ${jwks}`);

        logger.info('Inside Authenticate filter function');
    
        const transformer = new Transformer();
        logger.info('Token Options : ' + JSON.stringify(tokenOptions));
        const principal:AuthenticatedPrincipal = await transformer.transform(req, tokenOptions);
        return principal;

      }

}
