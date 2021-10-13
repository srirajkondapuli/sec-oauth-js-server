import { AuthenticatedPrincipal } from './models/authenticated.principal';

import { JwtTokenHandler, JwtTokenOptions } from './jwttokenhandler';
import { ExpressTransformer } from './express.transformer';
import { Request, response } from 'express';
import { logger } from './logger';
import { BearerTokenError } from './bearertoken.error';

export class Transformer {
  async transform(req: Request, tokenOptions: JwtTokenOptions): Promise<AuthenticatedPrincipal | any> {
    logger.info('Inside Transformer filter function');
    let principal: AuthenticatedPrincipal | undefined;
    const platform: string = 'express';
    switch (platform) {
      case 'express':
        logger.debug('Express Transformation');
        const expressTransformer = new ExpressTransformer();
        const authReq = expressTransformer.transform(req);
        logger.debug(JSON.stringify(authReq));

        logger.info('Token Options : ' + JSON.stringify(tokenOptions));
        const tokenHandler = new JwtTokenHandler(tokenOptions);
        const token: string | any = authReq?.authInfo?.token;
        principal = await tokenHandler.verifyToken(token, new BearerTokenError().handleError);

        break;
      case 'someframework':
        logger.debug('Some Framework');
        break;
      default:
        logger.debug('Express Transformation');
        break;
    }
    return principal;
  }
}


