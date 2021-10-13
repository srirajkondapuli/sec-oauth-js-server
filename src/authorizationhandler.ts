import { AuthenticatedPrincipal } from './models/authenticated.principal';
import { Request, Response, NextFunction } from 'express';

import { logger } from './logger';


import { Rbac } from './rbac';
export class AuthorizationHandler{
    authorize(res:Response) {
        const rbac = new Rbac();
        logger.debug('Inside Authorize filter function');
        const authenticatedPrincipal: AuthenticatedPrincipal = res.locals.user;
        logger.info('Authorized Principal : ' + JSON.stringify(authenticatedPrincipal,null,1));
        logger.info('Role Based Access Control: ' + JSON.stringify(rbac));

        const permission = rbac.isUserAuthorized(authenticatedPrincipal, 'create', 'profile');

        return permission;
      }
    
}
