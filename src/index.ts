import { Request, Response, NextFunction } from 'express';
import { configure, getLogger } from 'log4js';
const logger = getLogger();
logger.level = 'debug';

export class AppAuthMiddleware {
  async authenticate(req: Request, res: Response, next: NextFunction) {
    logger.debug('Inside Authenticate filter function');

    next();
  }
  async authorize(req: Request, res: Response, next: NextFunction) {
    logger.debug('Inside Authorize filter function');
    next();
  }
}

export default new AppAuthMiddleware();
