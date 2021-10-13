import * as JWT from 'jsonwebtoken';
import { logger } from './logger';
export interface ErrorParams {
  realm?: string;
  errorCode?: string;
  description?: string;
  uri?: string;
}
export class BearerTokenError {
  handleError = (errorParams: ErrorParams, payload?: JWT.JwtPayload) => {
    logger.info(errorParams);
    logger.info('Authenticated Principal Json:' + JSON.stringify(payload));
  };
  // testCallback = (name:string) => {

  //     console.log('Hello' + name);
  // }
}
