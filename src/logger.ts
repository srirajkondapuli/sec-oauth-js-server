import { configure, getLogger } from 'log4js';
import { environment } from './configuration/environment';
//console: { type: 'stdout', layout: { type: 'pattern', pattern: '%d %p %c %l %m%n' }},
//console: { type: 'stdout', layout: { type: 'coloured'}},
configure({

  appenders: {
    //console: { type: 'stdout', layout: { type: 'coloured'}},
    console: { type: 'stdout', layout: { type: 'pattern', pattern: '%d %[%p%] %c [%f:%l] %m%n' }},
    dateFile: {
      type: 'dateFile',
      filename: `${environment.logDir}/${environment.logFile}`,
      // filename: 'test.log',
      layout: { type: 'basic' },
      compress: true,
      daysToKeep: 14,
      keepFileExt: true,
    },
  },
  categories: {
    
    default: { appenders: ['console', 'dateFile'], level: environment.logLevel,enableCallStack:true },

    // default: { appenders: ['console', 'dateFile'], level: 'INFO' }
  },
  
});
export const logger = getLogger();
