import { AuthenticatedPrincipal } from './models/authenticated.principal';
import { JwtTokenHandler, JwtTokenOptions } from './jwttokenhandler';
import { BearerTokenError } from './bearertoken.error';
import * as jwt from "jsonwebtoken";
import * as permissions from './permissions.json';
import { Rbac } from './rbac';
import XRegExp = require("xregexp")
console.log('Hello There!!');
const testStr = 'Basic aGVsbG86aGVsbG8=';
const newString = String(testStr);
console.log(newString.split(' ')[1].trim());
const pattern='^[A-Za-z0-9\\-_=]+\\.[A-Za-z0-9\\-_=]+(\\.[A-Za-z0-9\\-_.+/=]+)?$';

const regex = RegExp(pattern)
let value = 'aaa.bbb.ccc';
console.log(regex.test(value));
const xreg = XRegExp(pattern);

console.log(xreg.test(value));
const results = xreg.exec(value);
console.log(results);
const rbac = new Rbac();
console.log(rbac.isAuthorized('basic','create','profile'));
console.log('Is Granted : ' + rbac.isAuthorized('basic','create','profile').granted);

console.log(rbac.getGrants());
console.log(rbac.getRoles());
console.log('Permisions' + JSON.stringify(permissions));

