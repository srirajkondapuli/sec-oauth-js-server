import { StringMap } from './types';
export interface AuthenticatedPrincipalJson {
  subject: string;
  given_name: string;
  family_name: string;
  email: string;
  access_token: string;
  groups: string;
  attributes: StringMap;
  is_authenticated: boolean;
}
export class AuthenticatedPrincipal {
  subject?: string;
  givenName?: string;
  familyName?: string;
  email?: string;
  groups?: string;
  accessToken?: string;
  attributes?: StringMap;
  isAuthenticated?: boolean = false;
  constructor(data: AuthenticatedPrincipalJson) {
    this.subject = data.subject;
    this.familyName = data.family_name;
    this.givenName = data.given_name;
    this.email = data.email;
    this.groups = data.groups;
    this.accessToken = data.access_token;
    this.attributes = data.attributes;
    this.isAuthenticated = data.is_authenticated;
  }
}
