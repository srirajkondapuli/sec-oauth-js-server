'use strict';
import { logger } from '../logger';
/*
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
Object.defineProperty(exports, '__esModule', { value: true });

/**
 * Represents an Access Token request.
 * For more information look at:
 * https://tools.ietf.org/html/rfc6749#section-4.1.3
 */
import { StringMap } from './types';
export enum AuthTypeEnum {
  basic = 'Basic',
  bearer = 'Bearer',
}
export type AuthTokenType = 'Basic' | 'Bearer';
export interface AuthRequestJson {
  method: string;
  base_url: string;
  body: string;
  cookies: string[];
  headers: any;
  host_name: string;
  ip: string;
  origin: string;
  req_params: StringMap;
  query_params: any;
  path: string;
  protocol: string;
  status: number | undefined;
  auth_info?: AuthInfo;
}
export class AuthInfo {
  tokenType: string;
  token?: string;
  user?: string;
  password?: string;
  constructor(data: AuthInfoJson) {
    this.token = data.token;
    this.tokenType = data.token_type;
    this.user = data.user;
    this.password = data.password;
  }
}
export interface AuthInfoJson {
  token_type: string;
  token?: string;
  user?: string;
  password?: string;
}
export class AuthRequest {
  method: string;
  baseUrl: string;
  body: string;
  cookies: string[];
  headers: any;
  hostName: string;
  ip: string;
  origin: string;
  reqParams: StringMap;
  queryParams: any;
  path: string;
  protocol: string;
  status: number | undefined;
  authInfo?: AuthInfo;

  constructor(request: AuthRequestJson) {
    this.method = request.method;
    this.baseUrl = request.base_url;
    this.body = request.body;
    this.cookies = request.cookies;
    this.headers = request.headers;
    this.ip = request.ip;
    this.origin = request.origin;
    this.reqParams = request.req_params;
    this.queryParams = request.query_params;
    this.path = request.path;
    this.protocol = request.protocol;
    this.status = request.status;
    this.hostName = request.host_name;
    this.authInfo = request.auth_info;
  }

  toJson(): AuthRequestJson {
    return {
      method: this.method,
      base_url: this.baseUrl,
      body: this.body,
      cookies: this.cookies,
      headers: this.headers,
      ip: this.ip,
      origin: this.origin,
      req_params: this.reqParams,
      query_params: this.queryParams,
      path: this.path,
      protocol: this.protocol,
      status: this.status,
      host_name: this.hostName,
      auth_info: this.authInfo,
    };
  }
  toStringMap(): StringMap {
    const json = this.toJson();
    logger.debug(json);
    return json as any;
  }
}
