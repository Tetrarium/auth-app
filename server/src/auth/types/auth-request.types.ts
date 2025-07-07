import { Request } from 'express';
import { JwtPayload } from './jwt-payload.types';

export interface AuthentificatedRequest extends Request {
  user: JwtPayload;
}

export interface RefreshTokenRequest extends AuthentificatedRequest {
  user: JwtPayload & { refreshToken: string };
}
