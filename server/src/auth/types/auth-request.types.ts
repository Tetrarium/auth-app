import { Request } from 'express';

interface JwtPayload {
  sub: string;
  username: string;
}

export interface AuthentificatedRequest extends Request {
  user: JwtPayload;
}

export interface RefreshTokenRequest extends AuthentificatedRequest {
  user: JwtPayload & { refreshToken: string };
}
