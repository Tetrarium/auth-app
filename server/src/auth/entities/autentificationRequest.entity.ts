import { Request } from 'express';

interface JwtPayload {
  sub: string;
  username: string;
}

export interface AutentificationRequest extends Request {
  user: JwtPayload;
}
