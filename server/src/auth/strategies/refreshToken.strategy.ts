import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

interface RequestWithRefreshToken extends Request {
  cookies: {
    refreshToken?: string;
  };
}

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private readonly configService: ConfigService) {
    const jwtSecret = configService.get<string>('JWT_REFRESH_SECRET');
    if (!jwtSecret) {
      throw new Error('JWT_REFRESH_SECRET is not defined');
    }
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: RequestWithRefreshToken) => {
          const token = request.cookies?.refreshToken;
          if (!token) {
            return null;
          }

          return token;
        },
      ]),
      secretOrKey: jwtSecret,
      passReqToCallback: true,
    });
  }

  validate<T extends Record<string, unknown>>(
    req: RequestWithRefreshToken,
    payload: T,
  ) {
    const refreshToken = req.cookies?.refreshToken;
    return { ...payload, refreshToken };
  }
}
