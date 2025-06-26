import { CookieOptions, Response } from 'express';

const baseCookieOptions: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: 'none',
  maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
};

const paths = ['/auth/refresh', '/auth/logout'];

export const setRefreshTokenCookies = (res: Response, refreshToken: string) => {
  paths.forEach((path) => {
    res.cookie('refreshToken', refreshToken, {
      ...baseCookieOptions,
      path,
    });
  });
};

export const clearRefreshTokenCookies = (res: Response) => {
  paths.forEach((path) => {
    res.clearCookie('refreshToken', { path });
  });
};
