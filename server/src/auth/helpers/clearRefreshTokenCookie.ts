import { Response } from 'express';

export const clearRefreshTokenCookie = (res: Response) => {
  res.clearCookie('refreshToken', { path: '/auth/refresh' });
};
