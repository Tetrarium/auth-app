import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload } from 'src/auth/types/jwt-payload.types';

export const CurrentUser = createParamDecorator<
  keyof JwtPayload | undefined,
  ExecutionContext
>((data, ctx: ExecutionContext): any => {
  const request = ctx.switchToHttp().getRequest<{ user?: JwtPayload }>();

  const user = request.user;

  return data ? user?.[data] : user;
});
