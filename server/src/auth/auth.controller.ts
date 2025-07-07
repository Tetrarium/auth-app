import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { AuthDto } from './dto/auth.dto';
import { AccessTokenGuard } from './common/guards/accessToken.guard';
import { RefreshTokenGuard } from './common/guards/refreshToken.guard';
import { Response } from 'express';
import {
  clearRefreshTokenCookies,
  setRefreshTokenCookies,
} from './helpers/refreshTokenCookie.helper';
import {
  AuthentificatedRequest,
  RefreshTokenRequest,
} from './types/auth-request.types';
import { Tokens } from './types/tokens.types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(
    @Body() dto: CreateUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.signUp(dto);
    return this.handleAuthResponse(res, tokens);
  }

  @Post('signin')
  async signin(
    @Body() dto: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.signIn(dto);
    return this.handleAuthResponse(res, tokens);
  }

  @UseGuards(AccessTokenGuard)
  @Post('logout')
  logout(
    @Req() req: RefreshTokenRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { sub } = req.user;
    const refreshToken = req.cookies?.refreshToken as string;

    clearRefreshTokenCookies(res);
    return this.authService.logout(sub, refreshToken);
  }

  @UseGuards(AccessTokenGuard)
  @Post('logout/all')
  logoutAllDevices(
    @Req() req: AuthentificatedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const userId = req.user.sub;

    clearRefreshTokenCookies(res);
    return this.authService.logoutAllDevices(userId);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refreshTokens(
    @Req() req: RefreshTokenRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { sub: userId, refreshToken: currentRefreshToken } = req.user;
    const tokens = await this.authService.refreshTokens(
      userId,
      currentRefreshToken,
    );

    setRefreshTokenCookies(res, tokens.refreshToken);

    return this.handleAuthResponse(res, tokens);
  }

  private handleAuthResponse(res: Response, tokens: Tokens) {
    setRefreshTokenCookies(res, tokens.refreshToken);

    return { accessToken: tokens.accessToken };
  }
}
