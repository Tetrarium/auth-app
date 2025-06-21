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
import {
  AuthentificatedRequest,
  RefreshTokenRequest,
} from './entities/autentificationRequest.entity';
import { AccessTokenGuard } from './common/guards/accessToken.guard';
import { RefreshTokenGuard } from './common/guards/refreshToken.guard';
import { Response } from 'express';
import { setRefreshTokenCookie } from './helpers/setRefreshTokenCookie';
import { clearRefreshTokenCookie } from './helpers/clearRefreshTokenCookie';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken } =
      await this.authService.signUp(createUserDto);

    setRefreshTokenCookie(res, refreshToken);

    return { accessToken };
  }

  @Post('signin')
  async signin(
    @Body() data: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    console.log('signin', data);
    const { accessToken, refreshToken } = await this.authService.signIn(data);
    console.log(accessToken);

    setRefreshTokenCookie(res, refreshToken);

    return { accessToken };
  }

  @UseGuards(AccessTokenGuard)
  @Post('logout')
  logout(
    @Req() req: AuthentificatedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    clearRefreshTokenCookie(res);

    return this.authService.logout(req.user.sub);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refreshTokens(
    @Req() req: RefreshTokenRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { sub: userId, refreshToken } = req.user;
    const { accessToken, refreshToken: newRefreshToken } =
      await this.authService.refreshTokens(userId, refreshToken);

    setRefreshTokenCookie(res, newRefreshToken);

    return { accessToken };
  }
}
