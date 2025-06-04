import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { AuthDto } from './dto/auth.dto';
import {
  AuthentificatedRequest,
  RefreshTokenRequest,
} from './entities/autentificationRequest.entity';
import { AccessTokenGuard } from './common/guards/accessToken.guard';
import { RefreshTokenGuard } from './common/guards/refreshToken.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() createUserDto: CreateUserDto) {
    return this.authService.signUp(createUserDto);
  }

  @Post('signin')
  signin(@Body() data: AuthDto) {
    return this.authService.signIn(data);
  }

  @UseGuards(AccessTokenGuard)
  @Post('logout')
  logout(@Req() req: AuthentificatedRequest) {
    return this.authService.logout(req.user.sub);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  refreshTokens(@Req() req: RefreshTokenRequest) {
    const { sub: userId, refreshToken } = req.user;
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
