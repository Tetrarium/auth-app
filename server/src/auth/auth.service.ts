import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as argon from 'argon2';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { UsersService } from 'src/users/users.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './entities/autentificationRequest.entity';
import {
  RefreshToken,
  RefreshTokenDocument,
} from './schemas/refresh-token.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    @InjectModel(RefreshToken.name)
    private refreshTokenModule: Model<RefreshTokenDocument>,
  ) {}

  async signUp(createUserDto: CreateUserDto): Promise<Tokens> {
    const userExist = await this.usersService.findByUsername(
      createUserDto.username,
    );
    if (userExist) {
      throw new BadRequestException('User already exist');
    }

    const hashedPasword = await this.hashData(createUserDto.password);

    const newUser = await this.usersService.create({
      ...createUserDto,
      password: hashedPasword,
    });

    const userId = newUser._id.toHexString();
    console.log(userId);

    const tokens = await this.getTokens(userId, newUser.username);
    await this.updateRefreshToken(userId, tokens.refreshToken);

    return tokens;
  }

  async signIn(data: AuthDto) {
    const user = await this.usersService.findByUsernameWithCredentials(
      data.username,
    );
    console.log(user);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    const passwordMatches = await argon.verify(user.password, data.password);

    if (!passwordMatches) {
      throw new BadRequestException('Password is incorrect');
    }

    const tokens = await this.getTokens(user._id.toHexString(), user.username);
    await this.updateRefreshToken(user._id.toHexString(), tokens.refreshToken);

    return tokens;
  }

  async logout(userId: string) {
    await this.usersService.update(userId, { refreshToken: null });
    return { message: 'Logout successful' };
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.usersService.findByIdWithCredentials(userId);

    console.log(user);

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    const refreshTokenMatches = await argon.verify(
      user.refreshToken,
      refreshToken,
    );

    if (!refreshTokenMatches) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens(user._id.toHexString(), user.username);
    await this.updateRefreshToken(user._id.toHexString(), tokens.refreshToken);

    return tokens;
  }

  hashData(data: string) {
    return argon.hash(data);
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hashData(refreshToken);
    await this.usersService.update(userId, {
      refreshToken: hashedRefreshToken,
    });
  }

  async getTokens(userId: string, username: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }
}
