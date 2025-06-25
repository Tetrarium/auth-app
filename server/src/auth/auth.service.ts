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
    private refreshTokenModel: Model<RefreshTokenDocument>,
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

    const tokens = await this.getTokens(userId, newUser.username);
    await this.createRefreshToken(userId, tokens.refreshToken);

    return tokens;
  }

  async signIn(data: AuthDto) {
    const user = await this.usersService.findByUsernameWithCredentials(
      data.username,
    );

    if (!user) {
      throw new BadRequestException('User not found');
    }

    const passwordMatches = await argon.verify(user.password, data.password);

    if (!passwordMatches) {
      throw new BadRequestException('Password is incorrect');
    }

    const tokens = await this.getTokens(user._id.toHexString(), user.username);
    await this.createRefreshToken(user._id.toHexString(), tokens.refreshToken);

    return tokens;
  }

  async logout(userId: string) {
    await this.usersService.update(userId, { refreshToken: null });
    return { message: 'Logout successful' };
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.usersService.findByIdWithCredentials(userId);

    if (!user) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens(userId, user.username);

    await this.updateRefreshToken(userId, refreshToken, tokens.refreshToken);

    return tokens;
  }

  hashData(data: string) {
    return argon.hash(data);
  }

  async createRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hashData(refreshToken);

    void this.refreshTokenModel.create({
      user: userId,
      tokenHash: hashedRefreshToken,
    });
  }

  async updateRefreshToken(
    userId: string,
    oldRefreshToken: string,
    newRefreshToken: string,
  ) {
    const hashedRefreshToken = await this.hashData(newRefreshToken);
    console.log('oldRefreshToken', oldRefreshToken);

    const tokenDocs = await this.refreshTokenModel.find({
      user: userId,
    });

    console.log('tokenDocs', tokenDocs);

    if (!tokenDocs || tokenDocs.length === 0) {
      throw new ForbiddenException('Access Denied');
    }

    const validToken = await Promise.any(
      tokenDocs.map(async (doc) => {
        const isMatch = await argon.verify(doc.tokenHash, oldRefreshToken);

        return isMatch ? doc : Promise.reject(new Error());
      }),
    ).catch(() => null);

    if (!validToken) {
      throw new ForbiddenException('Access Denied');
    }

    await this.refreshTokenModel.findByIdAndDelete(validToken._id);

    await this.createRefreshToken(userId, newRefreshToken);

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
