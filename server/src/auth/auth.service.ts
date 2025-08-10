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
import {
  RefreshToken,
  RefreshTokenDocument,
} from './schemas/refresh-token.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Tokens } from './types/tokens.types';

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

    return await this.issueTokensAndSave(userId, newUser.username);
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

    return await this.issueTokensAndSave(user._id.toHexString(), user.username);
  }

  async logout(userId: string, token: string) {
    const user = await this.usersService.findById(userId);

    if (!user) {
      throw new ForbiddenException('Access Denied');
    }

    const storedTokens = await this.refreshTokenModel.find({ user: userId });

    const matchedToken = await this.findMatchingToken(storedTokens, token);

    if (!matchedToken) {
      throw new ForbiddenException('Access Denied');
    }

    await this.revokeRefreshToken(matchedToken._id);
    return { message: 'Logout from all devices successful' };
  }

  async logoutAllDevices(userId: string) {
    await this.refreshTokenModel.deleteMany({ user: userId });
    return { massage: 'Logout successful' };
  }

  async refreshTokens(userId: string, oldToken: string) {
    const user = await this.usersService.findById(userId);

    if (!user) {
      throw new ForbiddenException('Access Denied');
    }

    const storedTokens = await this.refreshTokenModel.find({ user: userId });

    const matchedToken = await this.findMatchingToken(storedTokens, oldToken);

    if (!matchedToken) {
      throw new ForbiddenException('Access Denied');
    }

    await this.revokeRefreshToken(matchedToken._id);

    return this.issueTokensAndSave(userId, user.username);
  }

  private async issueTokensAndSave(
    userId: string,
    username: string,
  ): Promise<Tokens> {
    const tokens = await this.generateTokens(userId, username);
    await this.saveRefreshToken(userId, tokens.refreshToken);
    return tokens;
  }

  private async saveRefreshToken(userId: string, token: string) {
    const tokenHash = await this.hashData(token);

    await this.refreshTokenModel.create({ user: userId, tokenHash });
  }

  private async revokeRefreshToken(tokenId: Types.ObjectId): Promise<void> {
    await this.refreshTokenModel.findByIdAndDelete(tokenId);
  }

  private async findMatchingToken(
    tokens: RefreshTokenDocument[],
    rawToken: string,
  ): Promise<RefreshTokenDocument | null> {
    for (const tokenDoc of tokens) {
      const isMatch = await argon.verify(tokenDoc.tokenHash, rawToken);

      if (isMatch) {
        return tokenDoc;
      }
    }

    return null;
  }

  private async generateTokens(userId: string, username: string) {
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

  private hashData(data: string) {
    return argon.hash(data);
  }
}
