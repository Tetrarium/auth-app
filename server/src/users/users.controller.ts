import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  NotFoundException,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { AccessTokenGuard } from 'src/auth/common/guards/accessToken.guard';
import { sanitizeUser } from './common/sanitize-user';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    const user = await this.usersService.create(createUserDto);
    return sanitizeUser(user);
  }

  @Get()
  async findAll() {
    const users = await this.usersService.findAll();
    return users.map(sanitizeUser);
  }

  @UseGuards(AccessTokenGuard)
  @Get('me')
  async findMe(@CurrentUser('sub') userId: string) {
    console.log('userId:', userId);
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return sanitizeUser(user);
  }

  @Get(':id')
  async findById(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return sanitizeUser(user);
  }

  @UseGuards(AccessTokenGuard)
  @Patch('me')
  async update(
    @CurrentUser('sub') userId: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    const user = await this.usersService.update(userId, updateUserDto);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return sanitizeUser(user);
  }

  @UseGuards(AccessTokenGuard)
  @Delete('me')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@CurrentUser('sub') userId: string) {
    const user = await this.usersService.remove(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
  }
}
