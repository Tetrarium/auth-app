import { AuthService } from 'src/auth/auth.service';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { Test, TestingModule } from '@nestjs/testing';
import { Types } from 'mongoose';

interface MockUser {
  _id: Types.ObjectId;
  name: string;
  username: string;
  password: string;
  toObject(this: MockUser): Omit<MockUser, 'toObject'>;
}

const sanitizeUser = (
  user: MockUser,
): Omit<MockUser, 'toObject' | 'password'> => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, ...safeUser } = user.toObject();

  return safeUser;
};

function createMockUser(overrides?: Partial<MockUser>): MockUser {
  return {
    _id: '1' as unknown as Types.ObjectId,
    name: 'John Doe',
    username: 'johndoe',
    password: 'password',
    toObject: function (this: MockUser) {
      return {
        _id: this._id,
        username: this.username,
        name: this.name,
        password: this.password,
      };
    },
    ...overrides,
  };
}

describe('UserController', () => {
  let controller: UsersController;
  let usersService: Partial<Record<keyof UsersService, jest.Mock>>;
  let authService: Partial<Record<keyof AuthService, jest.Mock>>;

  beforeEach(async () => {
    usersService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findById: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
    };

    authService = {
      logoutAllDevices: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        { provide: UsersService, useValue: usersService },
        { provide: AuthService, useValue: authService },
      ],
    }).compile();

    controller = module.get<UsersController>(UsersController);
  });

  describe('create', () => {
    it('should create a user and return sanitized user', async () => {
      const mockUser = createMockUser();
      usersService.create!.mockResolvedValue(mockUser);

      const result = await controller.create({
        username: 'johndoe',
        password: 'password',
        name: 'John Doe',
      });

      expect(usersService.create).toHaveBeenCalledWith({
        username: 'johndoe',
        password: 'password',
        name: 'John Doe',
      });

      expect(result).toEqual(sanitizeUser(mockUser));
    });
  });
});
