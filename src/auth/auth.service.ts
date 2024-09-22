import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { CustomRpcException } from 'src/common/exceptions/rpc.exception';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginUserDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {
  private readonly expirationTime = 60000; // 1 minute

  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  private signJwtToken(payload: JwtPayload) {
    return this.jwtService.signAsync(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;
    try {
      const user = await this.prismaService.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new Error('User already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = await this.prismaService.user.create({
        data: { name, email, password: hashedPassword },
        select: { id: true, name: true, email: true },
      });

      const payload: JwtPayload = {
        ...newUser,
        userExpiresIn: Date.now() + this.expirationTime,
      };

      const token = await this.signJwtToken(payload);

      return {
        user: newUser,
        token,
      };
    } catch (error) {
      throw new CustomRpcException({
        statusCode: HttpStatus.BAD_REQUEST,
        error: 'Bad Request',
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.prismaService.user.findUnique({
        where: { email },
        select: { id: true, name: true, email: true, password: true },
      });

      if (!user) {
        throw new CustomRpcException({
          statusCode: HttpStatus.UNAUTHORIZED,
          error: 'Unauthorized',
          message: 'Invalid credentials',
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        throw new CustomRpcException({
          statusCode: HttpStatus.UNAUTHORIZED,
          error: 'Unauthorized',
          message: 'Invalid credentials',
        });
      }

      delete user.password;

      const payload: JwtPayload = {
        ...user,
        userExpiresIn: Date.now() + this.expirationTime,
      };

      const token = await this.signJwtToken(payload);

      return {
        user,
        token,
      };
    } catch (error) {
      throw new CustomRpcException({
        statusCode: HttpStatus.BAD_REQUEST,
        error: 'Bad Request',
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token);

      if (this.isTokenExpired(payload.userExpiresIn)) {
        const user = await this.getUserById(payload.id);
        return this.refreshToken(user);
      }

      return this.refreshToken(payload);
    } catch (error) {
      throw new CustomRpcException({
        statusCode: HttpStatus.UNAUTHORIZED,
        error: 'Unauthorized',
        message: 'Invalid token',
      });
    }
  }

  private isTokenExpired(expiresIn: number): boolean {
    return Date.now() > expiresIn;
  }

  private async getUserById(id: string) {
    const user = await this.prismaService.user.findUnique({
      where: { id },
      select: { id: true, name: true, email: true },
    });

    if (!user) {
      throw new CustomRpcException({
        statusCode: HttpStatus.UNAUTHORIZED,
        error: 'Unauthorized',
        message: 'User not found',
      });
    }

    return user;
  }

  private async refreshToken(user: Omit<JwtPayload, 'userExpiresIn'>) {
    const newUser = { id: user.id, name: user.name, email: user.email };
    const newPayload: JwtPayload = {
      ...newUser,
      userExpiresIn: Date.now() + this.expirationTime,
    };

    const newToken = await this.signJwtToken(newPayload);

    return {
      user: newUser,
      token: newToken,
    };
  }
}
