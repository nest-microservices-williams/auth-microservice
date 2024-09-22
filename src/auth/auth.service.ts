import { HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { CustomRpcException } from 'src/common/exceptions/rpc.exception';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginUserDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {
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

      const token = await this.signJwtToken(newUser);

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

      const token = await this.signJwtToken(user);

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

  verifyUser(data: any) {
    return 'Verify user';
  }
}
