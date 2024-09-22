import { HttpStatus, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginUserDto, RegisterUserDto } from './dto';
import { CustomRpcException } from 'src/common/exceptions/rpc.exception';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

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

      return {
        user: newUser,
      };
    } catch (error) {
      throw new CustomRpcException({
        statusCode: HttpStatus.BAD_REQUEST,
        error: 'Bad Request',
        message: error.message,
      });
    }
  }

  loginUser(loginUserDto: LoginUserDto) {
    return loginUserDto;
  }

  verifyUser(data: any) {
    return 'Verify user';
  }
}
