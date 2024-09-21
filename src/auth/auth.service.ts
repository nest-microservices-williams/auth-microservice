import { Injectable } from '@nestjs/common';
import { LoginUserDto, RegisterUserDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

  registerUser(registerUserDto: RegisterUserDto) {
    return registerUserDto;
  }

  loginUser(loginUserDto: LoginUserDto) {
    return loginUserDto;
  }

  verifyUser(data: any) {
    return 'Verify user';
  }
}
