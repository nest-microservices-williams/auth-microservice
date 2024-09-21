import { Injectable } from '@nestjs/common';
import { LoginUserDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {
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
