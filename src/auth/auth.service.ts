import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  verifyUser(data: any) {
    return 'Verify user';
  }

  loginUser(data: any) {
    return 'Login user';
  }

  registerUser(data: any) {
    return 'Register user';
  }
}
