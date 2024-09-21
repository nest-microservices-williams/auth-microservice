import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern } from '@nestjs/microservices';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  async registerUser(data: any) {
    return this.authService.registerUser(data);
  }

  @MessagePattern('auth.login.user')
  async loginUser(data: any) {
    return this.authService.loginUser(data);
  }

  @MessagePattern('auth.verify.user')
  async verifyUser(data: any) {
    return this.authService.verifyUser(data);
  }
}
