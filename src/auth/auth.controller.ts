import { Body, Controller, HttpException, Post } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService, private userService: UsersService) {}

  @Post('login')
  async login(@Body() body) {
    const auth = await this.authService.login(body);
    if (auth.status !== 200) {
      throw new HttpException(auth.msg, auth.status);
    }
    return auth.msg;
  }

  @Post('register')
  async register(@Body() body) {
    const auth = await this.authService.register(body);
    if (auth.status !== 201) {
      throw new HttpException(auth.content, auth.status);
    }
    return auth.content;
  }

  @Post('refresh-token')
  async refreshToken(@Body('refreshToken') refreshToken: string) {
    const auth = await this.authService.refreshAccessToken(refreshToken);
    if (auth.status !== 200) {
      throw new HttpException(auth.msg, auth.status);
    }
    return auth.msg;
  }
}
