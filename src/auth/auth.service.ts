import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compareSync, hashSync } from 'bcryptjs';
import { UsersDTO } from 'src/users/dto/create-user.dto';
import { validate } from 'class-validator';
import { LoggerService } from 'src/logger/logger.service';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly logger: LoggerService = new Logger(AuthService.name),
    private jwtService: JwtService,
    private userservice: UsersService,
  ) {}

  async login(user: any): Promise<Record<string, any>> {
    let isOk = false;

    const userDTO = new UsersDTO();
    userDTO.email = user.email;
    userDTO.password = user.password;

    const errors = await validate(userDTO);
    if (errors.length > 0) {
      this.logger.debug(`${errors}`);
      throw new Error('Validation failed');
    } else {
      isOk = true;
    }

    if (isOk) {
      const userDetails = await this.userservice.findOne(user.email);
      if (userDetails == null) {
        return { status: 401, msg: { msg: 'Invalid credentials' } };
      }

      const isValid = compareSync(user.password, userDetails.password);
      if (isValid) {
        const accessToken = this.jwtService.sign({ email: user.email }, { expiresIn: '1h' });
        const refreshToken = this.jwtService.sign({ email: user.email, isRefreshToken: true }, { expiresIn: '7d' });
        await this.userservice.storeRefreshToken(user.email, refreshToken);
        return {
          status: 200,
          msg: {
            email: user.email,
            access_token: accessToken,
            refresh_token: refreshToken,
          },
        };
      } else {
        return { status: 401, msg: { msg: 'Invalid credentials' } };
      }
    }
  }
  async register(body: any): Promise<Record<string, any>> {
    let isOk = false;
    const userDTO = new UsersDTO();
    userDTO.email = body.email;
    userDTO.name = body.name;
    userDTO.password = hashSync(body.password, 10);

    const errors = await validate(userDTO);
    if (errors.length > 0) {
      this.logger.debug(`${errors}`);
    } else {
      isOk = true;
    }
  
    if (isOk) {
      await this.userservice.create(userDTO).catch((error) => {
        this.logger.debug(error.message);
        isOk = false;
      });
      if (isOk) {
        // 회원가입이 성공한 후에 토큰 생성
        const accessToken = this.jwtService.sign({ email: body.email }, { expiresIn: '1h' });
        const refreshToken = this.jwtService.sign({ email: body.email, isRefreshToken: true }, { expiresIn: '7d' });
        await this.userservice.storeRefreshToken(body.email, refreshToken);
  
        return {
          status: 200,
          content: {
            msg: 'User created with success',
            access_token: accessToken,
            refresh_token: refreshToken,
          },
        };
      } else {
        return { status: 400, content: { msg: 'User already exists' } };
      }
    } else {
      return { status: 400, content: { msg: 'Invalid content' } };
    }
  }

  async refreshAccessToken(oldRefreshToken: string): Promise<Record<string, any>> {
    try {
      const payload = this.jwtService.verify(oldRefreshToken, { ignoreExpiration: false });

      if (payload.isRefreshToken) {
        const storedRefreshToken = await this.userservice.getRefreshToken(payload.email);
        if (storedRefreshToken !== oldRefreshToken) {
          throw new Error('Mismatched refresh token');
        }

        const newAccessToken = this.jwtService.sign({ email: payload.email }, { expiresIn: '1h' });
        const newRefreshToken = this.jwtService.sign({ email: payload.email, isRefreshToken: true }, { expiresIn: '7d' });

        await this.userservice.storeRefreshToken(payload.email, newRefreshToken);

        return {
          status: 200,
          msg: {
            access_token: newAccessToken,
            refresh_token: newRefreshToken,
          },
        };
      } else {
        throw new Error('Invalid token');
      }
    } catch (e) {
      this.logger.error(`Failed to refresh token: ${e.message}`);
      return { status: 401, msg: { msg: 'Invalid token or token expired' } };
    }
  }
}
