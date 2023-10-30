import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UsersDTO } from './dto/create-user.dto';
import { User } from './entities/user.entity';

// This should be a real class/interface representing a user entity
// export type User = any;

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private readonly usersRepository: Repository<User>) {}

  create(createUserDto: UsersDTO): Promise<User> {
    const user = new User();

    user.name = createUserDto.name;
    user.email = createUserDto.email;
    user.password = createUserDto.password;

    return this.usersRepository.save(user);
  }

  async storeRefreshToken(email: string, token: string): Promise<void> {
    const user = await this.usersRepository.findOne({ email });
    if (!user) {
      throw new Error('User not found');
    }
    user.refreshToken = token;
    await this.usersRepository.save(user);
  }

  async getRefreshToken(email: string): Promise<string | undefined> {
    const user = await this.usersRepository.findOne({ email });
    return user ? user.refreshToken : undefined;
  }

  async findAll(): Promise<User[]> {
    return this.usersRepository.find();
  }

  findOne(email: string): Promise<User> {
    return this.usersRepository.findOne({
      email,
    });
  }

  async remove(id: string): Promise<void> {
    await this.usersRepository.delete(id);
  }
}
