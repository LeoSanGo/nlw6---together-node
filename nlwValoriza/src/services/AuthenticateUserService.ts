import { getCustomRepository } from 'typeorm';
import { sign } from 'jsonwebtoken';
import { compare } from 'bcryptjs';
import { UserRepositories } from '../repositories/UsersRepositories';

interface IAuthenticateRequest {
  email: string;
  password: string;
}

class AuthenticateUserService {
  async execute({ email, password }: IAuthenticateRequest) {
    const userRepositories = getCustomRepository(UserRepositories);

    const user = await userRepositories.findOne({
      email,
    });

    if (!user) {
      throw new Error('Email/Password incorrect');
    }

    const passwordMatch = await compare(password, user.password);

    if (!passwordMatch) {
      throw new Error('Email/Password Incorrect');
    }

    const token = sign(
      {
        email: user.email,
      },
      '3c3c1868c31c040300c7e3a04f47b9a1',
      {
        subject: user.id,
        expiresIn: '1d',
      }
    );
    return token;
  } 
}

export { AuthenticateUserService };
