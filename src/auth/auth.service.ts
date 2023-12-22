import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async login(dto: AuthDto) {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException("Credentails didn't match");
    const isPWMatched = await argon.verify(user.hash, dto.password);
    if (!isPWMatched) throw new ForbiddenException("Password didn't match");
    return this.token(user.id, user.email);
  }

  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      return this.token(user.id, user.email);
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Email Already Exists');
        }
      }
      throw err;
    }
  }

  async token(
    userId: number,
    email: string,
  ): Promise<{ token: string; id: number }> {
    const data = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const generatedToken = await this.jwt.signAsync(data, {
      expiresIn: '15m',
      secret: secret,
    });
    return {
      id: userId,
      token: generatedToken,
    };
  }
}
