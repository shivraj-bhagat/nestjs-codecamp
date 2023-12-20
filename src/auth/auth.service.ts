import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  login() {
    return {
      msg: 'hi, login',
    };
  }

  signup() {
    return {
      msg: 'hi, sign up',
    };
  }
}
