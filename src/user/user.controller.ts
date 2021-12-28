import { BadRequestException, Body, Controller, Get, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { response, Response } from 'express';
import { Request } from "express"

@Controller('user')
export class UserController {
    constructor(
        private userService: UserService,
        private jwtService: JwtService
    ) { }

    @Post()
    async create(
        @Body('username')
        username: string,
        @Body('password')
        password: string,
    ) {
        const saltOrRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltOrRounds);

        const user = await this.userService.create({
            username,
            password: hashedPassword
        });
        delete user.password;

        return user;
    }

    @Post('login')
    async login(
        @Body('username')
        username: string,
        @Body('password')
        password: string,
        @Res({ passthrough: true }) response: Response
    ) {
        const user = await this.userService.findOne({ username });

        if (!user) {
            throw new BadRequestException('invalid credentials');
        }

        if (!await bcrypt.compare(password, user.password)) {
            throw new BadRequestException('invalid credentials')
        }

        const jwt = await this.jwtService.signAsync({ id: user.id });

        response.cookie('jwt', jwt, { httpOnly: true });


        return {
            message: 'success'
        };
    }

    @Get()
    async user(@Req() request: Request) {
        console.log(request.cookies);

        try {
            const cookie = request.cookies['jwt'];

            const data = await this.jwtService.verifyAsync(cookie);

            if (!data) {
                throw new UnauthorizedException();
            }

            const user = await this.userService.findOne({ id: data['id'] });

            const { password, ...result } = user;

            return result;
        } catch (e) {
            throw new UnauthorizedException();
        }
    }

    @Post('logout')
    async logout(@Res({ passthrough: true }) response: Response) {
        response.clearCookie('jwt');

        return {
            message: 'success'
        }
    }
}
