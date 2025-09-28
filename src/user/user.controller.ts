import {
  Controller,
  Get,
  Req,
  UseGuards,
  Patch,
  Body,
  Delete,
} from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/jwt/jwt.guard';

@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getMe(@Req() req) {
    const user = await this.userService.getUserById(req.user.sub);
    return { user };
  }

  @UseGuards(JwtAuthGuard)
  @Patch('me')
  async updateMe(
    @Req() req,
    @Body() dto: { email?: string; password?: string },
  ) {
    return this.userService.updateUser(req.user.sub, dto);
  }
  @UseGuards(JwtAuthGuard)
  @Delete('me')
  async deleteMe(@Req() req) {
    // Kullanıcı silme işlemi için userService'e bir method ekleyebilirsiniz
    await this.userService.deleteUser(req.user.sub);
    return { message: 'User deleted successfully' };
  }
}
