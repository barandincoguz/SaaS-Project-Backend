import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  //KULLANICI GETİRME İŞLEMİ
  async getUserById(userId: number) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        createdAt: true,
      },
    });
  }
  //KULLANICI GÜNCELLEME İŞLEMİ
  async updateUser(userId: number, dto: { email?: string; password?: string }) {
    const data: any = {};
    if (dto.email) data.email = dto.email;
    if (dto.password) data.password = await bcrypt.hash(dto.password, 10);

    return this.prisma.user.update({
      where: { id: userId },
      data,
      select: { id: true, email: true, createdAt: true },
    });
  }
  //KULLANICI SİLME İŞLEMİ
  async deleteUser(userId: number) {
    await this.prisma.user.delete({
      where: { id: userId },
    });
  }
}
