import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import * as nodemailer from 'nodemailer';
import { createHash, randomBytes } from 'crypto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly jwtSecret: string;
  private readonly transporter: nodemailer.Transporter | null;
  private readonly frontendUrl: string;
  private readonly resetTokenTtlMs = 15 * 60 * 1000;

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private jwtService: JwtService,
  ) {
    const secret = this.configService.get<string>('JWT_SECRET');
    if (!secret) {
      throw new Error('JWT_SECRET is not defined in environment variables');
    }
    this.jwtSecret = secret;

    const emailHost = this.configService.get<string>('EMAIL_HOST');
    const emailUser = this.configService.get<string>('EMAIL_USER');
    const emailPass = this.configService.get<string>('EMAIL_PASS');
    if (emailHost && emailUser && emailPass) {
      const port = Number(this.configService.get<string>('EMAIL_PORT') ?? 587);
      this.transporter = nodemailer.createTransport({
        host: emailHost,
        port,
        secure: port === 465,
        auth: {
          user: emailUser,
          pass: emailPass,
        },
      });
    } else {
      this.transporter = null;
      this.logger.warn(
        'Email transporter is not fully configured. Email features are disabled.',
      );
    }
    //BU URL FRONTEND'İN URL'Sİ SONRADAN METHODLARDA FORMLARA YONLENDIRECEGIZ

    this.frontendUrl =
      this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3000';
  }

  // REGISTER
  async register(email: string, password: string) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      throw new ConflictException('Email is already registered');
    }

    if (!password || password.length < 6) {
      throw new BadRequestException(
        'Password must be at least 6 characters long',
      );
    }

    const hashed = await bcrypt.hash(password, 12);

    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashed,
        ...(this.transporter ? {} : { isEmailVerified: true }),
      },
      select: {
        id: true,
        email: true,
        isEmailVerified: true,
        createdAt: true,
      },
    });

    if (this.transporter) {
      const verificationToken = this.jwtService.sign(
        { sub: user.id, type: 'email_verification' },
        { secret: this.jwtSecret, expiresIn: '1d' },
      );

      await this.sendVerificationEmail(user.email, verificationToken);
      this.logger.log(`Verification email queued for ${user.email}`);

      return {
        message: 'User registered. Verification email sent.',
        user,
      };
    }

    this.logger.warn(
      'Email verification skipped because transporter is not configured.',
    );
    return {
      message:
        'User registered. Email verification disabled in this environment.',
      user,
    };
  }

  // EMAIL DOGRULAMA
  async verifyEmail(token: string) {
    try {
      const payload = this.jwtService.verify<{ sub: number; type?: string }>(
        token,
        { secret: this.jwtSecret },
      );

      if (payload.type && payload.type !== 'email_verification') {
        throw new UnauthorizedException('Invalid token type');
      }

      await this.prisma.user.update({
        where: { id: payload.sub },
        data: { isEmailVerified: true },
      });

      this.logger.log(`Email verified for user ID ${payload.sub}`);
      return { message: 'Email verified successfully' };
    } catch (e) {
      this.logger.warn(`Failed email verification attempt: ${e.message}`);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  private async sendVerificationEmail(email: string, token: string) {
    if (!this.transporter) {
      this.logger.warn(
        'Attempted to send verification email without transporter configuration.',
      );
      return;
    }

    const url = `${this.frontendUrl}/auth/verify-email?token=${token}`;

    try {
      await this.transporter.sendMail({
        from:
          this.configService.get<string>('EMAIL_FROM') ??
          '"Mini SaaS" <no-reply@minisaas.com>',
        to: email,
        subject: 'Verify your email',
        html: `<p>Please verify your email by clicking <a href="${url}">here</a>.</p>`,
      });
    } catch (error) {
      this.logger.error(
        `Failed to send verification email to ${email}`,
        error as Error,
      );
    }
  }

  // LOGIN
  async login(email: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        password: true,
        isEmailVerified: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (this.transporter && !user.isEmailVerified) {
      throw new UnauthorizedException('Email not verified');
    }

    const token = this.jwtService.sign(
      { sub: user.id, email: user.email, type: 'access_token' },
      { secret: this.jwtSecret, expiresIn: '7d' },
    );

    return {
      access_token: token,
      user: {
        id: user.id,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
      },
    };
  }

  // PASSWORD RESET
  async resetPassword(token: string, newPassword: string) {
    if (!newPassword || newPassword.length < 6) {
      throw new BadRequestException(
        'Password must be at least 6 characters long',
      );
    }

    const tokenHash = this.hashToken(token);
    const now = new Date();

    const resetToken = await this.prisma.passwordResetToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!resetToken || !resetToken.user) {
      this.logger.warn('Password reset attempted with invalid token');
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (resetToken.usedAt) {
      this.logger.warn(
        `Password reset attempted with already used token (id: ${resetToken.id})`,
      );
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (resetToken.expiresAt.getTime() < now.getTime()) {
      this.logger.warn(
        `Password reset attempted with expired token (id: ${resetToken.id})`,
      );
      throw new UnauthorizedException('Invalid or expired token');
    }

    const hashed = await bcrypt.hash(newPassword, 12);

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: resetToken.userId },
        data: { password: hashed },
      }),
      this.prisma.passwordResetToken.update({
        where: { id: resetToken.id },
        data: { usedAt: now },
      }),
      this.prisma.passwordResetToken.deleteMany({
        where: {
          userId: resetToken.userId,
          id: { not: resetToken.id },
        },
      }),
    ]);

    this.logger.log(`Password reset for user ID ${resetToken.userId}`);
    return { message: 'Password reset successful' };
  }

  async requestPasswordReset(email: string) {
    if (!this.transporter) {
      throw new BadRequestException('Email service is not configured');
    }

    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      this.logger.warn(
        `Password reset requested for non-existing email ${email}`,
      );
      return { message: 'If the email exists, a reset link has been sent.' };
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.resetTokenTtlMs);
    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(rawToken);

    await this.prisma.$transaction([
      this.prisma.passwordResetToken.deleteMany({
        where: {
          userId: user.id,
          OR: [{ usedAt: { not: null } }, { expiresAt: { lt: now } }],
        },
      }),
      this.prisma.passwordResetToken.create({
        data: {
          userId: user.id,
          tokenHash,
          expiresAt,
        },
      }),
    ]);

    await this.sendPasswordResetEmail(user.email, rawToken);
    this.logger.log(`Password reset email queued for ${user.email}`);

    return { message: 'If the email exists, a reset link has been sent.' };
  }
  private async sendPasswordResetEmail(email: string, token: string) {
    if (!this.transporter) {
      this.logger.warn(
        'Attempted to send reset email without transporter configuration.',
      );
      return;
    }

    const url = `${this.frontendUrl}/auth/reset-password?token=${token}`;

    try {
      await this.transporter.sendMail({
        from:
          this.configService.get<string>('EMAIL_FROM') ??
          '"Mini SaaS" <no-reply@minisaas.com>',
        to: email,
        subject: 'Reset your password',
        html: `<p>Reset your password by clicking <a href="${url}">here</a>.</p>`,
      });
    } catch (error) {
      this.logger.error(
        `Failed to send reset email to ${email}`,
        error as Error,
      );
    }
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
