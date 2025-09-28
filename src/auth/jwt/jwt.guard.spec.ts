import { JwtAuthGuard } from './jwt.guard';
import { JwtService } from '@nestjs/jwt';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let jwtService: JwtService;

  beforeEach(() => {
    jwtService = {
      verify: jest.fn(),
    } as any;
    guard = new JwtAuthGuard(jwtService);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should throw UnauthorizedException when no auth header', () => {
    const mockContext = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: {},
        }),
      }),
    } as ExecutionContext;

    expect(() => guard.canActivate(mockContext)).toThrow(UnauthorizedException);
  });

  it('should throw UnauthorizedException when invalid token format', () => {
    const mockContext = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: {
            authorization: 'InvalidFormat',
          },
        }),
      }),
    } as ExecutionContext;

    expect(() => guard.canActivate(mockContext)).toThrow(UnauthorizedException);
  });

  it('should return true when valid token', () => {
    const mockPayload = { userId: 1, email: 'test@test.com' };
    (jwtService.verify as jest.Mock).mockReturnValue(mockPayload);

    const mockRequest = { headers: { authorization: 'Bearer validtoken' } };
    const mockContext = {
      switchToHttp: () => ({
        getRequest: () => mockRequest,
      }),
    } as ExecutionContext;

    const result = guard.canActivate(mockContext);

    expect(result).toBe(true);
    expect(mockRequest['user']).toEqual(mockPayload);
  });

  it('should throw UnauthorizedException when jwt verification fails', () => {
    (jwtService.verify as jest.Mock).mockImplementation(() => {
      throw new Error('Invalid token');
    });

    const mockContext = {
      switchToHttp: () => ({
        getRequest: () => ({
          headers: {
            authorization: 'Bearer invalidtoken',
          },
        }),
      }),
    } as ExecutionContext;

    expect(() => guard.canActivate(mockContext)).toThrow(UnauthorizedException);
  });
});
