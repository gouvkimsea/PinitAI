import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import prisma from '../../database/client';
import { config } from '../../config';
import { generateApiKey, hashApiKey } from '../../utils/helpers';
import { UserRole } from '../../types';

export interface RegisterDTO {
  email: string;
  password: string;
}

export interface LoginDTO {
  email: string;
  password: string;
}

export class AuthService {
  /**
   * Registers a new user account with hashed password, API key, and JWT token
   */
  async register(dto: RegisterDTO) {
    const email = dto.email.toLowerCase().trim();
    const existing = await prisma.user.findUnique({
      where: { email },
    });

    if (existing) {
      throw new Error('USER_ALREADY_EXISTS');
    }

    const passwordHash = await bcrypt.hash(dto.password, 12);
    const rawApiKey = generateApiKey();
    const apiKeyHash = hashApiKey(rawApiKey);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        apiKeyHash,
        role: 'user',
      },
    });

    const token = this.generateToken(user.id, user.email, user.role);

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        api_key: rawApiKey,
      },
      token,
    };
  }

  /**
   * Authenticates an existing user and returns JWT token
   */
  async login(dto: LoginDTO) {
    const email = dto.email.toLowerCase().trim();
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new Error('INVALID_CREDENTIALS');
    }

    const isValid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isValid) {
      throw new Error('INVALID_CREDENTIALS');
    }

    const token = this.generateToken(user.id, user.email, user.role);

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      token,
    };
  }

  /**
   * Regenerates a new API key for the user
   */
  async regenerateApiKey(userId: string) {
    const rawApiKey = generateApiKey();
    const apiKeyHash = hashApiKey(rawApiKey);

    await prisma.user.update({
      where: { id: userId },
      data: { apiKeyHash },
    });

    return rawApiKey;
  }

  generateToken(id: string, email: string, role: string): string {
    return jwt.sign(
      { id, email, role },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn } as jwt.SignOptions
    );
  }

  verifyToken(token: string): { id: string; email: string; role: UserRole } {
    return jwt.verify(token, config.jwtSecret) as { id: string; email: string; role: UserRole };
  }
}

export const authService = new AuthService();
