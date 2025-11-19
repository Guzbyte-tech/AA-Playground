import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../entities/User';
import AppDataSource from '../config/db';

// Extend the Express Request type to include your user
export interface AuthRequest extends Request {
  user?: User;
}

// Middleware to verify the token and attach user
export const authMiddleware = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ success: false, message: 'Missing Authorization header' });
    }

    const token = authHeader.split(' ')[1]; // Expect "Bearer <token>"
    if (!token) {
      return res.status(401).json({ success: false, message: 'Token missing' });
    }

    const secret = process.env.JWT_SECRET!;
    const decoded = jwt.verify(token, secret) as { userId: string | number };

    const userRepo = AppDataSource.getRepository(User);
    const user = await userRepo.findOne({ where: { id: String(decoded.userId) } });

    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};
