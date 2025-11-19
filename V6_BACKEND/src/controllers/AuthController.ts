import { Request, Response } from 'express';
import { User } from '../entities/User';
import { AAService } from '../services/AAService';
import jwt from 'jsonwebtoken';
import AppDataSource from '../config/db';
import bcrypt from 'bcryptjs';

export class AuthController {
    private aaService: AAService;

    constructor() {
        this.aaService = new AAService();
    }

    async init() {
        await this.aaService.init();
    }

    /**
     * Register: User creates account on device, sends public key
     */
    register = async (req: Request, res: Response) => {
        try {
            const { username, email, password, ownerWalletAddress, decryptingKey } = req.body;

            console.log('\n New user registration');
            console.log('   Username:', username);
            console.log('   Device public key:', decryptingKey);
            console.log('   Owner address:', ownerWalletAddress);

            const userRepo = AppDataSource.getRepository(User);

            // Check existing user
            const existing = await userRepo.findOne({
                where: [{ username }, { email }]
            });

            if (existing) {
                return res.status(400).json({
                    success: false,
                    error: 'Username or email already exists'
                });
            }

            // Hash password
            const passwordHash = await bcrypt.hash(password, 12);

            // Create smart account (counterfactual)
            const {
                smartAccountAddress,
                encryptedRecoveryData,
                salt,
                salt_BigInt
            } = await this.aaService.createSmartAccount(
                username,
                ownerWalletAddress,
                decryptingKey
            );

            // Save user
            const user = userRepo.create({
                username,
                email,
                passwordHash,
                smartAccountAddress,
                ownerAddress: ownerWalletAddress,
                encryptedRecoveryData,
                decryptingKey,
                isAccountDeployed: false,
                salt,
                saltDecimal: salt_BigInt
            });

            await userRepo.save(user);

            // Generate JWT
            const token = jwt.sign(
                { userId: user.id },
                process.env.JWT_SECRET!,
                { expiresIn: '7d' }
            );

            console.log('User registered');
            console.log('Smart Account:', smartAccountAddress);
            console.log('Deployed:', false);

            res.status(201).json({
                success: true,
                data: {
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        smartAccountAddress: user.smartAccountAddress,
                        isAccountDeployed: user.isAccountDeployed
                    },
                    token
                }
            });
        } catch (error: any) {
            console.error('Registration error:', error);
            res.status(500).json({
                success: false,
                error: 'Registration failed',
                details: error.message
            });
        }
    };

    /**
     * Login
     */
    login = async (req: Request, res: Response) => {
        try {
            const { username, password } = req.body;

            const userRepo = AppDataSource.getRepository(User);
            const user = await userRepo.findOne({ where: { username } });

            if (!user) {
                return res.status(401).json({
                    success: false,
                    error: 'Invalid credentials'
                });
            }

            // Verify password
            const isValid = await bcrypt.compare(password, user.passwordHash);
            if (!isValid) {
                return res.status(401).json({
                    success: false,
                    error: 'Invalid credentials'
                });
            }

            // Generate JWT
            const token = jwt.sign(
                { userId: user.id },
                process.env.JWT_SECRET!,
                { expiresIn: '7d' }
            );

            res.json({
                success: true,
                data: {
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        smartAccountAddress: user.smartAccountAddress,
                        isAccountDeployed: user.isAccountDeployed
                    },
                    token
                }
            });
        } catch (error: any) {
            console.error('Login error:', error);
            res.status(500).json({
                success: false,
                error: 'Login failed'
            });
        }
    };

    /**
     * Profile
     */
    profile = async (req: Request, res: Response) => {
        try {
            const user = (req as any).user as User;
            res.json({
                success: true,
                data: {
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        smartAccountAddress: user.smartAccountAddress,
                        isAccountDeployed: user.isAccountDeployed
                    }
                }
            });
        } catch (error: any) {
            console.error('Profile error:', error);
            res.status(500).json({
                success: false,
                error: 'Profile failed'
            });
        }
    }
}
