import { plainToInstance } from 'class-transformer';
import { CreateUserDTO } from '../dtos/CreateUserDTO';
import { JWTDTO } from '../dtos/JWTDTO';
import { UpdateUserDTO } from '../dtos/UpdateUserDTO';
import { User } from '../entities/User';
import { AuthService } from '../services/AuthService';
import { UserService } from './../services/UserService';
import { Request, Response } from 'express';
import { validate } from 'class-validator';
import { formatValidationErrors } from '../utils/helpers';

export class AuthController {

    private userService: UserService
    private authService: AuthService;
    
    constructor() {
        this.userService = new UserService();
        this.authService = new AuthService();
    }

    register = async(req: Request, res: Response) => {
        try {
            if (!req.body || Object.keys(req.body).length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "Request body is required" 
                });
            }

            // Check for required fields before transformation
            const requiredFields = ['role', 'walletAddress', 'signature', 'message', 'email'];
            const missingFields = requiredFields.filter(field => !req.body[field]);
            
            if (missingFields.length > 0) {
                return res.status(400).json({
                    success: false, 
                    message: `Missing required fields: ${missingFields.join(', ')}` 
                });
            }

            // Transform with explicit options
            const userData = plainToInstance(CreateUserDTO, req.body, {
                enableImplicitConversion: true
            });

            console.log("Transformed userData:", userData);

            // Validate the transformed data
            const errors = await validate(userData);
            if (errors.length > 0) {
                console.log("Validation errors:", errors);
                const formatted = formatValidationErrors(errors);
                return res.status(422).json(formatted);
            }

            // Create user
            const user = await this.userService.createUser(userData);
            res.status(201).json({success: true, message: "User created successfully", user});
            
        } catch (error) {
            console.error("Register error:", error);     
            this.handleError(res, error);
        }
    }

    login = async (req: Request, res: Response) => {
        try {
            if (!req.body || Object.keys(req.body).length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "Request body is required" 
                });
            }

             // Check for required fields before transformation
            const requiredFields = ['role', 'walletAddress', 'signature', 'message'];
            const missingFields = requiredFields.filter(field => !req.body[field]);
            
            if (missingFields.length > 0) {
                return res.status(400).json({
                    success: false, 
                    message: `Missing required fields: ${missingFields.join(', ')}` 
                });
            }
            
            const loginData = plainToInstance(JWTDTO, req.body, {
                enableImplicitConversion: true
            });

            const errors = await validate(loginData);
            if (errors.length > 0) {
                console.log("Validation errors:", errors);
                const formatted = formatValidationErrors(errors);
                return res.status(422).json(formatted);
            }
            const user = await this.authService.login(loginData);
            res.status(200).json({success: true, message: "User logged in successfully", user});
            
        } catch (error) {
            console.error("Login error:", error);
            this.handleError(res, error);
        }
    }

    private handleError(res: Response, error: unknown): void {
        if (error instanceof Error) {
            console.error("Handled Error:", error.message, error.stack);
            
            res.status(400).json({ message: error.message });
        } else if (typeof error === 'string') {
            console.error("String Error:", error);
            res.status(400).json({ message: error });
        } else {
            console.error("Unknown Error:", error);
            res.status(500).json({ message: "Internal server error" });
        }
    }
}