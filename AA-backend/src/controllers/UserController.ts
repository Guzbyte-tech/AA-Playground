import { CreateUserDTO } from '../dtos/CreateUserDTO';
import { UpdateUserDTO } from '../dtos/UpdateUserDTO';
import { User } from '../entities/User';
import { UserService } from './../services/UserService';
import { Request, Response } from 'express';

export class UserController {

    private userService: UserService
    constructor() {
        this.userService = new UserService();
    }

    getUserByWalletAddress =async (req: Request, res: Response): Promise<void> => {
        try {
            const walletAddress: string = req.params.walletAddress;
            const user: User | null = await this.userService.getUserByWalletAddress(walletAddress);
            res.status(200).json(user);
        } catch (error) {
            console.log(error);
            this.handleError(res, error);
        }
    }

    getUserById =async (req: Request, res: Response): Promise<void> => {
        try {
            const id: string = req.params.id;
            const user: User | null = await this.userService.getUserById(id);
            res.status(200).json(user);
        } catch (error) {
            console.log(error);
            this.handleError(res, error);
        }
    }

    getAllUsers = async (req: Request, res: Response): Promise<void> => {
        try {
            const users: User[] = await this.userService.getAllUsers();
            res.status(200).json(users);
        } catch (error) {
            console.log(error);
            this.handleError(res, error);
        }
    }

    updateUser =async (req: Request, res: Response): Promise<void> => {
        try {
            const id: string = req.params.id;
            const updateData: UpdateUserDTO = req.body;
            const user: User | null = await this.userService.updateUser(id, updateData);
            res.status(200).json(user);
        } catch (error) {
            console.log(error);
            this.handleError(res, error);
        }
    }

    deleteUser = async (req: Request, res: Response): Promise<void> => {
        try {
            const id: string = req.params.id;
            const user: User | null = await this.userService.deleteUser(id);
            res.status(200).json(user);
        } catch (error) {
            console.log(error);
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