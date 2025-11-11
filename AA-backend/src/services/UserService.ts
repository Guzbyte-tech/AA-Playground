import { Repository } from "typeorm";
import AppDataSource from "../config/db";
import { User } from "../entities/User";
import { CreateUserDTO } from "../dtos/CreateUserDTO";
import { validate } from "class-validator";
import { verifyMessage } from "ethers";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

export class UserService {
    private userRepo: Repository<User>;
    constructor() {
        this.userRepo = AppDataSource.getRepository(User);
        dotenv.config();
    }

    async createUser(data: CreateUserDTO): Promise<{ user: User; token: string }> {
        const dto = Object.assign(new CreateUserDTO(), data);

        const recoveredAddress = verifyMessage(dto.message, dto.signature);

        if (recoveredAddress.toLowerCase() !== dto.walletAddress.toLowerCase()) {
            throw new Error("Invalid signature");
        }

        if (await this.userRepo.findOneBy({ walletAddress: dto.walletAddress })) {
            throw new Error("User already exists");
        }

        const user = this.userRepo.create(dto);
        const savedUser = await this.userRepo.save(user);

        // const payload = {
        //     id: savedUser.id,
        //     email: savedUser.email,
        //     walletAddress: savedUser.walletAddress,
        //     role: savedUser.role,
        //     username: savedUser.username,
        //     profileImage: savedUser.profileImage,
        //     name: savedUser.name,
        //     rewardPoints: savedUser.rewardPoints,
        //     totalStreams: savedUser.totalStreams,
        //     totalStreamTime: savedUser.totalStreamTime,
        //     uniqueListeners: savedUser.uniqueListeners
        // };

        const JWT_SECRET = process.env.JWT_SECRET;
        if (!JWT_SECRET) throw new Error("JWT_SECRET is not defined");

        const token = jwt.sign({ savedUser }, JWT_SECRET, { expiresIn: "1d" });

        return { user: savedUser, token };

    }

    async getUserByWalletAddress(walletAddress: string): Promise<User | null> {
        return await this.userRepo.findOneBy({ walletAddress });
    }

    async getAllUsers(): Promise<User[]> {
        return await this.userRepo.find();
    }

    async getUserById(id: string): Promise<User | null> {
        return await this.userRepo.findOneBy({ id });
    }

    async updateUser(id: string, data: Partial<User>): Promise<User | null> {
        const user = await this.userRepo.findOneBy({ id });
        if (!user) {
            throw new Error("User not found");
        }

        if(data.walletAddress && data.walletAddress !== user.walletAddress) {
            const existingUser = await this.userRepo.findOneBy({ walletAddress: data.walletAddress });
            if (existingUser) {
                throw new Error("User already exists");
            }
        }

        if(data.email && data.email !== user.email) {
            const existingUser = await this.userRepo.findOneBy({ email: data.email });
            if (existingUser) {
                throw new Error("User already exists");
            }
        }

        if(data.username && data.username !== user.username) {
            const existingUser = await this.userRepo.findOneBy({ username: data.username });
            if (existingUser) {
                throw new Error("User already exists");
            }
        }

        Object.assign(user, data);
        return await this.userRepo.save(user);
    }

    async deleteUser(id: string): Promise<User | null> {
        const user = await this.userRepo.findOneBy({ id });
        if (!user) {
            throw new Error("User not found");
        }
        return await this.userRepo.remove(user);
    }

}