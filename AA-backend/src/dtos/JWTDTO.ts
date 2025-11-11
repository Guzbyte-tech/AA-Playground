import { IsString } from "class-validator";
import { UserRole } from "../entities/User";
import { Column } from "typeorm";

export class JWTDTO {

    @IsString()
    walletAddress!: string;

    @IsString()
    signature!: string;

    @IsString()
    message!: string;

    @Column({
        type: "enum",
        enum: UserRole,
        default: UserRole.LISTENER,
    })
    role!: string;
};

