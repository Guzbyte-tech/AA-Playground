// src/dtos/CreateUserDto.ts
import { IsEmail, IsEnum, IsOptional, IsString, IsNumber } from "class-validator";
import { UserRole } from "../entities/User";

export class CreateUserDTO {

  @IsOptional()
  @IsString()
  profileImage?: string;

  @IsEnum(UserRole)
  role!: UserRole;

  @IsString()
  walletAddress!: string;

  @IsString()
  @IsOptional()
  username?: string;

  @IsOptional()
  @IsString()
  name?: string;

  @IsEmail()
  email!: string;

  @IsOptional()
  @IsNumber()
  rewardPoints?: number;

  @IsOptional()
  @IsNumber()
  totalStreams?: number;

  @IsOptional()
  @IsNumber()
  totalStreamTime?: number;

  @IsOptional()
  @IsNumber()
  uniqueListeners?: number;

  @IsString()
  signature!: string;

  @IsString()
  message!: string;

}
