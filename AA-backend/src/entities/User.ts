import { IsEmail } from "class-validator";
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Unique,
} from "typeorm";

export enum UserRole {
  LISTENER = "listener",
  ARTIST = "artist",
  ADMIN = "admin",
}

@Entity("users")
@Unique(["walletAddress", "email", "username"])
export class User {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ nullable: true })
  profileImage?: string;

  @Column({
    type: "enum",
    enum: UserRole,
    default: UserRole.LISTENER,
  })
  role!: UserRole;

  @Column()
  walletAddress!: string;

  @Column({ unique: true, nullable: true })
  username?: string;

  @Column({ unique: true, nullable: true })
  name?: string;

  @Column({ unique: true, nullable: true })
  @IsEmail()
  email?: string;

  @Column("float", { default: 0 })
  rewardPoints!: number;

  @Column("int", { default: 0 })
  totalStreams!: number;

  @Column("int", { default: 0 })
  totalStreamTime!: number;

  @Column("int", { default: 0 })
  uniqueListeners!: number;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
