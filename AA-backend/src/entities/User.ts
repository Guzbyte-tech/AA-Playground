import { IsEmail } from "class-validator";
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Unique,
} from "typeorm";

@Entity("users")
export class User {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ unique: true })
  username!: string;

  @Column({ unique: true })
  email!: string;

  @Column({ name: "password_hash" })
  passwordHash!: string;

  @Column({ unique: true, name: "smart_account_address" })
  smartAccountAddress!: string;

  // IMPORTANT: Backend does NOT store device private key!
  // Only stores encrypted recovery data
  @Column({ type: "text", name: "encrypted_recovery_data" })
  encryptedRecoveryData!: string;

  @Column({ name: "decrypting_key" })
  decryptingKey!: string;

  @Column({ default: false, name: "is_account_deployed" })
  isAccountDeployed!: boolean;

  @Column({ type: "string" })
  salt!: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
