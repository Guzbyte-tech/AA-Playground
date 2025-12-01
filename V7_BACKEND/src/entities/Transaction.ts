import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, UpdateDateColumn } from 'typeorm';
import { User } from './User';

export enum TxStatus {
    PENDING = 'pending',
    CONFIRMED = 'confirmed',
    FAILED = 'failed'
}

@Entity('transactions')
export class Transaction {
    @PrimaryGeneratedColumn('uuid')
    id!: string;

    @Column({ name: 'user_op_hash', unique: true })
    userOpHash!: string;

    @Column({ name: 'from_address' })
    fromAddress!: string;

    @Column({ name: 'to_address' })
    toAddress!: string;

    @Column()
    amount!: string;

    @Column({ type: 'enum', enum: TxStatus, default: TxStatus.PENDING })
    status!: TxStatus;

    @Column({ nullable: true, name: 'tx_hash' })
    txHash!: string;

    @Column({ type: 'text', nullable: true, name: 'block_number' })
    blockNumber!: string | null;

    @ManyToOne(() => User)
    user!: User;

    @CreateDateColumn()
    createdAt!: Date;
    
    @UpdateDateColumn()
    updatedAt!: Date;
}