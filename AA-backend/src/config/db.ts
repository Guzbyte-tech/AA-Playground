import "reflect-metadata";
import { DataSource } from "typeorm";
import dotenv from "dotenv";
import { User } from "../entities/User";
import { Transaction } from "../entities/Transaction";


dotenv.config();

const AppDataSource = new DataSource({
  type: "postgres",
  host: process.env.POSTGRES_HOST || "localhost",
  port: Number(process.env.POSTGRES_PORT || 5321),
  username: process.env.POSTGRES_USER || "postgres",
  password: process.env.POSTGRES_PASSWORD || "1234",
  database: process.env.POSTGRES_DATABASE || "erc4337",
  synchronize: true,
  dropSchema: false,
  ssl: false,
  logging: true,
  entities: [
    User,
    Transaction
  ],
  migrations: ["src/migrations/*.ts"],
  migrationsTableName: "migrations",
});

export default AppDataSource;
