import { Sequelize } from "sequelize-typescript";
import dotenv from "dotenv";
dotenv.config();

export const db = new Sequelize(process.env.DB_URL, {
    dialectOptions: {
        ssl: {
            require: false
        }
    }
});