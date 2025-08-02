import { AllowNull, Column, DataType, Default, HasMany, Model, Table, Unique } from "sequelize-typescript";
import Budget from "./Budget";

@Table({
    tableName: 'user'
})
class User extends Model {
    @AllowNull(false)
    @Column({
        type: DataType.STRING(50),
    })
    declare name: string;
    
    @AllowNull(false)
    @Column({
        type: DataType.STRING(60),
    })
    declare password: string;
    
    @Unique(true)
    @AllowNull(false)
    @Column({
        type: DataType.STRING(50),
    })
    declare email: string;
    
    @Column({
        type: DataType.STRING(6),
    })
    declare token: string;
    
    @Default(false)
    @Column({
        type: DataType.BOOLEAN,
    })
    declare confirm: string;

    @HasMany(() => Budget, {
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE',
    })
    declare budgets: Budget[]
}

export default User;
