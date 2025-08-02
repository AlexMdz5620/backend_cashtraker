import type { Request, Response } from 'express'
import User from '../models/User';
import { hashPass } from '../utils/auth';
import { generateToken } from '../utils/token';
import { AuthEmail } from '../email/AuthEmail';

export class AuthController {
    static createAcount = async (req: Request, res: Response) => {
        const { email, password } = req.body;
        const userExist = await User.findOne({ where: { email } });
        if (userExist) {
            const { message } = new Error('El usuario ya existe');
            res.status(409).json({ error: message });
            return;
        }
        try {
            const user = new User(req.body);
            user.password = await hashPass(password);
            user.token = generateToken();
            await user.save();

            await AuthEmail.sendConfrimationEmail({
                name: user.name,
                email: user.email,
                token: user.token,
            })

            res.json('Cuenta creada correctamente');
        } catch (error) {
            // console.error(error);
            res.status(500).json({ error: 'Hubo un error' });
        }
    }
}
