import type { Request, Response } from 'express'
import User from '../models/User';
import { checkPass, hashPass } from '../utils/auth';
import { AuthEmail } from '../email/AuthEmail';
import { generateJWT } from '../utils/jwt';
import { generateToken } from '../utils/token';

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

    static confirmAcount = async (req: Request, res: Response) => {
        const { token } = req.body;
        const user = await User.findOne({ where: { token } });
        if (!user) {
            const { message } = new Error('Token no válido');
            res.status(401).json({ error: message });
            return;
        }

        user.confirm = true;
        user.token = null;
        await user.save();

        res.json('Cuenta confirmada correctametne');
    }

    static login = async (req: Request, res: Response) => {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) {
            const { message } = new Error('Usuario no encontrado');
            res.status(404).json({ error: message });
            return;
        }
        if (!user.confirm) {
            const { message } = new Error('La cuenta no a sido confirmada');
            res.status(403).json({ error: message });
            return;
        }

        const isPassCorrect = await checkPass(password, user.password);

        if (!isPassCorrect) {
            const { message } = new Error('Password incorrecto');
            res.status(401).json({ error: message });
            return;
        }

        const token = generateJWT(user.id);

        res.json(token);
    }

    static forgotPass = async (req: Request, res: Response) => {
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) {
            const { message } = new Error('El usuario ya existe');
            res.status(409).json({ error: message });
            return;
        }

        user.token = generateToken();
        await user.save();

        await AuthEmail.sendPassResetToken({
            name: user.name,
            email: user.email,
            token: user.token,
        });

        res.json('Revisa tu E-mail para instrucciones');
    }

    static validateToken = async (req: Request, res: Response) => {
        const { token } = req.body;
        const tokenExists = await User.findOne({ where: { token } });
        if (!tokenExists) {
            const { message } = new Error('Token no válido');
            res.status(404).json(message);
            return;
        }

        res.json('Token válido')
    }

    static resetPassWithToken = async (req: Request, res: Response) => {
        const { token } = req.params;
        const { password } = req.body;

        const user = await User.findOne({ where: { token } });
        if (!user) {
            const { message } = new Error('Token no válido');
            res.status(404).json(message);
            return;
        }

        user.password = await hashPass(password);
        user.token = null;
        await user.save();

        res.json('El password se modificó correctamente');
    }
    
}
