import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User';

declare global {
    namespace Express {
        interface Request {
            user?: User
        }
    }
}

export const auth = async (req: Request, res: Response, next: NextFunction) => {
    const bearer = req.headers.authorization;
    if (!bearer) {
        const { message } = new Error('No Autorizado');
        res.status(401).json({ error: message });
        return;
    }
    const token = bearer.split(' ')[1];
    if (!token) {
        const { message } = new Error('Token no válido');
        res.status(401).json({ error: message });
        return;
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (typeof decoded === 'object') {
            req.user = await User.findByPk(decoded.id, {
                attributes: ['id', 'name', 'email']
            });
            next()
        }
    } catch (error) {
        res.status(500).json({ error: 'Token no válido' });
    }
}