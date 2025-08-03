import { Request, Response, NextFunction } from 'express'
import { body, param, validationResult } from 'express-validator'
import Budget from '../models/Budget';

declare global {
    namespace Express {
        interface Request {
            budget?: Budget
        }
    }
}

export const validateBundgetId = async (req: Request, res: Response, next: NextFunction) => {
    await param('budgetId')
        .isInt().withMessage('ID no válido')
        .custom(value => value > 0).withMessage('ID no válido')
        .run(req);

    let errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }
    next();
}

export const validateBundgeExists = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { budgetId } = req.params;
        const budget = await Budget.findByPk(budgetId);

        if (!budget) {
            const { message } = new Error('Presupuesto no encontrado');
            res.status(404).json({ error: message });
            return;
        }

        req.budget = budget;

        next();
    } catch (error) {
        // console.log(error);
        res.status(500).json({ error: "Hubo un error" });
    }
}

export const validateBundgeInput = async (req: Request, res: Response, next: NextFunction) => {
    await body('name')
        .notEmpty().withMessage('El nombre del presupuesto no puede ir vacío').run(req);

    await body('amount')
        .notEmpty().withMessage('La cantidad del presupuesto no puede ir vacío')
        .isNumeric().withMessage('Cantidad no válida')
        .custom(value => value > 0).withMessage('El presupuesto debe de ser mayor a 0')
        .run(req);
        
    next();
}

export function hasAcces (req: Request, res: Response, next: NextFunction) {
    if (req.budget.userId !== req.user.id) {
        const { message } = new Error('Acción no válida');
        res.status(401).json({ error: message });
        return;
    }
    next()
}
