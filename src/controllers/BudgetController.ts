import type { Request, Response } from 'express'
import Budget from '../models/Budget';
import Expense from '../models/Expense';

export class BudgetController {
    static getAll = async (req: Request, res: Response) => {
        try {
            const budgets = await Budget.findAll({
                order: [
                    ['createdAt', 'DESC'],
                ],
                // TODO: filtrar por el usuario auth
            });
            res.json(budgets);
        } catch (error) {
            // console.log(error);
            res.status(500).json({ error: "Hubo un error" });
        }
    }

    static create = async (req: Request, res: Response) => {
        try {
            const budget = new Budget(req.body);
            await budget.save()
            res.status(201).json('Presupuesto creado correctamente');
        } catch (error) {
            // console.log(error);
            res.status(500).json({ error: "Hubo un error" });
        }
    }

    static getById = async (req: Request, res: Response) => {
        const budget = await Budget.findByPk(req.budget.id, {
            include: [Expense]
        });
        res.status(200).json(budget);
    }

    static updateById = async (req: Request, res: Response) => {
        await req.budget.update(req.body);
        res.json('Presupuesto actualizado correctamente');
    }

    static deleteById = async (req: Request, res: Response) => {
        await req.budget.destroy()
        res.json('Presupuesto eliminado correctamente');
    }
}