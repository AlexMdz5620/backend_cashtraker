import { createRequest, createResponse } from 'node-mocks-http';
import { hasAcces, validateBundgeExists } from '../../../middleware/budget';
import Budget from '../../../models/Budget';
import { budgets } from '../../mocks/budgets';

jest.mock('../../../models/Budget', () => ({
    findByPk: jest.fn(),
}));

describe('Budget Middleware - validateBundgeExists', () => {
    it('Should handle non-existent budget', async () => {
        (Budget.findByPk as jest.Mock).mockResolvedValue(null);
        const req = createRequest({
            params: {
                budgetId: 1
            }
        });
        const res = createResponse();
        const next = jest.fn();

        await validateBundgeExists(req, res, next);
        const data = res._getJSONData();
        expect(res.statusCode).toBe(404);
        expect(data).toEqual({ error: "Presupuesto no encontrado" });
        expect(next).not.toHaveBeenCalled();
    });

    it('Should handle non-existent budget', async () => {
        (Budget.findByPk as jest.Mock).mockRejectedValue(new Error);
        const req = createRequest({
            params: {
                budgetId: 1
            }
        });
        const res = createResponse();
        const next = jest.fn();

        await validateBundgeExists(req, res, next);
        const data = res._getJSONData();
        expect(res.statusCode).toBe(500);
        expect(data).toEqual({ error: "Hubo un error" });
        expect(next).not.toHaveBeenCalled();
    });

    it('Should proceed to next middlewate if budget exists', async () => {
        (Budget.findByPk as jest.Mock).mockResolvedValue(budgets[0]);
        const req = createRequest({
            params: {
                budgetId: 1
            }
        });
        const res = createResponse();
        const next = jest.fn();

        await validateBundgeExists(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(req.budget).toEqual(budgets[0]);
    });
});

describe('Budget Middleware - hasAcces', () => {
    it('Should call next() if user has access to budget', () => {
        const req = createRequest({
            budget: budgets[0],
            user: { id: 1 },
        });
        const res = createResponse();
        const next = jest.fn();

        hasAcces(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(next).toHaveBeenCalledTimes(1);
    });

    it('Should return 404 if userId not have access to budget', () => {
        const req = createRequest({
            budget: budgets[0],
            user: { id: 2 },
        });
        const res = createResponse();
        const next = jest.fn();

        hasAcces(req, res, next);
        expect(next).not.toHaveBeenCalled();
        expect(res.statusCode).toBe(401);
        expect(res._getJSONData()).toEqual({ error: 'Acción no válida' });
    });
});
