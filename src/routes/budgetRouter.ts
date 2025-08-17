import { Router } from "express";
import { BudgetController } from "../controllers/BudgetController";
import { handleInputErrors } from "../middleware/validator";
import { hasAccess, validateBundgeExists, validateBundgeInput, validateBundgetId } from "../middleware/budget";
import { ExpensesController } from "../controllers/ExpenseController";
import { belongsToBudget, validateExpenseExists, validateExpenseId, validateExpenseInput } from "../middleware/expense";
import { auth } from "../middleware/auth";

const router = Router();

router.use(auth);

router.get('/', BudgetController.getAll);
router.post('/', validateBundgeInput, handleInputErrors, BudgetController.create);

router.param('budgetId', validateBundgetId);
router.param('budgetId', validateBundgeExists);
router.param('budgetId', hasAccess);

router.param('expenseId', validateExpenseId);
router.param('expenseId', validateExpenseExists);
router.param('expenseId', belongsToBudget);

router.get('/:budgetId', BudgetController.getById);
router.put('/:budgetId', validateBundgeInput, handleInputErrors, BudgetController.updateById);
router.delete('/:budgetId', BudgetController.deleteById);

/** Routes of expenses */
router.post('/:budgetId/expenses',
    validateExpenseInput,
    handleInputErrors,
    ExpensesController.create
);
router.get('/:budgetId/expenses/:expenseId', ExpensesController.getById);
router.put('/:budgetId/expenses/:expenseId',
    validateExpenseInput,
    handleInputErrors,
    ExpensesController.updateById
);
router.delete('/:budgetId/expenses/:expenseId', ExpensesController.deleteById);

export default router;
