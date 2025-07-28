import { Router } from "express";
import { BudgetController } from "../controllers/BudgetController";
import { body, param } from "express-validator";
import { handleInputErrors } from "../middleware/validator";
import { validateBundgeExists, validateBundgeInput, validateBundgetId } from "../middleware/budget";

const router = Router();

router.get('/', BudgetController.getAll);
router.post('/', validateBundgeInput, handleInputErrors, BudgetController.create);

router.param('budgetId', validateBundgetId);
router.param('budgetId', validateBundgeExists);

router.get('/:budgetId', BudgetController.getById);
router.put('/:budgetId', validateBundgeInput, handleInputErrors, BudgetController.updateById);
router.delete('/:budgetId', BudgetController.deleteById);

export default router;
