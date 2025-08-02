import { Router } from "express";
import { AuthController } from "../controllers/AuthController";
import { body } from "express-validator";
import { handleInputErrors } from "../middleware/validator";

const router = Router();

router.post('/create-account',
    body('name')
        .notEmpty().withMessage('El nombre no puede ir vacío'),
    body('password')
        .isLength({ min: 8 }).withMessage('El password debe de tener mínimo 8 caracteres'),
    body('email')
        .isEmail().withMessage('E-mail no es válido'),
    handleInputErrors,
    AuthController.createAcount
);

export default router
