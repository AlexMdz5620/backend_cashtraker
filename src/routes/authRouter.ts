import { Router } from "express";
import { AuthController } from "../controllers/AuthController";
import { body } from "express-validator";
import { handleInputErrors } from "../middleware/validator";
import { limiter } from "../config/limiter";

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

router.post('/confrim-account',
    limiter,
    body('token')
        .notEmpty()
        .isLength({ min: 6, max: 6 })
        .withMessage('Token no válido'),
    handleInputErrors,
    AuthController.confirmAcount
);

export default router
