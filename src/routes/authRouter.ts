import { Router } from "express";
import { AuthController } from "../controllers/AuthController";
import { body, param } from "express-validator";
import { handleInputErrors } from "../middleware/validator";
import { limiter } from "../config/limiter";
import { auth } from '../middleware/auth';

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

router.post('/confirm-account',
    limiter,
    body('token')
        .isLength({ min: 6, max: 6 })
        .withMessage('Token no válido'),
    handleInputErrors,
    AuthController.confirmAcount
);

router.post('/login',
    limiter,
    body('email')
        .isEmail().withMessage('E-mail no válido'),
    body('password')
        .notEmpty().withMessage('El password es obligatorio'),
    handleInputErrors,
    AuthController.login
);

router.post('/forgot-password',
    body('email')
        .isEmail().withMessage('E-mail no válido'),
    handleInputErrors,
    AuthController.forgotPass
);

router.post('/validate-token',
    limiter,
    body('token')
        .notEmpty()
        .isLength({ min: 6, max: 6 })
        .withMessage('Token no válido'),
    handleInputErrors,
    AuthController.validateToken
);

router.post('/reset-password/:token',
    param('token')
        .notEmpty()
        .isLength({ min: 6, max: 6 })
        .withMessage('Token no válido'),
    body('password')
        .isLength({ min: 8 }).withMessage('El password debe de tener mínimo 8 caracteres'),
    handleInputErrors,
    AuthController.resetPassWithToken
);

router.get('/user',
    auth,
    AuthController.user
);

router.put('/user',
    auth,
    AuthController.updateUser
);

router.post('/update-password',
    auth,
    body('current_password')
        .notEmpty().withMessage('El password actual no puede ir vacío'),
    body('password')
        .isLength({ min: 8 }).withMessage('El password nuevo debe de tener mínimo 8 caracteres'),
    handleInputErrors,
    AuthController.updateCurrUserPass
);

router.post('/check-password',
    auth,
    body('password')
        .isLength({ min: 8 }).withMessage('El password actual no puede ir vacío'),
    handleInputErrors,
    AuthController.checkPass
);

export default router
