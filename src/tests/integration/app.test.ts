import request from "supertest";
import server from "../../server";
import { AuthController } from "../../controllers/AuthController";
import User from "../../models/User";
import * as authUtils from "../../utils/auth";
import * as jwtUtils from '../../utils/jwt';

describe('Auth - Create Account', () => {
    it('should display validation errors when form is empty', async () => {
        const response = await request(server)
            .post('/api/auth/create-account')
            .send({});
        const createAccountMock = jest.spyOn(AuthController, 'createAcount');

        expect(response.statusCode).toBe(400);
        expect(response.body).toHaveProperty('errors');
        expect(response.body.errors).toHaveLength(3);

        expect(response.statusCode).not.toBe(201);
        expect(response.body.errors).not.toHaveLength(2);
        expect(createAccountMock).not.toHaveBeenCalled();
    });

    it('should return 400 status code when the email is invalid', async () => {
        const response = await request(server)
            .post('/api/auth/create-account')
            .send({
                name: "Alex",
                password: "12345678",
                email: "not_valid_email"
            });
        const createAccountMock = jest.spyOn(AuthController, 'createAcount');

        expect(response.statusCode).toBe(400);
        expect(response.body).toHaveProperty('errors');
        expect(response.body.errors).toHaveLength(1);
        expect(response.body.errors[0].msg).toBe('E-mail no es válido');

        expect(response.statusCode).not.toBe(201);
        expect(response.body.errors).not.toHaveLength(2);
        expect(createAccountMock).not.toHaveBeenCalled();
    });

    it('should return 400 status code when the password is length is less than 8 characters', async () => {
        const response = await request(server)
            .post('/api/auth/create-account')
            .send({
                name: "Alex",
                password: "short",
                email: "test@test.code"
            });
        const createAccountMock = jest.spyOn(AuthController, 'createAcount');

        expect(response.statusCode).toBe(400);
        expect(response.body).toHaveProperty('errors');
        expect(response.body.errors).toHaveLength(1);
        expect(response.body.errors[0].msg).toBe('El password debe de tener mínimo 8 caracteres');

        expect(response.statusCode).not.toBe(201);
        expect(response.body.errors).not.toHaveLength(2);
        expect(createAccountMock).not.toHaveBeenCalled();
    });

    it('should register a new user successfully', async () => {
        const userData = {
            name: "Alex",
            password: "password",
            email: "test@test.code"
        }
        const response = await request(server)
            .post('/api/auth/create-account')
            .send(userData);

        expect(response.statusCode).toBe(201);
        expect(response.statusCode).not.toBe(400);
        expect(response.body).not.toHaveProperty('errors');
    });

    it('should return 409 conflict when a user is already registered', async () => {
        const userData = {
            name: "Alex",
            password: "password",
            email: "test@test.code"
        }
        const response = await request(server)
            .post('/api/auth/create-account')
            .send(userData);

        expect(response.statusCode).toBe(409);
        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toBe('El usuario con este email ya está registrado');
        expect(response.statusCode).not.toBe(400);
        expect(response.statusCode).not.toBe(201);
        expect(response.body).not.toHaveProperty('errors');
    });
});

describe('Auth - Account Confirmation with Token or not valid', () => {
    it('should display error if token is empty', async () => {
        const response = await request(server)
            .post('/api/auth/confrim-account')
            .send({
                token: "not_valid",
            });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('errors');
        expect(response.body.errors).toHaveLength(1);
        expect(response.body.errors[0].msg).toBe('Token no válido');
    });

    it('should display error if token doesnt exist', async () => {
        const response = await request(server)
            .post('/api/auth/confrim-account')
            .send({
                token: "123456",
            });

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toBe('Token no válido');
        expect(response.status).not.toBe(200);
    });

    it('should confirm account with a valid token', async () => {
        const token = globalThis.cashTrackrConfirmationToken
        const response = await request(server)
            .post('/api/auth/confrim-account')
            .send({ token });

        expect(response.status).toBe(200);
        expect(response.body).toEqual('Cuenta confirmada correctametne');
        expect(response.status).not.toBe(400);
    });
});

describe('Auth - Login', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should display validation errors when the from is empty', async () => {
        const response = await request(server)
            .post('/api/auth/login')
            .send({});

        const loginMock = jest.spyOn(AuthController, 'login');

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('errors');
        expect(response.body.errors).toHaveLength(2);

        expect(response.body.errors).not.toHaveLength(1);
        expect(loginMock).not.toHaveBeenCalled();
    });

    it('should return 400 bad request when the email is invalid', async () => {
        const response = await request(server)
            .post('/api/auth/login')
            .send({
                password: "password",
                email: "not-valid"
            });

        const loginMock = jest.spyOn(AuthController, 'login');

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('errors');
        expect(response.body.errors).toHaveLength(1);
        expect(response.body.errors[0].msg).toBe('E-mail no válido');

        expect(response.body.errors).not.toHaveLength(2);
        expect(loginMock).not.toHaveBeenCalled();
    });

    it('should return 404 error if the user not found', async () => {
        const response = await request(server)
            .post('/api/auth/login')
            .send({
                password: "password",
                email: "user_not_found@test.com"
            });

        expect(response.status).toBe(404);
        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toBe('Usuario no encontrado');
        expect(response.status).not.toBe(200);
    });

    it('should return 403 error if the user account is not confirmed', async () => {
        (jest.spyOn(User, 'findOne') as jest.Mock)
            .mockResolvedValue({
                id: 1,
                confirm: false,
                password: 'hashed_password',
                email: "user_not_confirmed@test.com"
            });

        const response = await request(server)
            .post('/api/auth/login')
            .send({
                password: "password",
                email: "user_not_confirmed@test.com"
            });

        expect(response.status).toBe(403);
        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toBe('La cuenta no a sido confirmada');
        expect(response.status).not.toBe(200);
        expect(response.status).not.toBe(404);
    });

    it('should return 403 error if the user account is not confirmed', async () => {
        const userData = {
            name: "Test",
            password: "password",
            email: "user_not_confirmed@test.com",
        }

        await request(server)
            .post('/api/auth/create-account')
            .send(userData);

        const response = await request(server)
            .post('/api/auth/login')
            .send({
                password: userData.password,
                email: userData.email
            });

        expect(response.status).toBe(403);
        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toBe('La cuenta no a sido confirmada');
        expect(response.status).not.toBe(200);
        expect(response.status).not.toBe(404);
    });

    it('should return 401 error if the password is incorrect', async () => {
        const findOne = (jest.spyOn(User, 'findOne') as jest.Mock)
            .mockResolvedValue({
                id: 1,
                confirm: true,
                password: 'hashed_password',
            });

        const checkPass = jest.spyOn(authUtils, 'checkPass').mockResolvedValue(false);

        const response = await request(server)
            .post('/api/auth/login')
            .send({
                password: "wrongPassword",
                email: "test@test.com"
            });

        expect(response.status).toBe(401);
        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toBe('Password incorrecto');

        expect(response.status).not.toBe(200);
        expect(response.status).not.toBe(404);
        expect(response.status).not.toBe(403);

        expect(findOne).toHaveBeenCalledTimes(1);
        expect(checkPass).toHaveBeenCalledTimes(1);
    });

    it('should return jwt', async () => {
        const findOne = (jest.spyOn(User, 'findOne') as jest.Mock)
            .mockResolvedValue({
                id: 1,
                confirm: true,
                password: 'hashed_password',
            });

        const checkPass = jest.spyOn(authUtils, 'checkPass').mockResolvedValue(true);
        const generateJWT = jest.spyOn(jwtUtils, 'generateJWT').mockReturnValue('jwt_token');

        const response = await request(server)
            .post('/api/auth/login')
            .send({
                password: "correctPassword",
                email: "test@test.com"
            });

        expect(response.status).toBe(200);
        expect(response.body).toEqual('jwt_token');

        expect(findOne).toHaveBeenCalled();
        expect(findOne).toHaveBeenCalledTimes(1);

        expect(checkPass).toHaveBeenCalled();
        expect(checkPass).toHaveBeenCalledTimes(1);
        expect(checkPass).toHaveBeenCalledWith('correctPassword', 'hashed_password');

        expect(generateJWT).toHaveBeenCalled();
        expect(generateJWT).toHaveBeenCalledTimes(1);
        expect(generateJWT).toHaveBeenCalledWith(1);
    });
});

let jwt: string;
async function authUser() {
    const res = await request(server)
        .post('/api/auth/login')
        .send({
            email: 'test@test.code',
            password: 'password'
        });
    jwt = res.body;
}

describe('Get /api/budgets', () => {
    beforeAll(() => {
        jest.restoreAllMocks();
    });

    beforeAll(async () => {
        await authUser();
    });

    it('should reject unauthenticated access to budgets without jwt', async () => {
        const res = await request(server)
            .get('/api/budgets');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('No Autorizado');
    });

    it('should reject unauthenticated access to budgets without a valid jwt', async () => {
        const res = await request(server)
            .get('/api/budgets')
            .auth('not_valid', { type: 'bearer' });

        expect(res.status).toBe(500);
        expect(res.body.error).toBe('Token no válido');
    });

    it('should allow auth access to budget with a valid jwt', async () => {
        const res = await request(server)
            .get('/api/budgets')
            .auth(jwt, { type: 'bearer' });

        expect(res.body).toHaveLength(0);

        expect(res.status).not.toBe(401);
        expect(res.body.error).not.toBe('No Autorizado');
    });
});

describe('POST /api/budgets', () => {
    beforeAll(async () => {
        await authUser();
    });

    it('should reject unauthenticated post request to budgets without jwt', async () => {
        const res = await request(server)
            .post('/api/budgets');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('No Autorizado');
    });

    it('should display validation when the form is submitted with invalid data', async () => {
        const res = await request(server)
            .post('/api/budgets')
            .auth(jwt, { type: 'bearer' })
            .send({});

        expect(res.status).toBe(400);
        expect(res.body.errors).toHaveLength(4);
    });

    it('should display validation when the form is submitted with invalid data', async () => {
        const res = await request(server)
            .post('/api/budgets')
            .auth(jwt, { type: 'bearer' })
            .send({
                name: 'Create budget',
                amount: 200
            });

        expect(res.status).toBe(201);
        expect(res.body).toBeTruthy();
    });
});

describe('GET /api/budgets/:id', () => {
    beforeAll(async () => {
        await authUser();
    });

    it('should reject unauthenticated get request to budget id without a jwt', async () => {
        const res = await request(server)
            .get('/api/budgets/1');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('No Autorizado');
    });

    it('should return 400 bad request whe id is not valid', async () => {
        const res = await request(server)
            .get('/api/budgets/not_valid')
            .auth(jwt, { type: 'bearer' });

        expect(res.status).toBe(400);
        expect(res.body.errors).toBeDefined();
        expect(res.body.errors).toBeTruthy();
        expect(res.body.errors).toHaveLength(1);
        expect(res.body.errors[0].msg).toBe('ID no válido');
        expect(res.status).not.toBe(401);
        expect(res.body.error).not.toBe('No Autorizado');
    });

    it('should return 404 not found when a budget doesnt exists', async () => {
        const res = await request(server)
            .get('/api/budgets/300')
            .auth(jwt, { type: 'bearer' });

        expect(res.status).toBe(404);
        expect(res.body.error).toBe('Presupuesto no encontrado');
        expect(res.status).not.toBe(400);
        expect(res.status).not.toBe(401);
    });

    it('should return a single budget by id', async () => {
        const res = await request(server)
            .get('/api/budgets/1')
            .auth(jwt, { type: 'bearer' });

        expect(res.status).toBe(200);
        expect(res.status).not.toBe(400);
        expect(res.status).not.toBe(401);
        expect(res.status).not.toBe(404);
    });
});

describe('PUT /api/budgets/:id', () => {
    beforeAll(async () => {
        await authUser();
    });

    it('should reject unauthenticated put request to budget id without a jwt', async () => {
        const res = await request(server)
            .put('/api/budgets/1');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('No Autorizado');
    });

    it('should display validation errors if the form is empty', async () => {
        const res = await request(server)
            .put('/api/budgets/1')
            .auth(jwt, { type: 'bearer' })
            .send({});

        expect(res.status).toBe(400);
        expect(res.body.errors).toBeTruthy();
        expect(res.body.errors).toHaveLength(4);
    });

    it('should display budget by id and return success message', async () => {
        const res = await request(server)
            .put('/api/budgets/1')
            .auth(jwt, { type: 'bearer' })
            .send({
                name: 'Update budget',
                amount: 300
            });

        expect(res.status).toBe(200);
        expect(res.body).toBe('Presupuesto actualizado correctamente');
    });
});

describe('DELETE /api/budgets/:id', () => {
    beforeAll(async () => {
        await authUser();
    });

    it('should reject unauthenticated put request to budget id without a jwt', async () => {
        const res = await request(server)
            .delete('/api/budgets/1');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('No Autorizado');
    });

    it('should return 404 not found when a budget doesnt exist', async () => {
        const res = await request(server)
            .delete('/api/budgets/300')
            .auth(jwt, { type: 'bearer' });

        expect(res.status).toBe(404);
        expect(res.body.error).toBe('Presupuesto no encontrado');
    });

    it('should delete a budget and return a successe message', async () => {
        const res = await request(server)
            .delete('/api/budgets/1')
            .auth(jwt, { type: 'bearer' });

        expect(res.status).toBe(200);
        expect(res.body).toBe('Presupuesto eliminado correctamente');
    });
});
