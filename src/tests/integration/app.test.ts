import request from "supertest";
import server from "../../server";
import { AuthController } from "../../controllers/AuthController";

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
