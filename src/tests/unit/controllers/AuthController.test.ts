import { createRequest, createResponse } from 'node-mocks-http';
import { AuthController } from '../../../controllers/AuthController';
import User from '../../../models/User';
import { checkPass, hashPass } from '../../../utils/auth';
import { generateToken } from '../../../utils/token';
import { AuthEmail } from '../../../email/AuthEmail';
import { generateJWT } from '../../../utils/jwt';

jest.mock('../../../models/User');
jest.mock('../../../utils/auth');
jest.mock('../../../utils/token');
jest.mock('../../../utils/jwt');

describe('AuthController.createAccount', () => {
    beforeEach(() => {
        jest.resetAllMocks();
    });

    it('Should return a 409 and an error message if the email is already registered', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(true);
        const req = createRequest({
            method: 'POST',
            url: 'api/auth/create-account',
            body: {
                email: 'test@test.com',
                password: 'testpassword',
            }
        });
        const res = createResponse();

        await AuthController.createAcount(req, res);

        const data = res._getJSONData();
        expect(res.statusCode).toBe(409);
        expect(data).toHaveProperty('error', 'El usuario con este email ya está registrado');
        expect(User.findOne).toHaveBeenCalled();
        expect(User.findOne).toHaveBeenCalledTimes(1);
    });

    it('Should register a new user and return a success message', async () => {
        const req = createRequest({
            method: 'POST',
            url: 'api/auth/create-account',
            body: {
                email: 'test@test.com',
                password: 'testpassword',
                name: 'Test Name',
            }
        });
        const res = createResponse();

        const mockUser = { ...req.body, save: jest.fn() };

        (User.create as jest.Mock).mockResolvedValue(mockUser);
        (hashPass as jest.Mock).mockResolvedValue('hashedpassword');
        (generateToken as jest.Mock).mockReturnValue('123456');
        jest.spyOn(AuthEmail, "sendConfrimationEmail").mockImplementation(() => Promise.resolve());

        await AuthController.createAcount(req, res);

        expect(User.create).toHaveBeenCalledWith(req.body);
        expect(User.create).toHaveBeenCalledTimes(1);
        expect(mockUser.save).toHaveBeenCalled();
        expect(mockUser.password).toBe('hashedpassword');
        expect(mockUser.token).toBe('123456');
        expect(AuthEmail.sendConfrimationEmail).toHaveBeenCalledWith({
            name: req.body.name,
            email: req.body.email,
            token: '123456'
        });
        expect(AuthEmail.sendConfrimationEmail).toHaveBeenCalledTimes(1);

        expect(res.statusCode).toBe(201);
    });
});

describe('AuthController.login', () => {
    it('Should return a 404 if user is not found', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const req = createRequest({
            method: 'POST',
            url: 'api/auth/login',
            body: {
                email: 'test@test.com',
                password: 'testpassword',
            }
        });
        const res = createResponse();

        await AuthController.login(req, res);

        const data = res._getJSONData();
        expect(res.statusCode).toBe(404);
        expect(data).toHaveProperty('error', 'Usuario no encontrado');
    });

    it('Should return a 403 if the account is not been confirmed', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({
            id: 1,
            email: 'test@test.com',
            password: 'testpassword',
            confirm: false,
        });

        const req = createRequest({
            method: 'POST',
            url: 'api/auth/login',
            body: {
                email: 'test@test.com',
                password: 'testpassword',
            }
        });
        const res = createResponse();

        await AuthController.login(req, res);

        const data = res._getJSONData();
        expect(res.statusCode).toBe(403);
        expect(data).toHaveProperty('error', 'La cuenta no a sido confirmada');
    });

    it('Should return a 401 if the password is incorrect', async () => {
        const userMock = {
            id: 1,
            email: 'test@test.com',
            password: 'password',
            confirm: true,
        };

        (User.findOne as jest.Mock).mockResolvedValue(userMock);

        const req = createRequest({
            method: 'POST',
            url: 'api/auth/login',
            body: {
                email: 'test@test.com',
                password: 'testpassword',
            }
        });
        const res = createResponse();

        (checkPass as jest.Mock).mockResolvedValue(false);

        await AuthController.login(req, res);

        const data = res._getJSONData();
        expect(res.statusCode).toBe(401);
        expect(data).toHaveProperty('error', 'Password incorrecto');
        expect(checkPass).toHaveBeenCalledWith(req.body.password, userMock.password);
        expect(checkPass).toHaveBeenCalledTimes(1);
    });

    it('Should return a JWT if authentication is successful', async () => {
        const userMock = {
            id: 1,
            email: 'test@test.com',
            password: 'hased_password',
            confirm: true,
        };

        const req = createRequest({
            method: 'POST',
            url: 'api/auth/login',
            body: {
                email: 'test@test.com',
                password: 'password',
            }
        });
        const res = createResponse();

        const fakeJwt = 'fake_jwt';

        (User.findOne as jest.Mock).mockResolvedValue(userMock);
        (checkPass as jest.Mock).mockResolvedValue(true);
        (generateJWT as jest.Mock) .mockReturnValue(fakeJwt);

        await AuthController.login(req, res);

        const data = res._getJSONData();
        expect(res.statusCode).toBe(200);
        expect(data).toEqual(fakeJwt);
        expect(generateJWT).toHaveBeenCalledTimes(1);
        expect(generateJWT).toHaveBeenCalledWith(userMock.id);
    });
});
