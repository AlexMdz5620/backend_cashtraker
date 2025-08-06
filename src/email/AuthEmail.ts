import { transport } from "../config/nodemailer";

type EmailType = {
    name: string;
    email: string;
    token: string;
}

export class AuthEmail {
    static sendConfrimationEmail = async (user: EmailType) => {
        const email = await transport.sendMail({
            from: 'CashTraker',
            to: user.email,
            subject: 'CashTraker - Confirma tu cuenta',
            html: `
                <p>Hola ${user.name}, has creado tu cuenta en CashTraker, ya está casi lista</p>
                <p>Visita el siguiente enlace:</p>
                <a href='#'>Confirmar tu cuenta</a>
                <p>E ingresa el código: <b>${user.token}</b></p>`,
        });

        // console.log('Mensaje enviado correctamente:', email.messageId);
    }

    static sendPassResetToken = async (user: EmailType) => {
        const email = await transport.sendMail({
            from: 'CashTraker',
            to: user.email,
            subject: 'CashTraker - Reestablece tu Password',
            html: `
                <p>Hola ${user.name}, has solicitado reestablecer tu password</p>
                <p>Visita el siguiente enlace:</p>
                <a href='#'>Reestablecer Password</a>
                <p>E ingresa el código: <b>${user.token}</b></p>`,
        });

        console.log('Mensaje enviado correctamente:', email.messageId);
    }
}
