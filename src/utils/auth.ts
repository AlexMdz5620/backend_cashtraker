import bcrypt from 'bcrypt';

export const hashPass = async (pass: string) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(pass, salt)
}

export const checkPass = async (pass: string, hash: string) => {
    return await bcrypt.compare(pass, hash);
}