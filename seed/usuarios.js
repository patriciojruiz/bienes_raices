import bcrypt from 'bcrypt'

const usuarios = [
    {
        nombre: 'Patricio Ruiz',
        email: 'patricio@correo.com',
        confirmado: 1,
        password: bcrypt.hashSync('123456', 10)
    },
    {
        nombre: 'Rocio Procel',
        email: 'rocio@correo.com',
        confirmado: 1,
        password: bcrypt.hashSync('1234567', 10)
    }
]

export default usuarios