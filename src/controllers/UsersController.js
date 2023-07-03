const { hash, compare } = require("bcryptjs");
const appError = require("../utils/appError");
const sqliteConnection = require("../database/sqlite")

class UsersController {
    async create(request, response) {
        const { name, email, password } = request.body;

        const database = await sqliteConnection();

        const checkUserExists = await database.get("SELECT * FROM users WHERE email = (?)", [email])

        if(checkUserExists) {
            throw new appError("Este e-mail já está sendo utilizado por outro usuário.");
        }

        const hashedPassword = await hash(password, 8);

        await database.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        [ name, email, hashedPassword ]
        );
       
        return response.status(201).json();
    }

    async update(request, response) {
        const { name, email, password, old_password } = request.body;
        const { id } = request.params;

        const database = await sqliteConnection();
        const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);

        if(!user) {
            throw new appError("Usuário não encontrado!");
        }

        const userWithUpdatedEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);

        if(userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id) {
            throw new appError("Este e-mail já está em uso. Por favor, entre com outro endereço de e-mail.");
        }

        user.name = name ?? user.name;
        user.email - email ?? user.email;

        if(password && !old_password) {
            throw new appError("É necessário digitar a senha antiga para alterar sua senha.");
        }

            if(password && old_password) {
            const checkOldPassword = await compare(old_password, user.password);

            if(!checkOldPassword) {
                throw new appError("A senha antiga não está correta.")
            }

            user.password = await hash(password, 8);

            }

        await database.run(`
        UPDATE users SET
        name = ?,
        email = ?,
        password = ?,
        updated_at = DATETIME('now')
        WHERE id = ?`,
        [user.name, user.email, user.password, id]
        );

        return response.status(200).json();
    }
    
}

module.exports = UsersController;