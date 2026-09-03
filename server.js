require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const db = require('./database');

const {
    hashPassword,
    verifyPassword,
    generateSessionId
} = require('./auth');

const helmet = require('helmet');

const {
    rateLimit
} = require('express-rate-limit');


const app = express();

app.disable('x-powered-by');

app.use(
    helmet({
        /*
         * A CSP será ativada posteriormente.
         * Por enquanto, o projeto ainda utiliza scripts
         * e estilos inline, além do TradingView externo.
         */
        contentSecurityPolicy: false
    })
);


const PORT = process.env.PORT || 3000;

// ======================================================
// MIDDLEWARES
// ======================================================

/**
 * Permite receber JSON.
 * O limite evita corpos de requisição excessivamente grandes.
 */
app.use(express.json({
    limit: '100kb'
}));

/**
 * Permite receber formulários HTML tradicionais.
 */
app.use(express.urlencoded({
    extended: true,
    limit: '100kb'
}));

/**
 * Permite ler cookies enviados pelo navegador.
 */
app.use(cookieParser());


// ======================================================
// FRONTEND - ARQUIVOS ESTÁTICOS
// ======================================================

/**
 * Disponibiliza os arquivos existentes dentro de /public.
 *
 * Exemplos:
 *
 * public/index.html
 * -> http://localhost:3000/
 *
 * public/noticias.html
 * -> http://localhost:3000/noticias.html
 *
 * public/css/style.css
 * -> http://localhost:3000/css/style.css
 *
 * IMPORTANTE:
 * express.static procura automaticamente por index.html
 * quando o navegador acessa "/".
 */
app.use(
    express.static(
        path.join(__dirname, 'public')
    )
);


// ======================================================
// FUNÇÕES AUXILIARES DE VALIDAÇÃO
// ======================================================

/**
 * Verifica se determinado valor é uma string.
 *
 * @param {*} valor
 * @returns {boolean}
 */
function ehString(valor) {
    return typeof valor === 'string';
}


/**
 * Faz uma validação básica de endereço de e-mail.
 *
 * @param {string} email
 * @returns {boolean}
 */
function emailValido(email) {
    if (!ehString(email)) {
        return false;
    }

    const regexEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    return regexEmail.test(email);
}


/**
 * Verifica se determinado valor representa
 * um número inteiro positivo.
 *
 * @param {*} valor
 * @returns {boolean}
 */
function idValido(valor) {
    const id = Number(valor);

    return Number.isInteger(id) && id > 0;
}


// ======================================================
// CONFIGURAÇÃO DE SESSÃO
// ======================================================

const SESSION_COOKIE = 'astromoney_session';

const SESSION_DURATION =
    1000 * 60 * 60 * 24 * 7; // 7 dias


/**
 * Cria uma sessão para o usuário autenticado.
 *
 * @param {number} userId
 * @param {object} res
 */
function criarSessao(userId, res) {
    const sessionId = generateSessionId();

    const expiresAt =
        Date.now() + SESSION_DURATION;

    db.prepare(`
        INSERT INTO sessions (
            id,
            user_id,
            expires_at
        )
        VALUES (?, ?, ?)
    `).run(
        sessionId,
        userId,
        expiresAt
    );

    res.cookie(
        SESSION_COOKIE,
        sessionId,
        {
            httpOnly: true,
            sameSite: 'strict',

            secure:
                process.env.NODE_ENV === 'production',

            maxAge: SESSION_DURATION
        }
    );
}


// ======================================================
// OBTER USUÁRIO DA SESSÃO
// ======================================================

/**
 * Procura o usuário associado ao cookie de sessão.
 *
 * @param {object} req
 * @returns {object|null}
 */
function obterUsuarioDaSessao(req) {
    const sessionId =
        req.cookies[SESSION_COOKIE];

    if (!sessionId) {
        return null;
    }

    const sessao = db.prepare(`
        SELECT
            sessions.id,
            sessions.expires_at,

            users.id AS user_id,
            users.nome,
            users.telefone,
            users.email,
            users.nivel

        FROM sessions

        INNER JOIN users
            ON users.id = sessions.user_id

        WHERE sessions.id = ?
    `).get(sessionId);

    if (!sessao) {
        return null;
    }

    /**
     * Remove automaticamente uma sessão expirada.
     */
    if (sessao.expires_at < Date.now()) {
        db.prepare(`
            DELETE FROM sessions
            WHERE id = ?
        `).run(sessionId);

        return null;
    }

    return {
        id: sessao.user_id,
        nome: sessao.nome,
        telefone: sessao.telefone,
        email: sessao.email,
        nivel: sessao.nivel
    };
}

// ======================================================
// LIMITAÇÃO DE REQUISIÇÕES
// ======================================================

const loginLimiter = rateLimit({
    windowMs:
        15 * 60 * 1000,

    limit: 10,

    standardHeaders:
        'draft-8',

    legacyHeaders:
        false,

    skipSuccessfulRequests:
        true,

    message: {
        erro:
            'Muitas tentativas de login. Aguarde 15 minutos e tente novamente.'
    }
});


const cadastroLimiter = rateLimit({
    windowMs:
        60 * 60 * 1000,

    limit: 5,

    standardHeaders:
        'draft-8',

    legacyHeaders:
        false,

    message: {
        erro:
            'Muitas tentativas de cadastro. Tente novamente mais tarde.'
    }
});


const senhaLimiter = rateLimit({
    windowMs:
        15 * 60 * 1000,

    limit: 5,

    standardHeaders:
        'draft-8',

    legacyHeaders:
        false,

    message: {
        erro:
            'Muitas tentativas de alteração de senha. Aguarde alguns minutos.'
    }
});

const exclusaoContaLimiter = rateLimit({
    windowMs:
        15 * 60 * 1000,

    limit: 5,

    standardHeaders:
        'draft-8',

    legacyHeaders:
        false,

    message: {
        erro:
            'Muitas tentativas de exclusão. Aguarde alguns minutos.'
    }
});


const noticiasLimiter = rateLimit({
    windowMs:
        5 * 60 * 1000,

    limit: 30,

    standardHeaders:
        'draft-8',

    legacyHeaders:
        false,

    message: {
        erro:
            'Muitas consultas de notícias. Aguarde alguns minutos.'
    }
});


// ======================================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ======================================================

/**
 * Protege endpoints que exigem usuário autenticado.
 */
function exigirLogin(req, res, next) {
    const usuario =
        obterUsuarioDaSessao(req);

    if (!usuario) {
        return res.status(401).json({
            erro: 'Não autenticado.'
        });
    }

    req.user = usuario;

    next();
}


// ======================================================
// REGISTRO
// ======================================================

app.post(
    '/api/auth/register',
    cadastroLimiter,
    async (req, res) => {
        try {
        let {
            nome,
            telefone,
            email,
            nivel,
            senha
        } = req.body;

        // ------------------------------
        // Normalização
        // ------------------------------

        nome =
            ehString(nome)
                ? nome.trim()
                : nome;

        telefone =
            ehString(telefone)
                ? telefone.trim()
                : telefone;

        email =
            ehString(email)
                ? email.trim().toLowerCase()
                : email;

        nivel =
            ehString(nivel)
                ? nivel.trim().toLowerCase()
                : nivel;


        // ------------------------------
        // Validação dos tipos
        // ------------------------------

        if (
            !ehString(nome) ||
            !ehString(email) ||
            !ehString(nivel) ||
            !ehString(senha)
        ) {
            return res.status(400).json({
                erro:
                    'Os dados enviados possuem formato inválido.'
            }
          );
        }


        // ------------------------------
        // Campos obrigatórios
        // ------------------------------

        if (
            !nome ||
            !email ||
            !nivel ||
            !senha
        ) {
            return res.status(400).json({
                erro:
                    'Preencha todos os campos obrigatórios.'
            });
        }


        // ------------------------------
        // Nome
        // ------------------------------

        if (
            nome.length < 2 ||
            nome.length > 100
        ) {
            return res.status(400).json({
                erro:
                    'O nome deve possuir entre 2 e 100 caracteres.'
            });
        }


        // ------------------------------
        // E-mail
        // ------------------------------

        if (
            email.length > 254 ||
            !emailValido(email)
        ) {
            return res.status(400).json({
                erro:
                    'Informe um endereço de e-mail válido.'
            });
        }


        // ------------------------------
        // Telefone
        // ------------------------------

        if (
            telefone !== undefined &&
            telefone !== null &&
            !ehString(telefone)
        ) {
            return res.status(400).json({
                erro:
                    'Informe um telefone válido.'
            });
        }

        if (
            telefone &&
            telefone.length > 30
        ) {
            return res.status(400).json({
                erro:
                    'Informe um telefone válido.'
            });
        }


        // ------------------------------
        // Senha
        // ------------------------------

        if (
            senha.length < 8 ||
            senha.length > 128
        ) {
            return res.status(400).json({
                erro:
                    'A senha deve possuir entre 8 e 128 caracteres.'
            });
        }


        // ------------------------------
        // Nível
        // ------------------------------

        const niveisPermitidos = [
            'novato',
            'regular',
            'profissional'
        ];

        if (!niveisPermitidos.includes(nivel)) {
            return res.status(400).json({
                erro:
                    'Nível de experiência inválido.'
            });
        }


        // ------------------------------
        // Verificar e-mail existente
        // ------------------------------

        const usuarioExistente =
            db.prepare(`
                SELECT id
                FROM users
                WHERE email = ?
            `).get(email);

        if (usuarioExistente) {
            return res.status(409).json({
                erro:
                    'Já existe uma conta com este e-mail.'
            });
        }


        // ------------------------------
        // Hash da senha
        // ------------------------------

        const passwordHash =
            await hashPassword(senha);


        // ------------------------------
        // Inserção
        // ------------------------------

        const resultado =
            db.prepare(`
                INSERT INTO users (
                    nome,
                    telefone,
                    email,
                    nivel,
                    password_hash
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                nome,
                telefone || null,
                email,
                nivel,
                passwordHash
            );

        return res.status(201).json({
            mensagem:
                'Conta criada com sucesso.',

            usuario: {
                id: resultado.lastInsertRowid,
                nome,
                telefone,
                email,
                nivel
            }
        });

    } catch (erro) {
        console.error(
            'Erro ao criar conta:',
            erro
        );

        return res.status(500).json({
            erro:
                'Erro interno ao criar a conta.'
        });
    }
});


// ======================================================
// LOGIN
// ======================================================

app.post(
    '/api/auth/login',
    loginLimiter,
    async (req, res) => {
    try {
        let {
            email,
            senha
        } = req.body;

        email =
            ehString(email)
                ? email.trim().toLowerCase()
                : email;


        if (
            !ehString(email) ||
            !ehString(senha)
        ) {
            return res.status(400).json({
                erro:
                    'E-mail ou senha possuem formato inválido.'
            });
        }


        if (!email || !senha) {
            return res.status(400).json({
                erro:
                    'Informe e-mail e senha.'
            });
        }


        if (
            email.length > 254 ||
            !emailValido(email)
        ) {
            return res.status(400).json({
                erro:
                    'Informe um endereço de e-mail válido.'
            });
        }


        if (
            senha.length < 1 ||
            senha.length > 128
        ) {
            return res.status(400).json({
                erro:
                    'E-mail ou senha possuem formato inválido.'
            });
        }


        const usuario =
            db.prepare(`
                SELECT *
                FROM users
                WHERE email = ?
            `).get(email);


        /**
         * Mensagem propositalmente genérica.
         *
         * Isso evita revelar se determinado
         * endereço possui uma conta cadastrada.
         */
        if (!usuario) {
            return res.status(401).json({
                erro:
                    'E-mail ou senha incorretos.'
            });
        }


        const senhaCorreta =
            await verifyPassword(
                senha,
                usuario.password_hash
            );

        if (!senhaCorreta) {
            return res.status(401).json({
                erro:
                    'E-mail ou senha incorretos.'
            });
        }


        /**
         * Remove sessões anteriores antes
         * de criar a nova sessão.
         */
        db.prepare(`
            DELETE FROM sessions
            WHERE user_id = ?
        `).run(usuario.id);


        criarSessao(
            usuario.id,
            res
        );


        return res.json({
            mensagem:
                'Login realizado com sucesso.',

            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                telefone: usuario.telefone,
                email: usuario.email,
                nivel: usuario.nivel
            }
        });

    } catch (erro) {
        console.error(
            'Erro durante login:',
            erro
        );

        return res.status(500).json({
            erro:
                'Erro interno durante o login.'
        });
    }
});


// ======================================================
// CONSULTAR SESSÃO
// ======================================================

app.get(
    '/api/auth/me',
    exigirLogin,
    (req, res) => {
        return res.json({
            usuario: req.user
        });
    }
);


// ======================================================
// LOGOUT
// ======================================================

app.post('/api/auth/logout', (req, res) => {
    const sessionId =
        req.cookies[SESSION_COOKIE];

    if (sessionId) {
        db.prepare(`
            DELETE FROM sessions
            WHERE id = ?
        `).run(sessionId);
    }


    res.clearCookie(
        SESSION_COOKIE,
        {
            httpOnly: true,
            sameSite: 'strict',

            secure:
                process.env.NODE_ENV ===
                'production'
        }
    );


    return res.json({
        mensagem:
            'Logout realizado com sucesso.'
    });
});


// ======================================================
// ROTA PROTEGIDA DE TESTE
// ======================================================

app.get(
    '/api/teste-protegido',
    exigirLogin,
    (req, res) => {
        return res.json({
            mensagem:
                `Olá, ${req.user.nome}. Esta rota é protegida.`
        });
    }
);


// ======================================================
// PERFIL
// ======================================================

app.get(
    '/api/users/profile',
    exigirLogin,
    (req, res) => {
        return res.json({
            usuario: req.user
        });
    }
);


// ======================================================
// ALTERAR SENHA
// ======================================================

app.put(
    '/api/users/password',
    exigirLogin,
    senhaLimiter,
    async (req, res) => {
        try {
            const {
                senhaAtual,
                novaSenha
            } = req.body;


            if (
                !ehString(senhaAtual) ||
                !ehString(novaSenha)
            ) {
                return res.status(400).json({
                    erro:
                        'As senhas enviadas possuem formato inválido.'
                });
            }


            if (
                !senhaAtual ||
                !novaSenha
            ) {
                return res.status(400).json({
                    erro:
                        'Informe a senha atual e a nova senha.'
                });
            }


            if (senhaAtual.length > 128) {
                return res.status(400).json({
                    erro:
                        'A senha atual possui formato inválido.'
                });
            }


            if (
                novaSenha.length < 8 ||
                novaSenha.length > 128
            ) {
                return res.status(400).json({
                    erro:
                        'A nova senha deve possuir entre 8 e 128 caracteres.'
                });
            }


            const usuario =
                db.prepare(`
                    SELECT
                        id,
                        password_hash

                    FROM users

                    WHERE id = ?
                `).get(req.user.id);


            if (!usuario) {
                return res.status(404).json({
                    erro:
                        'Usuário não encontrado.'
                });
            }


            const senhaCorreta =
                await verifyPassword(
                    senhaAtual,
                    usuario.password_hash
                );


            if (!senhaCorreta) {
                return res.status(401).json({
                    erro:
                        'A senha atual está incorreta.'
                });
            }


            const mesmaSenha =
                await verifyPassword(
                    novaSenha,
                    usuario.password_hash
                );


            if (mesmaSenha) {
                return res.status(400).json({
                    erro:
                        'A nova senha deve ser diferente da senha atual.'
                });
            }


            const novoHash =
                await hashPassword(
                    novaSenha
                );


            db.prepare(`
                UPDATE users

                SET password_hash = ?

                WHERE id = ?
            `).run(
                novoHash,
                req.user.id
            );


            /**
             * Encerra todas as outras sessões,
             * mantendo apenas a sessão atual.
             */
            const sessionId =
                req.cookies[SESSION_COOKIE];

            db.prepare(`
                DELETE FROM sessions

                WHERE user_id = ?
                AND id <> ?
            `).run(
                req.user.id,
                sessionId
            );


            return res.json({
                mensagem:
                    'Senha alterada com sucesso.'
            });

        } catch (erro) {
            console.error(
                'Erro ao alterar senha:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Erro interno ao alterar a senha.'
            });
        }
    }
);


// ======================================================
// APAGAR CONTA
// ======================================================

app.delete(
    '/api/users/profile',
    exigirLogin,
    exclusaoContaLimiter,
    async (req, res) => {
        try {
            const senha =
                req.body.senha;

            if (
                !ehString(senha) ||
                !senha ||
                senha.length > 128
            ) {
                return res.status(400).json({
                    erro:
                        'Informe a senha atual.'
                });
            }

            const usuario = db.prepare(`
                SELECT
                    id,
                    password_hash

                FROM users

                WHERE id = ?
            `).get(req.user.id);

            if (!usuario) {
                return res.status(404).json({
                    erro:
                        'Usuário não encontrado.'
                });
            }

            const senhaCorreta =
                await verifyPassword(
                    senha,
                    usuario.password_hash
                );

            if (!senhaCorreta) {
                return res.status(401).json({
                    erro:
                        'Senha incorreta.'
                });
            }

            const resultado = db.prepare(`
                DELETE FROM users
                WHERE id = ?
            `).run(usuario.id);

            if (resultado.changes === 0) {
                return res.status(404).json({
                    erro:
                        'Usuário não encontrado.'
                });
            }

            res.clearCookie(
                SESSION_COOKIE,
                {
                    httpOnly: true,
                    sameSite: 'strict',

                    secure:
                        process.env.NODE_ENV ===
                        'production'
                }
            );

            return res.json({
                mensagem:
                    'Conta apagada com sucesso.'
            });

        } catch (erro) {
            console.error(
                'Erro ao apagar conta:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Erro interno ao apagar a conta.'
            });
        }
    }
);


// ======================================================
// FÓRUM - LISTAR PUBLICAÇÕES
// ======================================================

app.get(
    '/api/posts',
    exigirLogin,
    (req, res) => {
        try {
            const posts =
                db.prepare(`
                    SELECT
                        posts.id,
                        posts.user_id,
                        posts.title,
                        posts.content,
                        posts.created_at,

                        users.nome AS autor

                    FROM posts

                    INNER JOIN users
                        ON users.id = posts.user_id

                    ORDER BY
                        posts.created_at DESC,
                        posts.id DESC
                `).all();


            const buscarComentarios =
                db.prepare(`
                    SELECT
                        comments.id,
                        comments.post_id,
                        comments.user_id,
                        comments.content,
                        comments.created_at,

                        users.nome AS autor

                    FROM comments

                    INNER JOIN users
                        ON users.id = comments.user_id

                    WHERE comments.post_id = ?

                    ORDER BY
                        comments.created_at ASC,
                        comments.id ASC
                `);


            const resultado =
                posts.map((post) => {
                    const comentarios =
                        buscarComentarios.all(
                            post.id
                        );


                    return {
                        id: post.id,

                        titulo:
                            post.title,

                        conteudo:
                            post.content,

                        autor:
                            post.autor,

                        userId:
                            post.user_id,

                        meuPost:
                            post.user_id ===
                            req.user.id,

                        data:
                            post.created_at,

                        comentarios:
                            comentarios.map(
                                (comentario) => ({
                                    id:
                                        comentario.id,

                                    postId:
                                        comentario.post_id,

                                    texto:
                                        comentario.content,

                                    autor:
                                        comentario.autor,

                                    userId:
                                        comentario.user_id,

                                    meuComentario:
                                        comentario.user_id ===
                                        req.user.id,

                                    data:
                                        comentario.created_at
                                })
                            )
                    };
                });


            return res.json({
                posts: resultado
            });

        } catch (erro) {
            console.error(
                'Erro ao carregar fórum:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível carregar as publicações.'
            });
        }
    }
);


// ======================================================
// FÓRUM - CRIAR PUBLICAÇÃO
// ======================================================

app.post(
    '/api/posts',
    exigirLogin,
    (req, res) => {
        try {
            const {
                titulo: tituloRecebido,
                conteudo: conteudoRecebido
            } = req.body;


            if (
                !ehString(tituloRecebido) ||
                !ehString(conteudoRecebido)
            ) {
                return res.status(400).json({
                    erro:
                        'Título ou conteúdo possuem formato inválido.'
                });
            }


            const titulo =
                tituloRecebido.trim();

            const conteudo =
                conteudoRecebido.trim();


            if (!titulo || !conteudo) {
                return res.status(400).json({
                    erro:
                        'Informe o título e o conteúdo.'
                });
            }


            if (titulo.length > 150) {
                return res.status(400).json({
                    erro:
                        'O título pode possuir no máximo 150 caracteres.'
                });
            }


            if (conteudo.length > 10000) {
                return res.status(400).json({
                    erro:
                        'A publicação é muito grande.'
                });
            }


            const resultado =
                db.prepare(`
                    INSERT INTO posts (
                        user_id,
                        title,
                        content
                    )
                    VALUES (?, ?, ?)
                `).run(
                    req.user.id,
                    titulo,
                    conteudo
                );


            return res.status(201).json({
                mensagem:
                    'Publicação criada com sucesso.',

                postId:
                    resultado.lastInsertRowid
            });

        } catch (erro) {
            console.error(
                'Erro ao publicar:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível criar a publicação.'
            });
        }
    }
);


// ======================================================
// FÓRUM - EDITAR PUBLICAÇÃO
// ======================================================

app.put(
    '/api/posts/:id',
    exigirLogin,
    (req, res) => {
        try {
            if (!idValido(req.params.id)) {
                return res.status(400).json({
                    erro:
                        'Publicação inválida.'
                });
            }


            const postId =
                Number(req.params.id);


            const {
                titulo: tituloRecebido,
                conteudo: conteudoRecebido
            } = req.body;


            if (
                !ehString(tituloRecebido) ||
                !ehString(conteudoRecebido)
            ) {
                return res.status(400).json({
                    erro:
                        'Título ou conteúdo possuem formato inválido.'
                });
            }


            const titulo =
                tituloRecebido.trim();

            const conteudo =
                conteudoRecebido.trim();


            if (!titulo || !conteudo) {
                return res.status(400).json({
                    erro:
                        'Título e conteúdo são obrigatórios.'
                });
            }


            if (titulo.length > 150) {
                return res.status(400).json({
                    erro:
                        'O título pode possuir no máximo 150 caracteres.'
                });
            }


            if (conteudo.length > 10000) {
                return res.status(400).json({
                    erro:
                        'A publicação é muito grande.'
                });
            }


            const post =
                db.prepare(`
                    SELECT
                        id,
                        user_id

                    FROM posts

                    WHERE id = ?
                `).get(postId);


            if (!post) {
                return res.status(404).json({
                    erro:
                        'Publicação não encontrada.'
                });
            }


            if (post.user_id !== req.user.id) {
                return res.status(403).json({
                    erro:
                        'Você não pode editar esta publicação.'
                });
            }


            db.prepare(`
                UPDATE posts

                SET
                    title = ?,
                    content = ?

                WHERE id = ?
            `).run(
                titulo,
                conteudo,
                postId
            );


            return res.json({
                mensagem:
                    'Publicação atualizada.'
            });

        } catch (erro) {
            console.error(
                'Erro ao editar publicação:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível editar a publicação.'
            });
        }
    }
);


// ======================================================
// FÓRUM - APAGAR PUBLICAÇÃO
// ======================================================

app.delete(
    '/api/posts/:id',
    exigirLogin,
    (req, res) => {
        try {
            if (!idValido(req.params.id)) {
                return res.status(400).json({
                    erro:
                        'Publicação inválida.'
                });
            }


            const postId =
                Number(req.params.id);


            const post =
                db.prepare(`
                    SELECT
                        id,
                        user_id

                    FROM posts

                    WHERE id = ?
                `).get(postId);


            if (!post) {
                return res.status(404).json({
                    erro:
                        'Publicação não encontrada.'
                });
            }


            if (post.user_id !== req.user.id) {
                return res.status(403).json({
                    erro:
                        'Você não pode apagar esta publicação.'
                });
            }


            db.prepare(`
                DELETE FROM posts
                WHERE id = ?
            `).run(postId);


            return res.json({
                mensagem:
                    'Publicação apagada.'
            });

        } catch (erro) {
            console.error(
                'Erro ao apagar publicação:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível apagar a publicação.'
            });
        }
    }
);


// ======================================================
// FÓRUM - CRIAR COMENTÁRIO
// ======================================================

app.post(
    '/api/posts/:postId/comments',
    exigirLogin,
    (req, res) => {
        try {
            if (!idValido(req.params.postId)) {
                return res.status(400).json({
                    erro:
                        'Publicação inválida.'
                });
            }


            const postId =
                Number(req.params.postId);


            const textoRecebido =
                req.body.texto;


            if (!ehString(textoRecebido)) {
                return res.status(400).json({
                    erro:
                        'O comentário possui formato inválido.'
                });
            }


            const texto =
                textoRecebido.trim();


            if (!texto) {
                return res.status(400).json({
                    erro:
                        'O comentário não pode ficar vazio.'
                });
            }


            if (texto.length > 2000) {
                return res.status(400).json({
                    erro:
                        'O comentário é muito grande.'
                });
            }


            const post =
                db.prepare(`
                    SELECT id
                    FROM posts
                    WHERE id = ?
                `).get(postId);


            if (!post) {
                return res.status(404).json({
                    erro:
                        'Publicação não encontrada.'
                });
            }


            const resultado =
                db.prepare(`
                    INSERT INTO comments (
                        post_id,
                        user_id,
                        content
                    )
                    VALUES (?, ?, ?)
                `).run(
                    postId,
                    req.user.id,
                    texto
                );


            return res.status(201).json({
                mensagem:
                    'Comentário publicado.',

                comentarioId:
                    resultado.lastInsertRowid
            });

        } catch (erro) {
            console.error(
                'Erro ao comentar:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível publicar o comentário.'
            });
        }
    }
);


// ======================================================
// FÓRUM - EDITAR COMENTÁRIO
// ======================================================

app.put(
    '/api/comments/:id',
    exigirLogin,
    (req, res) => {
        try {
            if (!idValido(req.params.id)) {
                return res.status(400).json({
                    erro:
                        'Comentário inválido.'
                });
            }


            const comentarioId =
                Number(req.params.id);


            const textoRecebido =
                req.body.texto;


            if (!ehString(textoRecebido)) {
                return res.status(400).json({
                    erro:
                        'O comentário possui formato inválido.'
                });
            }


            const texto =
                textoRecebido.trim();


            if (!texto) {
                return res.status(400).json({
                    erro:
                        'O comentário não pode ficar vazio.'
                });
            }


            if (texto.length > 2000) {
                return res.status(400).json({
                    erro:
                        'O comentário é muito grande.'
                });
            }


            const comentario =
                db.prepare(`
                    SELECT
                        id,
                        user_id

                    FROM comments

                    WHERE id = ?
                `).get(comentarioId);


            if (!comentario) {
                return res.status(404).json({
                    erro:
                        'Comentário não encontrado.'
                });
            }


            if (
                comentario.user_id !==
                req.user.id
            ) {
                return res.status(403).json({
                    erro:
                        'Você não pode editar este comentário.'
                });
            }


            db.prepare(`
                UPDATE comments

                SET content = ?

                WHERE id = ?
            `).run(
                texto,
                comentarioId
            );


            return res.json({
                mensagem:
                    'Comentário atualizado.'
            });

        } catch (erro) {
            console.error(
                'Erro ao editar comentário:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível editar o comentário.'
            });
        }
    }
);


// ======================================================
// FÓRUM - APAGAR COMENTÁRIO
// ======================================================

app.delete(
    '/api/comments/:id',
    exigirLogin,
    (req, res) => {
        try {
            if (!idValido(req.params.id)) {
                return res.status(400).json({
                    erro:
                        'Comentário inválido.'
                });
            }


            const comentarioId =
                Number(req.params.id);


            const comentario =
                db.prepare(`
                    SELECT
                        id,
                        user_id

                    FROM comments

                    WHERE id = ?
                `).get(comentarioId);


            if (!comentario) {
                return res.status(404).json({
                    erro:
                        'Comentário não encontrado.'
                });
            }


            if (
                comentario.user_id !==
                req.user.id
            ) {
                return res.status(403).json({
                    erro:
                        'Você não pode apagar este comentário.'
                });
            }


            db.prepare(`
                DELETE FROM comments
                WHERE id = ?
            `).run(comentarioId);


            return res.json({
                mensagem:
                    'Comentário apagado.'
            });

        } catch (erro) {
            console.error(
                'Erro ao apagar comentário:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível apagar o comentário.'
            });
        }
    }
);

// ======================================================
// DIÁRIO DE TRADES - LISTAR
// ======================================================

app.get(
    '/api/trades',
    exigirLogin,
    (req, res) => {
        try {
            const trades = db.prepare(`
                SELECT
                    id,
                    asset AS ativo,
                    order_type AS tipo,
                    entry_price AS entrada,
                    exit_price AS saida,
                    created_at AS data

                FROM trades

                WHERE user_id = ?

                ORDER BY
                    created_at DESC,
                    id DESC
            `).all(req.user.id);

            return res.json({
                trades
            });

        } catch (erro) {
            console.error(
                'Erro ao listar trades:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível carregar o diário de trades.'
            });
        }
    }
);


// ======================================================
// DIÁRIO DE TRADES - CRIAR
// ======================================================

app.post(
    '/api/trades',
    exigirLogin,
    (req, res) => {
        try {
            const {
                ativo: ativoRecebido,
                tipo: tipoRecebido,
                entrada: entradaRecebida,
                saida: saidaRecebida
            } = req.body;

            if (
                !ehString(ativoRecebido) ||
                !ehString(tipoRecebido)
            ) {
                return res.status(400).json({
                    erro:
                        'Os dados da operação possuem formato inválido.'
                });
            }

            const ativo =
                ativoRecebido.trim().toUpperCase();

            const tipo =
                tipoRecebido.trim().toLowerCase();

            const entrada =
                Number(entradaRecebida);

            const saida =
                Number(saidaRecebida);

            if (!ativo) {
                return res.status(400).json({
                    erro:
                        'Informe o ativo da operação.'
                });
            }

            if (ativo.length > 50) {
                return res.status(400).json({
                    erro:
                        'O nome do ativo pode possuir no máximo 50 caracteres.'
                });
            }

            const tiposPermitidos = [
                'compra',
                'venda'
            ];

            if (!tiposPermitidos.includes(tipo)) {
                return res.status(400).json({
                    erro:
                        'O tipo da operação deve ser compra ou venda.'
                });
            }

            if (
                !Number.isFinite(entrada) ||
                !Number.isFinite(saida) ||
                entrada <= 0 ||
                saida <= 0
            ) {
                return res.status(400).json({
                    erro:
                        'Os preços de entrada e saída devem ser números positivos.'
                });
            }

            const resultado = db.prepare(`
                INSERT INTO trades (
                    user_id,
                    asset,
                    order_type,
                    entry_price,
                    exit_price
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                req.user.id,
                ativo,
                tipo,
                entrada,
                saida
            );

            const trade = db.prepare(`
                SELECT
                    id,
                    asset AS ativo,
                    order_type AS tipo,
                    entry_price AS entrada,
                    exit_price AS saida,
                    created_at AS data

                FROM trades

                WHERE id = ?
                AND user_id = ?
            `).get(
                resultado.lastInsertRowid,
                req.user.id
            );

            return res.status(201).json({
                mensagem:
                    'Operação adicionada ao diário.',

                trade
            });

        } catch (erro) {
            console.error(
                'Erro ao criar trade:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível salvar a operação.'
            });
        }
    }
);


// ======================================================
// DIÁRIO DE TRADES - APAGAR
// ======================================================

app.delete(
    '/api/trades/:id',
    exigirLogin,
    (req, res) => {
        try {
            if (!idValido(req.params.id)) {
                return res.status(400).json({
                    erro:
                        'Operação inválida.'
                });
            }

            const tradeId =
                Number(req.params.id);

            const resultado = db.prepare(`
                DELETE FROM trades

                WHERE id = ?
                AND user_id = ?
            `).run(
                tradeId,
                req.user.id
            );

            if (resultado.changes === 0) {
                return res.status(404).json({
                    erro:
                        'Operação não encontrada.'
                });
            }

            return res.json({
                mensagem:
                    'Operação apagada do diário.'
            });

        } catch (erro) {
            console.error(
                'Erro ao apagar trade:',
                erro
            );

            return res.status(500).json({
                erro:
                    'Não foi possível apagar a operação.'
            });
        }
    }
);

// ======================================================
// NOTÍCIAS - NEWSAPI
// ======================================================

/**
 * Categorias aceitas pelo backend.
 *
 * O frontend envia somente o nome da categoria.
 * A consulta real da NewsAPI permanece definida
 * no servidor.
 */
const consultasNoticias = {
    ultimas:
        'mercado financeiro OR investimentos',

    money:
        'economia OR bolsa de valores',

    politica:
        'política brasil',

    agro:
        'agronegócio OR agricultura',

    ia:
        'inteligência artificial OR tecnologia',

    infra:
        'infraestrutura OR obras'
};


// ======================================================
// BUSCAR NOTÍCIAS
// ======================================================

const cacheNoticias = new Map();

const DURACAO_CACHE_NOTICIAS =
    5 * 60 * 1000;

const TIMEOUT_NOTICIAS =
    8 * 1000;


app.get(
    '/api/noticias',
    exigirLogin,
    noticiasLimiter,
    async (req, res) => {
        const categoria =
            req.query.categoria === undefined
                ? 'ultimas'
                : req.query.categoria;

        // Aceita somente categorias declaradas no objeto.
        if (
            !ehString(categoria) ||
            !Object.hasOwn(
                consultasNoticias,
                categoria
            )
        ) {
            return res.status(400).json({
                erro:
                    'Categoria de notícias inválida.'
            });
        }

        const apiKey =
            process.env.NEWS_API_KEY;

        if (
            !ehString(apiKey) ||
            !apiKey.trim()
        ) {
            return res.status(503).json({
                erro:
                    'Serviço de notícias não configurado.'
            });
        }

        // Consulta o cache antes de chamar a NewsAPI.
        const cache =
            cacheNoticias.get(categoria);

        if (
            cache &&
            cache.expiraEm > Date.now()
        ) {
            res.setHeader(
                'X-News-Cache',
                'HIT'
            );

            return res.json({
                categoria,
                artigos: cache.artigos
            });
        }

        // Não utiliza dados expirados silenciosamente.
        cacheNoticias.delete(categoria);

        const controlador =
            new AbortController();

        let tempoEsgotado = false;

        const temporizador = setTimeout(() => {
            tempoEsgotado = true;
            controlador.abort();
        }, TIMEOUT_NOTICIAS);

        try {
            const parametros =
                new URLSearchParams({
                    q:
                        consultasNoticias[categoria],

                    language:
                        'pt',

                    sortBy:
                        'publishedAt',

                    pageSize:
                        '30',

                    apiKey:
                        apiKey.trim()
                });

            const url =
                `https://newsapi.org/v2/everything?${parametros.toString()}`;

            const resposta =
                await fetch(url, {
                    signal:
                        controlador.signal
                });

            if (!resposta.ok) {
                // Registra somente o status, nunca a URL com a chave.
                console.error(
                    'Falha na NewsAPI. Status:',
                    resposta.status
                );

                return res.status(502).json({
                    erro:
                        'O serviço de notícias está temporariamente indisponível.'
                });
            }

            const dados =
                await resposta.json();

            if (
                dados?.status !== 'ok' ||
                !Array.isArray(dados.articles)
            ) {
                return res.status(502).json({
                    erro:
                        'O serviço de notícias retornou uma resposta inválida.'
                });
            }

            const artigos =
                dados.articles;

            // Guarda somente respostas bem-sucedidas.
            cacheNoticias.set(
                categoria,
                {
                    artigos,

                    expiraEm:
                        Date.now() +
                        DURACAO_CACHE_NOTICIAS
                }
            );

            res.setHeader(
                'X-News-Cache',
                'MISS'
            );

            return res.json({
                categoria,
                artigos
            });

        } catch {
            if (tempoEsgotado) {
                return res.status(504).json({
                    erro:
                        'O serviço de notícias demorou para responder. Tente novamente.'
                });
            }

            return res.status(502).json({
                erro:
                    'Não foi possível consultar o serviço de notícias.'
            });

        } finally {
            clearTimeout(temporizador);
        }
    }
);


// ======================================================
// 404 PARA ENDPOINTS DA API
// ======================================================

/**
 * Deve permanecer DEPOIS de todas as rotas /api.
 *
 * Assim qualquer endpoint inexistente recebe
 * JSON em vez de uma página HTML.
 */
app.use('/api', (req, res) => {
    return res.status(404).json({
        erro:
            'Endpoint não encontrado.'
    });
});


// ======================================================
// INICIAR SERVIDOR
// ======================================================

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(
            `ASTROMONEY rodando em http://localhost:${PORT}`
        );
    });
}

module.exports = app;