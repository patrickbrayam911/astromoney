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

const app = express();

const PORT = process.env.PORT || 3000;

// ==========================================
// MIDDLEWARES
// ==========================================

app.use(express.json());

app.use(express.urlencoded({
    extended: true
}));

app.use(cookieParser());

// Servir os seus HTML, CSS, JS, vídeo etc.
app.use(express.static(
    path.join(__dirname, 'public')
));

// ==========================================
// CONFIGURAÇÃO DE SESSÃO
// ==========================================

const SESSION_COOKIE = 'astromoney_session';

const SESSION_DURATION =
    1000 * 60 * 60 * 24 * 7;

// 7 dias

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

// ==========================================
// BUSCAR USUÁRIO DA SESSÃO
// ==========================================

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

    // Sessão expirada
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

// ==========================================
// MIDDLEWARE PARA ROTAS PROTEGIDAS
// ==========================================

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

// ==========================================
// REGISTRO
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {

        let {
            nome,
            telefone,
            email,
            nivel,
            senha
        } = req.body;

        nome = nome?.trim();

        telefone = telefone?.trim();

        email =
            email?.trim().toLowerCase();

        nivel = nivel?.trim();

        // ==================================
        // VALIDAÇÕES
        // ==================================

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

        if (senha.length < 8) {
            return res.status(400).json({
                erro:
                    'A senha deve possuir pelo menos 8 caracteres.'
            });
        }

        if (
            ![
                'novato',
                'regular',
                'profissional'
            ].includes(nivel)
        ) {
            return res.status(400).json({
                erro:
                    'Nível de experiência inválido.'
            });
        }

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

        // ==================================
        // HASH DA SENHA
        // ==================================

        const passwordHash =
            await hashPassword(senha);

        // ==================================
        // INSERT
        // ==================================

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

        console.error(erro);

        return res.status(500).json({
            erro:
                'Erro interno ao criar a conta.'
        });
    }
});

// ==========================================
// LOGIN
// ==========================================

app.post('/api/auth/login', async (req, res) => {
    try {

        let {
            email,
            senha
        } = req.body;

        email =
            email?.trim().toLowerCase();

        if (!email || !senha) {
            return res.status(400).json({
                erro:
                    'Informe e-mail e senha.'
            });
        }

        const usuario =
            db.prepare(`
                SELECT *
                FROM users
                WHERE email = ?
            `).get(email);

        // Mensagem genérica:
        // evita revelar se determinado e-mail existe.
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

        // Remove sessões antigas daquele usuário.
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

        console.error(erro);

        return res.status(500).json({
            erro:
                'Erro interno durante o login.'
        });
    }
});

// ==========================================
// CONSULTAR SESSÃO
// ==========================================

app.get(
    '/api/auth/me',
    exigirLogin,
    (req, res) => {

        return res.json({
            usuario: req.user
        });
    }
);

// ==========================================
// LOGOUT
// ==========================================

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
                process.env.NODE_ENV === 'production'
        }
    );

    return res.json({
        mensagem:
            'Logout realizado com sucesso.'
    });
});

// ==========================================
// ROTA DE TESTE PROTEGIDA
// ==========================================

app.get(
    '/api/teste-protegido',
    exigirLogin,
    (req, res) => {

        res.json({
            mensagem:
                `Olá, ${req.user.nome}. Esta rota é protegida.`
        });
    }
);

// ==========================================
// PERFIL DO USUÁRIO
// ==========================================

app.get(
    '/api/users/profile',
    exigirLogin,
    (req, res) => {

        return res.json({
            usuario: req.user
        });
    }
);

// ==========================================
// ALTERAR SENHA
// ==========================================

app.put(
    '/api/users/password',
    exigirLogin,
    async (req, res) => {

        try {

            const {
                senhaAtual,
                novaSenha
            } = req.body;

            // ==================================
            // VALIDAÇÃO
            // ==================================

            if (!senhaAtual || !novaSenha) {

                return res.status(400).json({
                    erro:
                        'Informe a senha atual e a nova senha.'
                });
            }

            if (novaSenha.length < 8) {

                return res.status(400).json({
                    erro:
                        'A nova senha deve possuir pelo menos 8 caracteres.'
                });
            }

            // ==================================
            // BUSCAR HASH ATUAL
            // ==================================

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

            // ==================================
            // VERIFICAR SENHA ATUAL
            // ==================================

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

            // ==================================
            // NÃO ACEITAR A MESMA SENHA
            // ==================================

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

            // ==================================
            // GERAR NOVO HASH
            // ==================================

            const novoHash =
                await hashPassword(
                    novaSenha
                );

            // ==================================
            // ATUALIZAR BANCO
            // ==================================

            db.prepare(`
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
            `).run(
                novoHash,
                req.user.id
            );

            // ==================================
            // ENCERRAR OUTRAS SESSÕES
            // ==================================

            const sessionId =
                req.cookies[
                    SESSION_COOKIE
                ];

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

// ==========================================
// APAGAR CONTA
// ==========================================

app.delete(
    '/api/users/profile',
    exigirLogin,
    (req, res) => {

        try {

            const userId =
                req.user.id;

            // Como configuramos
            // ON DELETE CASCADE,
            // sessões, posts e comentários
            // ligados ao usuário também
            // poderão ser removidos.

            const resultado =
                db.prepare(`
                    DELETE FROM users
                    WHERE id = ?
                `).run(userId);

            if (
                resultado.changes === 0
            ) {

                return res.status(404).json({
                    erro:
                        'Usuário não encontrado.'
                });
            }

            // Remove o cookie do navegador

            res.clearCookie(
                SESSION_COOKIE,
                {
                    httpOnly: true,

                    sameSite:
                        'strict',

                    secure:
                        process.env.NODE_ENV
                        === 'production'
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

// ==========================================
// FÓRUM - LISTAR PUBLICAÇÕES
// ==========================================

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
                        ON users.id =
                           posts.user_id

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
                        ON users.id =
                           comments.user_id

                    WHERE
                        comments.post_id = ?

                    ORDER BY
                        comments.created_at ASC,
                        comments.id ASC
                `);


            const resultado =
                posts.map(post => {

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
                                comentario => ({
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
// ==========================================
// FÓRUM - CRIAR PUBLICAÇÃO
// ==========================================

app.post(
    '/api/posts',
    exigirLogin,
    (req, res) => {

        try {

            const titulo =
                req.body.titulo?.trim();

            const conteudo =
                req.body.conteudo?.trim();


            if (
                !titulo ||
                !conteudo
            ) {

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
// ==========================================
// FÓRUM - EDITAR PUBLICAÇÃO
// ==========================================

app.put(
    '/api/posts/:id',
    exigirLogin,
    (req, res) => {

        try {

            const postId =
                Number(req.params.id);

            const titulo =
                req.body.titulo?.trim();

            const conteudo =
                req.body.conteudo?.trim();


            if (
                !Number.isInteger(postId)
            ) {

                return res.status(400).json({
                    erro:
                        'Publicação inválida.'
                });
            }


            if (
                !titulo ||
                !conteudo
            ) {

                return res.status(400).json({
                    erro:
                        'Título e conteúdo são obrigatórios.'
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


            if (
                post.user_id !==
                req.user.id
            ) {

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

// ==========================================
// FÓRUM - APAGAR PUBLICAÇÃO
// ==========================================

app.delete(
    '/api/posts/:id',
    exigirLogin,
    (req, res) => {

        try {

            const postId =
                Number(req.params.id);


            if (
                !Number.isInteger(postId)
            ) {

                return res.status(400).json({
                    erro:
                        'Publicação inválida.'
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


            if (
                post.user_id !==
                req.user.id
            ) {

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

// ==========================================
// FÓRUM - CRIAR COMENTÁRIO
// ==========================================

app.post(
    '/api/posts/:postId/comments',
    exigirLogin,
    (req, res) => {

        try {

            const postId =
                Number(
                    req.params.postId
                );

            const texto =
                req.body.texto?.trim();


            if (
                !Number.isInteger(postId)
            ) {

                return res.status(400).json({
                    erro:
                        'Publicação inválida.'
                });
            }


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

// ==========================================
// FÓRUM - EDITAR COMENTÁRIO
// ==========================================

app.put(
    '/api/comments/:id',
    exigirLogin,
    (req, res) => {

        try {

            const comentarioId =
                Number(req.params.id);

            const texto =
                req.body.texto?.trim();


            if (
                !Number.isInteger(
                    comentarioId
                )
            ) {

                return res.status(400).json({
                    erro:
                        'Comentário inválido.'
                });
            }


            if (!texto) {

                return res.status(400).json({
                    erro:
                        'O comentário não pode ficar vazio.'
                });
            }


            const comentario =
                db.prepare(`
                    SELECT
                        id,
                        user_id

                    FROM comments

                    WHERE id = ?
                `).get(
                    comentarioId
                );


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

// ==========================================
// FÓRUM - APAGAR COMENTÁRIO
// ==========================================

app.delete(
    '/api/comments/:id',
    exigirLogin,
    (req, res) => {

        try {

            const comentarioId =
                Number(req.params.id);


            if (
                !Number.isInteger(
                    comentarioId
                )
            ) {

                return res.status(400).json({
                    erro:
                        'Comentário inválido.'
                });
            }


            const comentario =
                db.prepare(`
                    SELECT
                        id,
                        user_id

                    FROM comments

                    WHERE id = ?
                `).get(
                    comentarioId
                );


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
            `).run(
                comentarioId
            );


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

// ==========================================
// NOTÍCIAS - NEWSAPI
// ==========================================

/**
 * Termos permitidos para pesquisa de notícias.
 *
 * A categoria recebida pelo navegador é convertida
 * em uma consulta definida pelo próprio servidor.
 *
 * Isso evita permitir que qualquer texto arbitrário
 * seja enviado diretamente para a API externa.
 */
const consultasNoticias = {
    ultimas: 'mercado financeiro OR investimentos',
    money: 'economia OR bolsa de valores',
    politica: 'política brasil',
    agro: 'agronegócio OR agricultura',
    ia: 'inteligência artificial OR tecnologia',
    infra: 'infraestrutura OR obras'
};


/**
 * GET /api/noticias
 *
 * Busca notícias através da NewsAPI sem expor
 * a chave privada para o navegador.
 *
 * Exemplo:
 *
 * /api/noticias?categoria=money
 */
app.get(
    '/api/noticias',
    exigirLogin,
    async (req, res) => {

        try {

            // Categoria enviada pelo frontend.
            const categoria =
                req.query.categoria || 'ultimas';


            // Verifica se a categoria existe
            // na nossa lista permitida.
            const consulta =
                consultasNoticias[categoria];


            if (!consulta) {

                return res.status(400).json({
                    erro:
                        'Categoria de notícias inválida.'
                });
            }


            // A chave fica somente no servidor.
            const apiKey =
                process.env.NEWS_API_KEY;


            if (!apiKey) {

                console.error(
                    'NEWS_API_KEY não foi configurada no arquivo .env.'
                );

                return res.status(500).json({
                    erro:
                        'Serviço de notícias não configurado.'
                });
            }


            // URLSearchParams monta os parâmetros
            // da URL de forma segura e legível.
            const parametros =
                new URLSearchParams({
                    q: consulta,
                    language: 'pt',
                    sortBy: 'publishedAt',
                    pageSize: '30',
                    apiKey: apiKey
                });


            const urlNewsAPI =
                `https://newsapi.org/v2/everything?${parametros.toString()}`;


            // Node.js moderno possui fetch nativo.
            const respostaNewsAPI =
                await fetch(urlNewsAPI);


            if (!respostaNewsAPI.ok) {

                console.error(
                    'Erro NewsAPI:',
                    respostaNewsAPI.status
                );

                return res.status(502).json({
                    erro:
                        'Não foi possível consultar o serviço de notícias.'
                });
            }


            const dados =
                await respostaNewsAPI.json();


            // Evitamos devolver dados desnecessários
            // recebidos da API externa.
            const artigos =
                Array.isArray(dados.articles)
                    ? dados.articles
                    : [];


            return res.json({
                categoria,
                artigos
            });

        } catch (erro) {

            console.error(
                'Erro ao buscar notícias:',
                erro
            );


            return res.status(500).json({
                erro:
                    'Erro interno ao carregar notícias.'
            });
        }
    }
);

// ==========================================
// 404 API
// ==========================================

app.use('/api', (req, res) => {

    res.status(404).json({
        erro:
            'Endpoint não encontrado.'
    });
});

// ==========================================
// INICIAR SERVIDOR
// ==========================================

app.listen(PORT, () => {

    console.log(
        `ASTROMONEY rodando em http://localhost:${PORT}`
    );
});

