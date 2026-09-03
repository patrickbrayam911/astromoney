const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';

const db = require('../database');

assert.equal(
    db.name,
    ':memory:',
    'TESTE INTERROMPIDO: o banco precisa estar em memória.'
);

const app = require('../server');

after(() => {
    db.close();
});

test(
    'exclusão exige senha e remove os registros relacionados',
    async () => {
        const navegador = request.agent(app);

        const email = 'exclusao@example.com';
        const senha = 'senha-segura-123';

        const cadastro = await navegador
            .post('/api/auth/register')
            .send({
                nome: 'Conta Temporária',
                email,
                nivel: 'novato',
                senha
            })
            .expect(201);

        const userId = cadastro.body.usuario.id;

        await navegador
            .post('/api/auth/login')
            .send({
                email,
                senha
            })
            .expect(200);

        // Guarda o cookie para testar sua invalidação.
        const login = await navegador
            .get('/api/auth/me')
            .expect(200);

        assert.equal(
            login.body.usuario.id,
            userId
        );

        const sessao = db.prepare(`
            SELECT id
            FROM sessions
            WHERE user_id = ?
        `).get(userId);

        assert.ok(sessao);

        const cookieAntigo =
            `astromoney_session=${sessao.id}`;

        // Cria uma operação pelo endpoint.
        await navegador
            .post('/api/trades')
            .send({
                ativo: 'ETH/USD',
                tipo: 'compra',
                entrada: 1800,
                saida: 1900
            })
            .expect(201);

        // Cria registros relacionados no banco de teste.
        const post = db.prepare(`
            INSERT INTO posts (
                user_id,
                title,
                content
            )
            VALUES (?, ?, ?)
        `).run(
            userId,
            'Publicação de teste',
            'Conteúdo de teste'
        );

        db.prepare(`
            INSERT INTO comments (
                post_id,
                user_id,
                content
            )
            VALUES (?, ?, ?)
        `).run(
            post.lastInsertRowid,
            userId,
            'Comentário de teste'
        );

        const consultas = {
            usuarios:
                'SELECT COUNT(*) AS total FROM users WHERE id = ?',

            sessoes:
                'SELECT COUNT(*) AS total FROM sessions WHERE user_id = ?',

            trades:
                'SELECT COUNT(*) AS total FROM trades WHERE user_id = ?',

            posts:
                'SELECT COUNT(*) AS total FROM posts WHERE user_id = ?',

            comentarios:
                'SELECT COUNT(*) AS total FROM comments WHERE user_id = ?'
        };

        function verificarQuantidade(esperado) {
            for (
                const [nome, sql]
                of Object.entries(consultas)
            ) {
                const resultado =
                    db.prepare(sql).get(userId);

                assert.equal(
                    resultado.total,
                    esperado,
                    `Quantidade inesperada em ${nome}`
                );
            }
        }

        // Confirma que os registros existem.
        verificarQuantidade(1);

        // Sem sessão, não pode excluir.
        await request(app)
            .delete('/api/users/profile')
            .send({ senha })
            .expect(401);

        // Sem senha, não pode excluir.
        await navegador
            .delete('/api/users/profile')
            .send({})
            .expect(400);

        verificarQuantidade(1);

        // Senha incorreta não pode excluir.
        await navegador
            .delete('/api/users/profile')
            .send({
                senha: 'senha-incorreta'
            })
            .expect(401);

        verificarQuantidade(1);

        // A sessão continua válida após a tentativa.
        await navegador
            .get('/api/auth/me')
            .expect(200);

        // Senha correta permite excluir.
        await navegador
            .delete('/api/users/profile')
            .send({ senha })
            .expect(200);

        // Confirma a exclusão em cascata.
        verificarQuantidade(0);

        // Nem o cookie antigo consegue autenticar.
        await request(app)
            .get('/api/auth/me')
            .set('Cookie', cookieAntigo)
            .expect(401);

        // A conta excluída não consegue fazer login.
        await request(app)
            .post('/api/auth/login')
            .send({
                email,
                senha
            })
            .expect(401);
    }
);