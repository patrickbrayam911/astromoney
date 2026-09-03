const {
    before,
    after,
    test
} = require('node:test');

const assert =
    require('node:assert/strict');

const request =
    require('supertest');


process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = ':memory:';


const app = require('../server');
const db = require('../database');

assert.equal(
    db.name,
    ':memory:',
    'TESTE INTERROMPIDO: o banco precisa estar em memória.'
);


after(() => {
    db.close();
});


test(
    'rota protegida rejeita usuário sem sessão',
    async () => {
        const resposta =
            await request(app)
                .get('/api/auth/me');

        assert.equal(
            resposta.status,
            401
        );

        assert.equal(
            resposta.body.erro,
            'Não autenticado.'
        );
    }
);


test(
    'usuário pode criar uma conta',
    async () => {
        const resposta =
            await request(app)
                .post('/api/auth/register')
                .send({
                    nome:
                        'Usuário de Teste',

                    telefone:
                        '11999999999',

                    email:
                        'teste@example.com',

                    nivel:
                        'novato',

                    senha:
                        'senha-segura-123'
                });

        assert.equal(
            resposta.status,
            201
        );

        assert.equal(
            resposta.body.usuario.email,
            'teste@example.com'
        );

        assert.equal(
            Object.hasOwn(
                resposta.body.usuario,
                'password_hash'
            ),
            false
        );
    }
);


test(
    'cadastro duplicado é recusado',
    async () => {
        const resposta =
            await request(app)
                .post('/api/auth/register')
                .send({
                    nome:
                        'Outro Nome',

                    email:
                        'teste@example.com',

                    nivel:
                        'regular',

                    senha:
                        'outra-senha-123'
                });

        assert.equal(
            resposta.status,
            409
        );
    }
);


test(
    'login com senha incorreta é recusado',
    async () => {
        const resposta =
            await request(app)
                .post('/api/auth/login')
                .send({
                    email:
                        'teste@example.com',

                    senha:
                        'senha-incorreta'
                });

        assert.equal(
            resposta.status,
            401
        );
    }
);


test(
    'login correto cria uma sessão',
    async () => {
        const navegador =
            request.agent(app);

        const login =
            await navegador
                .post('/api/auth/login')
                .send({
                    email:
                        'teste@example.com',

                    senha:
                        'senha-segura-123'
                });

        assert.equal(
            login.status,
            200
        );

        const sessao =
            await navegador
                .get('/api/auth/me');

        assert.equal(
            sessao.status,
            200
        );

        assert.equal(
            sessao.body.usuario.email,
            'teste@example.com'
        );
    }
);