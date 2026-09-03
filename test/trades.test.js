const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

// Configure antes de importar o servidor e o banco.
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

async function criarUsuario(email) {
    const navegador = request.agent(app);

    await navegador
        .post('/api/auth/register')
        .send({
            nome: 'Usuário de Teste',
            email,
            nivel: 'novato',
            senha: 'senha-segura-123'
        })
        .expect(201);

    await navegador
        .post('/api/auth/login')
        .send({
            email,
            senha: 'senha-segura-123'
        })
        .expect(200);

    return navegador;
}

test('trades exigem autenticação', async () => {
    await request(app)
        .get('/api/trades')
        .expect(401);

    await request(app)
        .post('/api/trades')
        .send({
            ativo: 'ETH/USD',
            tipo: 'compra',
            entrada: 1800,
            saida: 1900
        })
        .expect(401);

    await request(app)
        .delete('/api/trades/1')
        .expect(401);
});

test(
    'trades pertencem somente ao usuário que os cadastrou',
    async () => {
        const usuarioA = await criarUsuario(
            'trader-a@example.com'
        );

        const usuarioB = await criarUsuario(
            'trader-b@example.com'
        );

        // Usuário A cadastra uma operação.
        const criacao = await usuarioA
            .post('/api/trades')
            .send({
                ativo: 'ETH/USD',
                tipo: 'compra',
                entrada: 1800,
                saida: 1900
            })
            .expect(201);

        const tradeId = criacao.body.trade.id;

        assert.ok(Number.isInteger(tradeId));
        assert.equal(
            criacao.body.trade.ativo,
            'ETH/USD'
        );

        // A operação aparece para o proprietário.
        const listaA = await usuarioA
            .get('/api/trades')
            .expect(200);

        assert.equal(listaA.body.trades.length, 1);
        assert.equal(
            listaA.body.trades[0].id,
            tradeId
        );

        // Ela não aparece para o outro usuário.
        const listaB = await usuarioB
            .get('/api/trades')
            .expect(200);

        assert.deepEqual(listaB.body.trades, []);

        // Outro usuário não pode apagá-la.
        await usuarioB
            .delete(`/api/trades/${tradeId}`)
            .expect(404);

        // A tentativa não removeu a operação.
        const depoisDaTentativa = await usuarioA
            .get('/api/trades')
            .expect(200);

        assert.equal(
            depoisDaTentativa.body.trades.length,
            1
        );

        // Preço negativo deve ser recusado.
        await usuarioA
            .post('/api/trades')
            .send({
                ativo: 'BTC/USD',
                tipo: 'compra',
                entrada: -10,
                saida: 100
            })
            .expect(400);

        // Tipo de operação inválido deve ser recusado.
        await usuarioA
            .post('/api/trades')
            .send({
                ativo: 'BTC/USD',
                tipo: 'invalido',
                entrada: 100,
                saida: 110
            })
            .expect(400);

        // Nenhuma operação inválida foi salva.
        const depoisDasValidacoes = await usuarioA
            .get('/api/trades')
            .expect(200);

        assert.equal(
            depoisDasValidacoes.body.trades.length,
            1
        );

        // O proprietário consegue apagar.
        await usuarioA
            .delete(`/api/trades/${tradeId}`)
            .expect(200);

        const listaFinal = await usuarioA
            .get('/api/trades')
            .expect(200);

        assert.deepEqual(listaFinal.body.trades, []);
    }
);