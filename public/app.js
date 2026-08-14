/* =========================================
   APP.JS - CÉREBRO GLOBAL ASTROMONEY
   ========================================= */

/**
 * FUNÇÃO DE SEGURANÇA (Auth Guard)
 */
async function protegerPagina() {

    try {

        const resposta =
            await fetch(
                '/api/auth/me'
            );

        if (!resposta.ok) {

            window.location.href =
                'login.html';

            return null;
        }

        const dados =
            await resposta.json();

        return dados.usuario;

    } catch (erro) {

        console.error(
            'Erro ao verificar sessão:',
            erro
        );

        window.location.href =
            'login.html';

        return null;
    }
}

/**
 * FUNÇÃO DE LOGOUT
 */
async function fazerLogout() {

    try {

        await fetch(
            '/api/auth/logout',
            {
                method: 'POST'
            }
        );

    } catch (erro) {

        console.error(
            'Erro durante logout:',
            erro
        );
    }

    window.location.href =
        'astromoney_home.html';
}

/**
 * Função global para ativar o Modo Tela Cheia (Fullscreen)
 */
function ativarTelaCheia() {
    let areaTrabalho = document.getElementById("area-de-trabalho-completa") || document.documentElement;
    if (areaTrabalho.requestFullscreen) {
        areaTrabalho.requestFullscreen();
    } else if (areaTrabalho.webkitRequestFullscreen) { 
        areaTrabalho.webkitRequestFullscreen();
    } else if (areaTrabalho.msRequestFullscreen) { 
        areaTrabalho.msRequestFullscreen();
    }
}

/**
 * Função global para manipular o Menu Mobile (Hambúrguer)
 */
function alternarMenuMobile() {
    const navLinks = document.querySelector('.nav-links');
    if (navLinks) {
        navLinks.classList.toggle('menu-aberto');
    }
}

console.log("ASTROMONEY: Cérebro Global (app.js) carregado com segurança ativada!");

// =========================================
// LÓGICA DO TICKER EM TEMPO REAL
// =========================================

// Guarda os preços antigos para sabermos se o valor subiu ou desceu
let precosAnteriores = {
    eth: 0,
    sol: 0,
    oil: 0
};

/**
 * Atualiza o texto do preço e muda a cor (Verde para subida, Vermelho para descida)
 */
function atualizarElementoPreco(idElemento, precoNovo, ativoChave) {
    const elemento = document.getElementById(idElemento);
    if (!elemento) return;

    elemento.textContent = `$${precoNovo.toFixed(2)}`;
    const precoAntigo = precosAnteriores[ativoChave];

    if (precoAntigo > 0) { 
        if (precoNovo > precoAntigo) {
            elemento.classList.remove('preco-desceu');
            elemento.classList.add('preco-subiu');
        } else if (precoNovo < precoAntigo) {
            elemento.classList.remove('preco-subiu');
            elemento.classList.add('preco-desceu');
        }
    }

    precosAnteriores[ativoChave] = precoNovo;
}

/**
 * Tenta ir à internet buscar preços. Se o localhost for bloqueado, gera valores simulados imediatamente.
 */
async function atualizarTickerAstromoney() {
    try {
        const urlCripto = 'https://api.coingecko.com/api/v3/simple/price?ids=ethereum,solana&vs_currencies=usd';
        const respostaCripto = await fetch(urlCripto);
        
        if (!respostaCripto.ok) {
            throw new Error('Falha na API ou bloqueio de CORS no localhost.');
        }
        
        const dadosCripto = await respostaCripto.json();

        const novoEth = dadosCripto.ethereum.usd;
        const novoSol = dadosCripto.solana.usd;

        const precoBaseOil = 78.50; 
        const flutuacao = (Math.random() * 0.5 - 0.25);
        const novoOil = precoBaseOil + flutuacao;

        atualizarElementoPreco('price-eth', novoEth, 'eth');
        atualizarElementoPreco('price-sol', novoSol, 'sol');
        atualizarElementoPreco('price-oil', novoOil, 'oil');

    } catch (erro) {
        console.warn("Aviso Ticker ASTROMONEY:", erro.message, "A carregar dados simulados para desenvolvimento local.");
        
        // Se a API for bloqueada, simulamos os dados para a interface não encravar
        const baseEth = precosAnteriores.eth > 0 ? precosAnteriores.eth : 1850.50;
        const baseSol = precosAnteriores.sol > 0 ? precosAnteriores.sol : 145.20;
        const baseOil = precosAnteriores.oil > 0 ? precosAnteriores.oil : 78.50;

        // Cria uma oscilação realista para cima ou para baixo
        const simulaEth = baseEth + (Math.random() * 10 - 5);
        const simulaSol = baseSol + (Math.random() * 2 - 1);
        const simulaOil = baseOil + (Math.random() * 0.5 - 0.25);

        atualizarElementoPreco('price-eth', simulaEth, 'eth');
        atualizarElementoPreco('price-sol', simulaSol, 'sol');
        atualizarElementoPreco('price-oil', simulaOil, 'oil');
    }
}

// Inicializa a barra ao abrir a página e atualiza a cada 5 segundos
document.addEventListener('DOMContentLoaded', () => {
    const tickerContainer = document.getElementById('astromoney-ticker');
    if (tickerContainer) {
        atualizarTickerAstromoney(); 
        setInterval(atualizarTickerAstromoney, 5000); 
    }
});