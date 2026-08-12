/* =========================================
   APP.JS - CÉREBRO GLOBAL ASTROMONEY
   ========================================= */

/**
 * FUNÇÃO DE SEGURANÇA (Auth Guard)
 * Colocamos esta função nas páginas privadas. Se não houver login, expulsa o visitante.
 */
function protegerPagina() {
    const estadoLogin = localStorage.getItem('astromoney_logado');
    if (estadoLogin !== 'sim') {
        // Redireciona para a página de login
        window.location.href = 'login.html';
    }
}

/**
 * FUNÇÃO DE LOGOUT
 * Apaga o cartão de acesso e devolve o utilizador à página inicial pública.
 */
function fazerLogout() {
    localStorage.removeItem('astromoney_logado');
    window.location.href = 'astromoney_home.html';
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