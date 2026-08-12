/* =========================================
   APP.JS - CÉREBRO GLOBAL ASTROMONEY
   Este ficheiro contém as lógicas JavaScript partilhadas
   por todas as páginas do ecossistema.
   ========================================= */

/**
 * Função global para ativar o Modo Tela Cheia (Fullscreen)
 * Pode ser chamada a partir de qualquer página para focar o utilizador.
 */
function ativarTelaCheia() {
  // Procura a área principal de trabalho (como nos Gráficos) ou usa todo o documento
  let areaTrabalho =
    document.getElementById("area-de-trabalho-completa") ||
    document.documentElement;

  // Verificação de compatibilidade com os diferentes navegadores (Chrome, Firefox, Safari, Edge)
  if (areaTrabalho.requestFullscreen) {
    areaTrabalho.requestFullscreen();
  } else if (areaTrabalho.webkitRequestFullscreen) {
    /* Suporte para Safari */
    areaTrabalho.webkitRequestFullscreen();
  } else if (areaTrabalho.msRequestFullscreen) {
    /* Suporte para Internet Explorer/Edge antigo */
    areaTrabalho.msRequestFullscreen();
  }
}

/**
 * Função global para futuras manipulações de menu (Exemplo de utilidade partilhada)
 * Prepara o terreno para criarmos um menu "Hambúrguer" dinâmico para telemóveis.
 */
function alternarMenuMobile() {
  const navLinks = document.querySelector(".nav-links");
  if (navLinks) {
    navLinks.classList.toggle("menu-aberto");
  }
}

// Mensagem de segurança para confirmar que o cérebro global conectou com sucesso
console.log("ASTROMONEY: Cérebro Global (app.js) carregado com sucesso!");
