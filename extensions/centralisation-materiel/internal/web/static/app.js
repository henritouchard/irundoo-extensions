// Erreurs des requêtes htmx (rafraîchissement de la liste, détail) : htmx ne remplace pas le contenu
// sur une réponse 4xx/5xx ; sans ce bandeau, l'écran resterait figé sans rien dire.
(function () {
  function bandeau() { return document.getElementById("erreur-htmx"); }
  function montrer(texte) {
    var b = bandeau();
    if (!b) { return; }
    b.textContent = texte;
    b.hidden = false;
  }
  document.addEventListener("htmx:responseError", function (e) {
    var xhr = e.detail.xhr, titre = "", texte = "";
    try {
      var doc = new DOMParser().parseFromString(xhr.responseText, "text/html");
      var h1 = doc.querySelector("h1"), p = doc.querySelector("main p");
      titre = h1 ? h1.textContent : "";
      texte = p ? p.textContent : "";
    } catch (_) { /* corps illisible : statut seul */ }
    montrer("Mise à jour impossible (HTTP " + xhr.status + ")" + (titre ? " : " + titre : "") + (texte ? " — " + texte : "") +
      ". L'affichage ci-dessous n'est plus à jour.");
  });
  document.addEventListener("htmx:sendError", function () {
    montrer("Mise à jour impossible : l'application ne répond pas. L'affichage ci-dessous n'est plus à jour.");
  });
  document.addEventListener("htmx:afterSwap", function () {
    var b = bandeau();
    if (b) { b.hidden = true; }
  });
})();
