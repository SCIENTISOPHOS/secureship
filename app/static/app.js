"use strict";
// SecureShip — interface web. Aucune donnée n'est insérée en HTML brut :
// tout passe par textContent pour écarter toute injection (XSS).

const I18N = {
  fr: {
    skip: "Aller au formulaire",
    "nav.guide": "Comprendre", "nav.data": "Données", "nav.dev": "Développeurs", "nav.faq": "Questions",
    "hero.title": "Un lien, une adresse ou un fichier vous semble suspect ? Vérifiez-le ici.",
    "hero.lead": "SecureShip compare ce que vous collez à des milliers d'indicateurs de menaces signalés par la communauté cyber, mis à jour chaque matin.",
    "form.label": "Ce que vous voulez vérifier",
    "form.placeholder": "Exemple : https://site-douteux.example/connexion",
    "form.hint": "Un élément par ligne, 100 au maximum. Les liens «\u00a0désarmés\u00a0» comme hxxp://site[.]com sont acceptés.",
    "form.submit": "Vérifier", "form.checking": "Vérification…", "form.clear": "Effacer",
    "form.empty": "Collez au moins un élément à vérifier dans le champ ci-dessus.",
    "form.toomany": "100 éléments au maximum par vérification. Retirez quelques lignes et relancez.",
    "form.error": "La vérification n'a pas abouti. Vérifiez votre connexion puis réessayez.",
    "examples.title": "Pas d'exemple sous la main ? Essayez :",
    "examples.c2": "une adresse de serveur pirate", "examples.phishing": "un lien d'hameçonnage",
    "examples.eicar": "le fichier de test antivirus EICAR", "examples.clean": "un site ordinaire",
    privacy: "Vos recherches ne sont ni enregistrées ni transmises à un tiers : la comparaison se fait sur le serveur de SecureShip.",
    "results.title": "Résultats",
    "results.summary": (n, bad) => bad === 0
      ? `${n} élément${n > 1 ? "s" : ""} vérifié${n > 1 ? "s" : ""} : aucun n'est signalé.`
      : `${n} élément${n > 1 ? "s" : ""} vérifié${n > 1 ? "s" : ""} : ${bad} signalé${bad > 1 ? "s" : ""} comme malveillant${bad > 1 ? "s" : ""}.`,
    "verdict.bad": "Signalé", "verdict.good": "Rien trouvé", "verdict.invalid": "Non reconnu",
    "type.ipv4": "Adresse IPv4", "type.ipv6": "Adresse IPv6", "type.domain": "Nom de domaine",
    "type.md5": "Empreinte MD5", "type.sha1": "Empreinte SHA-1", "type.sha256": "Empreinte SHA-256",
    "type.invalid": "Format non reconnu",
    "type.fromurl": " (extrait du lien)", "type.private": " · adresse de réseau local",
    "fact.threat": "Menace", "fact.confidence": "Confiance", "fact.source": "Source",
    "fact.seen": "Signalé le", "fact.matched": "Domaine signalé",
    "advice.bad.domain": "N'ouvrez pas ce lien et ne saisissez rien sur ce site. Si c'est déjà fait, lisez la question «\u00a0J'ai cliqué sur un lien signalé\u00a0» plus bas.",
    "advice.bad.ip": "Ne vous connectez pas à cette adresse. Un administrateur peut la bloquer sur le pare-feu et rechercher d'éventuelles connexions passées dans les journaux.",
    "advice.bad.hash": "Ne lancez pas ce fichier : supprimez-le ou faites-le analyser par votre antivirus ou votre service informatique.",
    "advice.good": "Aucun signalement connu, ce qui n'est pas une garantie. Restez prudent si le message vous presse ou demande vos identifiants.",
    "advice.private": "Adresse interne à un réseau (box, entreprise) : elle n'est pas joignable depuis Internet et ne figure pas dans les bases publiques.",
    "advice.invalid": "Vérifiez la saisie : attendu une adresse IP, un domaine, un lien ou une empreinte de 32, 40 ou 64 caractères.",
    "guide.title": "Lire le résultat",
    "guide.bad.title": "Connu comme malveillant",
    "guide.bad.text": "L'élément figure dans une base de menaces. N'ouvrez pas le lien, ne lancez pas le fichier et prévenez votre service informatique si c'est un appareil professionnel.",
    "guide.good.title": "Absent de la base",
    "guide.good.text": "Aucun signalement connu. Ce n'est pas une garantie : une menace toute récente peut ne pas encore être répertoriée. Restez prudent si le message vous presse ou vous demande vos identifiants.",
    "guide.invalid.title": "Format inconnu",
    "guide.invalid.text": "Ce n'est ni une adresse IP, ni un domaine, ni un lien, ni une empreinte de fichier. Vérifiez qu'il n'y a pas de faute de frappe ou d'espace en trop.",
    "types.title": "Ce que vous pouvez vérifier",
    "types.url": "Un lien (URL)", "types.url.text": "Le domaine est extrait automatiquement. Copiez le lien avec un clic droit plutôt que de l'ouvrir.",
    "types.domain": "Un nom de domaine", "types.domain.text": "Les sous-domaines d'un domaine signalé sont signalés aussi.",
    "types.ip": "Une adresse IP", "types.ip.text": "IPv4 ou IPv6, avec ou sans numéro de port. Les adresses de réseau local sont identifiées comme privées.",
    "types.hash": "L'empreinte d'un fichier (hash)", "types.hash.text": "Une suite de 32, 40 ou 64 caractères qui identifie un fichier sans l'envoyer. Formats MD5, SHA-1 et SHA-256.",
    "hash.title": "Obtenir l'empreinte d'un fichier sans l'ouvrir",
    "hash.text": "Le fichier ne quitte jamais votre ordinateur : seule son empreinte est vérifiée. Ouvrez un terminal dans le dossier du fichier, puis tapez :",
    "data.title": "D'où viennent les données",
    "data.ips": "adresses IP", "data.domains": "domaines", "data.hashes": "empreintes de fichiers",
    "data.text": "Chaque matin, SecureShip télécharge les indicateurs des sept derniers jours publiés par ThreatFox, une base gratuite de l'organisation suisse abuse.ch alimentée par des chercheurs en sécurité. Chaque entrée est vérifiée avant d'être ajoutée, et les grands services légitimes sont exclus pour éviter les fausses alertes.",
    "data.demo": "Quelques entrées de démonstration, sans danger, sont toujours présentes pour tester l'outil : elles utilisent des adresses réservées à la documentation et le fichier de test antivirus EICAR.",
    "data.updated": (d) => `Base mise à jour le ${d}.`,
    "data.demoonly": "Mode démonstration : le flux ThreatFox n'est pas encore activé sur ce serveur.",
    "dev.title": "Pour les développeurs et les analystes",
    "dev.text": "Tout ce que fait cette page passe par une API REST publique, documentée et testable dans le navigateur :",
    "dev.docs": "ouvrir la documentation interactive",
    "dev.c1": "Un indicateur, type détecté automatiquement", "dev.c2": "Jusqu'à 100 indicateurs d'un coup",
    "dev.repo": "Code source, pipeline DevSecOps et infrastructure Azure :",
    "faq.title": "Questions fréquentes",
    "faq.q1": "Mes recherches sont-elles enregistrées ?",
    "faq.a1": "Non. Les éléments que vous vérifiez ne sont ni stockés ni envoyés à un autre service. La base de menaces est chargée sur le serveur, et la comparaison se fait localement.",
    "faq.q2": "«\u00a0Rien trouvé\u00a0» veut-il dire que c'est sans danger ?",
    "faq.a2": "Non. Cela veut dire qu'aucun signalement n'est connu. Les attaquants créent de nouveaux sites chaque jour. Méfiez-vous d'un message qui vous presse, promet un gain ou demande un mot de passe.",
    "faq.q3": "J'ai cliqué sur un lien signalé. Que faire ?",
    "faq.a3": "Si vous avez saisi un mot de passe, changez-le immédiatement sur le vrai site et activez la double authentification. Lancez une analyse antivirus. Sur un appareil professionnel, prévenez votre service informatique. En France, cybermalveillance.gouv.fr propose une aide gratuite.",
    "faq.q4": "Pourquoi un site réputé est-il parfois signalé ?",
    "faq.a4": "Des pirates hébergent parfois leurs fichiers sur des services légitimes. SecureShip exclut les plus grands pour limiter les fausses alertes, mais un signalement reste possible. Le détail du résultat indique la menace et le niveau de confiance.",
    "faq.q5": "Qui a créé ce site ?",
    "faq.a5": "Mahomed Arafat Anjoueneya Mouansie, étudiant ingénieur en sécurité des systèmes d'information à l'Université de Technologie de Troyes, dans le cadre d'un projet DevSecOps : chaque modification est testée, analysée et déployée automatiquement sur Azure.",
    "footer.text": "Projet open source sous licence MIT. Outil d'aide à la décision, sans garantie.",
    version: (v) => `Version ${v}`,
    "lang.switch": "Switch to English", "lang.code": "EN",
  },
  en: {
    skip: "Skip to the form",
    "nav.guide": "Understand", "nav.data": "Data", "nav.dev": "Developers", "nav.faq": "Questions",
    "hero.title": "Does a link, address or file look suspicious? Check it here.",
    "hero.lead": "SecureShip compares what you paste against thousands of threat indicators reported by the security community, refreshed every morning.",
    "form.label": "What you want to check",
    "form.placeholder": "Example: https://dodgy-site.example/login",
    "form.hint": "One item per line, up to 100. Defanged links such as hxxp://site[.]com are accepted.",
    "form.submit": "Check", "form.checking": "Checking…", "form.clear": "Clear",
    "form.empty": "Paste at least one item to check in the field above.",
    "form.toomany": "Up to 100 items per check. Remove a few lines and try again.",
    "form.error": "The check did not complete. Check your connection and try again.",
    "examples.title": "No example to hand? Try:",
    "examples.c2": "a hacker's server address", "examples.phishing": "a phishing link",
    "examples.eicar": "the EICAR antivirus test file", "examples.clean": "an ordinary website",
    privacy: "Your searches are neither stored nor shared with anyone: the comparison runs on the SecureShip server.",
    "results.title": "Results",
    "results.summary": (n, bad) => bad === 0
      ? `${n} item${n > 1 ? "s" : ""} checked: none reported.`
      : `${n} item${n > 1 ? "s" : ""} checked: ${bad} reported as malicious.`,
    "verdict.bad": "Reported", "verdict.good": "Nothing found", "verdict.invalid": "Not recognised",
    "type.ipv4": "IPv4 address", "type.ipv6": "IPv6 address", "type.domain": "Domain name",
    "type.md5": "MD5 hash", "type.sha1": "SHA-1 hash", "type.sha256": "SHA-256 hash",
    "type.invalid": "Unrecognised format",
    "type.fromurl": " (taken from the link)", "type.private": " · local network address",
    "fact.threat": "Threat", "fact.confidence": "Confidence", "fact.source": "Source",
    "fact.seen": "Reported on", "fact.matched": "Reported domain",
    "advice.bad.domain": "Do not open this link or enter anything on this site. If you already have, see “I clicked a reported link” below.",
    "advice.bad.ip": "Do not connect to this address. An administrator can block it on the firewall and search the logs for past connections.",
    "advice.bad.hash": "Do not run this file: delete it or have it scanned by your antivirus or IT team.",
    "advice.good": "No known reports, which is not a guarantee. Stay careful if the message rushes you or asks for your login details.",
    "advice.private": "Internal network address (home router, company): it cannot be reached from the Internet and is not in public databases.",
    "advice.invalid": "Check what you typed: expected an IP address, a domain, a link or a 32, 40 or 64-character hash.",
    "guide.title": "Reading the result",
    "guide.bad.title": "Known to be malicious",
    "guide.bad.text": "The item is listed in a threat database. Do not open the link or run the file, and tell your IT team if it is a work device.",
    "guide.good.title": "Not in the database",
    "guide.good.text": "No known reports. This is not a guarantee: a brand-new threat may not be listed yet. Stay careful if the message rushes you or asks for your login details.",
    "guide.invalid.title": "Unknown format",
    "guide.invalid.text": "It is not an IP address, domain, link or file hash. Check for typos or extra spaces.",
    "types.title": "What you can check",
    "types.url": "A link (URL)", "types.url.text": "The domain is extracted automatically. Copy the link with a right-click rather than opening it.",
    "types.domain": "A domain name", "types.domain.text": "Subdomains of a reported domain are reported too.",
    "types.ip": "An IP address", "types.ip.text": "IPv4 or IPv6, with or without a port number. Local network addresses are flagged as private.",
    "types.hash": "A file fingerprint (hash)", "types.hash.text": "A 32, 40 or 64-character string that identifies a file without sending it. MD5, SHA-1 and SHA-256 formats.",
    "hash.title": "Get a file's fingerprint without opening it",
    "hash.text": "The file never leaves your computer: only its fingerprint is checked. Open a terminal in the file's folder and type:",
    "data.title": "Where the data comes from",
    "data.ips": "IP addresses", "data.domains": "domains", "data.hashes": "file hashes",
    "data.text": "Every morning, SecureShip downloads the last seven days of indicators published by ThreatFox, a free database run by the Swiss organisation abuse.ch and fed by security researchers. Every entry is validated before being added, and major legitimate services are excluded to avoid false alarms.",
    "data.demo": "A few harmless demo entries are always present for testing: they use addresses reserved for documentation and the EICAR antivirus test file.",
    "data.updated": (d) => `Database updated on ${d}.`,
    "data.demoonly": "Demo mode: the ThreatFox feed is not enabled on this server yet.",
    "dev.title": "For developers and analysts",
    "dev.text": "Everything this page does goes through a public REST API, documented and testable in the browser:",
    "dev.docs": "open the interactive documentation",
    "dev.c1": "One indicator, type detected automatically", "dev.c2": "Up to 100 indicators at once",
    "dev.repo": "Source code, DevSecOps pipeline and Azure infrastructure:",
    "faq.title": "Frequently asked questions",
    "faq.q1": "Are my searches stored?",
    "faq.a1": "No. What you check is neither stored nor sent to another service. The threat database is loaded on the server and the comparison happens there.",
    "faq.q2": "Does “Nothing found” mean it is safe?",
    "faq.a2": "No. It means there are no known reports. Attackers create new sites every day. Be wary of any message that rushes you, promises a reward or asks for a password.",
    "faq.q3": "I clicked a reported link. What should I do?",
    "faq.a3": "If you typed a password, change it right away on the real site and turn on two-factor authentication. Run an antivirus scan. On a work device, tell your IT team. In France, cybermalveillance.gouv.fr offers free help.",
    "faq.q4": "Why is a well-known site sometimes reported?",
    "faq.a4": "Attackers sometimes host files on legitimate services. SecureShip excludes the largest ones to limit false alarms, but a report is still possible. The result details show the threat and the confidence level.",
    "faq.q5": "Who built this site?",
    "faq.a5": "Mahomed Arafat Anjoueneya Mouansie, an information systems security engineering student at the University of Technology of Troyes, as part of a DevSecOps project: every change is tested, scanned and deployed to Azure automatically.",
    "footer.text": "Open source project under the MIT licence. Decision-support tool, provided without warranty.",
    version: (v) => `Version ${v}`,
    "lang.switch": "Passer en français", "lang.code": "FR",
  },
};

const $ = (sel) => document.querySelector(sel);
let lang = "fr";
let lastResults = null;
let stats = null;

function t(key, ...args) {
  const value = I18N[lang][key] ?? I18N.fr[key] ?? key;
  return typeof value === "function" ? value(...args) : value;
}

function storage(action, value) {
  try {
    if (action === "get") return window.localStorage.getItem("secureship-lang");
    window.localStorage.setItem("secureship-lang", value);
  } catch { /* stockage indisponible : la langue n'est simplement pas mémorisée */ }
  return null;
}

function applyLanguage(next) {
  lang = next;
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  const toggle = $("#lang-toggle");
  toggle.textContent = t("lang.code");
  toggle.setAttribute("aria-label", t("lang.switch"));
  renderStats();
  if (lastResults) renderResults(lastResults, false);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatDate(value) {
  if (!value) return null;
  const date = new Date(value.replace(" UTC", "Z").replace(" ", "T"));
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString(lang === "fr" ? "fr-FR" : "en-GB", { day: "numeric", month: "long", year: "numeric" });
}

function renderEntry(result, fresh) {
  const li = el("li");
  const invalid = result.type === "invalid";
  const verdict = invalid ? "invalid" : result.malicious ? "bad" : "good";
  const stamp = el("span", `stamp stamp-${verdict === "invalid" ? "none" : verdict}${fresh ? " fresh" : ""}`, t(`verdict.${verdict}`));
  li.append(stamp);

  const entry = el("div", "entry");
  entry.append(el("p", "indicator", result.indicator));
  let kind = t(`type.${result.type}`);
  if (result.extracted_from === "url") kind += t("type.fromurl");
  if (result.private) kind += t("type.private");
  entry.append(el("p", "kind", kind));

  const d = result.details;
  if (d) {
    const facts = el("dl", "facts");
    const add = (label, value) => {
      if (value === null || value === undefined || value === "") return;
      facts.append(el("dt", null, t(label)));
      const dd = el("dd");
      if (value instanceof Node) dd.append(value); else dd.textContent = value;
      facts.append(dd);
    };
    add("fact.threat", d.threat);
    if (result.matched && result.matched !== result.indicator) add("fact.matched", result.matched);
    if (typeof d.confidence === "number") {
      const wrap = document.createDocumentFragment();
      const meter = el("span", "meter");
      meter.setAttribute("aria-hidden", "true");
      const bar = el("span");
      bar.style.width = `${Math.max(0, Math.min(100, d.confidence))}%`;
      meter.append(bar);
      wrap.append(meter, document.createTextNode(`${d.confidence} %`));
      add("fact.confidence", wrap);
    }
    add("fact.source", d.source);
    add("fact.seen", formatDate(d.first_seen));
    entry.append(facts);
  }

  const family = result.type.startsWith("ip") ? "ip" : result.type === "domain" ? "domain" : "hash";
  let advice = invalid ? "advice.invalid" : result.malicious ? `advice.bad.${family}` : "advice.good";
  if (!invalid && !result.malicious && result.private) advice = "advice.private";
  entry.append(el("p", "advice", t(advice)));
  li.append(entry);
  return li;
}

function renderResults(data, fresh) {
  lastResults = data;
  const section = $("#results");
  const list = $("#results-list");
  list.replaceChildren(...data.results.map((r) => renderEntry(r, fresh)));
  $("#results-summary").textContent = t("results.summary", data.count, data.malicious);
  section.hidden = false;
}

function showMessage(key) {
  lastResults = null;
  $("#results-list").replaceChildren();
  $("#results-summary").textContent = t(key);
  $("#results").hidden = false;
}

async function check(event) {
  event?.preventDefault();
  const lines = $("#indicators").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (lines.length === 0) { showMessage("form.empty"); $("#indicators").focus(); return; }
  if (lines.length > 100) { showMessage("form.toomany"); return; }

  const button = $("#submit-btn");
  button.disabled = true;
  button.textContent = t("form.checking");
  $("#results").setAttribute("aria-busy", "true");
  try {
    const response = await fetch("/api/v1/check/bulk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ indicators: lines }),
    });
    if (!response.ok) throw new Error(String(response.status));
    renderResults(await response.json(), true);
    $("#results-title").focus();
  } catch {
    showMessage("form.error");
  } finally {
    button.disabled = false;
    button.textContent = t("form.submit");
    $("#results").setAttribute("aria-busy", "false");
  }
}

function renderStats() {
  if (!stats) return;
  const fmt = new Intl.NumberFormat(lang === "fr" ? "fr-FR" : "en-GB");
  $("#stat-ips").textContent = fmt.format(stats.ips);
  $("#stat-domains").textContent = fmt.format(stats.domains);
  $("#stat-hashes").textContent = fmt.format(stats.hashes);
  const generated = stats.feed && stats.feed.generated_at;
  $("#feed-status").textContent = generated ? t("data.updated", formatDate(generated)) : t("data.demoonly");
}

async function loadMeta() {
  try {
    const [statsRes, healthRes] = await Promise.all([fetch("/api/v1/stats"), fetch("/health")]);
    stats = await statsRes.json();
    renderStats();
    const health = await healthRes.json();
    const v = String(health.version || "");
    $("#version").textContent = t("version", v.length > 12 ? v.slice(0, 7) : v);
  } catch { /* la page reste utilisable sans ces informations */ }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".origin").forEach((node) => { node.textContent = window.location.origin; });
  const saved = storage("get");
  const preferred = saved || ((navigator.language || "fr").toLowerCase().startsWith("fr") ? "fr" : "en");
  applyLanguage(preferred in I18N ? preferred : "fr");

  $("#check-form").addEventListener("submit", check);
  $("#indicators").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) check(e);
  });
  $("#clear-btn").addEventListener("click", () => {
    $("#indicators").value = "";
    lastResults = null;
    $("#results").hidden = true;
    $("#indicators").focus();
  });
  document.querySelectorAll("[data-example]").forEach((button) => {
    button.addEventListener("click", () => {
      $("#indicators").value = button.dataset.example;
      check();
    });
  });
  $("#lang-toggle").addEventListener("click", () => {
    const next = lang === "fr" ? "en" : "fr";
    storage("set", next);
    applyLanguage(next);
  });
  loadMeta();
});
