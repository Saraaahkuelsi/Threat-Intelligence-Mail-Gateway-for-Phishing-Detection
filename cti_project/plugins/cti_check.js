// plugins/cti_check.js
//
// Passerelle de sécurité email : extrait tous les IOC possibles d'un
// email (connexion SMTP, headers, corps, pièces jointes), déduplique,
// interroge la plateforme CTI via GET /check, et bloque l'email si au
// moins un IOC est jugé "malicious". Aucune décision locale : tout
// repose sur le verdict renvoyé par l'API.
//
// Config : config/cti_check.ini
//   [main]
//   api_host=127.0.0.1
//   api_port=8000

const crypto = require("crypto");
const http = require("http");
const { simpleParser } = require("mailparser");

// ------------------------------------------------------------------
// Config
// ------------------------------------------------------------------

exports.register = function () {
  this.load_cti_config();
};

exports.load_cti_config = function () {
  this.cfg = this.config.get("cti_check.ini", {});
};

exports.hook_data = function (next, connection) {
  // Doit être activé ICI, avant l'arrivée du corps du message,
  // sinon transaction.body reste vide dans hook_data_post.
  connection.transaction.parse_body = true;
  next();
};

// ------------------------------------------------------------------
// Regex de reconnaissance (réutilisées par toutes les fonctions
// d'extraction, pour rester cohérentes entre header/corps/subject)
// ------------------------------------------------------------------

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const URL_RE = /https?:\/\/[^\s"'<>\]\)]+/gi;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const HASH_RE = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g;

function isIPv4(str) {
  const m = str.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1, 5).every((o) => Number(o) >= 0 && Number(o) <= 255);
}

// ------------------------------------------------------------------
// Extraction générique depuis un texte libre (header, subject, corps)
// Retourne une liste de { type, value, source }
// ------------------------------------------------------------------

function extractIOCsFromText(text, source) {
  if (!text) return [];
  const results = [];

  // 1. Adresses email
  EMAIL_RE.lastIndex = 0;
  let m;
  while ((m = EMAIL_RE.exec(text)) !== null) {
    results.push({ type: "email", value: m[0].toLowerCase(), source });
  }
  let remaining = text.replace(EMAIL_RE, " ");

  // 2. URLs -> produit à la fois le type "url" et le type "ip"/"domain"
  //    déduit de l'hôte, jamais les deux (url + domain) pour un hôte IP
  URL_RE.lastIndex = 0;
  const urlMatches = [];
  while ((m = URL_RE.exec(remaining)) !== null) {
    urlMatches.push(m[0]);
  }
  for (const rawUrl of urlMatches) {
    results.push({ type: "url", value: rawUrl, source });
    try {
      const host = new URL(rawUrl).hostname;
      if (isIPv4(host)) {
        results.push({ type: "ip", value: host, source });
      } else {
        results.push({ type: "domain", value: host.toLowerCase(), source });
      }
    } catch (e) {
      // URL malformée, on garde uniquement l'entrée "url" brute
    }
  }
  remaining = remaining.replace(URL_RE, " ");

  // 3. IP en texte brut (hors URLs déjà traitées)
  IP_RE.lastIndex = 0;
  while ((m = IP_RE.exec(remaining)) !== null) {
    if (isIPv4(m[0])) results.push({ type: "ip", value: m[0], source });
  }
  remaining = remaining.replace(IP_RE, " ");

  // 4. Domaines en texte brut (hors URLs et hors IP déjà traitées)
  DOMAIN_RE.lastIndex = 0;
  while ((m = DOMAIN_RE.exec(remaining)) !== null) {
    if (!isIPv4(m[0])) results.push({ type: "domain", value: m[0].toLowerCase(), source });
  }

  // 5. Hash MD5 / SHA1 / SHA256 (scan du texte original)
  HASH_RE.lastIndex = 0;
  while ((m = HASH_RE.exec(text)) !== null) {
    results.push({ type: "hash", value: m[0].toLowerCase(), source });
  }

  return results;
}

// ------------------------------------------------------------------
// Extraction par zone de l'email
// ------------------------------------------------------------------

function extractFromConnection(connection) {
  const ip = connection.remote_ip || (connection.remote && connection.remote.ip);
  return ip ? [{ type: "ip", value: ip, source: "remote_ip" }] : [];
}

function extractFromHeaders(transaction) {
  let all = [];
  const simpleHeaders = ["From", "Reply-To", "Return-Path", "Sender", "To", "Cc", "Subject"];

  for (const name of simpleHeaders) {
    const val = transaction.header.get(name);
    if (val) {
      all = all.concat(extractIOCsFromText(val, `header:${name}`));
    }
  }

  // Received : potentiellement plusieurs occurrences, contient des IP
  const receivedAll =
    (transaction.header.get_all && transaction.header.get_all("Received")) || [];
  for (const rec of receivedAll) {
    all = all.concat(extractIOCsFromText(rec, "header:Received"));
  }

  return all;
}

function extractFromBody(transaction, connection) {
  const bodytext = (transaction.body && transaction.body.bodytext) || "";
  connection.loginfo("cti_check", `DEBUG bodytext: ${JSON.stringify(bodytext)}`);
  return extractIOCsFromText(bodytext, "body");
}

// Extraction des pièces jointes : on ne s'appuie plus sur les
// propriétés internes du parseur MIME de Haraka (bodytext/body_data),
// qui se sont révélées peu fiables selon le type de contenu et la
// version de Haraka. À la place, on récupère le message brut complet
// via transaction.message_stream.get_data (API publique documentée
// de Haraka) et on le fait parser par "mailparser", qui gère
// correctement tous les Content-Transfer-Encoding.
// Retourne une Promise résolue avec la liste des IOC de type hash.
function extractFromAttachments(transaction, connection) {
  return new Promise((resolve) => {
    if (!transaction.message_stream) {
      connection.loginfo("cti_check", "DEBUG message_stream absent, aucune pièce jointe extraite");
      return resolve([]);
    }

    const chunks = [];
    transaction.message_stream.get_data((err, buf) => {
      // Selon la version de Haraka, get_data peut appeler le callback
      // soit avec (buffer) directement, soit avec (err, buffer) ->
      // on gère les deux cas.
      let rawBuffer;
      if (Buffer.isBuffer(err)) {
        rawBuffer = err; // get_data(buffer) sans err
      } else if (err) {
        connection.logerror("cti_check", `DEBUG erreur message_stream.get_data: ${err}`);
        return resolve([]);
      } else {
        rawBuffer = buf;
      }

      if (!rawBuffer || rawBuffer.length === 0) {
        connection.loginfo("cti_check", "DEBUG message_stream: buffer vide");
        return resolve([]);
      }

      connection.loginfo("cti_check", `DEBUG message_stream: buffer récupéré, taille=${rawBuffer.length}`);

      simpleParser(rawBuffer)
        .then((parsed) => {
          const results = [];
          const attachments = parsed.attachments || [];
          connection.loginfo("cti_check", `DEBUG mailparser attachments trouvées: ${attachments.length}`);

          for (const att of attachments) {
            if (att.content && att.content.length > 0) {
              const hash = crypto.createHash("sha256").update(att.content).digest("hex");
              connection.loginfo(
                "cti_check",
                `DEBUG attachment: ${att.filename || "sans nom"} | taille=${att.content.length} | sha256=${hash}`
              );
              results.push({
                type: "hash",
                value: hash,
                source: `attachment:${att.filename || "sans nom"}`,
              });
            }
          }
          resolve(results);
        })
        .catch((parseErr) => {
          connection.logerror("cti_check", `DEBUG erreur mailparser: ${parseErr.stack || parseErr}`);
          resolve([]);
        });
    });
  });
}

// ------------------------------------------------------------------
// Déduplication : regroupe par (type, value), conserve toutes les
// provenances pour la traçabilité, mais un seul appel API par IOC
// ------------------------------------------------------------------

function deduplicateIOCs(rawList) {
  const map = new Map();
  for (const item of rawList) {
    const key = `${item.type}:${item.value}`;
    if (!map.has(key)) {
      map.set(key, { type: item.type, value: item.value, sources: new Set([item.source]) });
    } else {
      map.get(key).sources.add(item.source);
    }
  }
  return Array.from(map.values()).map((v) => ({
    type: v.type,
    value: v.value,
    sources: Array.from(v.sources),
  }));
}

// ------------------------------------------------------------------
// Hook principal
// ------------------------------------------------------------------

exports.hook_data_post = function (next, connection) {
  const plugin = this;
  const transaction = connection.transaction;
  if (!transaction) return next();

  let raw = [];
  raw = raw.concat(extractFromConnection(connection));
  raw = raw.concat(extractFromHeaders(transaction));
  raw = raw.concat(extractFromBody(transaction, connection));

  // extractFromAttachments est asynchrone (mailparser) -> on attend
  // son résultat avant de poursuivre le reste du traitement.
  extractFromAttachments(transaction, connection)
    .then((attachmentIOCs) => {
      raw = raw.concat(attachmentIOCs);

      // --- DEBUG TEMPORAIRE ---
      connection.loginfo(plugin, `cti_check: DEBUG raw=${JSON.stringify(raw)}`);
      // --- FIN DEBUG ---

      const uniqueIOCs = deduplicateIOCs(raw);

      if (uniqueIOCs.length === 0) {
        connection.loginfo(plugin, "cti_check: aucun IOC détecté dans cet email");
        return next();
      }

      connection.loginfo(
        plugin,
        `cti_check: ${uniqueIOCs.length} IOC(s) unique(s) détecté(s) (sur ${raw.length} mentions brutes), interrogation de l'API...`
      );

      plugin.check_iocs(uniqueIOCs, function (results) {
        try {
          let maliciousFound = null;

          for (const r of results) {
            connection.loginfo(
              plugin,
              `cti_check: [${r.type}] ${r.value} — sources=[${r.sources.join(", ")}] — verdict=${r.verdict}`
            );
            if (r.verdict === "malicious" && !maliciousFound) {
              maliciousFound = r;
            }
          }

          const nbMalicious = results.filter((r) => r.verdict === "malicious").length;
          const verdictFinal = maliciousFound ? "DENY" : "ACCEPT";

          connection.loginfo(
            plugin,
            `cti_check: résumé — Email analysé — IOC détectés=${results.length} — IOC malveillants=${nbMalicious} — Verdict final=${verdictFinal}`
          );

          plugin.log_mail_event(connection, results);

          if (maliciousFound) {
            return next(
              DENY,
              `Email bloqué — IOC malveillant détecté (${maliciousFound.type}: ${maliciousFound.value})`
            );
          }

          next();
        } catch (err) {
          connection.logerror(plugin, `cti_check: EXCEPTION lors du traitement du verdict: ${err.stack || err}`);
          next();
        }
      });
    })
    .catch((err) => {
      connection.logerror(plugin, `cti_check: EXCEPTION lors de l'extraction des pièces jointes: ${err.stack || err}`);
      next();
    });
};

// ------------------------------------------------------------------
// Appels à l'API CTI (en parallèle, un par IOC unique)
// ------------------------------------------------------------------

exports.check_iocs = function (iocs, callback) {
  const plugin = this;
  const results = [];
  let pending = iocs.length;

  if (pending === 0) return callback(results);

  for (const ioc of iocs) {
    plugin.call_api(ioc, function (result) {
      results.push(result);
      pending--;
      if (pending === 0) callback(results);
    });
  }
};

exports.call_api = function (ioc, callback) {
  const plugin = this;
  const apiHost = (plugin.cfg.main && plugin.cfg.main.api_host) || "127.0.0.1";
  const apiPort = (plugin.cfg.main && plugin.cfg.main.api_port) || 8000;
  const path = `/check?value=${encodeURIComponent(ioc.value)}&type=${encodeURIComponent(ioc.type)}`;

  const req = http.get(
    { host: apiHost, port: apiPort, path: path, timeout: 5000 },
    (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          const json = JSON.parse(data);
          let verdict, malware_name, threat_type;

          if (json.found) {
            verdict = json.ioc.consolidated_verdict.verdict;
            malware_name = json.ioc.malware_name || null;
            threat_type = json.ioc.threat_type || null;
          } else {
            // Même si l'IOC est absent en interne, /check peut renvoyer
            // un verdict basé sur VirusTotal (gap filling) -> ne pas
            // l'ignorer, la décision doit s'appuyer dessus aussi.
            verdict = (json.consolidated_verdict && json.consolidated_verdict.verdict) || "unknown";
            malware_name = null;
            threat_type = null;
          }

          callback({ ...ioc, verdict, malware_name, threat_type });
        } catch (e) {
          callback({ ...ioc, verdict: "error", malware_name: null, threat_type: null });
        }
      });
    }
  );

  req.on("error", () => {
    callback({ ...ioc, verdict: "api_unreachable", malware_name: null, threat_type: null });
  });
  req.on("timeout", () => {
    req.destroy();
    callback({ ...ioc, verdict: "api_timeout", malware_name: null, threat_type: null });
  });
};

// ------------------------------------------------------------------
// Journalisation vers /mail/log (alimente le dashboard)
// ------------------------------------------------------------------

exports.log_mail_event = function (connection, results) {
  const plugin = this;
  try {
    const transaction = connection.transaction;

    const messageId =
      (transaction.header.get("Message-Id") || "").trim() ||
      connection.transaction.uuid ||
      `unknown-${Date.now()}`;

    const sender =
      transaction.mail_from && typeof transaction.mail_from.address === "function"
        ? transaction.mail_from.address()
        : (transaction.mail_from ? String(transaction.mail_from) : null);

    const recipient =
      transaction.rcpt_to && transaction.rcpt_to[0] && typeof transaction.rcpt_to[0].address === "function"
        ? transaction.rcpt_to[0].address()
        : (transaction.rcpt_to && transaction.rcpt_to[0] ? String(transaction.rcpt_to[0]) : null);

    const payload = JSON.stringify({
      message_id: messageId,
      sender: sender,
      recipient: recipient,
      iocs: results.map((r) => ({
        type: r.type,
        value: r.value,
        verdict: r.verdict,
        malware_name: r.malware_name || null,
        threat_type: r.threat_type || null,
      })),
    });

    const apiHost = (plugin.cfg.main && plugin.cfg.main.api_host) || "127.0.0.1";
    const apiPort = (plugin.cfg.main && plugin.cfg.main.api_port) || 8000;

    const req = http.request(
      {
        host: apiHost,
        port: apiPort,
        path: "/mail/log",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
        timeout: 5000,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          if (res.statusCode >= 400) {
            connection.logerror(
              plugin,
              `cti_check: /mail/log a répondu ${res.statusCode} — ${body}`
            );
          } else {
            connection.loginfo(plugin, `cti_check: /mail/log OK (${res.statusCode}) — ${body}`);
          }
        });
      }
    );

    req.on("error", () => {
      connection.logerror(plugin, "cti_check: échec de journalisation vers /mail/log");
    });
    req.on("timeout", () => {
      req.destroy();
      connection.logerror(plugin, "cti_check: timeout lors de la journalisation vers /mail/log");
    });

    req.write(payload);
    req.end();
  } catch (err) {
    connection.logerror(plugin, `cti_check: EXCEPTION dans log_mail_event: ${err.stack || err}`);
  }
};
