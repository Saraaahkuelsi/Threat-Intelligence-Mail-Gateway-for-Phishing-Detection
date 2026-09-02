"""
Dashboard Streamlit pour la plateforme CTI.
Tout passe par l'API FastAPI (api.py) via requests.

Lancement : streamlit run dashboard.py
Prérequis : l'API doit tourner (uvicorn api:app --reload).
"""

import csv
import io
import json
import uuid
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

API_BASE_URL = "http://127.0.0.1:8000"

PLOTLY_TEMPLATE = "plotly_dark"
# Palette "ops center" : ambre signal (alerte radar) en accent primaire,
# teal pour les statuts sains/corroborés, violet pour les éléments
# techniques (MITRE), rouge réservé aux verdicts malveillants.
CHART_COLORS = ["#f5a623", "#2dd4bf", "#ff5470", "#8b7cf6", "#5b8def", "#e7e9ee"]


def check_api_status():
    """Ping rapide de l'API pour afficher un badge en-tête (🟢/🔴),
    sans attendre un vrai timeout ailleurs dans la page."""
    try:
        resp = requests.get(f"{API_BASE_URL}/", timeout=3)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False

st.set_page_config(page_title="CTI Platform Dashboard", layout="wide", page_icon="🛡️")

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap');

:root {
    --cti-bg: #08090c;
    --cti-surface: #12151b;
    --cti-surface-raised: #171b23;
    --cti-border: rgba(231, 233, 238, 0.10);
    --cti-text: #e7e9ee;
    --cti-text-dim: #8992a3;
    --cti-accent: #f5a623;
    --cti-teal: #2dd4bf;
    --cti-violet: #8b7cf6;
    --cti-red: #ff5470;
    /* JetBrains Mono en priorité (Google Fonts) ; si jamais le chargement
       échoue (réseau coupé plus tard, proxy...), on retombe sur la même
       identité "terminal" via les polices mono du système. */
    --cti-mono: 'JetBrains Mono', ui-monospace, 'SFMono-Regular', 'Cascadia Code',
                 Consolas, 'Liberation Mono', 'Courier New', monospace;
}

/* Tout en monospace : hiérarchie construite par la taille/graisse/
   espacement des lettres, pas par un changement de famille -> identité
   "terminal SOC" assumée, et rendu identique avec ou sans connexion. */
html, body, [class*="css"], [class*="st-"], .stMarkdown, .stMarkdown p,
.stMarkdown span, .stMarkdown div, p, span, div, label, button, input,
textarea, select {
    font-family: var(--cti-mono) !important;
}
h1, h2, h3, h4, h5, .stSubheader, [data-testid="stMarkdownContainer"] h1,
[data-testid="stMarkdownContainer"] h2, [data-testid="stMarkdownContainer"] h3,
[data-testid="stMarkdownContainer"] h4 {
    font-family: var(--cti-mono) !important;
    font-weight: 700;
    letter-spacing: -0.01em;
}
code, .stCode, div[data-testid="stMetricValue"], .cti-badge {
    font-family: var(--cti-mono) !important;
}

.stApp { background-color: var(--cti-bg); }

/* Mise en page : Streamlit centre le contenu avec une largeur max même
   en layout="wide" -> on force l'usage de (presque) toute la largeur
   de la fenêtre, avec un padding symétrique, pour que rien ne soit
   collé/poussé à gauche. On masque aussi la sidebar (inutilisée ici,
   la nav est en onglets) pour ne pas laisser d'espace fantôme. */
.block-container {
    max-width: 100% !important;
    padding-left: 3.5rem !important;
    padding-right: 3.5rem !important;
    padding-top: 2rem !important;
}
section[data-testid="stSidebar"] { display: none !important; }
[data-testid="collapsedControl"] { display: none !important; }


/* Metrics : cartes sobres, valeur en mono (registre "instrument de mesure") */
div[data-testid="stMetric"] {
    background-color: var(--cti-surface);
    border: 1px solid var(--cti-border);
    border-left: 2px solid var(--cti-accent);
    border-radius: 4px;
    padding: 14px 16px 10px 16px;
}
div[data-testid="stMetricLabel"] {
    font-size: 0.72em;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: var(--cti-text-dim) !important;
}

/* Navigation principale (catégories) : barre plein largeur type menu de
   terminal — segments égaux séparés par des filets verticaux, plutôt que
   des liens regroupés à gauche avec du vide à droite. Chaque segment
   prend une part égale de la largeur (flex: 1), le nom de la catégorie
   est centré, l'onglet actif reçoit un fond plein pour bien marquer
   "où on est" au premier coup d'œil. */
/* Navigation principale (catégories) : barre plein largeur type menu de
   terminal — segments égaux séparés par des filets verticaux, plutôt que
   des liens regroupés à gauche avec du vide à droite. Chaque segment
   prend une part égale de la largeur (flex: 1), le nom de la catégorie
   est centré, l'onglet actif reçoit un fond plein pour bien marquer
   "où on est" au premier coup d'œil.
   Sélecteurs basés sur le vrai DOM (react-aria) : role="tablist",
   role="tab" + data-testid="stTab", aria-selected="true" pour l'état
   actif — pas data-baseweb, qui appartient à l'ancienne lib de tabs
   (BaseWeb) et n'existe plus dans cette version de Streamlit. */
.stTabs [role="tablist"] {
    display: flex !important;
    width: 100% !important;
    gap: 0 !important;
    border: 1px solid var(--cti-border);
    border-left: none;
    border-right: none;
    background: var(--cti-surface);
}
.stTabs [data-testid="stTab"][role="tab"] {
    flex: 1 1 0 !important;
    display: flex !important;
    justify-content: center;
    align-items: center;
    height: auto;
    padding: 16px 8px;
    margin: 0;
    background: transparent;
    border-radius: 0;
    border-right: 1px solid var(--cti-border);
    cursor: pointer;
    transition: background-color 0.15s ease;
}
.stTabs [data-testid="stTab"] p {
    font-family: var(--cti-mono);
    font-weight: 800 !important;
    font-size: 0.95em;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--cti-text);
    margin: 0;
}
.stTabs [data-testid="stTab"]:last-child { border-right: none; }
.stTabs [data-testid="stTab"]:hover { background: rgba(245, 166, 35, 0.06); }
.stTabs [data-testid="stTab"][aria-selected="true"] {
    background: var(--cti-accent) !important;
}
.stTabs [data-testid="stTab"][aria-selected="true"] p {
    color: var(--cti-bg) !important;
}
/* Indicateur natif react-aria (soulignement) : masqué, le fond plein
   sur l'onglet actif joue déjà ce rôle, pas besoin des deux. */
.react-aria-SelectionIndicator { display: none !important; }

/* Sous-navigation (pages liées à une catégorie) : même logique plein
   largeur, mais surface plus sombre et accent teal pour rester
   subordonnée visuellement à la nav principale au-dessus. */
.stTabs .stTabs [role="tablist"] {
    background: transparent;
    border: none;
    border-bottom: 1px solid var(--cti-border);
    gap: 0;
}
.stTabs .stTabs [data-testid="stTab"] {
    border-right: 1px solid var(--cti-border);
    padding: 12px 8px;
}
.stTabs .stTabs [data-testid="stTab"] p {
    font-size: 0.76em;
    font-weight: 600 !important;
    letter-spacing: 0.06em;
    color: var(--cti-text-dim);
}
.stTabs .stTabs [data-testid="stTab"]:hover { background: rgba(45, 212, 191, 0.06); }
.stTabs .stTabs [data-testid="stTab"][aria-selected="true"] {
    background: rgba(45, 212, 191, 0.1) !important;
}
.stTabs .stTabs [data-testid="stTab"][aria-selected="true"] p {
    color: var(--cti-teal) !important;
}

/* Badges génériques (MITRE, alias, CVE, verdicts, statut API...) */
.cti-badge {
    display: inline-block;
    padding: 3px 10px;
    margin: 2px 4px 2px 0;
    border-radius: 3px;
    font-family: var(--cti-mono);
    font-size: 0.78em;
    font-weight: 500;
    letter-spacing: 0.01em;
    border: 1px solid transparent;
}
.cti-badge-neutral { background-color: rgba(137, 146, 163, 0.12); color: var(--cti-text-dim); border-color: rgba(137, 146, 163, 0.25); }
.cti-badge-red     { background-color: rgba(255, 84, 112, 0.12); color: var(--cti-red); border-color: rgba(255, 84, 112, 0.3); }
.cti-badge-orange  { background-color: rgba(245, 166, 35, 0.12); color: var(--cti-accent); border-color: rgba(245, 166, 35, 0.3); }
.cti-badge-green   { background-color: rgba(45, 212, 191, 0.12); color: var(--cti-teal); border-color: rgba(45, 212, 191, 0.3); }
.cti-badge-violet  { background-color: rgba(139, 124, 246, 0.12); color: var(--cti-violet); border-color: rgba(139, 124, 246, 0.3); }

/* Eyebrow : petit label discret au-dessus d'un titre de section */
.cti-eyebrow {
    font-family: var(--cti-mono);
    font-size: 0.72em;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--cti-text-dim);
    margin-bottom: 2px;
}

/* Cartes pour le profil malware / intelligence externe */

.cti-card {
    background-color: var(--cti-surface);
    border: 1px solid var(--cti-border);
    border-left: 2px solid var(--cti-violet);
    border-radius: 4px;
    padding: 18px 22px;
    margin-bottom: 12px;
}
.cti-card h4 { margin-top: 0; font-family: var(--cti-mono); }

/* ============================================================
   WIDGETS NATIFS — jusqu'ici seuls les metrics/tabs/badges étaient
   habillés ; boutons, champs, dataframe et alertes restaient en
   thème clair Streamlit par défaut, d'où l'effet "pas fini".
   Ces règles complètent (avec config.toml) l'habillage sombre.
   ============================================================ */

/* Boutons : secondaire discret, primaire accent ambre */
.stButton > button, .stDownloadButton > button {
    background-color: var(--cti-surface);
    border: 1px solid var(--cti-border);
    color: var(--cti-text);
    border-radius: 4px;
    font-weight: 500;
    transition: border-color 0.15s ease, transform 0.05s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color: var(--cti-accent);
    color: var(--cti-accent);
}
.stButton > button:active, .stDownloadButton > button:active { transform: scale(0.98); }
.stButton > button[kind="primary"] {
    background-color: var(--cti-accent);
    border: 1px solid var(--cti-accent);
    color: var(--cti-bg);
    font-weight: 600;
}
.stButton > button[kind="primary"]:hover {
    background-color: #ffb548;
    border-color: #ffb548;
    color: var(--cti-bg);
}

/* Champs texte / nombre / selectbox / multiselect : même surface,
   même bordure que le reste du système -> plus de blanc qui tranche */
.stTextInput input, .stNumberInput input,
div[data-baseweb="select"] > div,
div[data-baseweb="base-input"] {
    background-color: var(--cti-surface) !important;
    border-color: var(--cti-border) !important;
    color: var(--cti-text) !important;
    border-radius: 4px !important;
}
.stTextInput input:focus, .stNumberInput input:focus,
div[data-baseweb="select"]:focus-within > div {
    border-color: var(--cti-accent) !important;
    box-shadow: 0 0 0 1px var(--cti-accent) !important;
}
/* Menu déroulant du selectbox/multiselect */
ul[data-baseweb="menu"], div[data-baseweb="popover"] {
    background-color: var(--cti-surface) !important;
}
li[data-baseweb="option"] { color: var(--cti-text) !important; }
li[data-baseweb="option"]:hover { background-color: rgba(245, 166, 35, 0.1) !important; }
/* Tags du multiselect (valeurs sélectionnées) */
span[data-baseweb="tag"] {
    background-color: rgba(245, 166, 35, 0.15) !important;
    border: 1px solid rgba(245, 166, 35, 0.3);
}

/* Radio / checkbox : accent cohérent au lieu du rouge Streamlit par défaut */
.stRadio [role="radiogroup"] label, .stCheckbox label { color: var(--cti-text); }

/* Dataframe / tableaux */
[data-testid="stDataFrame"] {
    border: 1px solid var(--cti-border);
    border-radius: 4px;
    overflow: hidden;
}

/* Expander (profils malware, détails) */
[data-testid="stExpander"] {
    background-color: var(--cti-surface);
    border: 1px solid var(--cti-border);
    border-radius: 4px;
}
[data-testid="stExpander"] summary { font-weight: 500; }

/* Conteneurs à bordure (grille de familles de malware) */
[data-testid="stVerticalBlockBorderWrapper"] > div {
    border-color: var(--cti-border) !important;
    background-color: var(--cti-surface);
    border-radius: 4px;
}

/* Alertes : info/success/warning/error avec liseré coloré cohérent
   avec le reste du système de badges, plutôt que les blocs par défaut */
[data-testid="stAlertContainer"] {
    border-radius: 4px;
    border: 1px solid var(--cti-border);
    background-color: var(--cti-surface);
}
[data-testid="stAlertContainer"]:has(svg[data-icon="warning"]) { border-left: 3px solid var(--cti-accent); }
[data-testid="stAlertContainer"]:has(svg[data-icon="check"]) { border-left: 3px solid var(--cti-teal); }
[data-testid="stAlertContainer"]:has(svg[data-icon="info"]) { border-left: 3px solid var(--cti-violet); }
[data-testid="stAlertContainer"]:has(svg[data-icon="error"]) { border-left: 3px solid var(--cti-red); }

/* Dividers plus discrets que le gris clair par défaut */
hr { border-color: var(--cti-border) !important; }

/* Scrollbar sombre — détail qui évite le contraste "navigateur clair"
   au survol des tableaux/menus longs */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--cti-bg); }
::-webkit-scrollbar-thumb { background: var(--cti-border); border-radius: 5px; }
::-webkit-scrollbar-thumb:hover { background: var(--cti-accent); }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# Valeurs "placeholder" renvoyées telles quelles par certaines sources
# (VirusTotal, sources internes) qui ne veulent en réalité rien dire de
# plus qu'une absence de donnée -> à traiter comme None, pas affichées
# comme si c'était une vraie classification.
PLACEHOLDER_VALUES = {"unknown", "n/a", "na", "none", "null", "unclassified", "-", "undefined"}


def has_value(v):
    """True si `v` porte une information réelle (pas None/vide/placeholder).
    Détecte aussi les variantes du type 'Unknown malware', 'Unknown (APT)'...
    pas seulement le mot 'unknown' seul."""
    if v is None:
        return False
    s = str(v).strip().lower()
    if not s or s in PLACEHOLDER_VALUES:
        return False
    if s.startswith("unknown") or s.startswith("n/a") or s.startswith("undefined"):
        return False
    return True


def badge(text, color="neutral"):
    """Retourne le HTML d'un petit badge coloré (pour MITRE, alias, CVE...)."""
    return f'<span class="cti-badge cti-badge-{color}">{text}</span>'


def render_badges(items, color="neutral"):
    st.markdown(" ".join(badge(i, color) for i in items), unsafe_allow_html=True)


def render_malware_profile(profile):
    """Affiche un profil malware sous forme de carte lisible,
    au lieu du st.json brut."""
    st.markdown('<div class="cti-card">', unsafe_allow_html=True)
    st.markdown(f"#### 🦠 {profile.get('malware_name', 'Malware inconnu')}")
    if has_value(profile.get("malware_type")):
        st.caption(f"Type : {profile['malware_type']}")
    if profile.get("description"):
        st.write(profile["description"])
    if profile.get("aliases"):
        st.markdown("**Alias**")
        render_badges(profile["aliases"], "neutral")
    if profile.get("mitre_techniques"):
        st.markdown("**Techniques MITRE ATT&CK**")
        render_badges(profile["mitre_techniques"], "violet")
    if profile.get("related_cves"):
        st.markdown("**CVE associées**")
        render_badges(profile["related_cves"], "red")
    if profile.get("references"):
        st.markdown("**Références**")
        for ref in profile["references"]:
            st.markdown(f"- {ref}")
    st.markdown('</div>', unsafe_allow_html=True)


def render_external_intelligence(ext):
    """Affiche l'intelligence externe (VirusTotal) sous forme de
    carte lisible, au lieu du st.json brut."""
    if ext.get("error"):
        st.warning(ext["error"])
        return
    if not ext.get("found_in_vt"):
        st.info("IOC non trouvé sur VirusTotal.")
        return

    st.markdown('<div class="cti-card">', unsafe_allow_html=True)
    ratio = ext.get("detection_ratio") or "—"
    malicious = ext.get("malicious_votes") or 0
    total = ext.get("total_engines") or 0
    color = "red" if total and malicious / total > 0.3 else "orange" if malicious else "green"
    st.markdown(f"#### 🧪 VirusTotal — {ratio}", unsafe_allow_html=True)
    render_badges([f"{malicious} détections positives" if malicious else "aucune détection"], color)

    c1, c2 = st.columns(2)
    with c1:
        if has_value(ext.get("popular_names")):
            st.write(f"**Classification** : {ext['popular_names']}")
        if has_value(ext.get("type_description")):
            st.write(f"**Type de fichier** : {ext['type_description']}")
    with c2:
        if ext.get("first_submission"):
            st.write(f"**Première soumission** : {ext['first_submission']}")
        if ext.get("last_analysis"):
            st.write(f"**Dernière analyse** : {ext['last_analysis']}")

    if ext.get("mitre_techniques_observed"):
        st.markdown("**Techniques MITRE observées en sandbox**")
        render_badges(ext["mitre_techniques_observed"], "violet")
    st.markdown('</div>', unsafe_allow_html=True)


RED_GRADIENT = ["#3a0d16", "#ff5470"]  # du bordeaux sombre au rouge signal, selon l'intensité


def plotly_bar(df, x, y, color=None, horizontal=False, gradient=None):
    """Bar chart Plotly stylé (dark theme, sans fond).
    - `color` : couleur unique appliquée à toutes les barres.
    - `gradient` : liste [couleur_min, couleur_max] pour colorer chaque
      barre selon sa valeur (ex: RED_GRADIENT pour les familles de
      malware, où plus une famille est fréquente, plus le rouge est vif)."""
    common_kwargs = dict(
        x=y if horizontal else x,
        y=x if horizontal else y,
        orientation="h" if horizontal else "v",
        template=PLOTLY_TEMPLATE,
        text_auto=True,
    )
    if gradient:
        fig = px.bar(df, color=y, color_continuous_scale=gradient, **common_kwargs)
        fig.update_layout(coloraxis_showscale=False)
    else:
        fig = px.bar(df, color_discrete_sequence=[color or CHART_COLORS[0]], **common_kwargs)
    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        height=340,
        xaxis_title=None,
        yaxis_title=None,
    )
    fig.update_traces(marker_line_width=0)
    st.plotly_chart(fig, use_container_width=True)


def plotly_line(df, x, y, color=None):
    """Line chart Plotly stylé, à la place de st.line_chart."""
    color = color or CHART_COLORS[0]
    fig = px.line(df, x=x, y=y, template=PLOTLY_TEMPLATE, markers=True,
                  color_discrete_sequence=[color])
    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=320,
        xaxis_title=None,
        yaxis_title=None,
    )
    st.plotly_chart(fig, use_container_width=True)


def clean_placeholder_column(df, *columns):
    """Remplace les valeurs placeholder (unknown, n/a...) par une cellule
    vide dans les colonnes données d'un DataFrame, avant affichage.
    Utilise "" plutôt que None : dans une colonne object, None s'affiche
    littéralement comme "None" dans st.dataframe, ce qu'on veut éviter."""
    df = df.copy()
    for col in columns:
        if col in df.columns:
            df[col] = df[col].apply(lambda v: v if has_value(v) else "")
    return df


def api_get(path, params=None):
    try:
        resp = requests.get(f"{API_BASE_URL}{path}", params=params, timeout=15)
        resp.raise_for_status()
        return resp.json(), None
    except requests.exceptions.ConnectionError:
        return None, "Impossible de contacter l'API. Vérifie qu'uvicorn tourne (uvicorn api:app --reload)."
    except requests.exceptions.Timeout:
        return None, "L'API a mis trop de temps à répondre (timeout)."
    except requests.exceptions.HTTPError as e:
        return None, f"Erreur API : {e}"
    except Exception as e:
        return None, f"Erreur inattendue : {e}"


def ioc_to_stix_indicator(ioc):
    ioc_type = ioc.get("type")
    value = ioc.get("value")
    if ioc_type == "hash":
        pattern = f"[file:hashes.'SHA-256' = '{value}']" if len(value) == 64 else \
                  f"[file:hashes.MD5 = '{value}']" if len(value) == 32 else \
                  f"[file:hashes.'SHA-1' = '{value}']"
    elif ioc_type == "ip":
        pattern = f"[ipv4-addr:value = '{value}']"
    elif ioc_type == "domain":
        pattern = f"[domain-name:value = '{value}']"
    elif ioc_type == "url":
        pattern = f"[url:value = '{value}']"
    else:
        pattern = f"[x-cti-platform:value = '{value}']"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}",
        "created": now, "modified": now, "name": f"{ioc_type}: {value}",
        "description": ioc.get("justification", ""), "pattern": pattern,
        "pattern_type": "stix", "valid_from": now,
        "labels": ioc.get("tags", [])[:10], "confidence": ioc.get("confidence") or 50,
        "indicator_types": ["malicious-activity"] if ioc.get("score", {}).get("status") == "active" else ["unknown"],
    }


def build_stix_bundle(iocs):
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
            "objects": [ioc_to_stix_indicator(i) for i in iocs]}


def iocs_to_csv(iocs):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "type", "value", "threat_type", "malware_name", "confidence",
                      "current_score", "status", "is_active", "first_seen", "last_seen", "related_cves"])
    for ioc in iocs:
        writer.writerow([
            ioc.get("id"), ioc.get("type"), ioc.get("value"), ioc.get("threat_type"),
            ioc.get("malware_name"), ioc.get("confidence"),
            ioc.get("score", {}).get("current_score"), ioc.get("score", {}).get("status"),
            ioc.get("score", {}).get("is_active"), ioc.get("timeline", {}).get("first_seen"),
            ioc.get("timeline", {}).get("last_seen"), ";".join(ioc.get("related_cves", [])),
        ])
    return output.getvalue()


if "current_iocs" not in st.session_state:
    st.session_state.current_iocs = []


@st.cache_data(ttl=30, show_spinner=False)
def fetch_ops_snapshot():
    """Instantané pour le bandeau d'en-tête (cache 30s pour ne pas
    multiplier les appels API à chaque interaction utilisateur)."""
    stats, err1 = api_get("/stats")
    mail_stats, err2 = api_get("/mail/stats")
    return (stats if not err1 else None), (mail_stats if not err2 else None)


header_col1, header_col2 = st.columns([5, 1])
with header_col1:
    st.markdown(
        """
        <div class="cti-eyebrow">CYBER THREAT INTELLIGENCE — OPS CONSOLE</div>
        <div style="display:flex; align-items:baseline; gap:12px; margin-bottom:2px;">
            <span style="font-family:var(--cti-mono); font-size:2em; font-weight:700;
                         letter-spacing:-0.02em;">CTI Platform</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
with header_col2:
    api_online = check_api_status()
    status_color = "green" if api_online else "red"
    status_text = "● API EN LIGNE" if api_online else "● API HORS LIGNE"
    st.markdown(
        f'<div style="text-align:right; padding-top:18px;">{badge(status_text, status_color)}</div>',
        unsafe_allow_html=True,
    )
    if st.button("🔄 Actualiser", use_container_width=True):
        fetch_ops_snapshot.clear()
        st.rerun()

# Bandeau "ops" : indicateurs clés en pleine largeur sous le titre,
# dans le même esprit qu'un centre d'opérations de sécurité.
snapshot_stats, snapshot_mail = fetch_ops_snapshot()
ops_items = []
if snapshot_stats:
    ops_items.append(("IOC en base", f"{snapshot_stats['total_iocs']:,}".replace(",", " ")))
    ops_items.append(("Familles malware", snapshot_stats["total_malwares_profiles"]))
if snapshot_mail:
    ops_items.append(("Emails analysés", snapshot_mail["total_emails"]))
    ops_items.append(("Emails bloqués", snapshot_mail["total_malicious_emails"]))
    ops_items.append(("IOC extraits", snapshot_mail.get("total_distinct_iocs", "—")))

if ops_items:
    ops_html = "".join(
        f'<div style="display:flex; flex-direction:column; gap:2px;">'
        f'<span style="font-family:var(--cti-mono); font-size:1.15em; '
        f'font-weight:600; color:var(--cti-text);">{value}</span>'
        f'<span style="font-size:0.7em; letter-spacing:0.06em; text-transform:uppercase; '
        f'color:var(--cti-text-dim);">{label}</span>'
        f'</div>'
        for label, value in ops_items
    )
    st.markdown(
        f"""
        <div style="display:flex; justify-content:space-between; width:100%;
                     padding:14px 0 16px 0;
                     border-top:1px solid var(--cti-border); margin-top:10px;">
            {ops_html}
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

# ========================================================================
# Chaque page devient une fonction, appelée depuis le bon (sous-)onglet.
# ========================================================================


def page_recherche_ioc():
    st.subheader("Vérifier un indicateur")

    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        value = st.text_input("Valeur de l'IOC", placeholder="ex: 8.8.8.8, evil.com, ou un hash...")
    with col2:
        ioc_type = st.selectbox("Type (optionnel)", ["", "ip", "domain", "url", "hash", "email", "filename"])
    with col3:
        st.write("")
        st.write("")
        rechercher = st.button("Vérifier", type="primary", use_container_width=True)

    if rechercher and value:
        params = {"value": value}
        if ioc_type:
            params["type"] = ioc_type
        with st.spinner("Interrogation de l'API..."):
            data, error = api_get("/check", params=params)

        if error:
            st.error(error)
        elif not data.get("found"):
            st.warning(data.get("message", "IOC non trouvé."))
            ext = data.get("external_intelligence")
            if ext:
                st.info("Intelligence externe (VirusTotal) disponible malgré l'absence en base interne :")
                render_external_intelligence(ext)
            verdict = data.get("consolidated_verdict")
            if verdict:
                st.write(f"**Verdict consolidé** : {verdict['verdict']} ({verdict['confidence']})")
                st.caption(verdict["reasoning"])
        else:
            ioc = data["ioc"]
            st.session_state.current_iocs = [ioc]

            verdict = ioc["consolidated_verdict"]
            verdict_emoji = {
                "malicious": "🔴", "conflicting": "🟠", "low_confidence": "🟡",
                "suspicious": "🟠", "clean": "🟢", "unknown": "⚪",
            }
            verdict_badge_color = {
                "malicious": "red", "conflicting": "orange", "low_confidence": "orange",
                "suspicious": "orange", "clean": "green", "unknown": "neutral",
            }
            emoji = verdict_emoji.get(verdict["verdict"], "⚪")
            color = verdict_badge_color.get(verdict["verdict"], "neutral")
            st.markdown(f"### {emoji} Verdict")
            render_badges([f"{verdict['verdict']} — confiance : {verdict['confidence']}"], color)
            st.caption(verdict["reasoning"])

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Score actuel", f"{ioc['score']['current_score']}")
            m2.metric("Statut", ioc["score"]["status"])
            m3.metric("Confiance (source)", ioc["confidence"])
            m4.metric("Incertitude", ioc["uncertainty_score"])

            st.divider()
            colA, colB = st.columns(2)
            with colA:
                st.markdown("**Détails**")
                st.write(f"- Type : `{ioc['type']}`")
                st.write(f"- Valeur : `{ioc['value']}`")
                st.write(f"- Threat type : {ioc.get('threat_type') if has_value(ioc.get('threat_type')) else '—'}")
                st.write(f"- Malware : {ioc.get('malware_name') if has_value(ioc.get('malware_name')) else '—'}")
                st.write(f"- Première observation : {ioc['timeline']['first_seen']}")
                st.write(f"- Dernière observation : {ioc['timeline']['last_seen']}")
                if ioc.get("related_cves"):
                    st.write(f"- CVE liées : {', '.join(ioc['related_cves'])}")
            with colB:
                st.markdown("**Justification du score**")
                st.info(ioc["justification"])

            if ioc.get("malware_profile") and has_value(ioc["malware_profile"].get("malware_name")):
                st.markdown("**Profil malware**")
                render_malware_profile(ioc["malware_profile"])
            if ioc.get("sources"):
                st.markdown("**Sources**")
                st.dataframe(pd.DataFrame(ioc["sources"]), use_container_width=True)
            if ioc.get("external_intelligence"):
                st.markdown("**Intelligence externe (VirusTotal)**")
                render_external_intelligence(ioc["external_intelligence"])

            st.caption(f"ID de cet IOC : **{ioc['id']}** — utilise-le dans l'onglet Corrélation.")


IOC_TYPE_ICON = {
    "ip": "🌐", "domain": "🏷️", "url": "🔗", "hash": "#️",
    "email": "✉️", "filename": "📄",
}


def status_marker(status):
    """Pastille colorée pour le statut d'un IOC (actif/expiré/autre)."""
    if not has_value(status):
        return "⚪ —"
    s = str(status).lower()
    if "active" in s or "actif" in s:
        return f"🟢 {status}"
    if "expir" in s:
        return f"⚫ {status}"
    return f"⚪ {status}"


def page_correlation():
    st.subheader("Corrélation d'un IOC (cluster lié)")
    ioc_id = st.number_input("ID de l'IOC", min_value=1, step=1)

    if st.button("Chercher les IOC liés", type="primary"):
        with st.spinner("Recherche en cours..."):
            related_data, error = api_get(f"/related/{int(ioc_id)}")

        if error:
            st.error(error)
        elif related_data.get("related"):
            related_iocs = related_data["related"]
            st.session_state.current_iocs = related_iocs

            m1, m2, m3 = st.columns(3)
            m1.metric("IOC liés au total", related_data["total_related"])
            m2.metric("Affichés", related_data["returned_count"])
            with m3:
                st.markdown('<div style="padding-top:8px;">', unsafe_allow_html=True)
                st.caption("Type de lien")
                render_badges([related_data["link_type"]], "violet")
                st.markdown('</div>', unsafe_allow_html=True)

            st.write("")
            df = pd.DataFrame([
                {
                    "id": r["id"],
                    "type": f"{IOC_TYPE_ICON.get(r['type'], '📌')} {r['type']}",
                    "value": r["value"],
                    "malware_name": r.get("malware_name"),
                    "score": r["score"]["current_score"],
                    "statut": status_marker(r["score"]["status"]),
                }
                for r in related_iocs
            ])
            st.dataframe(
                clean_placeholder_column(df, "malware_name"),
                use_container_width=True,
                hide_index=True,
                column_config={
                    "id": st.column_config.NumberColumn("ID", width="small"),
                    "type": st.column_config.TextColumn("Type", width="small"),
                    "value": st.column_config.TextColumn("Valeur", width="large"),
                    "malware_name": st.column_config.TextColumn("Malware"),
                    "score": st.column_config.ProgressColumn(
                        "Score", min_value=0, max_value=100, format="%.0f"
                    ),
                    "statut": st.column_config.TextColumn("Statut", width="small"),
                },
            )
        else:
            st.info(related_data.get("message", "Aucun IOC lié trouvé."))


def page_sources_cti():
    st.subheader("Répartition par source CTI")

    stats, error = api_get("/stats")
    if error:
        st.error(error)
    else:
        m1, m2, m3 = st.columns(3)
        m1.metric("IOC total", f"{stats['total_iocs']:,}".replace(",", " "))
        m2.metric("Entrées sources", f"{stats['total_sources_liees']:,}".replace(",", " "))
        m3.metric("Familles de malware profilées", stats["total_malwares_profiles"])

        st.divider()
        df_source = pd.DataFrame(list(stats["par_source"].items()), columns=["Source", "Nombre"])
        plotly_bar(df_source, x="Source", y="Nombre", color=CHART_COLORS[0])

        st.markdown("**Répartition par type d'IOC**")
        df_type = pd.DataFrame(list(stats["par_type"].items()), columns=["Type", "Nombre"])
        plotly_bar(df_type, x="Type", y="Nombre", color=CHART_COLORS[1])


MALWARE_CATEGORY_STYLE = {
    # (mots-clés à chercher dans malware_type) -> (couleur badge, repère visuel)
    ("ransomware", "wiper", "stealer", "infostealer"): ("red", "🟥"),
    ("trojan", "rat", "remote access", "backdoor"): ("orange", "🟧"),
    ("botnet", "c2", "framework", "worm"): ("violet", "🟪"),
    ("loader", "spyware", "dropper"): ("green", "🟩"),
}


def classify_malware_type(malware_type):
    """Retourne (couleur_badge, repère_visuel) selon la catégorie du
    malware, par mots-clés simples -> donne un repère de risque immédiat
    dans la grille, au lieu d'une liste de texte uniforme."""
    if not has_value(malware_type):
        return "neutral", "⬜"
    t = malware_type.lower()
    for keywords, style in MALWARE_CATEGORY_STYLE.items():
        if any(k in t for k in keywords):
            return style
    return "neutral", "⬜"


CATEGORY_LABELS = {
    "red": "🟥 Ransomware · Stealer · Wiper",
    "orange": "🟧 Trojan · RAT · Backdoor",
    "violet": "🟪 Botnet · C2 · Worm",
    "green": "🟩 Loader · Spyware",
    "neutral": "⬜ Type inconnu / autre",
}
CATEGORY_ORDER = ["red", "orange", "violet", "green", "neutral"]  # du plus au moins critique


def page_malware():
    st.subheader("Profils malware (avec techniques MITRE ATT&CK)")

    malware_data, error = api_get("/malware")
    if error:
        st.error(error)
    elif malware_data["total"] == 0:
        st.info("Aucun profil malware en base.")
    else:
        st.write(f"**{malware_data['total']} familles de malware** profilées.")
        search = st.text_input("Filtrer par nom", placeholder="ex: Rhysida, Vidar...")

        filtered = [
            m for m in malware_data["malware_profiles"]
            if not search or search.lower() in m["malware_name"].lower()
        ]
        if not filtered:
            st.info("Aucune famille ne correspond à ce filtre.")
            return

        # Regroupement par catégorie (déduite du malware_type), du plus
        # critique au moins critique -> chaque section regroupe ses
        # familles, avec le détail dans un expander par carte.
        groups = {key: [] for key in CATEGORY_ORDER}
        for m in filtered:
            color, marker = classify_malware_type(m.get("malware_type"))
            groups[color].append((m, marker))

        for color in CATEGORY_ORDER:
            items = groups[color]
            if not items:
                continue

            st.markdown(f"#### {CATEGORY_LABELS[color]}")
            render_badges([f"{len(items)} famille(s)"], color)

            cols = st.columns(3)
            for i, (m, marker) in enumerate(items):
                type_label = m["malware_type"] if has_value(m.get("malware_type")) else "type inconnu"
                with cols[i % 3]:
                    with st.container(border=True):
                        st.markdown(f"**{marker} {m['malware_name']}**")
                        st.caption(type_label)
                        with st.expander("Détails"):
                            if m.get("description"):
                                st.write(m["description"])
                            if m.get("aliases"):
                                st.markdown("**Alias**")
                                render_badges(m["aliases"], "neutral")
                            if m.get("mitre_techniques"):
                                st.markdown("**Techniques MITRE ATT&CK**")
                                render_badges(m["mitre_techniques"], "violet")
                            if m.get("related_cves"):
                                st.markdown("**CVE associées**")
                                render_badges(m["related_cves"], "red")

            st.divider()


def page_mail_gateway():
    st.subheader("Vue d'ensemble du Mail Gateway (Haraka)")

    mail_stats, error = api_get("/mail/stats")
    if error:
        st.error(error)
    elif mail_stats["total_emails"] == 0:
        st.info("Aucun email traité pour l'instant.")
    else:
        m1, m2 = st.columns(2)
        m1.metric("Emails traités", mail_stats["total_emails"])
        m2.metric("Emails avec IOC malveillant", mail_stats["total_malicious_emails"])

        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Top familles de malware détectées**")
            if mail_stats["top_malware"]:
                plotly_bar(pd.DataFrame(mail_stats["top_malware"]), x="malware_name", y="count",
                           gradient=RED_GRADIENT, horizontal=True)
            else:
                st.info("Aucune famille associée pour l'instant.")
        with col2:
            st.markdown("**Top types de menace**")
            if mail_stats["top_threat_types"]:
                plotly_bar(pd.DataFrame(mail_stats["top_threat_types"]), x="threat_type", y="count",
                           color=CHART_COLORS[1], horizontal=True)
            else:
                st.info("Aucun type de menace associé pour l'instant.")

        st.markdown("**Timeline des emails traités (par jour)**")
        if mail_stats["timeline"]:
            plotly_line(pd.DataFrame(mail_stats["timeline"]), x="date", y="count", color=CHART_COLORS[0])
        else:
            st.info("Pas encore assez de données pour une timeline.")


def page_ioc_extraits():
    st.subheader("IOC extraits des emails")

    mail_stats, error = api_get("/mail/stats")
    if error:
        st.error(error)
    else:
        df = pd.DataFrame(mail_stats["recent_detections"])
        if df.empty:
            st.info("Aucun IOC extrait pour l'instant.")
        else:
            df_unique = df.drop_duplicates(subset=["ioc_type", "ioc_value"])[
                ["ioc_type", "ioc_value", "verdict", "malware_name", "threat_type"]
            ]
            st.write(f"**{len(df_unique)} IOC distincts** extraits (sur les 20 dernières détections journalisées).")
            st.dataframe(clean_placeholder_column(df_unique, "malware_name", "threat_type"), use_container_width=True)


def page_historique_emails():
    st.subheader("Historique des emails analysés")

    mail_stats, error = api_get("/mail/stats", params={"limit": 300})
    if error:
        st.error(error)
        return

    df = pd.DataFrame(mail_stats["recent_detections"])
    if df.empty:
        st.info("Aucun email traité pour l'instant.")
        return

    st.caption(f"{df['message_id'].nunique()} email(s) sur les {len(df)} dernières détections journalisées.")

    fcol1, fcol2, fcol3 = st.columns(3)
    with fcol1:
        verdict_filter = st.multiselect(
            "Verdict", options=sorted(df["verdict"].dropna().unique()), default=[]
        )
    with fcol2:
        malware_filter = st.multiselect(
            "Malware", options=sorted(df["malware_name"].dropna().unique()), default=[]
        )
    with fcol3:
        search = st.text_input("Recherche libre", placeholder="expéditeur, IOC, message_id...")

    df_filtered = df.copy()
    if verdict_filter:
        df_filtered = df_filtered[df_filtered["verdict"].isin(verdict_filter)]
    if malware_filter:
        df_filtered = df_filtered[df_filtered["malware_name"].isin(malware_filter)]
    if search:
        mask = df_filtered.apply(
            lambda row: search.lower() in " ".join(str(v) for v in row.values).lower(), axis=1
        )
        df_filtered = df_filtered[mask]

    st.write(f"**{len(df_filtered)} détection(s)** affichée(s) après filtrage.")
    st.dataframe(
        clean_placeholder_column(df_filtered, "malware_name", "threat_type").sort_values("received_at", ascending=False),
        use_container_width=True,
        column_config={
            "received_at": "Reçu le",
            "message_id": "Message ID",
            "sender": "Expéditeur",
            "recipient": "Destinataire",
            "ioc_type": "Type IOC",
            "ioc_value": "Valeur IOC",
            "verdict": "Verdict",
            "malware_name": "Malware",
            "threat_type": "Type de menace",
        },
    )


def page_emails_suspects():
    st.subheader("Emails contenant un IOC malveillant")

    mail_stats, error = api_get("/mail/stats")
    if error:
        st.error(error)
    else:
        df = pd.DataFrame(mail_stats["recent_detections"])
        if df.empty:
            st.info("Aucune détection pour l'instant.")
        else:
            df_suspects = df[df["verdict"].isin(["malicious", "conflicting"])]
            if df_suspects.empty:
                st.success("Aucun email suspect parmi les détections récentes.")
            else:
                st.warning(f"**{len(df_suspects)} email(s) suspect(s)** détecté(s) récemment.")
                st.dataframe(clean_placeholder_column(df_suspects, "malware_name", "threat_type"), use_container_width=True)


def page_statistiques():
    st.subheader("Statistiques globales de la plateforme")

    stats, error = api_get("/stats")
    if error:
        st.error(error)
    else:
        m1, m2, m3 = st.columns(3)
        m1.metric("IOC total", f"{stats['total_iocs']:,}".replace(",", " "))
        m2.metric("Entrées sources", f"{stats['total_sources_liees']:,}".replace(",", " "))
        m3.metric("Familles de malware profilées", stats["total_malwares_profiles"])

        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Actifs vs expirés**")
            df_actif = pd.DataFrame(list(stats["actifs_vs_expires"].items()), columns=["Statut", "Nombre"])
            plotly_bar(df_actif, x="Statut", y="Nombre", color=CHART_COLORS[2])
        with col2:
            st.markdown("**Top 10 des familles de malware**")
            if stats["top_malwares"]:
                plotly_bar(pd.DataFrame(stats["top_malwares"]), x="malware_name", y="count",
                           gradient=RED_GRADIENT, horizontal=True)
            else:
                st.info("Aucune famille de malware associée pour l'instant.")

        st.divider()
        st.caption(
            f"Plage temporelle : {stats['plage_temporelle']['first_seen_min']} "
            f"→ {stats['plage_temporelle']['last_seen_max']}"
        )


def page_alertes():
    st.subheader("Alertes récentes")
    st.caption(
        "Basées actuellement sur les détections du Mail Gateway. "
    )

    mail_stats, error = api_get("/mail/stats")
    if error:
        st.error(error)
    else:
        df = pd.DataFrame(mail_stats["recent_detections"])
        df_alertes = df[df["verdict"].isin(["malicious", "conflicting"])] if not df.empty else df
        if df_alertes.empty:
            st.success("Aucune alerte active.")
        else:
            st.error(f"**{len(df_alertes)} alerte(s) active(s)**")
            st.dataframe(clean_placeholder_column(df_alertes, "malware_name", "threat_type"), use_container_width=True)


def page_rapports():
    st.subheader("Export des IOC consultés")

    if not st.session_state.current_iocs:
        st.info("Fais d'abord une recherche ou une corrélation pour avoir des données à exporter.")
    else:
        n = len(st.session_state.current_iocs)
        st.write(f"**{n} IOC** actuellement disponibles pour export.")

        format_export = st.radio("Format d'export", ["CSV", "STIX 2.1 (JSON)"], horizontal=True)

        if format_export == "CSV":
            csv_data = iocs_to_csv(st.session_state.current_iocs)
            st.download_button(
                "⬇️ Télécharger en CSV", data=csv_data,
                file_name=f"export_iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )
            st.dataframe(pd.read_csv(io.StringIO(csv_data)), use_container_width=True)
        else:
            bundle = build_stix_bundle(st.session_state.current_iocs)
            stix_json = json.dumps(bundle, indent=2, ensure_ascii=False)
            st.download_button(
                "⬇️ Télécharger en STIX 2.1", data=stix_json,
                file_name=f"export_stix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
            )
            st.json(bundle)


# ========================================================================
# Navigation : onglets horizontaux en haut, organisés par catégorie.
# Chaque catégorie contient les endpoints/pages qui lui sont liés,
# accessibles via des sous-onglets à l'intérieur.
# ========================================================================

CATEGORIES = {
    "🔎 IOC Intelligence": {
        "Recherche IOC": page_recherche_ioc,
        "Corrélation": page_correlation,
    },
    "🧬 Threat Intelligence": {
        "Sources CTI": page_sources_cti,
        "Malware": page_malware,
    },
    "📧 Email Security": {
        "Mail Gateway": page_mail_gateway,
        "Historique": page_historique_emails,
        "IOC extraits": page_ioc_extraits,
        "Emails suspects": page_emails_suspects,
    },
    "📈 Analytics": {
        "Statistiques": page_statistiques,
        "Alertes": page_alertes,
        "Rapports": page_rapports,
    },
}

top_tabs = st.tabs(list(CATEGORIES.keys()))

for top_tab, (category_name, subpages) in zip(top_tabs, CATEGORIES.items()):
    with top_tab:
        sub_tabs = st.tabs(list(subpages.keys()))
        for sub_tab, (subpage_name, render_fn) in zip(sub_tabs, subpages.items()):
            with sub_tab:
                render_fn()
