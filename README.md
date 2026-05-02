# 🌐 Cybo-Stream — Cyber Threat Map · Purified Edition

> **Carte mondiale des cybermenaces en temps réel** — sans clés API hardcodées, sans IP de sondage fixes, avec chaînage dynamique feed→feed.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B?logo=streamlit)](https://streamlit.io)
[![Folium](https://img.shields.io/badge/Folium-0.15%2B-77b829?logo=leaflet)](https://python-visualization.github.io/folium/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Repo](https://img.shields.io/badge/GitHub-doktornand%2FCybo--Stream-181717?logo=github)](https://github.com/doktornand/Cybo-Stream)

---

## 📋 Table des matières

1. [Vue d'ensemble](#-vue-densemble)
2. [Philosophie de conception](#-philosophie-de-conception)
3. [Fonctionnalités](#-fonctionnalités)
4. [Architecture](#-architecture)
5. [Sources de données](#-sources-de-données)
6. [Prérequis](#-prérequis)
7. [Installation](#-installation)
8. [Configuration des clés API](#-configuration-des-clés-api)
9. [Lancement de l'application](#-lancement-de-lapplication)
10. [Déploiement sur Streamlit Cloud](#-déploiement-sur-streamlit-cloud)
11. [Déploiement avec Docker](#-déploiement-avec-docker)
12. [Guide d'utilisation de l'interface](#-guide-dutilisation-de-linterface)
13. [Structure du code](#-structure-du-code)
14. [Détail des modules](#-détail-des-modules)
15. [Flux d'exécution — chaînage feed→feed](#-flux-dexécution--chaînage-feedfeed)
16. [Modèle de données](#-modèle-de-données)
17. [Exports](#-exports)
18. [Sécurité](#-sécurité)
19. [Limitations connues](#-limitations-connues)
20. [Contribuer](#-contribuer)
21. [FAQ](#-faq)
22. [Licence](#-licence)

---

## 🔭 Vue d'ensemble

**Cybo-Stream** est une application web interactive construite avec [Streamlit](https://streamlit.io) qui affiche en quasi-temps réel les menaces cyber mondiales sur une carte géographique animée. Elle agrège des données provenant de sources de Threat Intelligence reconnues (DShield/SANS ISC, CIRCL CVE, AbuseIPDB, AlienVault OTX, GreyNoise, Shodan, VirusTotal) et les restitue sous forme de flux animés entre origines et cibles sur un fond de carte sombre.

L'application est conçue pour des cas d'usage de **SOC (Security Operations Center)**, de **recherche en sécurité**, de **formation**, ou simplement pour une **visualisation pédagogique** de la menace cyber mondiale.

---

## 🧠 Philosophie de conception

Cybo-Stream est construit autour de trois principes fondamentaux qui le distinguent des outils similaires :

### 1. Zéro clé API côté interface
Toutes les clés API sont chargées **exclusivement côté serveur** via `st.secrets` (Streamlit Cloud) ou des variables d'environnement. Elles ne transitent jamais par le navigateur de l'utilisateur. L'interface ne propose aucun champ de saisie pour les secrets.

### 2. Zéro IP de sondage hardcodée
Il n'existe pas de liste d'IPs fixes (« probe_ips ») embarquées dans le code. Les feeds d'**enrichissement** (Shodan, VirusTotal, GreyNoise) consomment exclusivement les IPs découvertes **dynamiquement** par les feeds **amont** (DShield, AbuseIPDB, OTX). Si aucune IP n'a été découverte, les feeds d'enrichissement s'abstiennent et le signalent honnêtement.

### 3. Honnêteté sur les données
Si aucune donnée fraîche n'est disponible (quota dépassé, API indisponible, pool d'IPs vide), l'application l'indique clairement à l'utilisateur au lieu de générer des données fictives présentées comme réelles.

---

## ✨ Fonctionnalités

- **Carte mondiale interactive** avec flux animés (AntPath) entre sources et cibles d'attaques
- **Heatmap de densité** des attaques par zone géographique, activable/désactivable
- **Coloration par sévérité** : critique (rouge), haute (orange), moyenne (jaune), faible (vert)
- **Popups détaillés** sur chaque attaque : IP source, pays, port, protocole, lien CVE, feed source
- **Chaînage dynamique** des feeds en trois phases : amont → pool d'IPs → enrichissement + CVE
- **7 sources de Threat Intelligence** intégrées, dont 2 gratuites sans clé
- **Résolution géographique des IPs** via ip-api.com avec cache TTL 1h
- **Métriques temps réel** : total, par sévérité, attaques enrichies par chaînage
- **Historique de session** : les données s'accumulent entre les requêtes
- **Export CSV et JSON** horodatés des données collectées
- **Tableau des derniers événements** avec badge « ENRICHIE » pour les attaques issues du chaînage
- **Interface dark-mode** avec thème cyber (fond `#0e1117`, accents verts)
- **Sidebar configurable** : heatmap, nombre max d'attaques affichées, guide de configuration
- **Gestion de rate-limiting** avec retry automatique et backoff exponentiel

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        STREAMLIT UI                             │
│  ┌──────────┐  ┌─────────────┐  ┌──────────┐  ┌────────────┐  │
│  │ Sidebar  │  │ Source Status│  │  Metrics │  │ Feed Select│  │
│  └──────────┘  └─────────────┘  └──────────┘  └────────────┘  │
│                         ↓ fetch_clicked                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │               ThreatFeedManager                          │   │
│  │                                                          │   │
│  │  Phase 1 — Sources AMONT (génèrent des IPs)              │   │
│  │  ┌──────────┐  ┌────────────┐  ┌─────────────────────┐  │   │
│  │  │ DShield  │  │ AbuseIPDB  │  │  AlienVault OTX      │  │   │
│  │  └────┬─────┘  └─────┬──────┘  └──────────┬──────────┘  │   │
│  │       └──────────────┴──────────────────────┘            │   │
│  │                       ↓                                  │   │
│  │              DiscoveredIPPool                            │   │
│  │                       ↓                                  │   │
│  │  Phase 2 — ENRICHISSEMENT (consomment le pool)           │   │
│  │  ┌──────────┐  ┌────────────┐  ┌─────────────────────┐  │   │
│  │  │  Shodan  │  │ VirusTotal │  │     GreyNoise        │  │   │
│  │  └──────────┘  └────────────┘  └─────────────────────┘  │   │
│  │                                                          │   │
│  │  Phase 3 — Sources INDÉPENDANTES                         │   │
│  │  ┌──────────────────────────────────────────────────┐   │   │
│  │  │                   CIRCL CVE                       │   │   │
│  │  └──────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         ↓ List[CyberAttack]                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  GeoIPResolver → build_map() → Folium/AntPath/HeatMap    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         ↓                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │         st_folium (carte) + DataFrames + Exports          │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Composants principaux

| Composant | Rôle |
|---|---|
| `SecretsManager` | Charge et expose les clés API depuis `st.secrets` ou variables d'environnement |
| `GeoIPResolver` | Résout les IPs en coordonnées GPS via ip-api.com, avec cache mémoire et TTL |
| `RateLimitedSession` | Session `requests` avec retry automatique sur les codes 429/5xx |
| `DiscoveredIPPool` | Pool dynamique des IPs découvertes par les feeds amont (max 50 IPs) |
| `ThreatFeedManager` | Orchestrateur des 7 feeds, gère le chaînage en 3 phases |
| `CyberAttack` | Dataclass représentant une attaque (source, cible, sévérité, feed, CVE…) |
| `build_map()` | Construit la carte Folium avec AntPath, marqueurs et heatmap |
| UI functions | `render_sidebar`, `render_metrics`, `render_stats_table`, `render_source_status` |

---

## 📡 Sources de données

### Sources gratuites (sans clé API)

| Source | URL | Description | Données fournies |
|---|---|---|---|
| **DShield (SANS ISC)** | `isc.sans.edu/api/sources/attacks/20` | Top 20 des sources d'attaques réseau mondiales | IPs, ports, nombre d'attaques, nombre de cibles |
| **CIRCL CVE Search** | `cve.circl.lu/api/last/{n}` | CVEs récentes publiées par le CERT Luxembourg | CVE ID, résumé, score CVSS |
| **Shodan InternetDB** | `internetdb.shodan.io/{ip}` | Enrichissement léger des IPs (ports ouverts, CVEs) | Ports, vulnérabilités, sans clé |
| **ip-api.com** | `ip-api.com/json/{ip}` | Géolocalisation des IPs | Latitude, longitude, code pays |

### Sources avec clé API (optionnelles)

| Source | Variable / Secret | Description | Données fournies |
|---|---|---|---|
| **AbuseIPDB** | `abuseipdb` | Blacklist d'IPs malveillantes | Score de confiance, nombre de signalements |
| **AlienVault OTX** | `otx` | Pulses et indicateurs de compromission | IPs, noms de menaces, tags |
| **GreyNoise** | `greynoise` | Classification du bruit Internet (scanners, benins) | Noise flag, VPN, Tor |
| **Shodan (API payante)** | `shodan` | Enrichissement complet des hôtes | Ports, vulnérabilités, localisation précise |
| **VirusTotal** | `virustotal` | Analyse multi-moteurs des IPs | Nombre de moteurs détectant comme malveillant |

> **Note :** Les sources gratuites (DShield, CIRCL CVE, Shodan InternetDB) sont **toujours actives** et permettent un usage complet sans aucune inscription.

---

## 📦 Prérequis

- **Python** 3.9 ou supérieur
- **pip** (gestionnaire de paquets Python)
- Accès Internet (pour les appels aux APIs de Threat Intelligence)
- (Optionnel) Clés API pour les sources premium

### Dépendances Python

```
streamlit>=1.30.0
streamlit-folium>=0.18.0
folium>=0.15.0
requests>=2.31.0
```

---

## 🚀 Installation

### Clonage du dépôt

```bash
git clone https://github.com/doktornand/Cybo-Stream.git
cd Cybo-Stream
```

### Création d'un environnement virtuel (recommandé)

```bash
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### Installation des dépendances

```bash
pip install -r requirements.txt
```

---

## 🔐 Configuration des clés API

Les clés API ne doivent **jamais** être commitées dans le dépôt. Cybo-Stream supporte trois méthodes de configuration, par ordre de priorité :

### Méthode 1 — Streamlit Secrets (recommandé pour Streamlit Cloud)

Créez le fichier `.streamlit/secrets.toml` (à ajouter impérativement à `.gitignore`) :

```toml
[api_keys]
abuseipdb  = "votre_clé_abuseipdb"
otx        = "votre_clé_alienvault_otx"
greynoise  = "votre_clé_greynoise"
shodan     = "votre_clé_shodan"
virustotal = "votre_clé_virustotal"
```

> Sur **Streamlit Cloud**, renseignez ces valeurs dans **Settings → Secrets** sans créer le fichier localement.

### Méthode 2 — Variables d'environnement (Docker, CI/CD)

```bash
export CTM_ABUSEIPDB="votre_clé_abuseipdb"
export CTM_OTX="votre_clé_alienvault_otx"
export CTM_GREYNOISE="votre_clé_greynoise"
export CTM_SHODAN="votre_clé_shodan"
export CTM_VIRUSTOTAL="votre_clé_virustotal"
```

### Méthode 3 — Fichier .env (développement local)

Si vous utilisez `python-dotenv`, créez un fichier `.env` à la racine :

```env
CTM_ABUSEIPDB=votre_clé_abuseipdb
CTM_OTX=votre_clé_alienvault_otx
CTM_GREYNOISE=votre_clé_greynoise
CTM_SHODAN=votre_clé_shodan
CTM_VIRUSTOTAL=votre_clé_virustotal
```

### Obtenir les clés API

| Service | URL d'inscription | Tier gratuit |
|---|---|---|
| AbuseIPDB | https://www.abuseipdb.com/register | ✅ 1000 req/jour |
| AlienVault OTX | https://otx.alienvault.com | ✅ Gratuit |
| GreyNoise | https://www.greynoise.io | ✅ Community tier |
| Shodan | https://account.shodan.io/register | ✅ Limité (InternetDB gratuit) |
| VirusTotal | https://www.virustotal.com/gui/join-us | ✅ 500 req/jour |

---

## ▶️ Lancement de l'application

```bash
streamlit run app.py
```

L'application sera accessible à l'adresse `http://localhost:8501` dans votre navigateur.

Pour spécifier un port personnalisé :

```bash
streamlit run app.py --server.port 8080
```

Pour désactiver l'ouverture automatique du navigateur :

```bash
streamlit run app.py --server.headless true
```

---

## ☁️ Déploiement sur Streamlit Cloud

1. Forkez ou importez ce dépôt sur votre compte GitHub.
2. Connectez-vous à [share.streamlit.io](https://share.streamlit.io).
3. Cliquez sur **New app** → sélectionnez votre repo → branche `main` → fichier `app.py`.
4. Dans **Advanced settings → Secrets**, collez votre configuration TOML :

```toml
[api_keys]
abuseipdb  = "..."
otx        = "..."
greynoise  = "..."
shodan     = "..."
virustotal = "..."
```

5. Cliquez sur **Deploy**. L'application sera disponible à `https://votre-app.streamlit.app`.

---

## 🐳 Déploiement avec Docker

### Dockerfile suggéré

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
```

### Build et lancement

```bash
docker build -t cybo-stream .

docker run -d \
  -p 8501:8501 \
  -e CTM_ABUSEIPDB="votre_clé" \
  -e CTM_OTX="votre_clé" \
  -e CTM_GREYNOISE="votre_clé" \
  -e CTM_SHODAN="votre_clé" \
  -e CTM_VIRUSTOTAL="votre_clé" \
  --name cybo-stream \
  cybo-stream
```

### Docker Compose

```yaml
version: "3.8"
services:
  cybo-stream:
    build: .
    ports:
      - "8501:8501"
    environment:
      - CTM_ABUSEIPDB=${CTM_ABUSEIPDB}
      - CTM_OTX=${CTM_OTX}
      - CTM_GREYNOISE=${CTM_GREYNOISE}
      - CTM_SHODAN=${CTM_SHODAN}
      - CTM_VIRUSTOTAL=${CTM_VIRUSTOTAL}
    restart: unless-stopped
```

---

## 🖥️ Guide d'utilisation de l'interface

### Sidebar (panneau gauche)

- **Statut des clés API** : indique combien de clés sont chargées et lesquelles sont actives.
- **Afficher Heatmap** : bascule l'affichage de la couche de chaleur sur la carte.
- **Max attaques affichées** : slider pour limiter le rendu entre 50 et 1000 événements (les données restent en mémoire).
- **Guide de configuration** : instructions condensées pour configurer les secrets selon l'environnement de déploiement.

### Zone principale

1. **État des sources** : panneau visuel indiquant quelle source est disponible (🟢 gratuite / 🔐 clé configurée / ❌ clé manquante).
2. **Sélecteur de sources** : multiselect pour choisir quelles sources interroger lors du prochain fetch.
3. **Bouton « Récupérer les données »** : déclenche le chaînage complet des feeds sélectionnés.
4. **Bouton « Vider l'historique »** : efface toutes les données accumulées en session.
5. **Métriques** : 5 compteurs (Total, Critical, High, Medium, Low) mis à jour après chaque fetch.
6. **Carte interactive Folium** :
   - Flux animés (AntPath) colorés par sévérité
   - Marqueurs circulaires sur les IPs sources
   - Marqueurs icône sur les pays cibles avec popup détaillé au clic
   - Heatmap de densité
   - Contrôleur de couches (flux / marqueurs / heatmap)
7. **Statistiques** : tableau par source de feed et top des pays d'origine.
8. **Exports** : boutons de téléchargement CSV et JSON horodatés.
9. **Derniers événements** : tableau des 20 dernières attaques avec badge « ✅ ENRICHIE » pour les attaques issues du chaînage.

### Lecture d'un popup d'attaque

Chaque marqueur cible affiche au clic un popup avec :
- Type d'attaque et sévérité (colorée)
- Score de confiance (%)
- IP source et pays d'origine
- Pays cible
- Port et protocole
- Lien cliquable vers la fiche CVE (si applicable)
- Feed source
- Horodatage
- Description courte

---

## 📂 Structure du code

```
Cybo-Stream/
├── app.py              # Application complète (1020 lignes)
└── requirements.txt    # Dépendances Python (4 lignes)
```

L'ensemble de la logique est contenu dans `app.py`, organisé en sections clairement délimitées par des commentaires `# ───────`.

---

## 🔬 Détail des modules

### `SecretsManager`

Charge les clés API depuis `st.secrets["api_keys"]` puis depuis les variables d'environnement préfixées `CTM_`. Expose les méthodes `get(name)`, `is_configured(name)`, `get_available_sources()` et `get_configured_key_names()`. Aucune clé n'est jamais exposée à l'interface utilisateur.

### `CyberAttack` (dataclass)

Représente un événement d'attaque avec les champs suivants :

| Champ | Type | Description |
|---|---|---|
| `source_lat`, `source_lon` | float | Coordonnées de la source |
| `target_lat`, `target_lon` | float | Coordonnées de la cible |
| `attack_type` | str | Type d'attaque (ex: SSH Bruteforce) |
| `severity` | str | `low` / `medium` / `high` / `critical` |
| `timestamp` | datetime | Heure de collecte |
| `source_ip` | str | IP de l'attaquant |
| `source_country` | str | Code pays ISO (ex: CN) |
| `target_country` | str | Code pays cible |
| `port` | int? | Port ciblé |
| `protocol` | str? | Protocole |
| `confidence` | int | Score de confiance (0-100) |
| `feed_source` | str | Nom du feed d'origine |
| `description` | str | Description courte |
| `cve_id` | str | Identifiant CVE si applicable |
| `is_derived` | bool | True si issu du chaînage d'enrichissement |

### `GeoIPResolver`

Résout les IPs en coordonnées GPS via `ip-api.com`. Dispose d'un dictionnaire de coordonnées de fallback pour 35 pays. Utilise `@st.cache_data(ttl=3600)` pour éviter les appels répétés à la même IP. Ignore les IPs privées (RFC1918).

### `RateLimitedSession`

Session `requests` préconfigurée avec :
- Retry automatique (max 2) sur les codes HTTP 429, 500, 502, 503, 504
- Backoff exponentiel (facteur 1.0)
- User-Agent : `CyberThreatMap/2.0-Purified (Research)`
- Pas de retry sur les erreurs de connexion réseau (connect=0, read=0) pour ne pas bloquer l'UI

### `DiscoveredIPPool`

Pool thread-safe (via `set`) des IPs découvertes par les feeds amont. Limité à 50 IPs pour éviter la surcharge des feeds d'enrichissement. Expose `add()`, `add_from_attacks()`, `get_sample(n)`, `is_empty()` et `size()`.

### `ThreatFeedManager`

Orchestrateur principal. Instancie tous les composants et expose `fetch_all_feeds(selected_feeds)` qui exécute le chaînage en 3 phases. Maintient des statistiques par feed (`success` / `errors`).

### `build_map(attacks, show_heatmap)`

Construit une carte Folium avec fond CartoDB dark matter. Ajoute 3 FeatureGroups (connexions, marqueurs, heatmap) contrôlables indépendamment. Les flux AntPath ont une animation CSS intégrée avec pulsation colorée selon la sévérité. La heatmap utilise un gradient bleu→vert→jaune→rouge pondéré par sévérité.

---

## 🔄 Flux d'exécution — chaînage feed→feed

```
Clic sur "Récupérer les données"
           │
           ▼
┌─────────────────────────────────────────────┐
│  Phase 1 — Sources AMONT                    │
│                                             │
│  Pour chaque feed sélectionné dans          │
│  {dshield, abuseipdb, otx} :                │
│    1. Appel API                             │
│    2. Résolution GeoIP de chaque IP         │
│    3. Construction CyberAttack              │
│    4. Alimentation DiscoveredIPPool         │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
         DiscoveredIPPool.size() > 0 ?
                   │
           Oui ────┤──── Non ──→ (skip phase 2)
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Phase 2 — ENRICHISSEMENT                   │
│                                             │
│  Pour chaque feed sélectionné dans          │
│  {shodan, virustotal, greynoise} :          │
│    1. Tirage aléatoire d'un échantillon     │
│       d'IPs depuis le pool (max 5-6 IPs)    │
│    2. Appel API sur ces IPs                 │
│    3. Construction CyberAttack              │
│       avec is_derived=True                  │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Phase 3 — Sources INDÉPENDANTES            │
│                                             │
│  Si circl_cve sélectionné :                 │
│    1. Fetch des N dernières CVEs            │
│    2. Attribution d'un pays source          │
│       aléatoire parmi les pays à risque     │
│    3. Construction CyberAttack avec CVE ID  │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
         st.session_state.attacks_history
         .extend(all_attacks)
                   │
                   ▼
         build_map() + render_metrics()
         + st_folium() + DataFrames
```

---

## 🗃️ Modèle de données

### Calcul de la sévérité

| Score de confiance | Sévérité |
|---|---|
| ≥ 90 | `critical` |
| ≥ 70 | `high` |
| ≥ 40 | `medium` |
| < 40 | `low` |

### Catégorisation des attaques AbuseIPDB

| Score | Catégories possibles |
|---|---|
| > 90 | Malware C2, Botnet, DDoS |
| > 70 | SSH Bruteforce, Port Scan, Web Attack |
| ≤ 70 | Suspicious Activity |

### Mapping port → type d'attaque (DShield)

| Port | Type |
|---|---|
| 22 | SSH Bruteforce |
| 3389 | RDP Attack |
| 445 | SMB Exploit |
| 80 | Web Attack |
| 443 | HTTPS Attack |
| Autre | Port Scan |

---

## 📤 Exports

Deux formats d'export sont disponibles via des boutons de téléchargement dans l'interface :

### CSV

Colonnes exportées :
```
source_lat, source_lon, target_lat, target_lon, attack_type, severity,
timestamp, source_ip, target_country, source_country, port, protocol,
confidence, feed_source, description, cve_id, is_derived
```

Nom de fichier : `cyber_threats_YYYYMMDD_HHMMSS.csv`

### JSON

Tableau JSON avec les mêmes champs, `timestamp` en format ISO 8601.

Nom de fichier : `cyber_threats_YYYYMMDD_HHMMSS.json`

---

## 🛡️ Sécurité

### Ce que fait l'application pour protéger les secrets

- Chargement des clés uniquement côté serveur (Python), jamais rendu dans le HTML/JS
- Aucun champ de saisie de clé dans l'interface utilisateur
- Avertissement explicite dans la documentation intégrée : *"Les clés ne transitent JAMAIS par le navigateur"*
- Suppression des avertissements SSL (urllib3) pour les appels internes uniquement

### Ce que vous devez faire

- Ajouter `.streamlit/secrets.toml` à votre `.gitignore`
- Ne jamais commiter de clés dans l'historique Git
- Utiliser des clés à faibles privilèges (lecture seule) pour chaque service
- Surveiller votre consommation de quota sur chaque plateforme API
- En production, considérer l'ajout d'une authentification Streamlit (via `st.secrets` ou un proxy)

### Avertissement sur les données

Les données affichées proviennent de sources tierces. Elles sont présentées à des fins **informationnelles et pédagogiques**. Toute utilisation à des fins opérationnelles (blocage d'IPs, réponse à incident) doit faire l'objet d'une vérification supplémentaire. L'auteur décline toute responsabilité quant à l'exactitude des données en temps réel.

---

## ⚠️ Limitations connues

| Limitation | Détail |
|---|---|
| **Rate limiting** | ip-api.com est limité à ~45 req/min (plan gratuit). En cas de fort volume d'IPs, certaines géolocalisations peuvent échouer. |
| **Quota AbuseIPDB** | 1000 req/jour sur le tier gratuit. Les blacklists peuvent être tronquées. |
| **VirusTotal** | Délai de 250ms entre chaque requête pour respecter le rate limit (4 req/min sur le tier gratuit). |
| **CIRCL CVE** | Les CVEs représentées sur la carte ont une géolocalisation source aléatoire (pas d'attribution réelle d'une origine géographique). |
| **Cibles** | La cible `FR` est définie par défaut (`TARGETS = ['FR']`). Pour une vue mondiale, modifier cette variable dans `ThreatFeedManager`. |
| **Session** | Les données sont stockées dans `st.session_state` et perdues à la fermeture de l'onglet ou au redémarrage du serveur. |
| **Concurrence** | Les fetches sont séquentiels (pas de parallelisme). Sur des latences API élevées, cela peut allonger le temps de chargement. |
| **ip-api.com** | Requiert HTTP (pas HTTPS) sur le plan gratuit. À considérer dans des environnements réseau stricts. |

---

## 🤝 Contribuer

Les contributions sont bienvenues ! Voici comment participer :

### Signaler un bug

Ouvrez une [issue GitHub](https://github.com/doktornand/Cybo-Stream/issues) en incluant :
- La version de Python et des dépendances
- Les étapes pour reproduire le problème
- Les logs d'erreur (masquez vos clés API !)

### Proposer une fonctionnalité

Ouvrez une issue avec le label `enhancement` en décrivant le cas d'usage et l'impact attendu.

### Soumettre du code

1. Forkez le dépôt
2. Créez une branche : `git checkout -b feature/ma-fonctionnalite`
3. Committez avec un message clair : `git commit -m "feat: ajout du feed XYZ"`
4. Poussez : `git push origin feature/ma-fonctionnalite`
5. Ouvrez une Pull Request

### Idées de contributions

- Ajout de la source **Feodo Tracker** (botnet C2, gratuit sans clé)
- Ajout de la source **URLhaus** (malware URLs, gratuit)
- Persistance des données entre sessions (SQLite ou CSV local)
- Mode temps réel avec auto-refresh toutes les N minutes (`st.rerun` + `time.sleep`)
- Filtres interactifs sur la carte (par sévérité, par feed, par pays)
- Graphiques temporels (attaques par heure, top ports)
- Support multilingue (EN/FR/DE)
- Tests unitaires pour les fetchers et le modèle de données

---

## ❓ FAQ

**Q : L'application fonctionne-t-elle sans aucune clé API ?**
Oui. DShield, CIRCL CVE et Shodan InternetDB sont disponibles sans inscription. Vous obtiendrez des données réelles sur les 20 principales sources d'attaques réseau et les CVEs récentes.

**Q : Pourquoi toutes mes attaques pointent vers la France ?**
La variable `TARGETS = ['FR']` dans `ThreatFeedManager` définit les pays cibles. Modifiez-la pour inclure d'autres pays (`['US', 'DE', 'FR', 'GB', 'JP']` par exemple).

**Q : Les données sont-elles vraiment en temps réel ?**
Les données sont fraîches au moment du clic sur « Récupérer les données ». Il n'y a pas de rafraîchissement automatique. DShield met à jour son API toutes les heures.

**Q : Pourquoi GreyNoise / VirusTotal ne retournent rien ?**
Ces feeds sont des enrichisseurs : ils nécessitent que DShield ou AbuseIPDB aient d'abord découvert des IPs. Si le pool est vide, l'application l'indique avec un message `st.info`.

**Q : Comment changer le fond de carte ?**
Dans `build_map()`, remplacez `tiles='CartoDB dark_matter'` par `tiles='OpenStreetMap'`, `tiles='CartoDB positron'`, ou n'importe quel tile provider Leaflet/TMS.

**Q : Puis-je utiliser cette application dans un SOC en production ?**
L'application est conçue à des fins pédagogiques et de démonstration. Pour un usage en production, vous devriez ajouter une authentification, une persistance des données, une gestion des erreurs plus robuste, et valider les données avec vos propres outils de Threat Intelligence.

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Vous êtes libre de l'utiliser, le modifier et le distribuer sous les termes de cette licence.

```
MIT License

Copyright (c) 2024 doktornand

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

*README généré avec ❤️ — dernière mise à jour : mai 2026*
