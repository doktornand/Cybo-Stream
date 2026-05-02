#!/usr/bin/env python3
"""
Cyber Threat Map — Version Streamlit
=====================================
Déploiement cloud-ready sur streamlit.io
• Pas de fichiers locaux persistant → st.session_state + st.cache_data
• Pas de boucle bloquante → bouton "Rafraîchir" + auto-refresh optionnel
• Carte Folium native via st_folium
• Export CSV/JSON via st.download_button
"""

import streamlit as st
import folium
from folium.plugins import HeatMap, AntPath
from streamlit_folium import st_folium
import requests
import requests.adapters
import json
import random
import time
import csv
import io
import ipaddress
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
from collections import Counter
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION & SECRETS
# ─────────────────────────────────────────────────────────────────────────────

def get_config():
    """Charge la config depuis st.secrets (prod) ou valeurs par défaut (dev)."""
    defaults = {
        'abuseipdb': '', 'otx': '', 'greynoise': '',
        'shodan': '', 'virustotal': '',
    }
    # Streamlit Cloud : st.secrets["api_keys"]["abuseipdb"]
    # Local : sidebar inputs
    if "api_keys" in st.secrets:
        return {k: st.secrets["api_keys"].get(k, v) for k, v in defaults.items()}
    return defaults


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODEL
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CyberAttack:
    source_lat:     float
    source_lon:     float
    target_lat:     float
    target_lon:     float
    attack_type:    str
    severity:       str
    timestamp:      datetime
    source_ip:      str
    target_country: str
    source_country: str
    port:           Optional[int]  = None
    protocol:       Optional[str]  = None
    confidence:     int            = 0
    feed_source:    str            = 'unknown'
    description:    str            = ''
    cve_id:         str            = ''

    def _get_color(self) -> str:
        return {'low': '#00ff00', 'medium': '#ffff00',
                'high': '#ff8800', 'critical': '#ff0000'}.get(self.severity, '#ffffff')

    def _get_popup_html(self) -> str:
        cve_line = f'<b>CVE:</b> <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={self.cve_id}" target="_blank" style="color:#00aaff;">{self.cve_id}</a><br>' if self.cve_id else ''
        return f"""
        <div style="font-family:monospace;background:#1a1a1a;color:#00ff00;padding:10px;
                    border-radius:5px;min-width:260px;">
            <h4 style="color:{self._get_color()};margin:0 0 8px 0;">⚠️ {self.attack_type}</h4>
            <hr style="border-color:#333;margin:4px 0;">
            <b>Sévérité :</b> <span style="color:{self._get_color()};">{self.severity.upper()}</span><br>
            <b>Confiance :</b> {self.confidence}%<br>
            <b>Source :</b> {self.source_ip} ({self.source_country})<br>
            <b>Cible :</b> {self.target_country}<br>
            <b>Port :</b> {self.port or 'N/A'} ({self.protocol or 'N/A'})<br>
            {cve_line}
            <b>Feed :</b> {self.feed_source}<br>
            <b>Heure :</b> {self.timestamp.strftime('%H:%M:%S')}<br>
            <hr style="border-color:#333;margin:4px 0;">
            <i style="color:#888;font-size:.85em;">{self.description[:120]}…</i>
        </div>"""

    def to_dict(self) -> dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d


# ─────────────────────────────────────────────────────────────────────────────
# GEO IP RESOLVER — Cache en mémoire (pas de fichiers locaux)
# ─────────────────────────────────────────────────────────────────────────────

class GeoIPResolver:
    COUNTRY_COORDS = {
        'CN': (35.86,104.19), 'US': (39.83,-98.58), 'RU': (61.52,105.32),
        'DE': (51.17,10.45),  'NL': (52.13,5.29),   'GB': (55.38,-3.44),
        'FR': (46.23,2.21),   'BR': (-14.24,-51.93), 'IN': (20.59,78.96),
        'JP': (36.20,138.25), 'KR': (35.91,127.77), 'IR': (32.43,53.69),
        'VN': (14.06,108.28), 'ID': (-0.79,113.92), 'UA': (48.38,31.17),
        'RO': (45.94,24.97),  'IT': (41.87,12.57),  'ES': (40.46,-3.75),
        'CA': (56.13,-106.35),'AU': (-25.27,133.78), 'PL': (51.92,19.15),
        'SG': (1.35,103.82),  'TW': (23.70,120.96), 'SE': (60.13,18.64),
        'TR': (38.96,35.24),  'MX': (23.63,-102.55),'ZA': (-30.56,22.94),
        'IL': (31.05,34.85),  'HK': (22.32,114.17), 'KP': (40.34,127.51),
        'SA': (23.89,45.08),  'AE': (23.42,53.85),  'PK': (30.38,69.35),
    }

    def __init__(self):
        self._mem: Dict[str, Optional[Tuple]] = {}
        self.session = requests.Session()

    @st.cache_data(ttl=3600, show_spinner=False)
    def _fetch_ip_api(_self, ip: str):
        """Cache Streamlit pour les requêtes GeoIP (1h)."""
        try:
            if ipaddress.ip_address(ip).is_private:
                return None
            resp = _self.session.get(
                f'http://ip-api.com/json/{ip}?fields=lat,lon,countryCode,status',
                timeout=5)
            data = resp.json()
            if data.get('status') == 'success':
                return (data['lat'], data['lon'], data['countryCode'])
        except Exception:
            pass
        return None

    def get_location(self, ip: str) -> Optional[Tuple[float, float, str]]:
        if ip in self._mem:
            return self._mem[ip]
        result = self._fetch_ip_api(ip)
        self._mem[ip] = result
        return result

    def get_random_location(self, country_code: str = None) -> Tuple[float, float, str]:
        if country_code and country_code in self.COUNTRY_COORDS:
            lat, lon = self.COUNTRY_COORDS[country_code]
        else:
            lat, lon = random.choice(list(self.COUNTRY_COORDS.values()))
            country_code = country_code or 'XX'
        return (lat + random.uniform(-2, 2), lon + random.uniform(-2, 2), country_code)


# ─────────────────────────────────────────────────────────────────────────────
# RATE-LIMITING SESSION
# ─────────────────────────────────────────────────────────────────────────────

class RateLimitedSession(requests.Session):
    def __init__(self, retries: int = 2, backoff_factor: float = 1.0):
        super().__init__()
        adapter = requests.adapters.HTTPAdapter(
            max_retries=requests.adapters.Retry(
                total=retries, backoff_factor=backoff_factor,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=['GET'], raise_on_status=False,
                connect=0, read=0))
        self.mount('https://', adapter)
        self.mount('http://', adapter)
        self.headers.update({'User-Agent': 'CyberThreatMap/2.0 (Research)'})


# ─────────────────────────────────────────────────────────────────────────────
# THREAT FEED MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class ThreatFeedManager:
    TARGETS = ['US', 'DE', 'FR', 'GB', 'JP']

    def __init__(self, api_keys: dict):
        self.api_keys = api_keys
        self.geo = GeoIPResolver()
        self.session = RateLimitedSession()
        self.stats = {s: {'success': 0, 'errors': 0}
                      for s in ('abuseipdb', 'otx', 'greynoise',
                                'dshield', 'shodan', 'virustotal', 'circl_cve')}

    def _score_to_severity(self, score: int) -> str:
        if score >= 90: return 'critical'
        if score >= 70: return 'high'
        if score >= 40: return 'medium'
        return 'low'

    def _random_target(self) -> Tuple[float, float, str]:
        country = random.choice(self.TARGETS)
        return self.geo.get_random_location(country)

    def _categorize_abuse(self, score: int) -> str:
        if score > 90: return random.choice(['Malware C2', 'Botnet', 'DDoS'])
        if score > 70: return random.choice(['SSH Bruteforce', 'Port Scan', 'Web Attack'])
        return 'Suspicious Activity'

    def _extract_target_from_tags(self, tags: List[str]) -> str:
        mapping = {'usa': 'US', 'united states': 'US', 'russia': 'RU',
                   'china': 'CN', 'iran': 'IR', 'germany': 'DE',
                   'france': 'FR', 'uk': 'GB', 'brazil': 'BR', 'india': 'IN'}
        for tag in tags:
            if tag.lower() in mapping:
                return mapping[tag.lower()]
        return random.choice(self.TARGETS)

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    def fetch_abuseipdb(self, limit: int = 100) -> List[CyberAttack]:
        key = self.api_keys.get('abuseipdb', '')
        if not key:
            return []
        attacks = []
        try:
            resp = self.session.get(
                'https://api.abuseipdb.com/api/v2/blacklist',
                headers={'Key': key, 'Accept': 'application/json'},
                params={'confidenceMinimum': 40, 'limit': limit}, timeout=8)
            for item in resp.json().get('data', []):
                ip = item.get('ipAddress')
                loc = self.geo.get_location(ip)
                if not loc:
                    continue
                lat, lon, country = loc
                tlat, tlon, tc = self._random_target()
                attacks.append(CyberAttack(
                    source_lat=lat, source_lon=lon,
                    target_lat=tlat, target_lon=tlon,
                    attack_type=self._categorize_abuse(item.get('abuseConfidenceScore', 0)),
                    severity=self._score_to_severity(item.get('abuseConfidenceScore', 0)),
                    timestamp=datetime.now(), source_ip=ip, source_country=country,
                    target_country=tc, confidence=item.get('abuseConfidenceScore', 0),
                    feed_source='AbuseIPDB',
                    description=f"Reports: {item.get('totalReports',0)}"))
            self.stats['abuseipdb']['success'] += len(attacks)
        except Exception as e:
            self.stats['abuseipdb']['errors'] += 1
            st.warning(f"AbuseIPDB: {e}")
        return attacks

    # ── AlienVault OTX ────────────────────────────────────────────────────────
    def fetch_otx_pulses(self, limit: int = 10) -> List[CyberAttack]:
        key = self.api_keys.get('otx', '')
        if not key:
            return []
        attacks = []
        try:
            resp = self.session.get(
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                headers={'X-OTX-API-KEY': key},
                params={'limit': limit}, timeout=10)
            for pulse in resp.json().get('results', []):
                for ind in pulse.get('indicators', []):
                    if ind.get('type') != 'IPv4':
                        continue
                    ip = ind.get('indicator')
                    loc = self.geo.get_location(ip)
                    if not loc:
                        continue
                    lat, lon, country = loc
                    tc = self._extract_target_from_tags(pulse.get('tags', []))
                    tlat, tlon, _ = self.geo.get_random_location(tc)
                    attacks.append(CyberAttack(
                        source_lat=lat, source_lon=lon,
                        target_lat=tlat, target_lon=tlon,
                        attack_type=pulse.get('name', 'Unknown Threat')[:30],
                        severity='high' if 'malware' in pulse.get('tags', []) else 'medium',
                        timestamp=datetime.now(), source_ip=ip, source_country=country,
                        target_country=tc, confidence=80,
                        feed_source='AlienVault OTX',
                        description=pulse.get('description', '')[:200]))
            self.stats['otx']['success'] += len(attacks)
        except Exception as e:
            self.stats['otx']['errors'] += 1
            st.warning(f"OTX: {e}")
        return attacks

    # ── DShield (SANS ISC) — SANS CLÉ ────────────────────────────────────────
    def fetch_dshield(self) -> List[CyberAttack]:
        attacks = []
        port_types = {22: 'SSH Bruteforce', 3389: 'RDP Attack',
                      445: 'SMB Exploit', 80: 'Web Attack', 443: 'HTTPS Attack'}
        try:
            resp = self.session.get(
                'https://isc.sans.edu/api/sources/attacks/20?json', timeout=10)
            raw = resp.json()
            items = []
            if isinstance(raw, list):
                items = raw[:20]
            elif isinstance(raw, dict):
                items = raw.get('sources', raw.get('data', []))[:20]
            for item in items:
                ip = item.get('ip')
                loc = self.geo.get_location(ip)
                if not loc:
                    continue
                lat, lon, country = loc
                ports = item.get('ports', '').split(',')
                port = int(ports[0]) if ports and ports[0].isdigit() else random.choice([22, 3389, 445])
                tlat, tlon, _ = self.geo.get_random_location('US')
                attacks.append(CyberAttack(
                    source_lat=lat, source_lon=lon,
                    target_lat=tlat, target_lon=tlon,
                    attack_type=port_types.get(port, 'Port Scan'),
                    severity='high' if item.get('attacks', 0) > 1000 else 'medium',
                    timestamp=datetime.now(), source_ip=ip, source_country=country,
                    target_country='US', port=port,
                    confidence=min(int(item.get('attacks', 0)) // 10, 100),
                    feed_source='DShield (SANS)',
                    description=f"Attacks: {item.get('attacks',0)} | Targets: {item.get('targets',0)}"))
            self.stats['dshield']['success'] += len(attacks)
        except Exception as e:
            self.stats['dshield']['errors'] += 1
            st.warning(f"DShield: {e}")
        return attacks

    # ── GreyNoise ────────────────────────────────────────────────────────────
    def fetch_greynoise(self, limit: int = 10) -> List[CyberAttack]:
        key = self.api_keys.get('greynoise', '')
        if not key:
            return []
        attacks = []
        test_ips = ['185.220.101.0', '194.32.107.0', '103.253.145.0',
                    '91.207.175.0',  '45.142.212.0', '185.156.173.0']
        try:
            for ip in test_ips[:limit]:
                try:
                    resp = self.session.get(
                        f'https://api.greynoise.io/v3/community/{ip}',
                        headers={'key': key}, timeout=5)
                    data = resp.json()
                    if data.get('noise') or data.get('riot'):
                        loc = self.geo.get_location(ip)
                        if loc:
                            lat, lon, country = loc
                            tlat, tlon, tc = self._random_target()
                            attacks.append(CyberAttack(
                                source_lat=lat, source_lon=lon,
                                target_lat=tlat, target_lon=tlon,
                                attack_type=data.get('classification', 'Internet Scan'),
                                severity='medium' if data.get('noise') else 'low',
                                timestamp=datetime.now(), source_ip=ip, source_country=country,
                                target_country=tc, confidence=70,
                                feed_source='GreyNoise',
                                description=f"VPN:{data.get('vpn',False)} Tor:{data.get('tor',False)}"))
                except Exception:
                    continue
            self.stats['greynoise']['success'] += len(attacks)
        except Exception as e:
            self.stats['greynoise']['errors'] += 1
            st.warning(f"GreyNoise: {e}")
        return attacks

    # ── Shodan InternetDB — SANS CLÉ ─────────────────────────────────────────
    def fetch_shodan(self) -> List[CyberAttack]:
        key = self.api_keys.get('shodan', '')
        attacks = []
        probe_ips = [
            '185.220.101.34', '192.42.116.16', '198.199.10.234',
            '45.33.32.156',   '104.236.42.18', '5.9.16.1',
        ]
        for ip in probe_ips:
            try:
                if key:
                    resp = self.session.get(
                        f'https://api.shodan.io/shodan/host/{ip}',
                        params={'key': key}, timeout=8)
                    data = resp.json()
                    open_ports = data.get('ports', [])
                    vulns = list(data.get('vulns', {}).keys())
                    country = data.get('country_code', 'XX')
                    lat = data.get('latitude', 0.0)
                    lon = data.get('longitude', 0.0)
                else:
                    resp = self.session.get(
                        f'https://internetdb.shodan.io/{ip}', timeout=8)
                    data = resp.json()
                    open_ports = data.get('ports', [])
                    vulns = data.get('vulns', [])
                    loc = self.geo.get_location(ip)
                    if not loc:
                        continue
                    lat, lon, country = loc

                if not open_ports:
                    continue
                severity = 'critical' if vulns else ('high' if len(open_ports) > 5 else 'medium')
                cve_id = vulns[0] if vulns else ''
                port = open_ports[0] if open_ports else None
                tlat, tlon, tc = self._random_target()
                attacks.append(CyberAttack(
                    source_lat=lat, source_lon=lon,
                    target_lat=tlat, target_lon=tlon,
                    attack_type='Exposed Service' if not vulns else 'Vulnerable Host',
                    severity=severity,
                    timestamp=datetime.now(), source_ip=ip, source_country=country,
                    target_country=tc, port=port, confidence=85,
                    feed_source='Shodan',
                    description=f"Open ports: {open_ports[:5]} | CVEs: {vulns[:3]}",
                    cve_id=cve_id))
            except Exception as e:
                pass
        self.stats['shodan']['success'] += len(attacks)
        return attacks

    # ── VirusTotal ───────────────────────────────────────────────────────────
    def fetch_virustotal(self) -> List[CyberAttack]:
        key = self.api_keys.get('virustotal', '')
        if not key:
            return []
        attacks = []
        probe_ips = [
            '5.188.86.172', '91.108.4.1', '185.220.102.8',
            '109.70.100.22', '176.10.104.240',
        ]
        for ip in probe_ips:
            try:
                resp = self.session.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                    headers={'x-apikey': key}, timeout=6)
                if resp.status_code != 200:
                    continue
                attr = resp.json().get('data', {}).get('attributes', {})
                malicious = attr.get('last_analysis_stats', {}).get('malicious', 0)
                if malicious == 0:
                    continue
                country = attr.get('country', 'XX')
                loc = self.geo.get_location(ip)
                if not loc:
                    loc = self.geo.get_random_location(country)
                lat, lon, _ = loc
                confidence = min(malicious * 5, 100)
                severity = self._score_to_severity(confidence)
                tlat, tlon, tc = self._random_target()
                attacks.append(CyberAttack(
                    source_lat=lat, source_lon=lon,
                    target_lat=tlat, target_lon=tlon,
                    attack_type='Malware Distribution',
                    severity=severity,
                    timestamp=datetime.now(), source_ip=ip, source_country=country,
                    target_country=tc, confidence=confidence,
                    feed_source='VirusTotal',
                    description=f"Malicious engines: {malicious}/72"))
            except Exception as e:
                pass
            finally:
                time.sleep(0.25)
        self.stats['virustotal']['success'] += len(attacks)
        return attacks

    # ── CIRCL CVE — SANS CLÉ ─────────────────────────────────────────────────
    def fetch_circl_cve(self, limit: int = 10) -> List[CyberAttack]:
        attacks = []
        try:
            resp = self.session.get(
                f'https://cve.circl.lu/api/last/{limit}', timeout=12)
            if resp.status_code != 200:
                return []
            for cve in resp.json():
                cve_id = cve.get('id', '')
                summary = cve.get('summary', '')
                score = float(cve.get('cvss', 0) or 0)
                severity = ('critical' if score >= 9 else 'high' if score >= 7
                            else 'medium' if score >= 4 else 'low')
                src_country = random.choice(['CN', 'RU', 'IR', 'KP', 'RO'])
                slat, slon, _ = self.geo.get_random_location(src_country)
                tlat, tlon, tc = self._random_target()
                attacks.append(CyberAttack(
                    source_lat=slat, source_lon=slon,
                    target_lat=tlat, target_lon=tlon,
                    attack_type=f'CVE Exploit ({cve_id})',
                    severity=severity,
                    timestamp=datetime.now(),
                    source_ip='0.0.0.0',
                    source_country=src_country,
                    target_country=tc,
                    confidence=int(score * 10),
                    feed_source='CIRCL CVE',
                    description=summary[:200],
                    cve_id=cve_id))
            self.stats['circl_cve']['success'] += len(attacks)
        except Exception as e:
            self.stats['circl_cve']['errors'] += 1
            st.warning(f"CIRCL CVE: {e}")
        return attacks

    # ── Agrégation séquentielle (pas de threads pour Streamlit) ──────────────
    def fetch_all_feeds(self, selected_feeds: List[str]) -> List[CyberAttack]:
        all_attacks: List[CyberAttack] = []
        tasks = {
            'abuseipdb': self.fetch_abuseipdb,
            'otx': self.fetch_otx_pulses,
            'greynoise': self.fetch_greynoise,
            'dshield': self.fetch_dshield,
            'shodan': self.fetch_shodan,
            'virustotal': self.fetch_virustotal,
            'circl_cve': self.fetch_circl_cve,
        }
        for name in selected_feeds:
            if name in tasks:
                with st.spinner(f"🔄 Récupération {name}..."):
                    all_attacks.extend(tasks[name]())
        return all_attacks


# ─────────────────────────────────────────────────────────────────────────────
# FOLIUM MAP BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_map(attacks: List[CyberAttack], show_heatmap: bool = True) -> folium.Map:
    m = folium.Map(location=[25, 10], zoom_start=3,
                   tiles='CartoDB dark_matter')

    connections = folium.FeatureGroup(name="Flux d'Attaques")
    markers = folium.FeatureGroup(name="Sources & Cibles")
    heatmap = folium.FeatureGroup(name="Heatmap")

    SEVERITY_COLORS = {
        'low': '#00ff00', 'medium': '#ffff00',
        'high': '#ff8800', 'critical': '#ff0000',
    }

    for attack in attacks:
        color = SEVERITY_COLORS.get(attack.severity, '#ffffff')
        AntPath(
            locations=[[attack.source_lat, attack.source_lon],
                       [attack.target_lat, attack.target_lon]],
            color=color, weight=3 if attack.severity in ('high', 'critical') else 2,
            opacity=0.8, dash_array=[10, 20], delay=800, pulse_color=color,
        ).add_to(connections)

        folium.CircleMarker(
            location=[attack.source_lat, attack.source_lon],
            radius=6, color=color, fill=True, fill_opacity=0.7,
            tooltip=f"🚨 {attack.attack_type} — {attack.source_country}",
        ).add_to(markers)

        icon_color = ('red' if attack.severity == 'critical'
                      else 'orange' if attack.severity == 'high' else 'green')
        folium.Marker(
            location=[attack.target_lat, attack.target_lon],
            popup=folium.Popup(attack._get_popup_html(), max_width=360),
            icon=folium.Icon(color=icon_color, icon='warning-sign', prefix='glyphicon'),
            tooltip=f"Target: {attack.target_country} | {attack.attack_type}",
        ).add_to(markers)

    if show_heatmap and attacks:
        heat_data = []
        weights = {'low': 1, 'medium': 2, 'high': 3, 'critical': 5}
        for a in attacks[-200:]:
            heat_data.append([a.target_lat, a.target_lon, weights.get(a.severity, 1)])
        HeatMap(heat_data, radius=20, blur=15, max_zoom=6,
                gradient={0.4: 'blue', 0.65: 'lime', 0.8: 'yellow', 1: 'red'}
                ).add_to(heatmap)
        heatmap.add_to(m)

    connections.add_to(m)
    markers.add_to(m)
    folium.LayerControl().add_to(m)
    return m


# ─────────────────────────────────────────────────────────────────────────────
# EXPORT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def attacks_to_csv(attacks: List[CyberAttack]) -> str:
    if not attacks:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=attacks[0].to_dict().keys())
    writer.writeheader()
    writer.writerows([a.to_dict() for a in attacks])
    return output.getvalue()

def attacks_to_json(attacks: List[CyberAttack]) -> str:
    return json.dumps([a.to_dict() for a in attacks], indent=2, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────────────────────

def init_session_state():
    defaults = {
        'attacks_history': [],
        'feed_manager': None,
        'last_update': None,
        'stats': {},
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def render_sidebar():
    with st.sidebar:
        st.title("🛡️ Configuration")
        st.markdown("---")

        # Clés API
        st.subheader("🔑 Clés API (optionnel)")
        st.caption("Sources sans clé : DShield, CIRCL CVE, Shodan InternetDB")

        api_keys = {}
        api_keys['abuseipdb'] = st.text_input("AbuseIPDB", type="password",
                                               value=st.secrets.get("api_keys", {}).get("abuseipdb", "")
                                               if "api_keys" in st.secrets else "")
        api_keys['otx'] = st.text_input("AlienVault OTX", type="password",
                                         value=st.secrets.get("api_keys", {}).get("otx", "")
                                         if "api_keys" in st.secrets else "")
        api_keys['greynoise'] = st.text_input("GreyNoise", type="password",
                                               value=st.secrets.get("api_keys", {}).get("greynoise", "")
                                               if "api_keys" in st.secrets else "")
        api_keys['shodan'] = st.text_input("Shodan (optionnel)", type="password",
                                            value=st.secrets.get("api_keys", {}).get("shodan", "")
                                            if "api_keys" in st.secrets else "")
        api_keys['virustotal'] = st.text_input("VirusTotal", type="password",
                                                value=st.secrets.get("api_keys", {}).get("virustotal", "")
                                                if "api_keys" in st.secrets else "")

        st.markdown("---")
        st.subheader("📡 Sources à activer")
        available = {
            'dshield': 'DShield (SANS) — sans clé',
            'circl_cve': 'CIRCL CVE — sans clé',
            'shodan': 'Shodan InternetDB — sans clé',
            'abuseipdb': 'AbuseIPDB — clé requise',
            'otx': 'AlienVault OTX — clé requise',
            'greynoise': 'GreyNoise — clé requise',
            'virustotal': 'VirusTotal — clé requise',
        }
        selected = []
        for key, label in available.items():
            needs_key = 'clé requise' in label
            disabled = needs_key and not api_keys.get(key)
            if st.checkbox(label, value=not disabled, disabled=disabled, key=f"chk_{key}"):
                selected.append(key)

        st.markdown("---")
        show_heatmap = st.toggle("🔥 Afficher Heatmap", value=True)
        max_display = st.slider("Max attaques affichées", 50, 1000, 500)

        return api_keys, selected, show_heatmap, max_display


def render_metrics(attacks: List[CyberAttack]):
    cols = st.columns(5)
    total = len(attacks)
    by_sev = Counter(a.severity for a in attacks)
    metrics = [
        ("Total", total, "#ffffff"),
        ("Critical", by_sev.get('critical', 0), "#ff0000"),
        ("High", by_sev.get('high', 0), "#ff8800"),
        ("Medium", by_sev.get('medium', 0), "#ffff00"),
        ("Low", by_sev.get('low', 0), "#00ff00"),
    ]
    for col, (label, value, color) in zip(cols, metrics):
        col.metric(label=label, value=value)


def render_stats_table(attacks: List[CyberAttack]):
    by_feed = Counter(a.feed_source for a in attacks).most_common(10)
    by_src = Counter(a.source_country for a in attacks).most_common(5)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📡 Par source")
        for feed, count in by_feed:
            st.write(f"• **{feed}** : {count}")
    with col2:
        st.subheader("🌍 Top origines")
        st.write(", ".join([f"{c} ({n})" for c, n in by_src]))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="Cyber Threat Map",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # CSS custom
    st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
    }
    .stMetric {
        background: rgba(0,255,0,0.05);
        border: 1px solid #00ff00;
        border-radius: 8px;
        padding: 10px;
    }
    .stMetric label {
        color: #00ff00 !important;
        font-family: 'Courier New', monospace;
    }
    </style>
    """, unsafe_allow_html=True)

    st.title("🌐 Cyber Threat Map — Streamlit Edition")
    st.caption("Carte interactive de menaces cyber en temps réel | Sources : AbuseIPDB, OTX, DShield, GreyNoise, Shodan, VirusTotal, CIRCL CVE")

    init_session_state()
    api_keys, selected_feeds, show_heatmap, max_display = render_sidebar()

    # Bouton principal
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 3])
    with col_btn1:
        fetch_clicked = st.button("🔄 Récupérer les données", type="primary", use_container_width=True)
    with col_btn2:
        clear_clicked = st.button("🗑️ Vider l'historique", use_container_width=True)

    if clear_clicked:
        st.session_state.attacks_history = []
        st.session_state.last_update = None
        st.rerun()

    # Récupération des données
    if fetch_clicked:
        with st.spinner("📡 Connexion aux sources de menaces..."):
            manager = ThreatFeedManager(api_keys)
            new_attacks = manager.fetch_all_feeds(selected_feeds)
            if new_attacks:
                st.session_state.attacks_history.extend(new_attacks)
                st.session_state.last_update = datetime.now()
                st.session_state.stats = manager.stats
                st.success(f"✅ {len(new_attacks)} nouvelles attaques récupérées !")
            else:
                st.info("ℹ️ Aucune nouvelle attaque détectée (vérifiez vos clés API)")

    # Affichage
    attacks = st.session_state.attacks_history[-max_display:]

    if attacks:
        st.markdown("---")
        render_metrics(attacks)
        st.markdown("---")

        # Carte
        m = build_map(attacks, show_heatmap)
        st_folium(m, width="100%", height=700, returned_objects=[])

        st.markdown("---")
        render_stats_table(attacks)

        # Exports
        st.markdown("---")
        st.subheader("📦 Exports")
        col_exp1, col_exp2 = st.columns(2)
        with col_exp1:
            st.download_button(
                label="⬇️ Télécharger CSV",
                data=attacks_to_csv(attacks),
                file_name=f"cyber_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with col_exp2:
            st.download_button(
                label="⬇️ Télécharger JSON",
                data=attacks_to_json(attacks),
                file_name=f"cyber_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )

        # Derniers événements
        st.markdown("---")
        st.subheader("📋 Derniers événements")
        df_data = []
        for a in attacks[-20:]:
            df_data.append({
                'Heure': a.timestamp.strftime('%H:%M:%S'),
                'Type': a.attack_type,
                'Sévérité': a.severity.upper(),
                'Source': f"{a.source_ip} ({a.source_country})",
                'Cible': a.target_country,
                'Feed': a.feed_source,
            })
        st.dataframe(df_data, use_container_width=True, hide_index=True)

    else:
        st.info("👈 Configurez vos sources dans la sidebar et cliquez sur **Récupérer les données** pour commencer.")

        # Demo placeholder
        st.markdown("### 🗺️ Aperçu (mode démo)")
        demo_attacks = [
            CyberAttack(35.86, 104.19, 39.83, -98.58, 'Malware C2', 'critical',
                       datetime.now(), '192.0.2.1', 'US', 'CN', 443, 'TCP', 95,
                       'Demo', 'Exemple de menace', 'CVE-2024-0001'),
            CyberAttack(55.38, -3.44, 48.86, 2.35, 'SSH Bruteforce', 'high',
                       datetime.now(), '198.51.100.5', 'FR', 'GB', 22, 'TCP', 78,
                       'Demo', 'Tentative de connexion SSH'),
        ]
        m = build_map(demo_attacks, show_heatmap=True)
        st_folium(m, width="100%", height=500, returned_objects=[])

    # Footer
    st.markdown("---")
    st.caption(f"Dernière mise à jour : {st.session_state.last_update.strftime('%H:%M:%S') if st.session_state.last_update else 'Jamais'}")


if __name__ == '__main__':
    main()
