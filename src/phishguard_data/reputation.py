"""
Módulo de Reputación y Prevalencia Global de Dominios para PhishGuard.
Utiliza el dataset científico oficial Tranco Top 1M y Public Suffix List (PSL)
para eliminar falsos positivos en sitios legítimos mundiales y detectar dominios sin reputación.
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Dict, Optional, Any
from urllib.parse import urlsplit


# Proveedores conocidos de hosting gratuito / dynamic DNS / user-generated content
# donde un subdominio puede ser malicioso a pesar de que el dominio raíz esté en Tranco
HOSTING_AND_USER_CONTENT_DOMAINS = frozenset({
    "firebaseapp.com", "web.app", "github.io", "gitlab.io", "pages.dev",
    "vercel.app", "netlify.app", "render.com", "glitch.me", "herokuapp.com",
    "ngrok-free.app", "ngrok.io", "duckdns.org", "no-ip.com", "000webhostapp.com",
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "sites.google.com"
})


class GlobalReputationEngine:
    _instance: Optional[GlobalReputationEngine] = None
    _rank_map: Dict[str, int] = {}
    _loaded: bool = False

    def __init__(self):
        if not self._loaded:
            self._load_tranco()

    @classmethod
    def get_instance(cls) -> GlobalReputationEngine:
        if cls._instance is None:
            cls._instance = GlobalReputationEngine()
        return cls._instance

    def _find_tranco_file(self) -> Optional[Path]:
        possible_roots = [
            Path("data"),
            Path("/app/data"),
            Path(__file__).resolve().parent.parent.parent / "data"
        ]
        for root in possible_roots:
            if root.exists():
                zips = list(root.rglob("tranco*.csv.zip"))
                if zips:
                    return sorted(zips)[-1]
                csvs = list(root.rglob("top-1m.csv"))
                if csvs:
                    return sorted(csvs)[-1]
        return None

    def _load_tranco(self) -> None:
        target_file = self._find_tranco_file()
        if not target_file:
            print("[ReputationEngine] AVISO: Dataset de Tranco no encontrado en data/")
            return

        try:
            print(f"[ReputationEngine] Cargando índice de reputación Tranco desde: {target_file}")
            ranks: Dict[str, int] = {}
            if target_file.suffix == ".zip":
                with zipfile.ZipFile(target_file, "r") as z:
                    for name in z.namelist():
                        if name.endswith(".csv"):
                            with z.open(name) as f:
                                for line in f:
                                    decoded = line.decode("utf-8", errors="ignore").strip()
                                    parts = decoded.split(",")
                                    if len(parts) >= 2 and parts[0].isdigit():
                                        ranks[parts[1].lower()] = int(parts[0])
                            break
            else:
                with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split(",")
                        if len(parts) >= 2 and parts[0].isdigit():
                            ranks[parts[1].lower()] = int(parts[0])

            self._rank_map = ranks
            self._loaded = True
            print(f"[ReputationEngine] Tranco Top 1M indexado con éxito: {len(self._rank_map):,} dominios en memoria.")
        except Exception as e:
            print(f"[ReputationEngine] Error cargando Tranco: {e}")

    def get_rank(self, domain: str) -> Optional[int]:
        if not self._loaded:
            self._load_tranco()
        domain = domain.lower().strip().rstrip(".")
        if domain.startswith("www."):
            domain = domain[4:]
        return self._rank_map.get(domain)

    def evaluate_url(self, url: str, psl: Optional[Any] = None) -> Dict[str, Any]:
        """
        Evalúa la reputación y prevalencia global de una URL.
        Retorna detalles forenses del dominio y factor de confianza.
        """
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower().strip()
        except Exception:
            host = url.lower()

        if host.startswith("www."):
            host = host[4:]

        registered_domain = host
        if psl is not None:
            try:
                reg = psl.registrable_domain(host)
                if reg:
                    registered_domain = reg
            except Exception:
                registered_domain = host
        else:
            # Fallback simple si PSL no está inyectado
            domain_parts = host.split(".")
            if len(domain_parts) >= 2:
                registered_domain = ".".join(domain_parts[-2:])

        # Consultar ranking tanto de host completo como de registered_domain
        host_rank = self.get_rank(host)
        reg_rank = self.get_rank(registered_domain)
        best_rank = host_rank if host_rank else reg_rank

        is_hosting = registered_domain in HOSTING_AND_USER_CONTENT_DOMAINS

        # Calcular nivel de reputación (tier) y trust score
        if best_rank is not None:
            if best_rank <= 1000:
                tier = "top_1k"
                trust_score = 0.99
                reputation_label = f"Top {best_rank:,} Global (Excelente)"
            elif best_rank <= 10000:
                tier = "top_10k"
                trust_score = 0.95
                reputation_label = f"Top {best_rank:,} Global (Alta)"
            elif best_rank <= 50000:
                tier = "top_50k"
                trust_score = 0.88
                reputation_label = f"Top {best_rank:,} Global (Buena)"
            elif best_rank <= 250000:
                tier = "top_250k"
                trust_score = 0.70
                reputation_label = f"Top {best_rank:,} Global (Estable)"
            else:
                tier = "top_1m"
                trust_score = 0.50
                reputation_label = f"Top {best_rank:,} Global (Conocido)"
        else:
            tier = "unranked"
            trust_score = 0.0
            reputation_label = "Sin ranking global Tranco (Dominio no listado)"

        # Si es un hosting compartido, el trust score del dominio raíz no ampara
        # ciegamente a los subdominios
        if is_hosting:
            subdomain_present = host != registered_domain
            if subdomain_present:
                trust_score = min(trust_score, 0.25)
                reputation_label += " · Hosting/Subdominios de usuario (requiere inspección estricta)"

        return {
            "host": host,
            "registered_domain": registered_domain,
            "tranco_rank": best_rank,
            "reputation_tier": tier,
            "trust_score": trust_score,
            "reputation_label": reputation_label,
            "is_user_hosting": is_hosting
        }


def get_reputation(url: str, psl: Optional[Any] = None) -> Dict[str, Any]:
    return GlobalReputationEngine.get_instance().evaluate_url(url, psl=psl)
