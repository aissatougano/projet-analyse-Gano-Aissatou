"""Projet 1 - Analyse des journaux d'un pare-feu.

Usage : python analyse.py
Lit data/logs_reseau.csv, nettoie les donnees, calcule les resultats,
enregistre les figures dans figures/ et ecrit resultats.json.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas besoin d'ecran pour generer les PNG
import matplotlib.pyplot as plt
import pandas as pd

RACINE = Path(__file__).resolve().parent
CSV = RACINE / "data" / "logs_reseau.csv"
DOSSIER_FIGURES = RACINE / "figures"
SORTIE_JSON = RACINE / "resultats.json"

NOMS_PORTS = {
    22: "22 (SSH)", 23: "23 (Telnet)", 53: "53 (DNS)", 80: "80 (HTTP)",
    443: "443 (HTTPS)", 1883: "1883 (MQTT)", 3389: "3389 (RDP)", 8080: "8080 (HTTP alt.)",
}


def charger_et_nettoyer(chemin: Path) -> pd.DataFrame:
    """Charge le CSV puis applique les 3 etapes de nettoyage de l'enonce."""
    df = pd.read_csv(chemin)
    df = df.drop_duplicates()                                   # 1. doublons exacts
    df["protocol"] = df["protocol"].str.upper()                 # 2. casse du protocole
    df["bytes_sent"] = df["bytes_sent"].fillna(df["bytes_sent"].median())  # 3. mediane
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.reset_index(drop=True)


def calculer_resultats(df: pd.DataFrame) -> dict:
    """Calcule les 5 resultats demandes."""
    ports_par_ip = df.groupby("src_ip")["dst_port"].nunique()
    octets_par_ip = df.groupby("src_ip")["bytes_sent"].sum()
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(ports_par_ip.idxmax()),
        "ip_exfiltration": str(octets_par_ip.idxmax()),
    }


def _sauver(fig, nom: str) -> None:
    fig.tight_layout()
    fig.savefig(DOSSIER_FIGURES / nom, dpi=130)
    plt.close(fig)


def faire_figures(df: pd.DataFrame, res: dict) -> None:
    DOSSIER_FIGURES.mkdir(exist_ok=True)

    # 1. Top 10 des ports de destination
    top = df["dst_port"].value_counts().head(10)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    etiquettes = [NOMS_PORTS.get(p, str(p)) for p in top.index]
    ax.bar(etiquettes, top.values, color="#2b6cb0")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination")
    ax.set_ylabel("Nombre de connexions")
    plt.setp(ax.get_xticklabels(), rotation=35, ha="right")
    _sauver(fig, "01_top_ports.png")

    # 2. Repartition ALLOW / DENY
    rep = df["action"].value_counts()
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    ax.pie(rep.values, labels=rep.index, autopct="%1.1f%%", startangle=90,
           colors=["#38a169", "#e53e3e"])
    ax.set_title("Repartition des connexions ALLOW / DENY")
    _sauver(fig, "02_allow_deny.png")

    # 3. Octets envoyes par type d'appareil (echelle log : un appareil ecrase les autres)
    octets = df.groupby("device_type")["bytes_sent"].sum().sort_values(ascending=False)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(octets.index, octets.values / 1e6, color="#dd6b20")
    ax.set_yscale("log")
    ax.set_title("Volume total d'octets envoyes par type d'appareil")
    ax.set_xlabel("Type d'appareil")
    ax.set_ylabel("Mo envoyes (echelle logarithmique)")
    _sauver(fig, "03_octets_par_appareil.png")

    # 4. Connexions par heure (le pic de minuit trahit le scan)
    par_heure = df.groupby(df["timestamp"].dt.hour).size()
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(par_heure.index, par_heure.values, color="#805ad5")
    ax.set_title("Nombre de connexions par heure de la journee")
    ax.set_xlabel("Heure (0-23)")
    ax.set_ylabel("Nombre de connexions")
    ax.set_xticks(range(0, 24, 2))
    _sauver(fig, "04_connexions_par_heure.png")

    # 5. Nombre de ports distincts contactes par IP source (preuve du scan)
    ports_par_ip = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    couleurs = ["#e53e3e" if ip == res["ip_scanner"] else "#a0aec0" for ip in ports_par_ip.index]
    ax.bar(ports_par_ip.index, ports_par_ip.values, color=couleurs)
    ax.set_title("Ports distincts contactes par IP source (top 10)")
    ax.set_xlabel("Adresse IP source")
    ax.set_ylabel("Nombre de ports distincts")
    plt.setp(ax.get_xticklabels(), rotation=35, ha="right")
    _sauver(fig, "05_ports_distincts_par_ip.png")

    # 6. Total d'octets par IP source (preuve de l'exfiltration)
    octets_ip = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    couleurs = ["#e53e3e" if ip == res["ip_exfiltration"] else "#a0aec0" for ip in octets_ip.index]
    ax.bar(octets_ip.index, octets_ip.values / 1e6, color=couleurs)
    ax.set_yscale("log")
    ax.set_title("Total d'octets envoyes par IP source (top 10)")
    ax.set_xlabel("Adresse IP source")
    ax.set_ylabel("Mo envoyes (echelle logarithmique)")
    plt.setp(ax.get_xticklabels(), rotation=35, ha="right")
    _sauver(fig, "06_octets_par_ip.png")


def main() -> None:
    df = charger_et_nettoyer(CSV)
    res = calculer_resultats(df)
    SORTIE_JSON.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    faire_figures(df, res)

    # Quelques chiffres de preuve pour le rapport
    scan = df[df["src_ip"] == res["ip_scanner"]]
    exfil = df[df["src_ip"] == res["ip_exfiltration"]]
    print("Resultats :", json.dumps(res, indent=2, ensure_ascii=False))
    print(f"[Scan] {res['ip_scanner']} : {len(scan)} connexions, "
          f"{scan['dst_port'].nunique()} ports distincts, "
          f"{(scan['action'] == 'DENY').mean() * 100:.1f}% DENY, "
          f"de {scan['timestamp'].min()} a {scan['timestamp'].max()}")
    print(f"[Exfiltration] {res['ip_exfiltration']} ({exfil['device_type'].iloc[0]}) : "
          f"{exfil['bytes_sent'].sum() / 1e6:.1f} Mo envoyes, "
          f"{(exfil['bytes_sent'] > 1e6).sum()} transferts > 1 Mo")


if __name__ == "__main__":
    main()
