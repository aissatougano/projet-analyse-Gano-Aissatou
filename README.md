# Projet 1 — Analyse des journaux d'un pare-feu

**Auteure :** Aïssatou Gano — aissatougano997@gmail.com

Analyse d'une semaine de connexions d'un pare-feu (5 500 lignes brutes) pour repérer
les comportements suspects sur un réseau mêlant PC, serveurs et objets connectés.

## Lancer le projet

```bash
pip install -r requirements.txt
python analyse.py
```

Le script nettoie les données, écrit `resultats.json` et génère les graphiques dans `figures/`.

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `analyse.py` | nettoyage, calculs, figures, `resultats.json` |
| `rapport.md` | observations, comportements suspects, recommandations |
| `resultats.json` | les 5 résultats demandés (généré) |
| `figures/` | 6 graphiques PNG (générés) |
| `data/logs_reseau.csv` | journaux du pare-feu |
| `Enonce_Projet1_Analyse_de_donnees.pdf` | énoncé |

## Résultats

| Clé | Valeur |
|---|---|
| `nb_lignes_apres_nettoyage` | 5440 |
| `top_port` | 443 |
| `taux_deny_pct` | 13.57 |
| `ip_scanner` | 192.168.1.99 |
| `ip_exfiltration` | 192.168.1.11 |
