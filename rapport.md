# Rapport — Analyse des journaux du pare-feu

**Auteure :** Aïssatou Gano

## 1. Résumé

Après suppression de 60 doublons, 5 440 connexions ont été analysées sur la semaine du 5 au 11 octobre 2026.
Le trafic est dominé par le web chiffré (port 443, 1 874 connexions) puis HTTP (80) et DNS (53).
13,57 % des connexions sont bloquées (`DENY`), mais ce taux est tiré vers le haut par quelques sources seulement :
un scan de ports massif et du trafic sur des services à risque (Telnet 23, RDP 3389).
Deux comportements clairement anormaux ressortent : **un scan de ports** et **une exfiltration de données**
depuis une caméra IoT.

## 2. Les deux comportements suspects

### a) Scan de ports depuis `192.168.1.99`

- **Preuve :** cette IP (un PC) a contacté **328 ports distincts** (de 9 à 1023) en 400 connexions,
  alors que toutes les autres IP en contactent 8 au plus (graphique `figures/05_ports_distincts_par_ip.png`).
- Tout s'est passé en **15 minutes**, le 8 octobre entre 00:00:02 et 00:14:58. C'est ce qui crée le pic
  de minuit dans `figures/04_connexions_par_heure.png` (610 connexions entre 0 h et 1 h contre ~210 les autres heures).
- **95,8 % des connexions sont bloquées** (383 DENY sur 400) : le pare-feu a arrêté presque tout,
  mais 17 connexions ont été **autorisées**, donc l'attaquant a pu identifier au moins quelques ports ouverts.
- **Interprétation :** reconnaissance classique avant une attaque (type `nmap`). Le PC est probablement
  compromis ou utilisé par une personne malveillante en interne.

### b) Exfiltration de données depuis la caméra `192.168.1.11`

- **Preuve :** cette caméra IoT a envoyé **≈ 260 Mo** au total, soit environ **400 fois plus** que
  l'IP qui vient en deuxième position (0,62 Mo). Toutes les autres IP envoient moins de 1 Mo chacune sur la semaine
  (`figures/06_octets_par_ip.png`, échelle logarithmique) ; les caméras représentent à elles seules ~262 Mo sur 274 Mo
  (`figures/03_octets_par_appareil.png`).
- **38 transferts de 5 à 8,7 Mo** vers `8.8.8.8` sur le port **8080**, tous le **10 octobre**, répartis sur toute la journée
  y compris la nuit (00 h 08, 02 h 21, 03 h 05…), tous **autorisés** par le pare-feu.
- **Interprétation :** une caméra n'a aucune raison d'envoyer des mégaoctets vers Internet sur un port HTTP alternatif.
  Elle est probablement compromise et sert à sortir des données (ou à relayer du trafic). L'adresse `8.8.8.8` est celle
  du DNS public de Google : l'utiliser comme destination sur le port 8080 est lui-même suspect (usurpation ou tunnel).

## 3. Autres observations

- Le port **23 (Telnet)** reçoit 100 connexions : protocole non chiffré et obsolète, à interdire (74 bloquées, 26 autorisées).
- Le port **3389 (RDP)** est visé 111 fois, dont 81 bloquées : indice de tentatives d'accès à distance.

## 4. Recommandations de sécurité

1. **Isoler la caméra `192.168.1.11` immédiatement**, la réinitialiser, changer ses identifiants et mettre à jour son firmware.
2. **Segmenter le réseau** : placer les objets IoT dans un VLAN dédié, sans accès à Internet sauf liste blanche
   (serveur de stockage / MQTT interne), et sans accès aux PC et serveurs.
3. **Filtrer les flux sortants** : bloquer le port 8080 en sortie depuis les caméras et capteurs ; n'autoriser que les destinations utiles.
4. **Fermer Telnet (23)** partout au profit de SSH, et n'ouvrir RDP (3389) que via VPN.
5. **Détecter les scans** : règle IDS/pare-feu qui bloque temporairement une IP contactant plus de ~20 ports distincts en quelques minutes
   (ici `192.168.1.99` en a contacté 328), avec alerte à l'administrateur.
6. **Superviser le volume** : alerte dès qu'un équipement dépasse un seuil d'octets sortants (par exemple 10 Mo/heure pour une caméra).
7. **Enquêter sur le PC `192.168.1.99`** : antivirus/EDR, vérification du propriétaire et des comptes utilisés le 8 octobre vers minuit.
