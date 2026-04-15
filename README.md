 L'Agence Detechtive — Infrastructure Sécurisée

> Projet de fin de formation 
> Certification **RNCP37680 niveau 6**  
> *Administrateur d'Infrastructures Sécurisées (AIS)*

---

## Présentation

**L'Agence Detechtive** est un projet de mise en situation réelle simulant le déploiement d'une infrastructure sécurisée pour une agence de renseignement fictive. 
Ce projet couvre l'architecture réseau, la virtualisation, le durcissement des systèmes mis en place ainsi qu ele développement d'un intranet métier. 

**L'Objectif clé** est démontrer la capacité à concevoir une architecture réseau en :
- Segmentant l'infrastructure en zones de sécurité indépendantes
- Chiffrant les communications critiques
- Assurant la continuité d'activité via une solution de sauvegarde isolée
- Garantissant l'interopérabilité entre l'application web et le domaine Active Directory

La **Stack Technique** utilisée pour ce projet est celle ci-contre : 

| Catégorie | Technologies |
|-----------|-------------|
| **Virtualisation** | GNS3, VMware Workstation |
| **Réseau / Sécurité** | pfSense, WireGuard, IOU L2 |
| **OS Serveurs** | Windows Server 2022 |
| **Web** | Apache, PHP 8.x |
| **Base de données** | MariaDB |
| **SIEM / XDR** | Wazuh |
| **Sauvegarde** | BorgBackup |
| **Annuaire** | Active Directory DS, DNS |
| **Frontend** | HTML5, CSS3 (thème Terminal) |
---
## Avant de commencer

**Les besoins métiers :**
1. Gestion des enquêtes
- Stocker les dossiers - clients (preuves photos, rapports)
- Accéder rapidement aux informations
- Travailler à plusieurs sur une affaire

2. Confidentialité des données
- Protéger les informations sensibles (clients, enquêtes, preuves)
- Éviter les fuites ou accès non autorisés

3. Gestion des utilisateurs
- Créer des comptes 
- Gérer les droits selon les rôles
- Contrôler qui accède à quoi

4. Accès aux services internes
- Accéder à la WebApp (gestion des dossiers)
- Accéder aux fichiers et bases de données

5. Surveillance et détection des menaces
- Détecter les intrusions ou comportements suspects
- Réagir rapidement à une attaque

6. Sauvegarde et continuité d’activité
- Éviter la perte de données
- Reprendre rapidement après incident

**Les Valeurs Métiers :** 

1. Sécurité renforcée
- Protection des données sensibles
- Réduction du risque de piratage

2. Efficacité opérationnelle
- Accès rapide aux dossiers
- Collaboration facilitée entre détectives

3. Traçabilité et contrôle
- Surpervision des connexions
- Suivi des actions utilisateurs

4. Architecture organisée et évolutive
- Séparation logique des services
- Communication contrôlée

5. Réduction des risques
- Isolation des réseaux 
- Firewall contrôle les flux

6. Conformité réglementaire
- Protection des données personnelles (type RGPD)
- Gestion des accès et des logs

## I. Architecture et Infrastructure

### A. Virtualisation et Réseau

| Composant | Détail |
|-----------|--------|
| **Hyperviseur / Émulateur** | GNS3, VMware Workstation |
| **Switch L2** | IOU — mode L2 pur (`no ip routing`), 6 VLANs, trunk dot1q vers pfSense sur `eth0/0`. Ports inutilisés → VLAN 999 et shutdown |
| **Routage inter-VLAN** | pfSense en *Router-on-a-Stick* — 6 sous-interfaces VLAN, firewalling granulaire, NAT, VPN WireGuard, Syslog vers Wazuh |
| **Sauvegarde** | Un VLAN (60) totalement isolé, flux unidirectionnels depuis le VLAN des Serveurs et celui de l'Active Directory |
| **Supervision** | Wazuh (SIEM & XDR) — collecte d'alertes sur tous les VLANs depuis le VLAN dédié |

---
### B. Systèmes et Services

L'infrastructure repose sur Windows Server 2022 pour assurer une cohérence d'administration permise via Active Directory.

#### Serveurs (Windows Server 2022)

- **SRV-AD-01** — Active Directory DS + DNS. Isolé en VLAN 40, inaccessible depuis la DMZ.
- **File Server (FS)** — Stockage, partages SMB sécurisés, quotas.
- **Serveur Web** — Apache (XAMPP/WAMP), PHP 8.x
- **Serveur Base de Données** — MariaDB (MySQL)
- **NAS/Serveur Backup** — Zone passive, BorgBackup. Aucun accès Internet, aucun flux initié vers les autres VLANs.

#### Application Intranet

- **Frontend :** HTML5 / CSS3 — design "Terminal" immersif
- **Backend :** PHP natif sécurisé
- **Outils projet :** Trello (Kanban), Excalidraw (Schématisation)

--- 
### C. La Topologie Réseau 

| Zone | VLAN | CIDR | Passerelle | Plage IP | Services | Confiance |
|------|------|------|------------|----------|----------|-----------|
| **DMZ** | 10 | `192.168.10.0/28` | `192.168.10.1` | `.2 → .14` | Serveur Web Apache/PHP `.10`, Webterm `.11` | Faible |
| **Serveurs Internes** | 20 | `192.168.10.16/28` | `192.168.10.17` | `.18 → .30` | File Server `.20`, MariaDB `.21` | Moyen |
| **Postes Clients** | 30 | `192.168.10.128/25` | `192.168.10.129` | `.130 → .254` | Workstations agents Windows (DHCP `.130→.200`) | Standard |
| **Active Directory** | 40 | `192.168.10.32/29` | `192.168.10.33` | `.34 → .38` | Contrôleur de Domaine SRV-AD-01 / DNS `.34` | Critique |
| **Management & Sécurité** | 50 | `192.168.10.40/29` | `192.168.10.41` | `.42 → .46` | SIEM Wazuh `.42`, Admin réseau `.43` | Critique |
| **Backup & Restauration** | 60 | `192.168.10.48/29` | `192.168.10.49` | `.50 → .54` | NAS/Serveur Backup `.50` | Isolé |

Schéma de l'addressage IP 
![PlanIP](Images/schéma_et_addressage_ip.png)

---
### D. Segmentation Réseau & Règles pfSense

**Principe :** whitelist stricte par port/service — aucune règle `any to any`.

| Flux | Règle |
|------|-------|
| **LAN internes à Internet** | ALLOW sortant, logs vers Wazuh (VLAN 50) |
| **WAN entrant** | Ports 80/443 (NAT → `.10`) et 51820/UDP (WireGuard) uniquement. Tout le reste : BLOCK/DROP + log |
| **DMZ à VLANs internes** | BLOCK par défaut. Exception : Web (`.10`) vers MariaDB VLAN 20 port `:3306/TCP` et File Server VLAN 20 port `:445/TCP` |
| **VLAN 40 (Active Directory)** | Isolé de la DMZ. Accessible depuis VLAN 20, 30, 50 sur LDAP `:389`, LDAPS `:636`, DNS `:53` |
| **VLAN 50 (Wazuh)** | Collecte logs de tous VLANs en lecture seule (ports `:1514/1515`). Aucun flux entrant depuis DMZ |
| **VLAN 60 (Backup)** | Reçoit sauvegardes depuis VLAN 20 et 40 sur le port `:9102/TCP` uniquement. Aucun flux sortant (sauf logs Wazuh). Internet : BLOCK |

Vue de l'architecture réseau sur GNS3 :

![GNS3](Images/architecture.png)

---

## II. Sécurisation de l'Infrastructure

### A. Continuité d'Activité & Sauvegardes

- **Zone passive dédiée :** VLAN 60 — NAS sur `192.168.10.50`
- **Flux unidirectionnels :** VLAN 20 et 40 poussent vers VLAN 60 (`:9102/TCP`). Le backup n'initie aucune connexion sortante.
- **Protection anti-ransomware :** accès Internet depuis VLAN 60 bloqué. Un ransomware compromettant un serveur ne peut pas atteindre les sauvegardes.
- **Règle 3-2-1 :** base pour évoluer vers 3 copies, 2 supports différents, 1 hors-site.
- **Supervision :** logs du backup remontés vers Wazuh en lecture seule.

---

### B. Chiffrement des Flux Critiques

- **HTTPS strict :** application web uniquement via TLS (certificat auto-signé / autorité privée)
- **Database SSL/TLS :** connexion PHP ↔ MariaDB chiffrée via `PDO::MYSQL_ATTR_SSL_CA` (ca-cert.pem) — protection contre les attaques Man-in-the-Middle
- **Vérification active :** le dashboard affiche en temps réel le statut du chiffrement SQL (`Ssl_cipher`)

---

### C. VPN WireGuard — Deux Tunnels Distincts

**Protocole :** UDP, port `51820` sur l'interface WAN de pfSense  
**Plage VPN :** `10.10.10.0/24` — IP tunnel pfSense : `10.10.10.1`

| Tunnel | Accès | Profil |
|--------|-------|--------|
| **Administrateurs** | VLAN 40 (AD), VLAN 50 (Management), VLAN 60 (Backup) | Gestion pfSense, AD, Wazuh, sauvegardes — sans exposer RDP/SSH |
| **Développeurs** | VLAN 10 (DMZ — Web), VLAN 20 (Serveurs — MariaDB, File Server) | Déploiements et maintenance applicative |

> **Règle commune :** VLAN 30 (postes clients) inaccessible depuis les deux tunnels.  
> **Justification :** principe du moindre privilège — séparation stricte des profils d'accès.

---

### D. Gestion des Identités & Interopérabilité

- **Authentification centralisée :** utilisateurs gérés via Active Directory (`detechtive.local` — VLAN 40)
- **Interopérabilité PHP ↔ SMB :** l'application web ne stocke pas de fichiers localement — elle s'authentifie dynamiquement sur le File Server via `net use` pour monter les partages sécurisés uniquement le temps de la session

---

### E. Sécurité Applicative (AppSec)

- **Upload sécurisé :** whitelist d'extensions stricte (`jpg`, `png`, `pdf`, `docx`...), renommage forcé des fichiers, vérification de taille (max 5 Mo)
- **Protection SQL :** requêtes préparées (PDO) systématiques contre les injections SQL
- **Gestion d'erreurs :** mode silencieux en production, système de fallback si SSL échoue, alerte administrateur

---

## ⚙️ III. Reproduction de l'Environnement (GNS3)

> ℹ️ Ce projet est une simulation dans le cadre d'une certification. Le code source est donc privé.

Pour reproduire cet environnement sous GNS3 :

**1. Importer les appliances**
- pfSense, Windows Server 2022, Kali Linux, Webterm, NAS/Backup

**2. Configurer le switch IOU (L2 pur)**
```
no ip routing
! 6 VLANs (10, 20, 30, 40, 50, 60) + trunk dot1q vers pfSense sur eth0/0
! Ports inutilisés → VLAN 999 + shutdown
! VLAN 60 : eth2/0 et eth2/1 en mode access
```

**3. Configurer pfSense (Router-on-a-Stick)**

Créer 6 sous-interfaces VLAN :

| Sous-interface | IP Passerelle |
|----------------|--------------|
| VLAN 10 | `192.168.10.1` |
| VLAN 20 | `192.168.10.17` |
| VLAN 30 | `192.168.10.129` |
| VLAN 40 | `192.168.10.33` |
| VLAN 50 | `192.168.10.41` |
| VLAN 60 | `192.168.10.49` |

- VPN WireGuard : UDP `51820`, tunnel `10.10.10.0/24`
- Syslog : remote log server `192.168.10.42:514`, source `192.168.10.41`

**4. Déployer les règles pfSense par interface VLAN**
- WAN → NAT HTTP/HTTPS vers `192.168.10.10` (Web DMZ)
- DMZ → VLAN 20 : `:3306/TCP` (MariaDB) et `:445/TCP` (SMB) uniquement
- DMZ → VLAN 40/50/60 : BLOCK
- VLAN 30 → VLAN 40 : LDAP `:389`, LDAPS `:636`, DNS `:53` uniquement
- VLAN 30 → VLAN 60 : BLOCK
- VLAN 20 et 40 → VLAN 60 : `:9102/TCP` uniquement (backup unidirectionnel)
- VLAN 60 → Tous VLANs : BLOCK (sauf logs Wazuh `:1514/1515`)
- VLAN 60 → Internet : BLOCK (anti-ransomware)
- Tous VLANs → Wazuh `192.168.10.42` : `:1514/1515` (lecture seule)
- LAN internes → Internet : ALLOW sortant + logs

**5. Initialiser Active Directory**
- Joindre les serveurs Web, BDD et FS au domaine `detechtive.local`

**6. Configurer les agents Wazuh**
- Sur chaque serveur : remontée des alertes vers `192.168.10.42` (VLAN 50)

**7. Déployer le NAS/Serveur Backup**
- Adresse : `192.168.10.50`
- Configurer les jobs de sauvegarde depuis VLAN 20 (Serveurs) et VLAN 40 (AD)

---

*Projet réalisé dans le cadre de la certification RNCP37680 niveau 6 — Administrateur d'Infrastructures Sécurisées.*
