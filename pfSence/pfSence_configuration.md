# pfSense — Routage, Pare-feu & Services Réseau

Le pfSense est le cœur du réseau : il assure le routage inter-VLANs, le filtrage, le NAT et l'accès VPN.

---

## Table des matières

- Architecture réseau
- Création des VLANs
- Assignation & Adressage IP des interfaces
- Interface WAN — Accès Internet & NAT
- Alias — Simplification des règles
- Règles Pare-feu WAN
- Règles Pare-feu Inter-VLANs
- NAT Outbound — Sortie Internet sélective
- VPN WireGuard
- DHCP — VLAN Workstations
- Logs & Supervision SIEM
- Validation & Tests finaux


**Architecture réseau**

```
Internet
    │
   [em0] WAN
    │
 pfSense
    │
   [em1] LAN (trunk 802.1q)
    │
   IOU (L2)
    │
    ├── VLAN 10 — DMZ          192.168.10.8/29
    ├── VLAN 20 — Servers      192.168.10.32/29
    ├── VLAN 30 — Workstations 192.168.10.128/26
    ├── VLAN 40 — AD           192.168.10.32/29
    ├── VLAN 50 — MGMT         192.168.10.40/29
    └── VLAN 60 — Backup       192.168.10.48/29
```

Principe de sécurité appliqué : chaque VLAN est un segment isolé par défaut. Tout trafic inter-VLAN passe obligatoirement par pfSense, qui applique les règles de filtrage avant tout transit.

**Création des VLANs**

**Objectif :** Déclarer les VLANs reçus en trunk depuis l'IOU et créer les sous-interfaces logiques correspondantes sur pfSense.

Configuration :
- pfSense reçoit un trunk *802.1q* depuis `eth0/0` de l'IOU (commutateur L2 pur)
- L'interface physique LAN (`em1`) sert de parent pour toutes les sous-interfaces
- Six sous-interfaces logiques sont créées, une par VLAN

| VLAN | Nom logique | Usage |
|---|---|---|
| 10 | `em1.10` | DMZ — Serveur Web exposé |
| 20 | `em1.20` | Servers — Serveurs internes |
| 30 | `em1.30` | Workstations — Postes clients |
| 40 | `em1.40` | AD — Contrôleur de domaine |
| 50 | `em1.50` | MGMT — Supervision (Wazuh) |
| 60 | `em1.60` | Backup — Sauvegardes isolées |

**Impact :** Sans ces sous-interfaces, pfSense ne peut pas router entre les VLANs ni appliquer de règles de filtrage par segment. C'est la fondation sur laquelle repose toute la segmentation du projet.

**Assignation & Adressage IP des interfaces**

**Objectif :** Attribuer une IP fixe (passerelle) à chaque interface VLAN — cette IP est le point de sortie de chaque segment.

| Interface | VLAN | Réseau | IP Passerelle (pfSense) |
|---|---|---|---|
| `em1.10` | DMZ | `192.168.10.8/29` | `192.168.10.9` |
| `em1.20` | Servers | `192.168.10.16/29` | `192.168.10.17` |
| `em1.30` | Workstations | `192.168.10.128/26` | `192.168.10.129` |
| `em1.40` | AD | `192.168.10.32/29` | `192.168.10.33` |
| `em1.50` | MGMT | `192.168.10.40/29` | `192.168.10.41` |
| `em1.60` | Backup | `192.168.10.48/29` | `192.168.10.49` |

**Impact :** Aucune route statique interne n'est nécessaire, pfSense connaît directement tous les sous-réseaux via ses propres interfaces. Chaque machine du réseau doit avoir l'IP de son interface VLAN comme passerelle par défaut.

**Interface WAN — Accès Internet & NAT**

**Objectif :** Configurer le point d'entrée/sortie Internet et exposer le serveur Web de la DMZ.

Configuration :
- Interface WAN : `em0`
- Adresse IP : obtenue par DHCP depuis la box/opérateur (ou IP fixe selon l'environnement)
- NAT Outbound appliqué sur cette interface pour tous les VLANs autorisés à sortir
- Port Forwarding (NAT entrant) pour exposer le serveur Web (`192.168.10.10`) sur les ports 80 et 443
- La règle par défaut bloque tout trafic entrant non sollicité

**Impact :**
- Le WAN est la seule interface exposée à Internet — toutes les communications entrent et sortent par ce point unique
- Le NAT masque les adresses privées internes derrière l'IP publique du pfSense
- Le Port Forward permet d'exposer uniquement le serveur Web, sans ouvrir le reste du réseau

**Alias — Simplification des règles**

**Objectif :** Nommer les réseaux et hôtes critiques pour rendre les règles pare-feu lisibles et maintenables.

Alias de réseaux :

| Alias | Contenu | Usage |
|---|---|---|
| `DMZ_NET` | `192.168.10.8/29` | Règles vers/depuis la DMZ |
| `SERVERS_NET` | `192.168.10.16/29` | Règles vers/depuis les serveurs |
| `WORKSTATIONS_NET` | `192.168.10.128/26` | Règles vers/depuis les postes |
| `AD_NET` | `192.168.10.32/29` | Règles vers/depuis l'AD |
| `MGMT_NET` | `192.168.10.40/29` | Règles vers/depuis Wazuh |
| `BACKUP_NET` | `192.168.10.48/29` | Règles vers/depuis les backups |
| `ALL_INTERNAL` | Tous les sous-réseaux ci-dessus | Règles de blocage inter-VLAN global |

Alias d'hôtes :

| Alias | IP | Usage |
|---|---|---|
| `WEBSERVER` | `192.168.10.10` | Serveur Web DMZ |
| `DATABASE` | `192.168.10.18` | Serveur de base de données |
| `WAZUH_SIEM` | `192.168.10.42` | Collecteur Wazuh |
| `SRV_AD01` | `192.168.10.34` | Contrôleur de domaine |
| `SRV_FILE01` | `192.168.10.35` | Serveur de fichiers |

**Impact :** Sans alias, chaque règle contient des IPs brutes illisibles. Avec les alias, modifier une IP ne nécessite qu'un seul changement (dans l'alias) — toutes les règles qui l'utilisent sont mises à jour automatiquement.

**Règles Pare-feu WAN**

**Objectif :** Sécuriser le périmètre — bloquer tout trafic entrant non autorisé depuis Internet.

Politique globale : `BLOCK ALL` par défaut sur le WAN.

Exceptions autorisées :

| Règle | Port/Proto | Destination | Justification |
|---|---|---|---|
| PASS | UDP 51820 | pfSense (WAN) | Tunnel VPN WireGuard Admins |
| PASS | UDP 51821 | pfSense (WAN) | Tunnel VPN WireGuard Devs |
| PASS | TCP 80 | `WEBSERVER` (via NAT) | HTTP vers serveur Web DMZ |
| PASS | TCP 443 | `WEBSERVER` (via NAT) | HTTPS vers serveur Web DMZ |
| BLOCK | Any | Any | Politique par défaut |

**Impact :** La surface d'attaque exposée à Internet est réduite au strict minimum. Seuls les ports VPN et Web sont ouverts — tout le reste est silencieusement rejeté.

**Règles Pare-feu Inter-VLANs**

**Objectif :** Contrôler précisément les flux entre chaque segment réseau selon le principe du moindre privilège.

Règle fondamentale pfSense : par défaut, tout trafic est bloqué (Implicit Deny). L'ordre des règles est critique — la première règle qui correspond s'applique (`first match wins`). L'ordre à respecter : `PASS spécifiques -> PASS Internet -> BLOCK`.

**Matrice de flux autorisés**

| Source | Destination | Ports autorisés | Justification |
|---|---|---|---|
| `WORKSTATIONS_NET` | `AD_NET` | TCP 389, 636, 88, 445 | LDAP, Kerberos, SMB (jonction domaine) |
| `WORKSTATIONS_NET` | `SERVERS_NET` | TCP 445 | Accès partages fichiers |
| `WORKSTATIONS_NET` | `MGMT_NET` | TCP 1514, 1515 | Remontée logs agent Wazuh |
| `WORKSTATIONS_NET` | Internet | TCP 80, 443 | Navigation web |
| `WORKSTATIONS_NET` | `DMZ_NET` | ❌ BLOCK | Isolation DMZ |
| `WORKSTATIONS_NET` | `BACKUP_NET` | ❌ BLOCK | Protection sauvegardes |
| `SERVERS_NET` | `AD_NET` | TCP 389, 88 | Authentification AD |
| `SERVERS_NET` | `MGMT_NET` | TCP 1514, 1515 | Remontée logs Wazuh |
| `SERVERS_NET` | Internet | ❌ BLOCK | Isolation — pas de sortie Internet |
| `DMZ_NET` | `SERVERS_NET` | TCP 3306 | Web → DB (accès applicatif) |
| `DMZ_NET` | `AD_NET` | ❌ BLOCK | Isolation DMZ / AD |
| `DMZ_NET` | Internet | TCP 80, 443 | Mises à jour applicatives |
| `MGMT_NET` | `ALL_INTERNAL` | Any | Supervision totale Wazuh |
| `BACKUP_NET` | `ALL_INTERNAL` | ❌ BLOCK | Isolation totale anti-ransomware |
| VPN Admins | `AD_NET`, `MGMT_NET` | Any | Administration complète |
| VPN Admins | `DMZ_NET`, `WORKSTATIONS_NET` | ❌ BLOCK | Moindre privilège VPN admin |
| VPN Devs | `WORKSTATIONS_NET` | TCP 3389 | RDP postes de dev |
| VPN Devs | `MGMT_NET`, pfSense | ❌ BLOCK | Pas d'accès SIEM/firewall |

**Impact :** La segmentation par VLAN n'a de valeur que si les flux inter-segments sont strictement contrôlés. Ces règles garantissent qu'une compromission d'un segment (ex. DMZ) ne peut pas latéralement atteindre l'AD ou les sauvegardes.

**NAT Outbound — Sortie Internet sélective**

**Objectif :** Contrôler précisément quels VLANs peuvent accéder à Internet via le NAT.

Mode utilisé : `Hybrid Outbound NAT` — pfSense ne génère pas automatiquement de règles NAT pour les sous-interfaces VLAN. Chaque règle est créée manuellement.

Règles NAT Outbound :

| VLAN | NAT activé | Justification |
|---|---|---|
| VLAN 10 — DMZ | ✅ Oui | Le serveur Web a besoin d'Internet (mises à jour) |
| VLAN 20 — Servers | ❌ Non | Isolation totale — les serveurs internes n'ont pas besoin d'Internet |
| VLAN 30 — Workstations | ✅ Oui | Navigation web des utilisateurs |
| VLAN 40 — AD | ❌ Non | L'AD n'a pas besoin d'accès Internet direct |
| VLAN 50 — MGMT | ✅ Oui | Mises à jour Wazuh, threat intelligence |
| VLAN 60 — Backup | ❌ Non | Isolation absolue — protection anti-ransomware |

**Impact :** L'absence de NAT sur les VLANs Servers et Backup constitue une protection supplémentaire — même si une règle pare-feu était mal configurée, ces segments ne pourraient pas communiquer avec Internet.

**VPN WireGuard**

**Objectif :** Fournir un accès distant sécurisé et différencié selon le profil, en appliquant le principe du moindre privilège.

1. Tunnel Admins

| Paramètre | Valeur |
|---|---|
| Port d'écoute | UDP 51820 |
| Plage IP tunnel | `10.10.10.0/24` |
| Accès autorisé | AD (`AD_NET`), SIEM (`MGMT_NET`), pfSense |
| Accès refusé | DMZ, Workstations |

Usage : Administration du domaine AD, gestion du SIEM Wazuh et configuration pfSense depuis l'extérieur.

2. Tunnel Developpeurs

| Paramètre | Valeur |
|---|---|
| Port d'écoute | UDP 51821 |
| Plage IP tunnel | `10.10.20.0/24` |
| Accès autorisé | Workstations (RDP), serveurs de dev |
| Accès refusé | pfSense, SIEM (`MGMT_NET`), AD direct |

Usage : Accès RDP aux postes de développement sans visibilité sur l'infrastructure de sécurité.

**Impact :**
- Deux tunnels distincts évitent qu'un compte développeur compromis puisse atteindre l'AD ou le SIEM
- WireGuard offre de meilleures performances et une surface d'attaque réduite par rapport à OpenVPN
- L'authentification par clés cryptographiques remplace les mots de passe, éliminant les risques de brute force sur le VPN

**DHCP — VLAN Workstations**

**Objectif :** Distribuer automatiquement les adresses IP aux postes clients du VLAN 30.

Configuration du serveur DHCP sur l'interface VLAN 30 :

| Paramètre | Valeur |
|---|---|
| Plage DHCP | `192.168.10.130` → `192.168.10.200` |
| Passerelle distribuée | `192.168.10.129` (pfSense VLAN 30) |
| DNS distribué | `192.168.10.34` (SRV-AD01) |
| Durée du bail | 8 heures |

**Impact :**
- Le DNS pointant vers `SRV-AD01` garantit que les postes peuvent résoudre `detechtive.local` dès leur démarrage — condition indispensable à la jonction au domaine et à l'authentification Kerberos
- La plage `.130` → `.200` laisse les adresses basses disponibles pour des IP statiques futures (imprimantes, etc.)
- pfSense centralise le DHCP, permettant de consulter les baux actifs et d'identifier facilement les machines par leur MAC

**Logs & Supervision SIEM**

**Objectif :** Centraliser tous les logs du pare-feu vers Wazuh pour une détection et une corrélation en temps réel.

Configuration :
- pfSense envoie ses logs via Syslog vers `192.168.10.42:514` (agent Wazuh, VLAN 50 MGMT)
- Toutes les règles `BLOCK` sont loggées (les règles `PASS` peuvent l'être sélectivement)

Flux de collecte :

```
pfSense (toutes interfaces)
    │
    └── Syslog UDP/TCP 514
            │
            └── Wazuh Agent (192.168.10.42 — VLAN 50 MGMT)
                    │
                    └── Wazuh Manager → Corrélation & Alerting temps réel
```

Quelques événements détectés via les règles Wazuh :

| Règle Wazuh | Événement pfSense |
|---|---|
| `100601` | Trafic bloqué depuis Kali vers VLAN 10 (Servers) |
| `100602` | Scan de ports détecté (SYN Scan, Nmap) |
| `100700` | Brute force sur l'interface web pfSense |
| `100703` | Scan de ports intensif → blocage automatique |

**Impact :**
- Sans logs Syslog, pfSense est une boîte noire — aucune visibilité sur les tentatives d'intrusion ou les violations de politique
- La corrélation avec les logs AD et système permet de reconstituer une kill chain complète (scan → exploitation → mouvement latéral)
- Les règles de réponse active Wazuh peuvent bloquer automatiquement des IPs via pfSense à la suite d'une détection

**Validation & Tests finaux**

Méthodologie : Toujours déboguer de la couche la plus basse vers la plus haute.

- Couche physique/VM -> Passerelle locale -> Inter-VLAN -> Internet ->  Services applicatifs
```

**Tests par étape :**

| Étape | Test | Résultat attendu |
|---|---|---|
| 1. Connectivité locale | `ping` passerelle du VLAN | Réponse de l'interface pfSense |
| 2. Routage inter-VLAN | `ping` depuis WORKSTATION vers SRV-AD01 | Réponse si règle PASS active |
| 3. Blocage inter-VLAN | `ping` depuis WORKSTATION vers BACKUP_NET | Timeout (règle BLOCK) |
| 4. Sortie Internet | `ping 8.8.8.8` depuis WORKSTATION | Réponse (NAT actif) |
| 5. DNS | `nslookup detechtive.local` depuis un poste | Résolution via SRV-AD01 |
| 6. VPN | Connexion WireGuard + ping vers AD_NET | Tunnel établi, accès OK |
| 7. Logs Wazuh | Générer un BLOCK → vérifier l'alerte | Alerte visible dans Wazuh |
```

**Références Utilisées**

| Composant | Standard / Documentation |
|---|---|
| Segmentation VLAN | IEEE 802.1q |
| Politique de filtrage | Principe du moindre privilège (Zero Trust Network) |
| VPN | WireGuard — [wireguard.com](https://www.wireguard.com) |
| Intégration SIEM | Wazuh pfSense integration — [documentation Wazuh](https://documentation.wazuh.com) |
| Règles de détection | Voir `wazuh-rules-documentation.md` |
