pfsence routing et parefeu

création des VLANS
déclarer les vlans reçus du trunk IOU
pfSense reçoit un trunk 802.1q depuis eth0/0 de l'IOU (L2 pur). On crée 6 sous-interfaces logiques pour les VLANs 10, 20, 30, 40, 50 et 60. L'interface physique pfSense côté LAN (ex. em1) sert de parent pour tous.

Assignation et Adressage IP (Passerelles)
Configurer l'IP passerelle sur chaque interface VLAN 

Chaque VLAN obtient une interface virtuelle avec une IP fixe. Aucune route statique interne n'est nécessaire : pfSense connaît directement les sous-réseaux via ses sous-interfaces.

Configuration Intercae WAN 
Configurer l'accès Internet et la sortie NAT via l'interface WAN
L'interface WAN (em0) est le point d'entrée/sortie Internet. Elle obtient son IP via DHCP (box/opérateur) ou en IP fixe. C'est sur cette interface que pfSense applique le NAT Outbound et expose les services publics (serveur Web DMZ). La règle par défaut bloque tout trafic entrant non sollicité.

Création des Alias 
Regroupers les IPs et réseaux pour simplifier les règles 
Les Alias permettent de nommer les réseaux (DMZ_NET, SERVERS_NET…) et les hôtes critiques (WEBSERVER, DATABASE, WAZUH_SIEM…). Toutes les règles de pare-feu référenceront ces alias, rendant la config lisible et maintenable.

Règles Pare-Feu (Interface WAN)
Sécuriser le périmètre entrant depuis internet
La politique globale sur le WAN est de bloquer tout trafic entrant. On n'autorise que le strict nécessaire : le tunnel VPN WireGuard et les flux HTTP/HTTPS redirigés par le NAT vers la DMZ.

règles Pare-Feu  Inter-VLam
Appliquer la sécurité par interface VLAN
PAR DÉFAUT, PFSENSE BLOQUE TOUT (Implicit Deny). L'ordre est critique (first match wins) : PASS spécifiques → PASS Internet → BLOCK. Alias ALL_INTERNAL regroupe tous les sous-réseaux internes pour simplifier les règles de blocage.

Nat Outbound - Internet sélectif par VLAN
En mode Hybrid Outbound NAT, pfSense ne génère pas automatiquement de règles NAT pour chaque sous-interface VLAN. Il faut créer manuellement une règle par VLAN autorisé à sortir sur Internet.

VLAN 20 SERVERS : isolé — pas de NAT, les serveurs internes n'ont pas besoin d'Internet.
VLAN 60 BACKUP : isolé — pas de NAT, protection anti-ransomware absolue.

Des règles Port Forward (NAT entrant) exposent le Serveur Web DMZ (192.168.10.10) sur les ports 80 et 443 depuis Internet.

VPN WireGuard (Tunnels admin et dev)

Accès distant séparés sous le principe du moindre privilèges
Tunnel 1 (Admins) : Écoute sur UDP 51820. La plage 10.10.10.0/24 permet de gérer l'AD, le SIEM et pfSense. La DMZ et les WORKSTATIONS leur sont interdites.

Tunnel 2 (Devs) : Évolution pour les utilisateurs. Écoute sur UDP 51821 (10.10.20.0/24). Permet l'accès aux postes (RDP) et serveurs de dev, mais bloque strictement l'accès au pare-feu et au SIEM.

DHCP sur VLAN Workstations
distribuer automatiques les IPs aux postes clients 
pfSense active le DHCP sur l'interface VLAN 30. Le DNS pointe vers SRV-AD01 (192.168.10.34) pour la résolution interne du domaine Active Directory. La plage couvre les IPs .130 à .200.

Logs et Supervisions SIEM
Centraliser tous les logs firewall vers Wazuh
pfSense envoie ses logs syslog vers l'agent Wazuh (192.168.10.42:514). Toutes les règles BLOCK sont loggées. La console Wazuh reçoit les alertes en temps réel pour détecter les scans, tentatives d'intrusion et violations de politique.

Vérificatio et Tests finaux 
Toujours déboguer de la couche la plus basse vers la plus haute : d'abord pinger la passerelle locale, puis inter-VLAN, puis Internet. Si une passerelle ne répond pas → problème VM/switch. Si inter-VLAN échoue → vérifier règles pfSense.
