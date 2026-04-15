# Wazuh — Règles de Détection & Configuration

Documentation des règles SIEM.
La configuration est appliquée via l'interface graphique Wazuh dans le fichier `local_rules.xml`.

**Table des matières**

- Vue d'ensemble des règles
- Active Directory & Windows
- Sécurité Système — LSASS
- Base de données
- File Server
- Web Server & Attaques Applicatives
- Réseau & pfSense
- File Integrity Monitoring (FIM)
- Réponse Active — Blocage automatique

---

## Vue d'ensemble des règles

| Catégorie | ID Règle | Niveau | Menace ciblée |
|---|---|---|---|
| Active Directory | 100100 | 15 | Ajout d'un membre dans "Domain Admins" |
| Active Directory | 100101 | 15 | Attaque DCSync (réplication suspecte) |
| Active Directory | 100102 | 15 | Ajout d'utilisateur dans un groupe Admin |
| Sécurité Système | 100200 | 15 | Dump mémoire LSASS (via Sysmon) |
| Sécurité Système | 100201 | 15 | Exécution de commande via LSASS |
| Ransomware | 100300 | 15 | Suppression des Shadow Copies |
| Ransomware | 100301 | 13 | Suppression massive de fichiers sur FileServer |
| Database | 100400 | 14 | Dump de base de données (extraction) |
| Database | 100401 | 12 | Brute Force SQL (5 échecs / 120s) |
| Web Server | 100500 | 15 | Exécution de Webshell (cmd.exe, bash) |
| Web Server | 100501 | 12 | Tentative d'injection SQL |
| Reconnaissance | 100600 | 13 | Détection d'outils de scan (Nmap, Masscan) |
| Mouvement Latéral | 100601 | 12 | Blocage pfSense inter-VLANs |
| Mouvement Latéral | 100602 | 10 | Scan de ports |
| Brute Force pfSense | 100700 | 12 | Échecs répétés sur l'interface web pfSense |


## Active Directory & Windows

**Objectif :** Surveiller les modifications de privilèges et les activités suspectes sur l'Active Directory.

```xml
<group name="windows,ad,security">

  <!-- Ajout dans Domain Admins -->
  <rule id="100100" level="15">
    <if_sid>60103</if_sid>
    <field name="win.eventdata.TargetUserName">Domain Admins</field>
    <description>CRITICAL - Utilisateur ajouté au groupe Domain Admins</description>
    <mitre>
      <id>T1098</id>
    </mitre>
  </rule>

  <!-- Attaque DCSync -->
  <rule id="100101" level="15">
    <if_sid>60102</if_sid>
    <match>Replicating Directory Changes</match>
    <description>CRITICAL - Tentative d'attaque DCSync (réplication AD non autorisée)</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

  <!-- Ajout dans un groupe Admin générique -->
  <rule id="100102" level="15">
    <if_sid>60103</if_sid>
    <regex type="pcre2">TargetUserName=(Administrators)</regex>
    <description>CRITICAL - Utilisateur ajouté à un groupe AD sensible</description>
    <mitre>
      <id>T1098</id>
    </mitre>
  </rule>

</group>
```

**Événements Windows surveillés :**
- `60103` → Modification de groupe (Event ID 4728/4732)
- `60102` → Audit d'accès aux objets AD (réplication)


## Sécurité Système — LSASS

**Objectif :** Détecter les tentatives de dump de mémoire LSASS pour extraction de credentials (via Sysmon Event ID 10).

```xml
<group name="windows,lsass,security">

  <!-- Accès direct à LSASS -->
  <rule id="100200" level="15">
    <if_sid>61612</if_sid>
    <field name="win.eventdata.TargetImage">C:\\Windows\\System32\\lsass.exe</field>
    <description>CRITICAL - Accès suspect au processus LSASS (tentative de dump)</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

  <!-- Accès LSASS depuis un processus parent inhabituel -->
  <rule id="100201" level="15">
    <if_sid>61612</if_sid>
    <field name="win.eventdata.TargetImage">C:\\Windows\\System32\\lsass.exe</field>
    <regex type="pcre2">ParentImage=(?:.*\\cmd\.exe|.*\\powershell\.exe|.*\\wscript\.exe)</regex>
    <description>CRITICAL - Accès à LSASS depuis un processus parent inhabituel</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

</group>
```

**Note :** Ces règles nécessitent que *Sysmon* soit installé et configuré sur les hôtes Windows cibles. L'ID parent `61612` correspond à l'événement Sysmon de type *ProcessAccess*.

---

## Base de données

**Objectif :** Surveiller les exports de données, les requêtes dangereuses et les attaques brute force.

```xml
<group name="database,security">

  <!-- Dump de base de données -->
  <rule id="100400" level="14">
    <match>mysqldump|pg_dump|BACKUP DATABASE</match>
    <description>HIGH - Export de base de données détecté (dump)</description>
    <mitre>
      <id>T1005</id>
    </mitre>
  </rule>

  <!-- Brute force sur la DB -->
  <rule id="100401" level="12" frequency="5" timeframe="120">
    <if_matched_sid>501</if_matched_sid>
    <same_source_ip />
    <description>HIGH - Attaque brute force sur la base de données (5 échecs / 120s)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- Requête SQL dangereuse (exfiltration potentielle) -->
  <rule id="100403" level="14">
    <match>LOAD_FILE|INTO OUTFILE|INTO DUMPFILE|UNION SELECT</match>
    <description>HIGH - Requête SQL dangereuse détectée (exfiltration possible)</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

</group>
```

## File Server

**Objectif :** Détecter la destruction des sauvegardes (Shadow Copies) et les suppressions massives de fichiers caractéristiques d'un ransomware.

```xml
<group name="windows,fileserver,ransomware">

  <!-- Suppression des Shadow Copies -->
  <rule id="100300" level="15">
    <match>vssadmin delete shadows|wmic shadowcopy delete</match>
    <description>CRITICAL - Suppression des Shadow Copies (comportement ransomware)</description>
    <mitre>
      <id>T1490</id>
    </mitre>
  </rule>

  <!-- Suppression massive de fichiers -->
  <rule id="100301" level="13" frequency="10" timeframe="60">
    <match>del /s|Remove-Item</match>
    <description>HIGH - Suppression massive de fichiers détectée (10 occurrences / 60s)</description>
    <mitre>
      <id>T1485</id>
    </mitre>
  </rule>

</group>
```

## Web Server & Attaques Applicatives

**Objectif :** Détecter les webshells, les injections SQL et les tentatives d'exécution de code distant (RCE).

```xml
<group name="web,attack">

  <!-- Webshell — exécution de shell système -->
  <rule id="100500" level="15">
    <match>cmd.exe|powershell.exe|/bin/bash|/bin/sh</match>
    <description>CRITICAL - Webshell suspect détecté sur le serveur web</description>
    <mitre>
      <id>T1505</id>
    </mitre>
  </rule>

  <!-- Injection SQL -->
  <rule id="100501" level="12">
    <match>union select|or 1=1|sleep\(|benchmark\(|xp_cmdshell</match>
    <description>HIGH - Tentative d'injection SQL détectée</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

</group>
```

**Randsomware couverts :**
- Webshell (exécution de `cmd.exe` / `bash` via le serveur web)
- Injection SQL (UNION-based, Boolean-based, Time-based)
- Upload malveillant (à compléter via règles FIM sur `C:\inetpub\`)

## Réseau pfSense

**Objectif :** Détecter les mouvements latéraux inter-VLANs et les tentatives de brute force sur pfSense.

> **Prérequis :** pfSense doit être configuré pour envoyer ses logs de blocage à Wazuh via **Syslog** (UDP/514 ou TCP/514).

```xml
<group name="network,firewall,pfsense">

  <!-- Trafic bloqué inter-VLAN depuis Kali -->
  <rule id="100601" level="12">
    <if_sid>60000</if_sid>
    <match>BLOCK</match>
    <field name="source.ip">IP_KALI</field>
    <field name="destination.vlan">10</field>
    <description>HIGH - Trafic bloqué de Kali vers le VLAN Serveurs (VLAN 10)</description>
    <mitre>
      <id>T1048</id>
    </mitre>
  </rule>

  <!-- Scan de ports -->
  <rule id="100602" level="10" frequency="20" timeframe="60">
    <match>portscan|SYN Scan|Nmap</match>
    <description>MEDIUM - Scan de ports détecté sur le réseau (20 événements / 60s)</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <!-- Détection d'outils de reconnaissance -->
  <rule id="100600" level="13">
    <match>nmap|masscan|zmap</match>
    <description>HIGH - Outil de scan réseau détecté (Nmap / Masscan)</description>
    <mitre>
      <id>T1595</id>
    </mitre>
  </rule>

  <!-- Brute force sur l'interface web pfSense -->
  <rule id="100700" level="12" frequency="5" timeframe="120">
    <if_matched_sid>5402</if_matched_sid>
    <match>webConfigurator authentication error</match>
    <same_source_ip />
    <description>HIGH - Tentative de brute force sur l'interface de gestion pfSense</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

</group>
```

## File Integrity Monitoring (FIM)

**Objectif :** Surveiller en temps réel les modifications sur les répertoires sensibles du système.

Ne pas surveiller tout `System32` — cela génère trop de bruit et impacte les performances. Cibler uniquement les sous-répertoires critiques.

```xml
<syscheck>
  <!-- Fichiers hosts et configuration réseau -->
  <directories realtime="yes" check_all="yes">C:\Windows\System32\drivers\etc</directories>

  <!-- Ruche de registre et fichiers SAM -->
  <directories realtime="yes" check_all="yes">C:\Windows\System32\config\</directories>

  <!-- Répertoire du serveur web IIS -->
  <directories realtime="yes" check_all="yes">C:\inetpub\</directories>

  <!-- Exclusions : fichiers temporaires, logs, sauvegardes -->
  <ignore type="sregex">\.tmp$|\.log$|\.bak$</ignore>
</syscheck>
```

**Répertoires surveillés :**

| Répertoire | Raison |
|---|---|
| `System32\drivers\etc` | Fichier `hosts` (détection de DNS hijacking) |
| `System32\config\` | Fichiers SAM / SYSTEM (credentials locaux) |
| `C:\inetpub\` | Détection d'upload de webshell |


## Réponse Active — Blocage automatique

**Architecture**

```
Wazuh Manager
    │
    ├── Détection d'alerte (règle déclenchante)
    │
    └── Active Response → block_ip.sh → SSH vers pfSense → pfctl
```

**Script de blocage (`/var/ossec/active-response/bin/block_ip.sh`)**

```bash
#!/bin/bash
LOCAL=$(dirname $0)
IP=$1

# Blocage de l'IP via pfSense
ssh admin@IP_PFSENSE "pfctl -t blocked_ips -T add $IP"
logger -t wazuh "IP bloquée : $IP"
```

**Prérequis :** Configurer une clé SSH sans mot de passe entre le Wazuh Manager et pfSense.

**Configuration Wazuh (`/var/ossec/etc/ossec.conf`)**

```xml
<ossec_config>

  <!-- Définition de la commande de blocage -->
  <command>
    <name>block_ip</name>
    <executable>/var/ossec/active-response/bin/block_ip.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Brute force SSH → blocage 10 minutes -->
  <active-response>
    <command>block_ip</command>
    <location>local</location>
    <rules_id>100700</rules_id>
    <timeout>600</timeout>
  </active-response>

  <!-- Brute force DB → blocage 30 minutes -->
  <active-response>
    <command>block_ip</command>
    <location>local</location>
    <rules_id>100701</rules_id>
    <timeout>1800</timeout>
  </active-response>

  <!-- Comportement ransomware → blocage 1 heure -->
  <active-response>
    <command>block_ip</command>
    <location>local</location>
    <rules_id>100702</rules_id>
    <timeout>3600</timeout>
  </active-response>

  <!-- Scan de ports intensif → blocage 1 heure -->
  <active-response>
    <command>block_ip</command>
    <location>local</location>
    <rules_id>100703</rules_id>
    <timeout>3600</timeout>
  </active-response>

  <!-- Dump LSASS → isolation immédiate (sans timeout) -->
  <active-response>
    <command>block_ip</command>
    <location>local</location>
    <rules_id>100200</rules_id>
    <timeout>0</timeout>
  </active-response>

</ossec_config>
```

**Règles de déclenchement pour la réponse active**

```xml
<group name="active-response,blocking">

  <!-- Brute force SSH (5 échecs / 60s depuis la même IP) -->
  <rule id="100700" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip />
    <description>HIGH - 5 échecs de connexion SSH depuis la même IP (possible brute force)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- Brute force base de données (5 échecs / 120s) -->
  <rule id="100701" level="12" frequency="5" timeframe="120">
    <if_matched_sid>501</if_matched_sid>
    <same_source_ip />
    <description>HIGH - 5 échecs de connexion à la base de données depuis la même IP</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- Comportement ransomware répété (suppression massive × 3 / 30s) -->
  <rule id="100702" level="15" frequency="3" timeframe="30">
    <if_matched_sid>100301</if_matched_sid>
    <same_source_ip />
    <description>CRITICAL - Suppression massive de fichiers répétée (ransomware confirmé)</description>
    <mitre>
      <id>T1485</id>
    </mitre>
  </rule>

  <!-- Scan de ports intensif (15 événements / 30s) -->
  <rule id="100703" level="10" frequency="15" timeframe="30">
    <if_matched_sid>100602</if_matched_sid>
    <same_source_ip />
    <description>ATTACK - Scan de ports intensif détecté : blocage immédiat</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <!-- Webshell détecté → blocage IP source -->
  <rule id="100704" level="15">
    <if_sid>100500</if_sid>
    <description>CRITICAL - Exécution de webshell confirmée : blocage de l'IP source</description>
    <mitre>
      <id>T1505</id>
    </mitre>
  </rule>

</group>
```

**Récapitulatif des réponses actives**

| Règle déclenchante | Menace | Durée de blocage |
|---|---|---|
| 100700 | Brute force SSH | 10 minutes |
| 100701 | Brute force DB | 30 minutes |
| 100702 | Ransomware | 1 heure |
| 100703 | Scan de ports intensif | 1 heure |
| 100200 | Dump LSASS | Permanent (timeout = 0) |


## Références MITRE ATT&CK

| Technique | ID | Description |
|---|---|---|
| Account Manipulation | T1098 | Ajout dans groupes privilégiés |
| OS Credential Dumping | T1003 | DCSync, dump LSASS |
| Brute Force | T1110 | SSH, DB, pfSense |
| Data from Local System | T1005 | Dump de base de données |
| Inhibit System Recovery | T1490 | Suppression Shadow Copies |
| Data Destruction | T1485 | Suppression massive de fichiers |
| Server Software Component | T1505 | Webshell |
| Exploit Public-Facing App | T1190 | SQLi, RCE |
| Network Service Discovery | T1046 | Scan de ports |
| Active Scanning | T1595 | Nmap, Masscan |
| Exfiltration Over C2 | T1048 | Trafic inter-VLAN suspect |
