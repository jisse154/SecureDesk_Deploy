# SecureDesk

**SecureDesk** déploie, avec un assistant, un accès bureau à distance sécurisé entre :

- le **PC du bureau** (Windows 11 Pro, allumé en permanence), appelé ici le **serveur** ;
- votre **PC personnel** (Windows 11), appelé ici le **client**.

Chaque connexion franchit trois protections successives :

| Protection | Rôle |
|---|---|
| **Tunnel WireGuard** (clés + clé pré-partagée) | Seul le port UDP du tunnel est exposé sur Internet. Sans la clé privée du PC client, rien d'autre ne répond. |
| **Mot de passe Windows** (NLA) | Chaque utilisateur a son propre compte Windows et sa propre session. |
| **Code TOTP** (multiOTP, hors ligne) | Code à 6 chiffres de votre application d'authentification, exigé à chaque ouverture de session à distance. |

**TSplus Remote Access** permet à deux utilisateurs de travailler en même temps sur le PC serveur, chacun dans sa session, sans contourner la licence Microsoft.

> Modèle de menace, limites et choix de sécurité : [`docs/SECURITY.md`](docs/SECURITY.md).
> Tests à faire sur vos vrais PC : [`docs/RECETTE.md`](docs/RECETTE.md).
> Conception détaillée : [`docs/PLAN.md`](docs/PLAN.md).

---

## Sommaire

1. [Prérequis](#1-prérequis)
2. [Télécharger et vérifier SecureDesk](#2-télécharger-et-vérifier-securedesk)
3. [Étape 1 — Serveur](#3-étape-1--serveur-pc-du-bureau)
4. [Étape 2 — Box Internet](#4-étape-2--box-internet)
5. [Étape 3 — Client](#5-étape-3--client-pc-personnel)
6. [Étape 4 — Double authentification (2FA)](#6-étape-4--double-authentification-2fa)
7. [Utilisation quotidienne](#7-utilisation-quotidienne)
8. [Maintenance : pairs, clés, réappairage](#8-maintenance--pairs-clés-réappairage)
9. [Ligne de commande et fichier de configuration](#9-ligne-de-commande-et-fichier-de-configuration)
10. [Dépannage](#10-dépannage)
11. [Récupération en cas de verrouillage](#11-récupération-en-cas-de-verrouillage-2fa)
12. [Désinstallation](#12-désinstallation)
13. [Ce qui est automatisé, ce qui reste manuel](#13-ce-qui-est-automatisé-ce-qui-reste-manuel)
14. [Développement](#14-développement)

---

## 1. Prérequis

| Élément | Détail |
|---|---|
| PC serveur | **Windows 11 Pro** (l'édition Famille ne peut pas recevoir de connexions Bureau à distance), allumé en permanence. 8 Go de RAM recommandés pour deux sessions. |
| PC client | Windows 11, Famille ou Pro. |
| **Licence TSplus Remote Access** | À **acheter séparément** auprès de TSplus. Gardez l'installeur (`Setup-TSplus.exe`) et la clé de licence. SecureDesk ne télécharge pas TSplus et n'active jamais la licence. |
| Box Internet | Accès administrateur pour rediriger **un** port UDP. |
| Adresse publique | IP fixe, ou nom **DDNS** si l'IP du bureau change (ex. `monbureau.ddns.net`). |
| Téléphone | Application TOTP standard : Google Authenticator, Microsoft Authenticator, Aegis… |
| Clé USB | Pour transporter les fichiers d'appairage. |
| Accès console | Vous devez pouvoir vous asseoir devant le PC serveur pour l'étape 2FA. |
| Fonctionnalité Windows **VBScript** (PC serveur) | Le MSI multiOTP exécute une action personnalisée VBScript. Elle est présente par défaut sur Windows 11 24H2 (Paramètres → Système → Fonctionnalités facultatives). Microsoft prévoit de la retirer progressivement : SecureDesk vérifie sa présence avant d'installer multiOTP. |
| **BitLocker (fortement recommandé)** | Sur les deux PC. Conservez les clés de récupération **hors** des PC. |

Sans accès Internet, prévoyez aussi les installeurs officiels (mode hors ligne) :

- le MSI de WireGuard (`wireguard-amd64-x.y.z.msi`, sur download.wireguard.com) ;
- le MSI de multiOTP Credential Provider (download.multiotp.net) ;
- le Visual C++ Redistributable x64 (`vc_redist.x64.exe`).

---

## 2. Télécharger et vérifier SecureDesk

1. Dans les **Releases** du dépôt, téléchargez `SecureDesk.exe` et `SHA256SUMS`.
2. Vérifiez l'empreinte dans PowerShell :
   ```powershell
   (Get-FileHash .\SecureDesk.exe -Algorithm SHA256).Hash.ToLower()
   ```
   Le résultat doit être **identique** à la ligne `SecureDesk.exe` de `SHA256SUMS`.
3. **Avertissement SmartScreen.** Si la release n'est pas signée par un certificat Authenticode, Windows affiche « Windows a protégé votre ordinateur ». Après avoir vérifié l'empreinte (étape 2), cliquez sur **Informations complémentaires**, puis **Exécuter quand même**. Si la release est signée, l'éditeur apparaît dans **Propriétés → Signatures numériques**.

SecureDesk demande toujours les droits administrateur. Il les exige pour configurer le pare-feu, les services, le registre et les comptes.

---

## 3. Étape 1 — Serveur (PC du bureau)

Ouvrez une session **à la console** (physiquement devant le PC) avec un compte administrateur, puis double-cliquez sur `SecureDesk.exe` et choisissez **SERVEUR**.

| Page de l'assistant | Ce qu'elle fait |
|---|---|
| 1. Pré-vérifications | Vérifie l'édition Windows, les droits, un éventuel redémarrage en attente, la RAM et le CPU, TSplus, l'IP du LAN, le type de session (locale ou distante) et l'heure. |
| 2. Réseau et tunnel | Saisie de l'adresse publique (IP ou DDNS). Un **port UDP aléatoire** est proposé. Saisie du sous-réseau du tunnel (`10.77.0.0/24` par défaut) et choix d'autoriser ou non l'accès depuis le LAN. |
| 3. TSplus | Détecte TSplus et affiche la procédure d'installation et d'activation de la licence. L'installation silencieuse (`/verysilent`, documentée par TSplus) est possible en option. **Redémarrez** après l'installation de TSplus. |
| 4. Comptes | Deux comptes Windows distincts, à créer ou à choisir parmi les existants, avec la politique de mot de passe et le verrouillage après N échecs. |
| 5. Sécurité RDP | Redirections (presse-papiers, lecteurs, imprimantes), **désactivées par défaut**. Délais avant fermeture des sessions inactives et des sessions déconnectées. |
| 6. Déploiement | Installe WireGuard, crée le tunnel, les règles de pare-feu, les comptes et le durcissement, puis exporte **`pairing-server.sdpair`** (chiffré). |
| 7. Ajout du PC client | Importe `pairing-client.sdpair` (après l'étape 3). |
| 8. Box et rapport | Affiche la checklist de la box et le rapport final. |

### Le fichier d'appairage serveur

- Il est **chiffré** (AES-256-GCM) par une phrase de passe : l'assistant en **propose** une, ou vous saisissez la vôtre (14 caractères minimum). **Notez-la sur papier.**
- Il contient la clé pré-partagée du tunnel : **copiez-le sur une clé USB**, jamais par e-mail ni par messagerie.
- Communiquez la phrase de passe par un autre canal (papier, oral).
- Il expire au bout de 7 jours.
- **L'empreinte** de la clé du serveur (ex. `3F2A-91C4-…`) s'affiche à l'écran. Vous la comparerez sur le client.

### Réglages TSplus à faire dans l'AdminTool

L'assistant les rappelle :

- **Sessions → Permissions** : laissez « Allow access from Microsoft RDP client for everyone » (SecureDesk utilise `mstsc`).
- **Sessions → Permissions** : cochez « **Deny access from Outside** ». Seules les IP privées sont alors acceptées, et le tunnel en fait partie.
- **N'activez pas** le module Two-Factor Authentication de TSplus.
- Le **portail web TSplus n'est pas utilisé**. SecureDesk arrête son serveur web (`AdminTool.exe /webstop`) et bloque les ports 80 et 443 hors tunnel. **TSplus achemine aussi RDP par ces ports**, d'où ce blocage.

---

## 4. Étape 2 — Box Internet

Le rapport de la page 8 (ou `SecureDesk.exe report`) liste les réglages exacts :

1. **Redirection de port** : **UDP `<port choisi>`** vers **l'IP LAN du PC serveur**, même port. **Aucune autre redirection.**
2. Ne redirigez **jamais** 3389, 80 ou 443, et n'activez pas de « DMZ » vers ce PC. Désactivez l'UPnP si possible.
3. **Réservation DHCP** : fixez l'IP LAN du PC serveur (bail statique), sinon la redirection cassera au prochain changement d'adresse.
4. **DDNS** : si l'IP publique change, configurez le nom DDNS dans la box ou dans un client DDNS.

---

## 5. Étape 3 — Client (PC personnel)

1. Branchez la clé USB, lancez `SecureDesk.exe` et choisissez **CLIENT**.
2. **Pré-vérifications.** Si BitLocker est inactif, une alerte s'affiche : il protège la clé privée WireGuard en cas de vol du PC.
3. **Appairage.**
   1. Importez `pairing-server.sdpair` et saisissez la phrase de passe.
   2. **Comparez l'empreinte** affichée avec celle du serveur.
   3. Choisissez le démarrage du tunnel :
      - **automatique** : un service Windows démarre le tunnel avec le PC ;
      - **manuel** (par défaut) : la configuration est confiée au gestionnaire WireGuard, qui la **chiffre** (DPAPI). Vous activez le tunnel depuis l'icône WireGuard, dans la barre des tâches.
   4. Les clés du client sont **générées sur ce PC**. La clé privée n'en sort jamais.
   5. Enregistrez **`pairing-client.sdpair`** sur la clé USB. Il ne contient que la clé publique, authentifiée par la clé pré-partagée.
4. Un raccourci **« Bureau SecureDesk.rdp »** est créé sur le bureau, sans mot de passe enregistré.

Retournez au **serveur**, page **7. Ajout du PC client**, et importez `pairing-client.sdpair`. Le tunnel redémarre et le premier handshake s'affiche.

De retour sur le client, page **3. Test et raccourci** : le tunnel, le ping et le port RDP doivent être au vert. **Testez une vraie connexion RDP** avant de passer au 2FA. Supprimez ensuite les fichiers `.sdpair` de la clé USB.

---

## 6. Étape 4 — Double authentification (2FA)

À faire **en dernier**, **à la console du PC serveur**, une fois le tunnel et le RDP validés. Page **9. Double authentification** :

1. **Installer multiOTP.**
   - Le Credential Provider officiel est installé en mode **local uniquement**, sans aucun serveur ni service cloud.
   - Il est installé **désactivé** : rien ne change tant que l'activation n'a pas réussi.
   - Les signatures et la configuration sont vérifiées.
2. **Enrôler chaque compte**, au minimum **un compte administrateur** et **tous** les comptes autorisés en RDP.
   1. Le QR code s'affiche **une seule fois**. Scannez-le avec votre application.
   2. Saisissez le code affiché : il est vérifié **avant** toute activation.
   3. Des **codes de secours à usage unique** s'affichent (fonction native de multiOTP). **Imprimez-les ou notez-les** et gardez-les hors du PC.
   4. Aucun QR code ni aucune graine n'est écrit sur le disque ou dans un journal.
3. **Choisir la portée** :
   - **Distant seulement** (recommandé) : TOTP exigé pour toute connexion Bureau à distance, **ouverture de session à la console inchangée** ;
   - **Distant et local** : TOTP exigé aussi à la console.
4. **Activer (probatoire)**. SecureDesk **refuse** l'activation dans les cas suivants :
   - SecureDesk est lancé depuis une session à distance (sauf avec `--i-have-console-access`) ;
   - aucun administrateur n'est enrôlé et vérifié ;
   - un compte RDP n'est pas enrôlé ;
   - l'horloge dérive de plus de 30 s.

   Une **tâche de secours** désactivera automatiquement le 2FA au bout de **20 minutes** si vous ne confirmez pas.
5. **Tester depuis le PC client** : mot de passe dans mstsc, puis **code TOTP** à l'écran. Pour la première connexion, attendez le code suivant celui utilisé à l'enrôlement.
6. **Confirmer** (`confirm-2fa`) : le 2FA devient permanent.

---

## 7. Utilisation quotidienne

1. Activez le tunnel s'il est en démarrage manuel (icône WireGuard → Activer).
2. Double-cliquez sur **« Bureau SecureDesk.rdp »**.
3. Saisissez votre compte (`NOM-DU-PC\utilisateur`) et votre mot de passe, puis le **code TOTP**.

Un deuxième utilisateur peut travailler en même temps, sur place ou à distance, avec **son propre compte**. Une connexion RDP depuis le LAN compte comme distante et demande aussi le code.

---

## 8. Maintenance : pairs, clés, réappairage

| Besoin | Commande (sur le serveur sauf mention) |
|---|---|
| Ajouter un autre PC client | `SecureDesk.exe invite --name portable --out E:\` puis `join` sur ce PC, puis `add-peer` |
| Lister les pairs et le dernier handshake | `SecureDesk.exe list-peers` |
| Révoquer un PC (perdu, volé) | `SecureDesk.exe revoke-peer pc-perso` |
| Renouveler la clé pré-partagée d'un pair | `SecureDesk.exe rotate-keys --peer pc-perso --out E:\` puis `join` sur le client, puis `add-peer` |
| Renouveler les clés du serveur | `SecureDesk.exe rotate-keys --server --out E:\` (chaque client refait `join`, puis `add-peer`) |
| **Réappairer un client réinstallé** (moins de 10 min) | Serveur : `revoke-peer pc-perso` puis `invite --name pc-perso --out E:\`. Client : `join E:\pairing-server.sdpair`. Serveur : `add-peer E:\pairing-client.sdpair`. |
| Enrôler à nouveau un utilisateur (nouveau téléphone) | `SecureDesk.exe enroll-user alice`, à la console |

---

## 9. Ligne de commande et fichier de configuration

```text
SecureDesk.exe --help
SecureDesk.exe <commande> [argument] [--config fichier.json] [--dry-run] [--yes] [--verbose]
```

- `--dry-run` liste **toutes** les actions (« à faire » ou « déjà conforme ») sans rien modifier.
- Le fichier JSON contient tous les paramètres de l'assistant. Exemple : [`securedesk.example.json`](securedesk.example.json). **Il ne contient aucun secret** : mots de passe et phrases de passe sont toujours demandés à l'écran.
- Relancer une commande est sans danger (**idempotence**) : ce qui est déjà conforme est laissé tel quel, sans doublon.

Exemple de déploiement serveur sans assistant :

```powershell
SecureDesk.exe init --config securedesk.json --dry-run
```

```powershell
SecureDesk.exe init --config securedesk.json --out E:\
```

```powershell
SecureDesk.exe accounts --config securedesk.json
```

```powershell
SecureDesk.exe harden --config securedesk.json
```

```powershell
SecureDesk.exe tsplus-check --config securedesk.json
```

```powershell
SecureDesk.exe add-peer E:\pairing-client.sdpair
```

```powershell
SecureDesk.exe report
```

Mode hors ligne : ajoutez `--wireguard-msi C:\offline\wireguard-amd64-0.5.3.msi`, `--multiotp-msi …`, `--vcredist …` et, si l'empreinte n'est pas épinglée dans l'exécutable, `--sha256 <empreinte publiée par l'éditeur>`.

Les journaux sont dans `%ProgramData%\SecureDesk\logs`. Aucun secret n'y est écrit : un filtre masque en plus tout ce qui ressemble à une clé ou à une graine.

---

## 10. Dépannage

| Symptôme | Piste |
|---|---|
| Pas de handshake | Box : la redirection UDP pointe-t-elle vers la bonne IP LAN, avec le bon port ? Le DDNS est-il à jour ? Le tunnel est-il activé sur le client ? Comparez les empreintes. Lancez `diagnose` des deux côtés. |
| Handshake OK mais RDP injoignable | `diagnose` sur le serveur : les règles `SecureDesk-*` sont-elles conformes ? Le service Bureau à distance ou TSplus est-il démarré ? Vérifiez aussi le port RDP s'il a été changé dans TSplus (relancez `init` pour mettre le pare-feu à jour). |
| « Phrase de passe incorrecte ou fichier modifié » | Mauvaise phrase de passe, ou fichier abîmé pendant la copie. Générez une nouvelle invitation (`invite`). |
| « Invitation expirée » | Générez une nouvelle invitation (`invite --name …`). |
| Code TOTP refusé | Vérifiez l'heure du téléphone (réglage automatique) et celle du serveur (`diagnose` signale toute dérive > 30 s). Un code ne sert qu'une fois : attendez le suivant. Après trop d'échecs, multiOTP temporise ou verrouille l'utilisateur. |
| Mot de passe demandé deux fois | Voir [`docs/RECETTE.md`](docs/RECETTE.md), test R-2FA-4 (NLA + TSplus + multiOTP). Ne désactivez pas NLA. |
| Compte Windows verrouillé | Après N échecs, attendez la durée de verrouillage (30 min par défaut), ou déverrouillez le compte depuis un compte administrateur (Gestion de l'ordinateur → Utilisateurs). |
| SmartScreen bloque l'exécutable | Voir le §2. |

---

## 11. Récupération en cas de verrouillage (2FA)

Avant d'activer le 2FA, **conservez** :

- les codes de secours ;
- le mot de passe d'un compte administrateur local ;
- la **clé de récupération BitLocker** du PC serveur.

### A. La console fonctionne (mode « distant seulement »)

À la console, ouvrez une session administrateur normalement (aucun TOTP n'est demandé), puis :

```powershell
& "C:\Program Files\SecureDesk\SecureDesk.exe" disable-2fa
```

Le Credential Provider est désactivé (`cpus_logon = 3d`) et les enrôlements sont conservés. Corrigez le problème, puis réactivez avec `enable-2fa`.

### B. Activation probatoire non confirmée

Sans `confirm-2fa`, la tâche planifiée `\SecureDesk\Desactivation-2FA-probatoire` désactive le 2FA à l'échéance. Il suffit d'attendre.

### C. Mode sans échec

1. Redémarrez en maintenant **Maj** enfoncée, puis choisissez **Dépannage → Options avancées → Paramètres → Redémarrer → 4 (mode sans échec)**.
2. Connectez-vous en administrateur, puis lancez `disable-2fa` comme au point A.

> Le chargement d'un Credential Provider tiers en mode sans échec n'est pas documenté par multiOTP : ce point est un test de la recette (R-2FA-8). Si multiOTP s'affiche aussi en mode sans échec, utilisez le point D.

### D. Hors ligne, depuis l'environnement de récupération (méthode garantie)

1. Ouvrez **Dépannage → Options avancées → Invite de commandes**. La clé de récupération BitLocker est demandée si le disque est chiffré.
2. Exécutez (adaptez la lettre `C:` si besoin, avec `dir C:\Windows`) :
   ```bat
   reg load HKLM\OFF C:\Windows\System32\config\SOFTWARE
   ```
   ```bat
   reg add "HKLM\OFF\Classes\CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}" /v cpus_logon /t REG_SZ /d 3d /f
   ```
   ```bat
   reg add "HKLM\OFF\Classes\CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}" /v cpus_unlock /t REG_SZ /d 3d /f
   ```
   ```bat
   reg unload HKLM\OFF
   ```
3. Redémarrez. Le 2FA est désactivé.

### E. Dernier recours (documentation multiOTP)

Désinstallez multiOTP Credential Provider (Paramètres → Applications), ou importez le fichier `multiOTPCredentialProvider-unregister.reg` fourni par multiOTP.

---

## 12. Désinstallation

```powershell
SecureDesk.exe uninstall --dry-run
```

```powershell
SecureDesk.exe uninstall
```

La désinstallation :

- désactive puis désinstalle multiOTP s'il a été installé par SecureDesk ;
- supprime le tunnel, sa configuration et les règles de pare-feu `SecureDesk-*` ;
- restaure **chaque réglage modifié à sa valeur d'origine** (stratégies RDP, mots de passe, audit, journaux, heure Windows, serveur web TSplus) ;
- désinstalle WireGuard s'il a été installé par SecureDesk ;
- **conserve** TSplus et les comptes Windows. Ajoutez `--remove-accounts` pour supprimer les comptes créés par SecureDesk ; TSplus n'est jamais supprimé.

---

## 13. Ce qui est automatisé, ce qui reste manuel

| Automatisé par SecureDesk | Manuel (guidé) |
|---|---|
| Installation vérifiée de WireGuard, de VC++ et de multiOTP (en ligne ou hors ligne) | Achat, installation (sauf option `/verysilent`) et **activation de la licence TSplus** |
| Génération locale des clés, PSK par pair, fichiers d'appairage chiffrés et authentifiés | Transport des fichiers d'appairage par clé USB, puis effacement |
| Tunnel en service, split tunnel, keepalive | Configuration de la box : redirection UDP, réservation DHCP, DDNS |
| Pare-feu : RDP et TSplus uniquement via le tunnel (et le LAN en option), le reste bloqué | Réglages TSplus dans l'AdminTool (permissions, « Deny access from Outside ») |
| Comptes, groupe RDP, politique de mot de passe et verrouillage | Scan du QR code, conservation des codes de secours |
| NLA, TLS, chiffrement élevé, délais d'expiration, redirections, audit, heure Windows | Activation de BitLocker et sauvegarde des clés de récupération |
| Enrôlement TOTP vérifié, activation probatoire, garde-fous anti-verrouillage | Les tests de la recette sur les vrais PC |
| Diagnostic sans secret, désinstallation avec rollback | TSplus Portable Client Generator (option, ci-dessous) |

### Option : client TSplus portable verrouillé sur le PC client

TSplus fournit un *Portable Client Generator*. Dans son onglet **Security**, un client peut être verrouillé sur un **nom de PC** ou sur le numéro de série d'un disque (documentation TSplus : « Securing a TSplus server » et « Portable Client Generator »). Si vous l'utilisez :

- adresse du serveur : **10.77.0.1** (l'IP du tunnel) ;
- **ne renseignez pas de mot de passe** : l'option `-psw` de `ClientGenerator.exe` l'enregistrerait dans le client ;
- verrouillez-le sur le nom de votre PC client.

Ce client passe toujours par le tunnel et par le 2FA. Il n'est pas nécessaire : le raccourci `.rdp` suffit.

---

## 14. Développement

- C# / **.NET 10** (LTS). Publication **self-contained single-file win-x64** avec un manifeste `requireAdministrator`.
- Arborescence : `src/` (Core multiplateforme, Windows, App), `tests/`, `docs/`, `scripts/`, `.github/workflows/`.
- CI :
  - `ci.yml` : tests sous Linux et Windows, format, build strict avec analyseurs ;
  - `integration.yml` : runner Windows avec WireGuard réel, pare-feu, multiOTP **désactivé** et scénario de bout en bout ;
  - `release.yml` : tag `v*`, exécutable, `SHA256SUMS`, signature si un certificat est fourni.
- Signature Authenticode : créez les secrets `SIGNING_CERT_PFX_BASE64` (fichier PFX en base64) et `SIGNING_CERT_PASSWORD`. Sans eux, l'exécutable n'est pas signé (voir le §2).

```bash
dotnet test tests/SecureDesk.Core.Tests
```
