# SecureDesk — Plan de conception

> Statut : **validé le 30/10/2026** (voir le §14). Document vivant, mis à jour à chaque incrément.
> Les mentions **[VÉRIFIÉ]** renvoient à une source officielle consultée pendant la rédaction.
> Les mentions **[À VÉRIFIER]** signalent un comportement non documenté ou une source inaccessible : chacune devient soit une question pour vous, soit un point de la recette manuelle.
> **v2 en préparation :** le remplacement de WireGuard direct par Tailscale (aucune redirection de port sur la box) est décrit dans [`PLAN-TAILSCALE.md`](PLAN-TAILSCALE.md), en attente de validation.

---

## 0. Nom du produit

« SecureDesk Deploy » convient et reste neutre. Alternative proposée : **« Sas »** (*SasDesk*) : un sas est exactement ce que l'outil met en place, avec trois portes successives (clé WireGuard, mot de passe Windows, code TOTP). Je garde **SecureDesk** comme nom de code dans le dépôt (exécutable `SecureDesk.exe`, préfixe des règles de pare-feu `SecureDesk-`) tant que vous n'avez pas tranché. Le renommage est trivial.

---

## 1. Choix du langage et de la plateforme

| Option | Verdict |
|---|---|
| **C# / .NET 10 LTS**, self-contained single-file win-x64, manifeste `requireAdministrator` | **Retenu** |
| C# / .NET 8 | Écarté : **le support de .NET 8 se termine le 10 novembre 2026**, soit dans 11 jours. Un outil de sécurité ne doit pas sortir sur un runtime sans correctifs. .NET 10 est LTS (support jusqu'en novembre 2028) ; le code reste identique. |
| PowerShell + PS2EXE | Écarté : faux positifs antivirus, tests unitaires plus faibles, parsing et chiffrement moins sûrs. |
| Go / Rust | Possible, mais l'interface WinForms, l'API pare-feu COM, WMI et DPAPI sont plus directes en .NET. |

**Pourquoi .NET convient ici :**
- AES-256-GCM, PBKDF2-SHA256, HKDF, HMAC et CSPRNG sont intégrés à la BCL : **aucune bibliothèque cryptographique tierce**.
- Les API Windows natives sont accessibles directement : pare-feu (COM `INetFwPolicy2`), registre, services, ACL, `WinVerifyTrust` pour Authenticode, WMI (BitLocker), WTS (détection de session distante).
- La logique métier (« Core ») est multiplateforme et testable sous Linux, donc dans ma session cloud, puis sous Windows en CI.

**Interface graphique :** WinForms (intégré au SDK, compatible single-file). Un seul exécutable :
- `SecureDesk.exe` sans argument → assistant graphique ;
- `SecureDesk.exe <commande> …` → ligne de commande.

**Dépendances tierces embarquées (aucune ne fait d'appel réseau) :**
- `System.CommandLine` (Microsoft) : parsing de la ligne de commande ;
- `QRCoder` (MIT) : rendu du QR code **en mémoire uniquement**, jamais sur disque ;
- tests : xUnit et FluentAssertions (ou Shouldly, sous licence plus permissive).

---

## 2. Architecture logicielle

```
src/
  SecureDesk.Core/          (net10.0, multiplateforme, aucune E/S système)
    Config/                 modèle JSON, validation, valeurs par défaut
    Net/                    calcul CIDR, allocation d'IP de pairs, complément d'intervalles IPv4
    WireGuard/              génération des .conf serveur et client, modèle de pair
    Pairing/                format .sdpair : chiffrement, MAC, parsing, versionnage
    Firewall/               plan de règles (allow ciblé + block complémentaire)
    Rdp/                    génération du fichier .rdp
    MultiOtp/               plan registre CP, interprétation des codes retour CLI, TOTP (vérif. tests)
    Hardening/              plan des politiques RDP, mots de passe, audit
    Engine/                 IAction { Describe, Check, Apply, Rollback }, planificateur, dry-run
    State/                  état persistant + valeurs d'origine pour le rollback
    Logging/                journal avec filtre anti-secrets (redaction)
  SecureDesk.Windows/       (net10.0-windows) exécuteurs concrets : registre, pare-feu, services,
                            msiexec, Authenticode, ACL, comptes locaux, auditpol, W32Time, BitLocker…
  SecureDesk.App/           (net10.0-windows, WinExe/console) CLI + assistant WinForms
tests/
  SecureDesk.Core.Tests/            unitaires, exécutés sous Linux ET Windows
  SecureDesk.Windows.IntegrationTests/  uniquement sur runner Windows (admin)
docs/  scripts/  .github/workflows/
```

### 2.1 Moteur d'actions (idempotence, dry-run, rollback)

Chaque opération est une `IAction` :
- `Describe()` : texte affiché en `--dry-run` et dans le rapport ;
- `Check()` : l'état voulu est-il déjà en place ? Si oui, l'action est « déjà conforme » et ne fait rien. **C'est le fondement de l'idempotence.**
- `Apply()` : avant toute modification, la **valeur d'origine** est enregistrée dans `%ProgramData%\SecureDesk\state.json` (ACL SYSTEM et Administrateurs), uniquement à la première application.
- `Rollback()` : `uninstall` rejoue les rollbacks dans l'ordre inverse à partir de `state.json`.

`--dry-run` construit le plan complet, exécute uniquement les `Check()` (lecture seule) et affiche la liste « à faire / déjà conforme ».

### 2.2 Journalisation et secrets
- Journaux dans `%ProgramData%\SecureDesk\logs\securedesk-AAAAMMJJ.log`, avec ACL SYSTEM et Administrateurs.
- Les secrets transitent dans un type `Secret` dont `ToString()` renvoie `***`. Un filtre de rédaction supplémentaire masque toute chaîne ressemblant à une clé WireGuard (44 caractères base64 terminés par `=`), à une URI `otpauth://` ou à une graine base32.
- **Un test unitaire dédié** passe des secrets connus dans tout le pipeline (logs, rapport, fichiers d'appairage client) et vérifie qu'ils n'en ressortent jamais.

---

## 3. Réseau, WireGuard et appairage

### 3.1 WireGuard pour Windows [VÉRIFIÉ — `wireguard-windows/docs/enterprise.md`]
- **Installation :** `msiexec /i wireguard-amd64-<ver>.msi /qn DO_NOT_LAUNCH=1`. La propriété `DO_NOT_LAUNCH` est documentée. Avant de lancer l'installeur, l'outil vérifie :
  - la signature Authenticode (`WinVerifyTrust`, éditeur attendu : « WireGuard LLC ») ;
  - le SHA-256, épinglé dans un manifeste `installers.json` embarqué dans l'exe.
- **Mode hors ligne :** `--wireguard-msi <chemin>`, avec les mêmes vérifications.
- **Tunnel :** `wireguard /installtunnelservice <chemin>\sd-tunnel.conf` crée le service `WireGuardTunnel$sd-tunnel`. On règle ensuite son type de démarrage (automatique sur le serveur, automatique ou manuel au choix sur le client) via l'API des services. Désinstallation : `wireguard /uninstalltunnelservice sd-tunnel`.
- **Fichier de configuration :** `%ProgramData%\SecureDesk\wireguard\sd-tunnel.conf`, avec une ACL **protégée** (sans héritage) limitée à SYSTEM et Administrateurs. Variante évaluée : le format `.conf.dpapi` documenté. [À VÉRIFIER] Ce format chiffre avec le contexte du compte qui l'écrit, et il n'est pas certain qu'on puisse le produire depuis un processus administrateur et non SYSTEM. Par défaut je retiens donc le `.conf` protégé par ACL. Le disque doit de toute façon être protégé par BitLocker.
- **Génération des clés :** `wg.exe genkey`, puis `wg.exe pubkey` et `wg.exe genpsk`, par **pipes stdin/stdout** : la clé privée ne passe jamais par un argument de ligne de commande ni par un fichier temporaire. Elle n'existe que dans la mémoire de l'outil, puis dans le `.conf` protégé.
- **Lecture de l'état :** `wg show sd-tunnel latest-handshakes` et `transfer`.
- **Note sur le téléchargement :** depuis ma session cloud, `download.wireguard.com` est bloqué. Le manifeste (URL, version, SHA-256) sera rempli **par la CI Windows**, qui a accès au réseau, puis figé dans chaque release.

### 3.2 Plan d'adressage
- Sous-réseau par défaut : `10.77.0.0/24` (paramétrable). Serveur en `.1`, pairs à partir de `.2`.
- Port UDP : l'assistant **propose un port aléatoire** entre 20000 et 60999, en excluant une liste de ports connus (51820, 3389, 1194, 500, 4500…). Le port reste modifiable.

**Configuration générée côté serveur :**
```ini
[Interface]
PrivateKey = <locale>
Address    = 10.77.0.1/24
ListenPort = <port>

[Peer]      # nom: pc-perso
PublicKey    = <client>
PresharedKey = <psk propre à ce pair>
AllowedIPs   = 10.77.0.2/32
```

**Configuration générée côté client :**
```ini
[Interface]
PrivateKey = <locale>
Address    = 10.77.0.2/32

[Peer]
PublicKey           = <serveur>
PresharedKey        = <psk>
Endpoint            = mon-bureau.ddns.net:<port>
AllowedIPs          = 10.77.0.1/32        # split tunnel strict
PersistentKeepalive = 25
```

**Pairs multiples :** chaque pair reçoit **sa propre PSK** et sa propre IP. La PSK étant générée par le serveur *avant* de connaître le client, je découple « invitation » et « ajout » :
- `init` crée le serveur et la première invitation ;
- `invite --name <pair>` crée les invitations suivantes : nouvelle PSK, prochaine IP libre.

### 3.3 Fichiers d'appairage `.sdpair`

| | `pairing-server.sdpair` | `pairing-client.sdpair` |
|---|---|---|
| Contenu | clé publique du serveur, endpoint, port, IP serveur, IP assignée au client, sous-réseau, **PSK**, identifiant d'invitation | clé publique du client, identifiant d'invitation, nom du pair |
| Protection | **chiffré** : AES-256-GCM, clé dérivée de la phrase de passe par PBKDF2-HMAC-SHA256 (600 000 itérations, sel aléatoire de 16 octets). L'en-tête en clair (version, type, paramètres KDF) est authentifié comme AAD. | en clair (aucun secret), mais **authentifié** par HMAC-SHA256 avec une clé dérivée de la PSK (HKDF, info `sdpair-client-v1`). Le serveur rejette donc un fichier client falsifié ou destiné à une autre invitation. |
| Clé privée | **jamais** | **jamais** |

- **Phrase de passe :** 14 caractères minimum, avec un contrôle de répétition. L'assistant propose une phrase générée de 6 groupes de 4 caractères sans ambiguïté (ex. `K7QM-2XRP-…`, environ 118 bits), facile à dicter. Elle est saisie deux fois et n'est jamais journalisée.
- **Empreinte affichée :** chaque côté affiche une empreinte courte (8 groupes hexadécimaux) des clés publiques, à comparer à voix haute ou visuellement.
- **Après export :** l'outil recommande la clé USB, puis propose la **suppression du fichier** des deux côtés. Sur un SSD, l'écrasement n'est pas garanti, ce que l'outil signale. La PSK étant de toute façon chiffrée dans le fichier, le risque résiduel est faible.
- **Expiration :** une invitation expire au bout de 7 jours par défaut, ce que l'outil contrôle à l'import.

### 3.4 Flux
1. **Serveur, `init` :** clés, PSK, `sd-tunnel.conf`, service, règles de pare-feu, export de `pairing-server.sdpair` chiffré.
2. **Client, `join pairing-server.sdpair` :** déchiffrement, génération de ses clés, installation et activation du tunnel, export de `pairing-client.sdpair`, création du `.rdp`. Le premier handshake n'aboutira qu'après l'étape 3, ce qui est normal ; l'outil l'explique.
3. **Serveur, `add-peer pairing-client.sdpair` :** vérification du MAC, ajout du `[Peer]`, redémarrage du service, puis attente du handshake (affichée).
4. **Maintenance :**
   - `rotate-keys --server` : nouvelle paire serveur, puis nouvelles invitations pour tous les pairs ;
   - `rotate-keys --peer <nom>` : nouvelle PSK et réinvitation ;
   - `revoke-peer <nom>` : retrait du `[Peer]`, redémarrage, journalisation ;
   - `list-peers`.

**Réappairage d'un client réinstallé (objectif < 10 min) :**
- serveur : `revoke-peer` puis `invite` ;
- client : `join` ;
- serveur : `add-peer`.

---

## 4. Pare-feu Windows du serveur

Ports protégés, paramétrables :
- port RDP effectif, lu dans `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber`, en TCP et UDP ;
- ports web TSplus : 80 et 443 par défaut, modifiables. **Ils doivent impérativement être protégés, car TSplus y achemine aussi RDP** (voir le §5).

**Stratégie, en tenant compte d'un piège du pare-feu Windows :** une règle *block* l'emporte toujours sur une règle *allow*. Une règle « bloquer partout » couperait donc aussi le tunnel. La stratégie retenue :
1. `SecureDesk-Allow-RDP-Tunnel` : autorise les ports protégés depuis `10.77.0.0/24`, plus en option `SecureDesk-Allow-RDP-LAN` depuis le sous-réseau LAN détecté. Les deux règles s'appliquent à tous les profils.
2. `SecureDesk-Block-RDP-Others` : bloque les mêmes ports depuis **le complément exact** des plages autorisées (IPv4, calculé et testé unitairement), plus **tout IPv6**.
   - **Pourquoi c'est nécessaire :** cette règle neutralise toute autre règle *allow* existante ou ajoutée plus tard, y compris celles créées par Windows (groupe « Bureau à distance ») ou par l'installeur TSplus.
3. `SecureDesk-Allow-WireGuard-UDP` : autorise le port UDP d'écoute WireGuard.
4. Le pare-feu est activé sur les trois profils. L'état d'origine est enregistré pour le rollback.
5. `uninstall` supprime toutes les règles dont le nom commence par `SecureDesk-`.

**Écoute de RDP :** RDP écoute sur `0.0.0.0`. Le lier à l'interface WireGuard (`LanAdapter`) serait fragile, car l'adaptateur n'existe qu'une fois le tunnel démarré, et un démarrage raté rendrait RDP muet même à la console. Je ne le fais donc pas : **la protection repose sur le pare-feu et sur l'absence de redirection dans la box**. `diagnose` vérifie les règles *effectives* (toute règle *allow* active sur ces ports dont la portée dépasse le tunnel ou le LAN est signalée) et l'état du pare-feu par profil.

---

## 5. TSplus

Sources consultées **[VÉRIFIÉ]** sur docs.tsplus.net : `installation`, `commands-list`, `built-in-web-server`, `securing-a-terminal-service-plus-server`, `volume-licensing-install`, `portable-client-generator-cli`, `activating-your-license`.

### 5.1 Ce que la documentation dit et ce que l'outil en fait

| Fait documenté | Conséquence dans l'outil |
|---|---|
| Les outils d'administration sont dans `C:\Program Files (x86)\TSplus\UserDesktop\files` (`AdminTool.exe`). Le désinstalleur est `C:\Program Files (x86)\TSplus\unins000.exe`. | **Détection** par la présence d'`AdminTool.exe` (version tirée des métadonnées du fichier) et par les entrées « Désinstaller » du registre (`DisplayName` contenant « TSplus », `DisplayVersion`). |
| Le programme d'installation accepte **`/verysilent`** (page *Volume Licensing – install*). | **Installation silencieuse en option**, désactivée par défaut et seulement avec un installeur fourni localement : `Setup-TSplus.exe /verysilent`. L'installation reste **guidée** par défaut. Un redémarrage est nécessaire après coup ; l'outil le signale et ne redémarre jamais seul. |
| L'installeur télécharge le produit pendant l'installation. Une option « Advanced » permet de ne pas installer *Advanced Security*. | Aucune option documentée ne désactive *Advanced Security* en mode silencieux. **[À VÉRIFIER]** En `/verysilent`, l'essai *Advanced Security* est probablement installé ; si vous voulez l'éviter, utilisez l'installation guidée (mode Advanced). |
| « TSplus Remote Access will require you to manually enter your username and password at each login. » | **Cause probable des doubles invites** avec NLA et multiOTP. Voir le §7.4 : c'est le test prioritaire de la recette. |
| **« Regardless the RDP port that has been set, the RDP will also be available on the HTTP and on the HTTPS port number! »** (serveur web intégré, ports 80 et 443 par défaut) | **Les ports web TSplus sont un second chemin vers RDP.** Ils figurent dans la liste des ports protégés du pare-feu (autorisés depuis le tunnel seulement, bloqués ailleurs). De plus, l'outil **arrête le serveur web** par la commande documentée `AdminTool.exe /webstop`, et `uninstall` exécute `/webstart` s'il était actif à l'origine. **[À VÉRIFIER]** La doc ne dit pas si `/webstop` persiste après un redémarrage, donc `diagnose` contrôle l'écoute sur ces ports. |
| Le port RDP se change dans l'AdminTool (onglet Home, crayon « RDP Port »). | L'outil **lit** le port effectif dans `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` et ne le change pas. |
| Sessions → Permissions : « Allow access from Microsoft RDP client for everyone / Admins only / Deny » et « Deny access from Outside » (IP privées uniquement). | **Instructions manuelles affichées :** garder « Allow access from Microsoft RDP client for everyone », car on utilise mstsc. Activer « Deny access from Outside », qui ajoute une défense en profondeur puisque 10.77.0.0/24 est une plage privée. |
| Activation de licence : `AdminTool.exe /activate <fichier .lic>` et `/vl /activate` pour les licences en volume. | **Jamais utilisé** (votre consigne). L'outil affiche la procédure : AdminTool → onglet License → « Activate your license ». |
| 2FA TSplus : `TwoFactor.Admin.exe`. | Non utilisé. L'outil vérifie seulement qu'il n'est pas configuré (`TwoFactor.Admin.exe /getusers` renvoie une liste vide) et **avertit** dans le cas contraire, sans rien modifier. |
| Portable Client Generator : verrouillage sur un nom de PC (onglet Security) et CLI `ClientGenerator.exe` (`-server`, `-user`, `-psw`…). | **Documenté dans le README uniquement** (option manuelle). La CLI ne documente **pas** d'option de verrouillage sur le nom de PC ; la procédure passe donc par l'interface graphique. Ne jamais passer `-psw` (mot de passe enregistré dans le client). |

### 5.2 Services TSplus
**[À VÉRIFIER]** Les noms des services Windows de TSplus ne figurent pas dans les pages consultées. La recherche se fait par nom d'affichage contenant « TSplus », c'est une heuristique signalée comme telle. Le critère bloquant reste la présence d'`AdminTool.exe` et la réponse RDP en local.

## 6. Durcissement du serveur

Les valeurs sont posées via les clés de stratégie Microsoft `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` (équivalent GPO local, ADMX `TerminalServer.admx`). Chaque valeur d'origine est sauvegardée.

| Objectif | Valeur |
|---|---|
| NLA obligatoire | `UserAuthentication = 1` |
| Couche de sécurité TLS | `SecurityLayer = 2` |
| Chiffrement élevé | `MinEncryptionLevel = 3` |
| Session inactive | `MaxIdleTime` (ms), par défaut 30 min |
| Session déconnectée | `MaxDisconnectionTime` (ms), par défaut 60 min |
| Presse-papiers | `fDisableClip = 1` par défaut |
| Lecteurs | `fDisableCdm = 1` par défaut |
| Imprimantes | `fDisableCpm = 1` par défaut |
| Ports COM et LPT, PnP | `fDisableCcm`, `fDisableLPT`, `fDisablePNPRedir = 1` |
| **Ne PAS définir** | `fPromptForPassword` : source de doubles invites avec multiOTP (voir §7.4) |

[À VÉRIFIER en recette] TSplus peut appliquer ses propres réglages de redirection ; la recette contrôle l'effet réel.

**Comptes :**
- création de comptes locaux ou sélection de comptes existants, avec un mot de passe saisi deux fois et contrôlé (longueur ≥ 14, complexité) ;
- ajout au groupe **par SID `S-1-5-32-555`** (« Utilisateurs du Bureau à distance »), ce qui évite les problèmes de nom localisé ;
- les comptes ne sont pas ajoutés aux Administrateurs.

**Politique de mots de passe et verrouillage :**
- `net accounts /minpwlen:14 /lockoutthreshold:N /lockoutduration:30 /lockoutwindow:30` ;
- complexité via `secedit` (export, puis modification de `PasswordComplexity=1`, puis réimport).
- Valeurs d'origine sauvegardées. N vaut 5 par défaut.

**Audit :**
- `auditpol` **par GUID de sous-catégorie** (Logon `{0CCE9215-…}`, Logoff, Account Lockout), succès et échec, d'où les événements 4624 et 4625 ;
- l'événement 1149 se trouve dans `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` : on vérifie que ce journal est actif ;
- la taille du journal Security est portée à 256 Mo ;
- les logs multiOTP sont inclus dans `diagnose` (sans secrets).

**Horloge :** service W32Time en démarrage automatique, synchronisation NTP (`time.windows.com` par défaut, paramétrable) et `w32tm /resync`. La **dérive est mesurée par un client SNTP intégré** (testable), avec une alerte au-delà de 30 s.

**BitLocker :** lecture de l'état via WMI `Win32_EncryptableVolume` et alerte si inactif. **Jamais d'activation automatique.**

---

## 7. multiOTP — configuration retenue et garde-fous

Sources consultées **[VÉRIFIÉ]** : `multiOTP/multiOTPCredentialProvider` (README, `WixInstall/…/Product.wxs`, `multiOTP_settings_*.wxs`, `Shared/Shared.cpp`, `CredentialProviderFilter/CCredentialProviderFilter.cpp`, build 5.10.2.2) et `multiOTP/multiotp` (`readme.md`, aide de la CLI et codes de retour).

### 7.1 Installation
- Prérequis : **Visual C++ Redistributable 2015-2022 x64** (README). Installeur Microsoft signé, vérifié par Authenticode.
- Commande retenue :
  ```
  msiexec /i multiOTPCredentialProvider-<ver>-x64.msi /qn /norestart
          MULTIOTP_URL="" MULTIOTP_SECRET="" MULTIOTP_CACHE=0
          CPUS_LOGON=3d CPUS_UNLOCK=3d CPUS_CREDUI=3d
          MULTIOTP_TWO_STEP_HIDE_OTP=1
          MULTIOTP_DISPLAYSMSLINK=0 MULTIOTP_DISPLAYEMAILLINK=0
          MULTIOTP_WITHOUT2FA=0 /l*v <log>
  ```
- **Mode local uniquement :** dans l'installeur, c'est la case `MULTIOTP_LOCALSERVERONLY` (« No remote server, local multiOTP only ») qui n'a qu'un rôle de validation dans l'interface. L'effet réel est `multiOTPServers` vide. Ma lecture des sources, à confirmer en recette : avec une URL vide, l'exécutable `multiotp.exe` embarqué authentifie localement.
- **`CPUS_*=3d` à l'installation :** la valeur `3` est documentée comme « multiOTP Credential Provider completely disabled ». C'est aussi la valeur par défaut du MSI. **Le CP est donc installé mais inactif** tant que l'enrôlement n'est pas validé. C'est la pierre angulaire de l'anti-verrouillage.
- **Intégrité :** le README indique que « DLL and EXE files are digitally signed », mais ne dit rien de la signature du **MSI** [À VÉRIFIER]. Je vérifie donc (MSI signé par SysCo : vérifié en CI, voir §15) :
  - le **SHA-256 épinglé** du MSI avant installation ;
  - la **signature Authenticode** de `multiOTPCredentialProvider.dll` et de `multiotp.exe` après installation, **avant** toute activation.
  Si la signature est invalide, l'outil désinstalle et s'arrête.
- **Mise en garde officielle :** le changelog 5.6.1.6 dit « Silent install supported (WARNING! No test will be done, be sure the registry parameters are correct!) ». C'est pourquoi l'outil **relit et valide chaque valeur de registre** après installation.

### 7.2 Valeurs de registre à l'activation

Clé : `HKCR\CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}`. L'installeur restreint déjà les ACL de cette clé.

| Valeur | Distant seulement (défaut) | Distant + local | Désactivé (`disable-2fa`) |
|---|---|---|---|
| `cpus_logon` | `1e` | `0e` | `3d` |
| `cpus_unlock` | `1e` | `0e` | `3d` |
| `cpus_credui` | `3d` | `3d` | `3d` |

**Pourquoi `e` et non `d`** [VÉRIFIÉ dans `Shared.cpp`] : le filtre ne masque les autres fournisseurs que pour `0e`, `1e` en session distante, ou `2e`. Avec `1d`, le fournisseur de mot de passe standard resterait proposé **en RDP** et permettrait de **contourner le TOTP**. Avec `1e` :
- en session distante, multiOTP est le seul fournisseur ;
- **à la console, rien n'est filtré et le CP multiOTP n'est pas énuméré**, donc l'ouverture de session locale reste strictement inchangée et tous les fournisseurs restent disponibles pour la récupération.

C'est exactement le comportement « distant seulement » demandé.

**Autres choix :**
- **`cpus_credui = 3d` :** les invites UAC ne sont pas modifiées, pour éviter de casser l'élévation dans une session distante. Option avancée possible.
- **`included_providers_id` reste vide :** l'ajouter en RDP créerait un contournement.
- **`excluded_account` reste vide :** un compte exclu serait une porte dérobée en RDP.
- **Point de vigilance « Distant + local » :** dans ce mode, la console n'offre plus que multiOTP. La récupération passe alors par `disable-2fa` à la console avec TOTP, ou par la procédure hors ligne du §7.6.

### 7.3 Enrôlement (`enroll-user <compte>`)
1. `multiotp.exe -fastcreatenopin <compte>` crée un jeton TOTP (6 chiffres, 30 s par défaut).
2. `multiotp.exe -urllink <compte>` renvoie l'URI `otpauth://` sur **stdout**. Elle est capturée en mémoire et la graine ne passe **jamais** en argument. Je n'utilise pas `-createga` pour cette raison.
3. Le QR code est rendu en mémoire (QRCoder) et **affiché une seule fois** : fenêtre WinForms dans l'assistant, blocs Unicode dans la console. Rien n'est écrit sur disque ; la mémoire est effacée et l'écran nettoyé après validation. `-qrcode` n'est pas utilisé, car il écrit un PNG.
4. **Validation :** saisie d'un code, puis `multiotp.exe <compte> <code>`. Le code retour `0` signifie « Token accepted ». En cas d'échec après trois essais, `-delete <compte>`.
   - Note : un code déjà utilisé est refusé ensuite (code `26`). L'outil prévient qu'il faut attendre le code suivant pour la première connexion.
5. **Codes de secours :** multiOTP les supporte **nativement** (« TAN (emergency scratch passwords) », `multiotp -scratchlist user`). Ils sont affichés une seule fois, avec une invite à les imprimer ou à les noter sur papier. [À VÉRIFIER] Je dois confirmer en recette que `-scratchlist` n'écrit aucun fichier en plus de la sortie standard ; à défaut, l'outil supprime tout fichier produit.
6. **Nom d'utilisateur :** [À VÉRIFIER] Pour un compte local hors domaine, le CP préfixe par défaut avec le nom de l'ordinateur et essaie ensuite « un nom de domaine plus court » (changelog 5.8.6.1). Je crée l'utilisateur multiOTP sous le **nom court** du compte Windows. Ce point est **le test n° 1 de la recette 2FA**.

**ACL :** l'installeur retire déjà la lecture aux Utilisateurs sur `config`, `users`, `tokens` et `templates`. L'outil le **vérifie** et le réapplique si besoin. `diagnose` recherche tout `*.png` ou `*.html` résiduel dans le dossier multiOTP et dans `%TEMP%`.

### 7.4 NLA + TSplus + multiOTP (doubles invites)
D'après le CP :
- son *filtre* reprend les identifiants sérialisés envoyés par le client (CredSSP/NLA) via `UpdateRemoteCredential` ;
- avec `two_step_hide_otp=1`, l'écran distant ne demande plus **que** le code OTP ;
- les changelogs 5.8.2.9 (« password must not be typed twice anymore ») et 5.10.1.2 concernent précisément les doubles saisies.

**Configuration retenue pour éviter la double invite :**
- NLA activé (`UserAuthentication=1`) ;
- `fPromptForPassword` **non défini** (cette stratégie force une ressaisie du mot de passe côté serveur) ;
- `.rdp` avec `enablecredsspsupport:i:1` et `authentication level:i:2`, sans mot de passe enregistré ;
- `MULTIOTP_TWO_STEP_HIDE_OTP=1` ;
- CP en version ≥ 5.10.1.2.

**Parcours attendu :**
1. mstsc demande le mot de passe (NLA) ;
2. la session s'ouvre sur un écran multiOTP qui demande **uniquement** le code TOTP ;
3. ouverture de session.

[À VÉRIFIER] L'interaction avec TSplus n'est pas documentée côté multiOTP et je n'ai pas pu lire la documentation TSplus. C'est un **test prioritaire de la recette**. Si la double invite persiste, **on ne désactive pas NLA** : on accepte une seconde saisie, la sécurité passant avant le confort.

### 7.5 Garde-fous anti-verrouillage (`enable-2fa`)
L'activation refuse de continuer tant que **toutes** les conditions suivantes ne sont pas remplies :
1. **Session locale :** refus si le processus tourne dans une session distante (`GetSystemMetrics(SM_REMOTESESSION)` et `WTSQuerySessionInformation`), sauf avec `--i-have-console-access`.
2. **Un administrateur enrôlé :** au moins un membre de `S-1-5-32-544` est enrôlé **et vérifié** (état de l'outil et `multiotp -user-info`).
3. **Comptes du périmètre :** **tous** les comptes dans la portée du 2FA et membres de `S-1-5-32-555` ou des Administrateurs sont enrôlés. Un compte non enrôlé serait bloqué en RDP (code `21`, « User doesn't exist »).
4. **Mode distant seulement :** un administrateur local est actif, a un mot de passe, n'est pas verrouillé et n'est pas visé par `SeDenyInteractiveLogonRight`. La valeur écrite est bien `1e`, qui ne filtre pas la console.
5. Dérive de l'horloge inférieure à 30 s.
6. Signatures Authenticode du CP valides et lecture de contrôle des valeurs de registre réussie.
7. **Activation probatoire (proposition) :**
   - après activation, une tâche planifiée SYSTEM exécute `disable-2fa` **dans 20 minutes** ;
   - vous testez une vraie connexion via le tunnel avec TOTP, puis lancez `confirm-2fa`, qui supprime la tâche ;
   - sans confirmation, le 2FA se désactive tout seul.

**`disable-2fa`** remet `cpus_logon`, `cpus_unlock` et `cpus_credui` à `3d` (« completely disabled » selon la doc). Le CP reste installé ; l'opération est instantanée et réversible.

### 7.6 Récupération (README)
1. **À la console** (mode distant seulement) : ouverture de session normale, puis `SecureDesk.exe disable-2fa`.
2. **Mode sans échec :** [À VÉRIFIER] Je n'ai pas trouvé de documentation officielle indiquant si un CP tiers est chargé en mode sans échec. La procédure est rédigée, puis testée en recette.
3. **Hors ligne, quel que soit le mode, méthode garantie :**
   - WinRE → Invite de commandes (**clé de récupération BitLocker nécessaire**) ;
   - `reg load HKLM\OFF C:\Windows\System32\config\SOFTWARE` ;
   - `reg add "HKLM\OFF\Classes\CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}" /v cpus_logon /t REG_SZ /d 3d /f`, puis la même commande pour `cpus_unlock` ;
   - `reg unload HKLM\OFF`.
4. **Dernier recours documenté par multiOTP :** `multiOTPCredentialProvider-unregister.reg` ou désinstallation du CP.

---

## 8. Mode client
- Pré-vérifications : droits administrateur et édition Windows (Famille acceptée).
- Installation de WireGuard (en ligne ou hors ligne, avec vérification), puis `join`.
- **Démarrage du tunnel :**
  - **automatique** : service de tunnel en démarrage automatique ;
  - **manuel** : le `.conf` est déposé dans `%ProgramFiles%\WireGuard\Data\Configurations\`, où le *manager service* le chiffre en `.conf.dpapi` [VÉRIFIÉ, `enterprise.md`]. Vous activez ensuite le tunnel d'un clic dans l'interface WireGuard. Ce mode est plus sûr que le précédent, puisque la configuration est chiffrée par DPAPI.
- **Raccourci `.rdp` sur le bureau :**
  - `full address:s:10.77.0.1:<port>`, `prompt for credentials:i:1`, `enablecredsspsupport:i:1` ;
  - redirections alignées sur celles du serveur ;
  - aucun mot de passe enregistré.
- **Test :** handshake, ping de 10.77.0.1, connexion TCP au port RDP.
- **BitLocker :** vérification de l'état et alerte forte si inactif, puisqu'il protège la clé privée en cas de vol.

---

## 9. Commandes de la ligne de commande

`SecureDesk.exe [commande] [--config fichier.json] [--dry-run] [--yes] [--verbose]`

| Commande | Rôle | Effet |
|---|---|---|
| *(aucune)* | — | assistant graphique |
| `precheck` | S/C | pré-vérifications |
| `init` | S | WireGuard, clés, tunnel, pare-feu, export de l'invitation chiffrée |
| `invite --name` | S | invitation supplémentaire |
| `add-peer <fichier>` | S | ajout d'un pair |
| `list-peers`, `revoke-peer <nom>` | S | gestion des pairs |
| `rotate-keys [--server\|--peer <nom>]` | S/C | rotation |
| `tsplus-check` | S | détection et guidage TSplus |
| `accounts` | S | création ou sélection des comptes, groupe RDP, politique de mots de passe |
| `harden` | S | durcissement RDP, audit, horloge, BitLocker (alerte) |
| `install-2fa` | S | VC++, puis MSI multiOTP CP **désactivé** (`3d`) |
| `enroll-user <compte>` | S | QR code, validation, codes de secours |
| `enable-2fa [--scope remote\|all] [--i-have-console-access]` | S | activation probatoire |
| `confirm-2fa` | S | confirmation de l'activation |
| `disable-2fa` | S | désactivation propre |
| `join <fichier>` | C | appairage client |
| `rdp-shortcut`, `test` | C | raccourci et test de connectivité |
| `diagnose [--export <fichier>]` | S/C | état et rapport sans secret |
| `report` | S | rapport final et checklist de la box |
| `uninstall [--remove-accounts]` | S/C | rollback complet (TSplus jamais supprimé) |

**Fichier JSON (`--config`) :** il contient tous les paramètres non secrets de l'assistant. Les secrets (mots de passe, phrase de passe) sont **toujours** demandés de façon interactive, ou lus depuis stdin avec `--passphrase-stdin`, jamais depuis le JSON. Un schéma JSON est publié dans `docs/`.

---

## 10. Écrans de l'assistant

**Serveur :**
1. Rôle (serveur ou client) et avertissements.
2. Pré-vérifications : feux tricolores. Les erreurs bloquantes empêchent de continuer.
3. Réseau : endpoint (IP ou DDNS), port UDP proposé, sous-réseau, accès LAN (oui/non, sous-réseau détecté).
4. WireGuard : en ligne ou MSI local, puis installation.
5. TSplus : détection, instructions et case « J'ai installé et activé TSplus ».
6. Comptes : deux comptes, créés ou existants, et politique de mots de passe.
7. Durcissement : redirections (décochées par défaut) et délais d'expiration.
8. Appairage : phrase de passe, export, conseils pour la clé USB.
9. Ajout du pair : import du fichier client, attente du handshake.
10. Rapport et checklist de la box (redirection UDP vers l'IP LAN, bail DHCP, DDNS).

**Serveur, 2FA** (accessible seulement une fois le tunnel et le RDP validés) :
- 11 : installation de multiOTP ;
- 12 : enrôlement, avec un QR code par compte ;
- 13 : portée et activation probatoire ;
- 14 : confirmation.

**Client :**
1. Rôle.
2. Fichier et phrase de passe.
3. Démarrage automatique ou manuel.
4. Installation et test.
5. Export du fichier client.
6. BitLocker et rapport.

---

## 11. Points non automatisables, ou volontairement manuels
- Achat, installation et **activation de licence** TSplus. Réglages dans l'AdminTool (serveur web, 2FA TSplus).
- Configuration de la box : redirection UDP, réservation DHCP, DDNS.
- Transfert des fichiers d'appairage sur clé USB.
- Scan du QR code avec le téléphone et conservation des codes de secours.
- Activation de BitLocker et sauvegarde de la clé de récupération.
- TSplus Portable Client Generator (option).
- Les tests réels à deux utilisateurs simultanés, d'Internet et de la box (recette manuelle).

---

## 12. Dépôt, CI et release
- **Dépôt :** `jisse154/securedesk_deploy` (il existe déjà, je travaille sur la branche `claude/hopeful-brahmagupta-hrnw5i`).
- **`ci.yml`** (sur push et PR) :
  - `windows-latest` : `dotnet build` avec warnings traités comme erreurs, analyseurs .NET et règles de sécurité CA, `dotnet format --verify-no-changes`, tests unitaires ;
  - `ubuntu-latest` : tests Core.
- **`integration.yml`** (`windows-latest`, administrateur) :
  - téléchargement et vérification du MSI WireGuard, installation silencieuse ;
  - **test réaliste : deux tunnels sur la même machine** (deux sous-réseaux, appairés via 127.0.0.1), avec handshake vérifié par `wg show` puis désinstallation ;
  - création, vérification et suppression des règles de pare-feu, contrôle d'idempotence (deux exécutions, aucun doublon) ;
  - génération des configurations, `uninstall` et vérification du retour à l'état initial.
- **multiOTP sur le runner :** installation du MSI **en mode `3d` (désactivé)**. C'est sans risque : le runner est éphémère, sans ouverture de session interactive, et le CP n'est pas actif. On teste ensuite le parcours de la CLI : `-fastcreatenopin`, `-urllink`, calcul du TOTP par le test, puis `<user> <code>` qui doit renvoyer `0`, et `-scratchlist`. On vérifie aussi les ACL et qu'aucun fichier QR ne subsiste. **L'activation (`1e`) n'est jamais testée sur le runner** : elle est simulée par des tests sur le plan de registre.
- **`release.yml`** (sur tag `v*`) :
  - `dotnet publish` en self-contained single-file win-x64 ;
  - signature Authenticode **si** les secrets `SIGNING_CERT_PFX_BASE64` et `SIGNING_CERT_PASSWORD` existent ;
  - `SHA256SUMS`, puis release GitHub.
  - Sans signature, le README documente l'avertissement SmartScreen (« Informations complémentaires → Exécuter quand même », après vérification du SHA-256).

---

## 13. Incréments prévus (une CI verte à chaque étape)
1. Squelette de la solution, CI (build, format, analyse), README minimal.
2. Core : configuration, CIDR et complément IPv4, configurations WireGuard, format `.sdpair` (cryptographie), plan de pare-feu, `.rdp`, moteur d'actions, dry-run, état et redaction. **Tests unitaires poussés.**
3. Windows : WireGuard (installation, vérification, service, clés via `wg.exe`), pare-feu, ACL. **Tests d'intégration sur le runner.**
4. Commandes `init`, `invite`, `add-peer`, `join`, `test`, `rdp-shortcut`, `revoke-peer`, `rotate-keys`, `diagnose`, `uninstall`.
5. Pré-vérifications, comptes, durcissement, audit, horloge, BitLocker, TSplus (détection et guidage), rapport et checklist de la box.
6. Assistant WinForms.
7. **multiOTP** : installation désactivée, enrôlement, activation probatoire et garde-fous, `disable-2fa`, intégration CI.
8. Documentation : `README.md`, `docs/SECURITY.md`, `docs/RECETTE.md` (en français), puis **release v1.0.0**.

---

## 14. Décisions validées (30/10/2026)
1. Nom : **SecureDesk**.
2. **.NET 10 LTS**.
3. Documentation TSplus consultée : voir le §5.
4. **Activation probatoire du 2FA** : désactivation automatique au bout de 20 min sans `confirm-2fa`.
5. **Accès LAN désactivé par défaut.**
6. **Client en mode manuel** : configuration confiée au manager WireGuard (DPAPI).

## 15. Constats vérifiés en CI (runner Windows Server 2025, build 26100)

| Point du plan | Résultat |
|---|---|
| WireGuard : MSI signé « WireGuard LLC », `DO_NOT_LAUNCH=1`, `/installtunnelservice` | **Vérifié.** Version 1.1.1 épinglée. Le service démarre de lui-même après `/installtunnelservice`, et l'outil en tient compte. |
| Handshake réel serveur ↔ client (deux tunnels sur la même machine) | **Vérifié** (`init` → `join` → `add-peer`, handshake en moins de 5 s). |
| Pare-feu COM : règles allow/block, relecture conforme, idempotence, suppression | **Vérifié.** |
| multiOTP CP 5.10.2.2 : archive officielle épinglée, **MSI signé « SysCo systemes de communication sa »** | **Vérifié.** Le MSI est signé, ce qui lève le point [À VÉRIFIER] du §7.1. La signature est désormais exigée. |
| Installation silencieuse multiOTP désactivée (`CPUS_*=3d`), valeurs de registre relues | **Vérifié.** |
| CLI multiotp : `-fastcreatenopin`, `-urllink` (URI sur stdout), `<user> <code>` = 0, rejeu refusé, `-scratchlist` | **Vérifié**, sans fichier QR résiduel. |
| `msiexec` et les propriétés vides | **Piège corrigé.** `ArgumentList` produit `PROP=\"\"`, que msiexec ne comprend pas : il reste bloqué sur sa fenêtre d'aide invisible. La ligne msiexec est donc construite selon la syntaxe Windows, avec des propriétés validées. |
| MSI multiOTP et VBScript | L'action personnalisée `cleanIntegerValues` est en VBScript (`Product.wxs`). La présence de `vbscript.dll` est vérifiée avant l'installation. |
| Rollback complet (stratégies RDP, secedit, audit, journaux, comptes, WireGuard) | **Vérifié** : valeurs identiques avant et après. |
| Aucun secret (clés privées, PSK, phrases de passe, mots de passe) dans les journaux, le rapport ou les fichiers d'appairage | **Vérifié** sur les vraies clés générées. |

**Restent à vérifier sur les vrais PC (voir RECETTE) :**
- l'activation réelle du Credential Provider (`1e`) ;
- la combinaison NLA + TSplus + multiOTP ;
- le mode sans échec ;
- les sessions simultanées TSplus ;
- l'exposition vue d'Internet.
