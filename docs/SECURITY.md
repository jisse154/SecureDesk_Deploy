# SecureDesk — Modèle de sécurité

Ce document décrit ce que SecureDesk protège, comment, et **ce qu'il ne protège pas**.

## 1. Actifs à protéger

| Actif | Où il se trouve |
|---|---|
| Données sensibles de l'entreprise | Disque du PC serveur |
| Sessions Windows des deux utilisateurs | PC serveur (TSplus / RDP) |
| Clé privée WireGuard du serveur | `%ProgramData%\SecureDesk\wireguard\securedesk.conf` (ACL SYSTEM + Administrateurs) |
| Clé privée WireGuard du client | Côté client : soit le gestionnaire WireGuard (`…\Data\Configurations\*.conf.dpapi`, chiffré DPAPI), soit un `.conf` protégé par ACL (démarrage automatique) |
| Clés pré-partagées (PSK, une par pair) | Configurations ci-dessus ; avant appairage : fichier d'invitation chiffré + magasin DPAPI machine du serveur |
| Graines TOTP | Dossiers `users` et `tokens` de multiOTP (ACL : lecture retirée aux Utilisateurs) |
| Codes de secours | Papier de l'utilisateur, et base multiOTP |

## 2. Attaquants considérés

| Attaquant | Capacités supposées |
|---|---|
| **A1. Attaquant Internet** | Scanne l'IP publique du bureau, tente RDP, du bruteforce, des failles RDP ou TSplus. |
| **A2. Voleur de mots de passe** | Connaît le mot de passe Windows d'un utilisateur (hameçonnage, réutilisation). |
| **A3. Voleur du PC client** | Dispose physiquement du PC personnel, allumé ou éteint. |
| **A4. Interception du transfert d'appairage** | Récupère le fichier `pairing-server.sdpair` (clé USB perdue, copie). |
| **A5. Utilisateur local non administrateur du serveur** | A une session sur le serveur et cherche à lire les secrets. |
| **A6. Personne présente sur le LAN du bureau** | Accès au réseau local, pas aux comptes. |

## 3. Les trois facteurs

### Facteur 1 — Clé WireGuard (possession du PC client)

- **Seul le port UDP WireGuard** est redirigé par la box. WireGuard ne répond à aucun paquet non authentifié : pour A1, le port paraît fermé et ne révèle pas le service.
- RDP et TSplus (3389, 80, 443) ne sont **jamais** redirigés. Le pare-feu du serveur :
  - les autorise seulement depuis le sous-réseau du tunnel (et du LAN si l'option est choisie) ;
  - les **bloque** depuis toute autre adresse, IPv4 et IPv6.

  La règle de blocage l'emporte sur toute autre autorisation, y compris celles ajoutées par Windows ou TSplus.
- **Authentification :**
  - paires de clés Curve25519 générées **localement** (`wg genkey`, par pipe, sans fichier temporaire ni argument de ligne de commande) ;
  - plus une **PresharedKey propre à chaque pair**, qui ajoute une couche symétrique (résistance post-quantique du handshake).
- **Split tunnel :** `AllowedIPs = 10.77.0.1/32`. Le trafic Internet du PC personnel ne passe pas par le bureau, et le client n'accède qu'à l'adresse du serveur.
- **Révocation :** `revoke-peer` retire immédiatement la clé.

*Limites :*

- un PC client compromis (malware) **pendant** une session peut agir dans cette session ;
- sans BitLocker, un PC client volé (A3) livre sa configuration chiffrée DPAPI. DPAPI est lié au compte ou à la machine : il protège surtout contre la copie du fichier vers un autre PC, pas contre un accès au disque du PC lui-même. **D'où l'alerte BitLocker côté client.**

### Facteur 2 — Mot de passe Windows

- NLA imposée (`UserAuthentication=1`) : l'authentification a lieu **avant** la création de la session.
- TLS (`SecurityLayer=2`) et chiffrement élevé (`MinEncryptionLevel=3`).
- Politique locale :
  - 14 caractères minimum, avec complexité ;
  - **verrouillage après N échecs** (5 par défaut, pendant 30 minutes).
- Deux comptes distincts, sans droit administrateur, membres du seul groupe « Utilisateurs du Bureau à distance » (identifié par SID).
- Audit : succès et échecs d'ouverture de session (4624, 4625), verrouillages, journal RDP (1149).

*Limite :* le mot de passe seul ne suffit pas. Il faut aussi le facteur 1 (accès réseau) et le facteur 3.

### Facteur 3 — Code TOTP (possession du téléphone)

- multiOTP Credential Provider en **mode local** : multiOTP est embarqué, sans serveur ni cloud. La graine ne quitte le PC qu'**une fois**, par le QR code affiché à l'écran.
- **Portée par défaut « distant seulement » (`cpus_logon = 1e`) :**
  - en session distante, le filtre multiOTP **masque tous les autres fournisseurs d'identification**. Impossible de choisir « mot de passe seul » ;
  - à la console, rien ne change.
- **SecureDesk n'utilise jamais le suffixe `d`** en activation. `1d` laisserait le fournisseur « mot de passe » disponible en RDP, et donc permettrait de contourner le TOTP. Un test unitaire le garantit.
- Aucun compte exclu (`excluded_account` vide) et aucun fournisseur additionnel (`included_providers_id` vide) : ce seraient des portes dérobées.
- Les codes ne sont valables qu'une fois : multiOTP refuse un code déjà utilisé.
- Après plusieurs échecs, multiOTP temporise puis verrouille l'utilisateur (paramètres par défaut de multiOTP).

*Limites :*

- un administrateur local du serveur peut lire les graines TOTP ;
- un utilisateur **à la console** n'a pas de TOTP en mode « distant seulement » : la protection de la console repose sur la sécurité physique du bureau et sur le mot de passe ;
- la synchronisation de l'heure est critique : une dérive de plus de 30 s est signalée et bloque l'activation.

## 4. Analyse par attaquant

| Attaquant | Ce qui l'arrête |
|---|---|
| A1 Internet | Il ne voit qu'un port UDP muet. RDP et TSplus sont injoignables (box et pare-feu). |
| A2 Mot de passe volé | Il n'a ni la clé WireGuard ni le TOTP. Ses essais verrouillent le compte et sont audités. |
| A3 PC client volé | BitLocker (recommandé et contrôlé) protège la clé, et il n'a ni mot de passe ni TOTP. Vous révoquez le pair (`revoke-peer`). |
| A4 Fichier d'appairage intercepté | Le fichier est chiffré : AES-256-GCM, avec une clé dérivée par PBKDF2-SHA256 (600 000 itérations) d'une phrase de passe de 14 caractères minimum (environ 118 bits si elle est générée). L'en-tête est authentifié, ce qui empêche d'affaiblir les paramètres. L'invitation expire au bout de 7 jours. |
| A4 bis Fichier client falsifié | Ce fichier est authentifié par un HMAC dont la clé est dérivée de la PSK : le serveur rejette toute clé publique substituée. Les **empreintes** affichées des deux côtés permettent en plus de comparer les clés. |
| A5 Utilisateur local du serveur | Configurations WireGuard, état, journaux et secrets sont protégés par ACL (SYSTEM et Administrateurs) ; le magasin des invitations est chiffré par DPAPI machine. Les dossiers multiOTP sont restreints. |
| A6 LAN | Par défaut, RDP est fermé depuis le LAN (règle de blocage). Avec l'option LAN : mot de passe + TOTP, car une connexion depuis le LAN compte comme distante. |

## 5. Secrets et journaux

- Les types `SensitiveText` et `WgSecretKey` ne s'affichent jamais. Leur `ToString()` renvoie `***` ou `(secret)`.
- Tout ce qui est écrit (journaux, rapports, console de l'assistant) passe par un **filtre de masquage** des formes de secrets : clés WireGuard, lignes `PrivateKey` et `PresharedKey`, URI `otpauth://`, graines base32 et hexadécimales, `password=` et formules proches.
- La sortie de `multiotp -urllink` (qui contient la graine) n'est **jamais** journalisée. La graine ne passe pas en argument de ligne de commande (`-createga` n'est pas utilisé).
- Le QR code est rendu **en mémoire** et effacé de l'écran après lecture. Aucun fichier QR n'est créé ; `diagnose` vérifie qu'il n'en reste aucun.
- Des tests automatisés vérifient l'absence de secrets :
  - tests unitaires : `NoSecretLeakTests` ;
  - scénario de bout en bout sur Windows : clés réelles recherchées dans les journaux, le rapport et les fichiers d'appairage.

## 6. Intégrité de la chaîne d'installation

- **WireGuard :** MSI officiel, signature Authenticode « WireGuard LLC » vérifiée, empreinte SHA-256 épinglée dans l'exécutable au moment de la release (CI).
- **multiOTP CP :** archive officielle à l'empreinte épinglée, et MSI signé « SysCo systemes de communication sa ». Après installation, la signature de la DLL du Credential Provider et de `multiotp.exe` est vérifiée **avant** toute activation.
- **VC++ Redistributable :** signature « Microsoft Corporation » exigée.
- **TSplus :** jamais téléchargé par SecureDesk. Un installeur fourni n'est exécuté (`/verysilent`) que s'il est correctement signé.
- **SecureDesk lui-même :**
  - `SHA256SUMS` publié avec chaque release ;
  - signature Authenticode en CI si un certificat est fourni (sinon, avertissement SmartScreen documenté) ;
  - aucune dépendance réseau tierce à l'exécution. Dépendances embarquées : bibliothèques Microsoft et QRCoder (MIT).

## 7. Anti-verrouillage (2FA)

1. Installation du Credential Provider **désactivé** (`3d`).
2. Activation refusée si l'une de ces conditions est remplie :
   - lancement en session distante (sauf `--i-have-console-access`) ;
   - aucun administrateur enrôlé **et vérifié** ;
   - un compte RDP non enrôlé ;
   - aucun administrateur local utilisable ;
   - signature de la DLL invalide ;
   - dérive d'horloge de plus de 30 s ;
   - outil absent de `Program Files`.
3. **Activation probatoire :** une tâche SYSTEM, créée *avant* l'activation, désactive le 2FA après 20 minutes sans `confirm-2fa`.
4. Récupération : `disable-2fa` à la console, mode sans échec, édition hors ligne du registre via WinRE (voir README §11).

## 8. Limites connues et risques résiduels

- **Machine serveur compromise** (malware avec droits administrateur) : aucun des trois facteurs ne protège des données déjà accessibles sur la machine.
- **TSplus** est un logiciel tiers dans la chaîne RDP. Il est maintenu à jour par vous (`AdminTool.exe /update`). Son serveur web est arrêté et ses ports sont fermés hors tunnel.
- **Console du serveur** en mode « distant seulement » : mot de passe seul. Choisissez « distant et local » si la sécurité physique du bureau est insuffisante, en connaissant le risque de verrouillage.
- **Effacement des fichiers d'appairage :** sur SSD et clé USB, l'effacement physique n'est pas garanti. Formatez la clé USB après usage. Le fichier serveur reste chiffré dans tous les cas.
- **Codes de secours :** quiconque détient le papier et le mot de passe, avec accès au tunnel, peut se connecter. Rangez-les comme une clé.
- **Comptes administrateurs :** les administrateurs locaux peuvent tout désactiver. Gardez leur nombre au minimum et ne les utilisez pas pour le travail courant.
- Sur Windows, **RDP écoute sur toutes les interfaces**. L'isolation repose sur le pare-feu et la box, et `diagnose` vérifie les règles effectives. SecureDesk ne lie pas RDP à l'interface du tunnel (`LanAdapter`), car ce réglage rendrait la console de secours RDP inaccessible si le tunnel tombait.
