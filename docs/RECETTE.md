# SecureDesk — Recette sur les vrais PC

Ces tests ne peuvent pas être automatisés en CI : box Internet, vraies sessions RDP, Credential Provider actif. Faites-les **dans l'ordre**. Notez pour chacun : date, résultat (OK / KO) et remarques. En cas de KO, joignez la sortie de `SecureDesk.exe diagnose --export rapport.txt`, qui ne contient aucun secret.

**Prérequis :**

- un téléphone en **4G/5G, Wi-Fi coupé**, pour tester depuis l'extérieur ;
- le PC client connecté à un autre réseau que celui du bureau (domicile ou partage de connexion) ;
- **l'accès physique à la console du serveur** pendant toute la partie 2FA ;
- la clé de récupération BitLocker du serveur.

Les tests marqués ⭐ sont **prioritaires**.

---

## A. Installation et tunnel

| # | Test | Résultat attendu |
|---|---|---|
| R-INST-1 | Lancer `SecureDesk.exe init --dry-run --config …` sur le serveur | Liste « à faire » ; **aucune** modification (pas de règle `SecureDesk-*` dans `wf.msc`, pas de service WireGuard). |
| R-INST-2 | Assistant serveur, pages 1 à 6 | Pré-vérifications cohérentes (Windows 11 Pro, TSplus détecté, IP LAN correcte). Déploiement sans erreur. Fichier `pairing-server.sdpair` créé. |
| R-INST-3 | Relancer le déploiement (page 6) | Tout est « déjà conforme », sans doublon de règle (`Get-NetFirewallRule -DisplayName 'SecureDesk-*'`, 5 règles sans LAN, 7 avec LAN). |
| R-INST-4 | Ouvrir `pairing-server.sdpair` dans le Bloc-notes | Fichier JSON avec des champs chiffrés : aucune clé, aucun endpoint en clair. |
| R-INST-5 | Client : `join`, avec une **mauvaise** phrase de passe, puis la bonne | Refus clair, puis succès. L'empreinte affichée est identique à celle du serveur. |
| R-INST-6 | Serveur : `add-peer` | « Handshake réussi ». `list-peers` montre le pair avec un handshake récent. |
| R-INST-7 ⭐ | Client : `test` | Tunnel actif, handshake récent, RDP `10.77.0.1:3389` joignable. |
| R-INST-8 | Client en mode **manuel** : redémarrer le PC client | Le tunnel est inactif au démarrage. Il s'active depuis l'icône WireGuard. Le fichier de `C:\Program Files\WireGuard\Data\Configurations` est un `.conf.dpapi` (pas de `.conf` en clair). |
| R-INST-9 | Serveur : redémarrer le PC serveur | Le tunnel remonte seul (service automatique) et le client se reconnecte en moins de 30 s. |
| R-INST-10 | Client : `ipconfig` / `route print` tunnel actif | Seule une route `10.77.0.1/32` passe par le tunnel. La navigation Internet du PC perso ne passe **pas** par le bureau : comparez l'IP publique sur un site « quelle est mon IP » tunnel actif et inactif, elle ne change pas. |

## B. Exposition sur Internet

| # | Test | Résultat attendu |
|---|---|---|
| R-NET-1 ⭐ | Depuis le téléphone en 4G (appli de scan de ports, ex. « Fing » ou « Net Analyzer »), scanner l'IP publique du bureau en TCP sur 3389, 80, 443 et 1-1024 | **Aucun port TCP ouvert**. |
| R-NET-2 ⭐ | Même téléphone, client RDP mobile vers `IP-publique:3389` | Échec (délai dépassé). |
| R-NET-3 | Scanner le port UDP WireGuard | Aucune réponse : comportement normal de WireGuard, qui ne répond qu'aux pairs authentifiés. |
| R-NET-4 | Interface de la box | Une seule redirection (UDP `<port>` vers l'IP LAN du serveur), pas de DMZ, UPnP désactivé si possible. |
| R-NET-5 ⭐ | **Tunnel coupé** (client : désactiver le tunnel) puis ouvrir le raccourci `.rdp` | **Échec** de la connexion. |
| R-NET-6 | Depuis un autre PC du LAN du bureau, `mstsc` vers l'IP LAN du serveur | Sans l'option LAN : échec. Avec l'option LAN : invite de mot de passe (et TOTP si le 2FA est actif). |

## C. Sessions simultanées (TSplus)

| # | Test | Résultat attendu |
|---|---|---|
| R-SES-1 ⭐ | Utilisateur 1 connecté à distance via le tunnel ; utilisateur 2 connecté (à distance ou en RDP depuis le LAN si autorisé) **en même temps** | Deux sessions indépendantes. **Aucune ne déconnecte l'autre.** Vérifier avec le Gestionnaire des tâches → Utilisateurs. |
| R-SES-2 | Utilisateur 2 à la **console** pendant que l'utilisateur 1 est à distance | Les deux sessions coexistent (comportement TSplus, à confirmer selon votre licence et édition TSplus). |
| R-SES-3 | Copier-coller entre le PC perso et la session (redirections désactivées par défaut) | Le presse-papiers ne passe pas, les lecteurs du PC perso ne sont pas visibles, pas d'imprimante redirigée. |
| R-SES-4 | Laisser une session inactive au-delà du délai, puis une session déconnectée au-delà du délai | Session inactive déconnectée, puis session déconnectée fermée. |
| R-SES-5 | 5 mots de passe faux sur un compte | Compte verrouillé (événement 4740 / 4625), déverrouillé après 30 min. |
| R-SES-6 | Observateur d'événements | Sécurité : 4624 (type 10 = RDP) et 4625. *Applications et services → Microsoft → Windows → TerminalServices-RemoteConnectionManager → Operational* : 1149. |

## D. Double authentification (à la console du serveur)

**Avant de commencer :** codes de secours imprimés, mot de passe administrateur local connu, clé BitLocker disponible.

| # | Test | Résultat attendu |
|---|---|---|
| R-2FA-1 ⭐ | `install-2fa` | multiOTP installé. `diagnose` : multiOTP **inactif**, `cpus_logon=3d`, DLL signée. Aucune connexion ne demande de TOTP. |
| R-2FA-2 ⭐ | `enroll-user <admin>`, puis chaque compte RDP | QR code scanné, premier code accepté, codes de secours affichés. **Point non documenté à vérifier :** l'enrôlement utilise le **nom court** du compte local. Le test R-2FA-5 valide que le Credential Provider retrouve bien l'utilisateur sous ce nom. |
| R-2FA-3 | `enable-2fa` lancé depuis une **session RDP** | **Refusé** (session à distance). |
| R-2FA-4 ⭐ | **NLA + TSplus + multiOTP (doubles invites).** À la console : `enable-2fa` (distant seulement). Depuis le client : ouvrir le raccourci `.rdp`. | **Configuration retenue :** NLA actif, `fPromptForPassword` non défini par SecureDesk, `.rdp` avec CredSSP, multiOTP `two_step_hide_otp=1`, version ≥ 5.10.1.2. **Attendu :** mstsc demande le mot de passe (NLA), puis l'écran du serveur ne demande **que** le code TOTP. **À noter :** la documentation TSplus indique « TSplus Remote Access will require you to manually enter your username and password at each login ». Si le mot de passe est redemandé côté serveur, c'est ce comportement de TSplus. Vérifiez alors la valeur `fPromptForPassword` dans `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` et dans `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`. **Ne désactivez pas NLA** : une double saisie du mot de passe est acceptable, l'absence de NLA ne l'est pas. Consignez le comportement observé. |
| R-2FA-5 ⭐ | Connexion distante : bon mot de passe, **code TOTP faux** | **Refus.** |
| R-2FA-6 ⭐ | Connexion distante : bon mot de passe, **code TOTP valide** | **Succès.** |
| R-2FA-7 | Connexion distante avec un **code de secours** | Succès une fois ; le même code est refusé la fois suivante. |
| R-2FA-8 ⭐ | Ouverture de session **locale à la console** (mode « distant seulement ») | **Aucun code TOTP demandé.** Les fournisseurs habituels (mot de passe, PIN) restent disponibles. |
| R-2FA-9 | Ne **pas** lancer `confirm-2fa` et attendre l'échéance de la période probatoire | Le 2FA se désactive seul. `diagnose` indique « inactif ». Réactivez, testez, puis lancez `confirm-2fa`. |
| R-2FA-10 ⭐ | À la console : `disable-2fa` | Connexion distante **sans** TOTP, qui fonctionne. Réactivez ensuite. |
| R-2FA-11 | Mode sans échec (README §11-C) | Notez si l'écran multiOTP apparaît ou non en mode sans échec. Ce comportement n'est pas documenté par multiOTP. Si oui, utilisez la procédure §11-D. |
| R-2FA-12 | Procédure WinRE (README §11-D) sur une **fenêtre de maintenance** | Après redémarrage, le 2FA est désactivé. Réactivez ensuite. |
| R-2FA-13 | Décaler l'heure du serveur de 2 minutes, puis lancer `diagnose` | La dérive de plus de 30 s est signalée. Rétablissez avec `harden` ou `w32tm /resync`. |
| R-2FA-14 | Portée « distant et local » (optionnel) | La console exige aussi le TOTP. Revenez à « distant seulement » si ce n'est pas souhaité. |
| R-2FA-15 | Après chaque enrôlement : rechercher `*.png`, `*.svg` et les fichiers `*qr*` dans `C:\Program Files\multiOTP` et `%TEMP%` | Aucun fichier. `diagnose` : « Fichiers QR résiduels : aucun ». |

## E. Secrets et journaux

| # | Test | Résultat attendu |
|---|---|---|
| R-SEC-1 ⭐ | Ouvrir `%ProgramData%\SecureDesk\logs\*.log`, le rapport `diagnose --export` et les deux fichiers `.sdpair` ; y chercher `PrivateKey`, `PresharedKey`, `otpauth`, `secret=` | Aucun résultat, ou uniquement `[MASQUÉ]`. |
| R-SEC-2 | Avec un compte **non administrateur** du serveur, tenter d'ouvrir `C:\ProgramData\SecureDesk\wireguard\securedesk.conf` et `C:\Program Files\multiOTP\users` | Accès refusé. |
| R-SEC-3 | Vérifier BitLocker sur les deux PC (`manage-bde -status`) | Actif, ou l'alerte de SecureDesk a été vue et traitée. |

## F. Maintenance et réappairage

| # | Test | Résultat attendu |
|---|---|---|
| R-MNT-1 ⭐ | **Réappairage chronométré :** simuler un client réinstallé (`uninstall` sur le client), puis serveur `revoke-peer pc-perso` et `invite --name pc-perso`, client `join`, serveur `add-peer` | Connexion RDP rétablie en **moins de 10 minutes**. |
| R-MNT-2 | `revoke-peer` sur un client connecté | Le tunnel tombe pour ce client, sa reconnexion échoue. |
| R-MNT-3 | `rotate-keys --peer pc-perso`, puis `join` et `add-peer` | La connexion fonctionne avec la nouvelle PSK. |
| R-MNT-4 | Changer l'IP publique (ou simuler via DDNS) | Le client se reconnecte via le nom DDNS sans réappairage. |

## G. Désinstallation

| # | Test | Résultat attendu |
|---|---|---|
| R-UNI-1 | Noter avant déploiement : `net accounts`, `auditpol /get /category:*`, `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"` | Valeurs de référence. |
| R-UNI-2 ⭐ | `uninstall` (serveur), puis `uninstall` (client) | Plus de règle `SecureDesk-*`, plus de tunnel ni de multiOTP, WireGuard désinstallé s'il avait été installé par SecureDesk. Valeurs R-UNI-1 **identiques**. **TSplus et les comptes sont toujours présents.** |
| R-UNI-3 | `uninstall --remove-accounts` | Les comptes créés par SecureDesk sont supprimés (les profils `C:\Users\…` restent, à supprimer manuellement si souhaité). |

---

## Correspondance avec les critères d'acceptation

| Critère | Tests |
|---|---|
| Deux sessions simultanées sans déconnexion mutuelle | R-SES-1, R-SES-2 |
| Seul le port UDP WireGuard répond vu d'Internet | R-NET-1, R-NET-2, R-NET-3, R-NET-4 |
| Tunnel coupé = RDP impossible | R-NET-5 |
| Mot de passe sans TOTP valide = échec ; avec TOTP = succès | R-2FA-5, R-2FA-6 |
| Console sans TOTP en mode « distant seulement » | R-2FA-8 |
| `disable-2fa` à la console rétablit l'accès | R-2FA-10 |
| Aucune clé privée, graine ni QR dans les logs, rapports et fichiers d'appairage | R-SEC-1, R-2FA-15 (et tests automatisés en CI) |
| Réappairage en moins de 10 min | R-MNT-1 |
| Désinstallation = état initial (hors comptes et TSplus) | R-UNI-1, R-UNI-2 (et scénario de bout en bout en CI) |
