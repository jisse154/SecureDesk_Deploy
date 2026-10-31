# SecureDesk v2 — Remplacement de WireGuard direct par Tailscale

> Statut : **proposition, à valider** (31/10/2026). Ce document décrit uniquement ce qui change par rapport à [`PLAN.md`](PLAN.md) (v1.0.0). Une fois validé et implémenté, son contenu sera fusionné dans `PLAN.md` et `SECURITY.md`.
>
> **Sources.** Le site `tailscale.com` est bloqué par la politique réseau de ma session. Les mentions **[VÉRIFIÉ — source]** renvoient donc au **code source officiel de Tailscale v1.104.4** (module Go `tailscale.com`, commit `27047635`), lu fichier par fichier. Ce qui relève du service en ligne (console d'administration, offres, expiration des clés) n'est pas dans le code client : c'est marqué **[À VÉRIFIER]** et devient un point de la CI ou de la recette.

---

## 1. Pourquoi ce changement

En v1, le seul point d'entrée est un **port UDP redirigé par la box** vers le serveur. Or **aucune redirection n'est possible** sur votre box. Il faut donc une solution où **les deux PC n'ouvrent que des connexions sortantes**.

**Principe de Tailscale :**
- chaque PC se connecte en sortie au **serveur de coordination** de Tailscale, qui ne fait que distribuer les clés publiques et les adresses ;
- les deux PC établissent ensuite un **tunnel WireGuard de bout en bout**, en direct si la traversée de NAT réussit ;
- sinon, le trafic passe par un **relais DERP en HTTPS (TCP 443)**. Le relais ne voit que du trafic chiffré.

**Conséquences :**
- **aucune redirection de port sur la box**, et l'accès fonctionne aussi derrière un CGNAT ;
- côté client, ça passe sur les réseaux qui n'autorisent que le web (443).

**Ce qu'on gagne en sécurité :** l'IP publique du bureau n'expose plus **rien**, même pas un port UDP muet.

**Ce qu'on perd :** un **tiers de confiance** (Tailscale Inc.) et votre **compte d'identité** (Google, Microsoft, GitHub…) entrent dans la chaîne. Le §6 traite ce point.

**Ce qui ne change pas :** NLA, durcissement RDP, comptes, multiOTP, TSplus, le moteur d'actions, l'état, les journaux et l'anti-verrouillage. Le pare-feu change peu (§4).

---

## 2. Installation et réglage de Tailscale sur Windows

### 2.1 Installation
- **MSI officiel** depuis `pkgs.tailscale.com/stable/` (dernière version stable, x64), en suivant la même chaîne que WireGuard en v1 :
  - URL, version et SHA-256 **épinglés par la CI** dans `installers.json` (`scripts/pin-installers.ps1`) ;
  - signature Authenticode vérifiée avant `msiexec /i … /qn /norestart`.
  - **[À VÉRIFIER en CI]** le nom de l'éditeur signataire (attendu : « Tailscale Inc. »). Les propriétés MSI documentées (`TS_UNATTENDEDMODE`, etc.) ne sont pas dans le code open source : je **ne m'appuie pas dessus** et j'utilise les stratégies système du §2.2, qui sont vérifiées.
- **Mode hors ligne** : `--tailscale-msi <chemin>`, avec les mêmes vérifications.
- **Service Windows** : `Tailscale` [VÉRIFIÉ — `cmd/tailscaled/tailscaled_windows.go`]. Démarrage automatique.
- **[À VÉRIFIER en CI]** le chemin de `tailscale.exe` (attendu : `%ProgramFiles%\Tailscale\tailscale.exe`).

### 2.2 Stratégies système (équivalent GPO)

Les valeurs sont écrites sous `HKLM\SOFTWARE\Policies\Tailscale` [VÉRIFIÉ — `util/syspolicy/source/policy_store_windows.go`], avec sauvegarde de l'origine pour le rollback. Les valeurs texte acceptent `always`, `never` ou `user-decides` [VÉRIFIÉ — `util/syspolicy/pkey/pkey.go`]. Une valeur `always` ou `never` retire le choix à l'utilisateur, ce qui empêche un utilisateur non administrateur de défaire le réglage depuis l'interface.

| Clé | Serveur | Client | Effet [VÉRIFIÉ — `ipn/ipnlocal/local.go`] |
|---|---|---|---|
| `UnattendedMode` | `always` | `user-decides` | `ForceDaemon` : Tailscale reste connecté **sans session ouverte** et après la déconnexion de l'utilisateur. **Indispensable** pour un serveur allumé en permanence. |
| `AllowIncomingConnections` | `always` | `never` | Inverse de `ShieldsUp`. Le client **refuse toute connexion entrante** : il ne fait qu'appeler le serveur. |
| `UseTailscaleSubnets` | `never` | `never` | `RouteAll` désactivé. **Attention : la valeur par défaut est `true` sous Windows** [VÉRIFIÉ — `ipn/prefs.go`, `DefaultRouteAll`]. On évite ainsi qu'une route annoncée dans le tailnet détourne le trafic local d'un des PC. |
| `UseTailscaleDNSSettings` | `never` | `never` | Le DNS des PC n'est pas modifié. Le `.rdp` vise l'**adresse IP** Tailscale du serveur, sans dépendance à MagicDNS. |
| `AdvertiseExitNode` | `never` | `never` | Aucun des deux PC ne sert de sortie Internet. |
| `EncryptState` (DWORD 1) | si TPM | si TPM | Chiffre l'état de Tailscale, donc la clé privée du nœud, **avec le TPM**. Désactivé par défaut sous Windows et lu **au démarrage du service** [VÉRIFIÉ — `cmd/tailscaled/tailscaled.go`, `canEncryptState`]. **[À VÉRIFIER en CI]** la migration d'un état existant : on pose donc la stratégie **avant** la première connexion. |
| `InstallUpdates` | `always` | `always` | Mises à jour automatiques (signées par Tailscale). Décision à valider (§9). |

Les mêmes réglages sont aussi passés à `tailscale up` [VÉRIFIÉ — `cmd/tailscale/cli/up.go`] : `--unattended` (Windows uniquement), `--shields-up`, `--accept-routes=false`, `--accept-dns=false` et `--hostname`.

### 2.3 Connexion au tailnet
- **Prérequis manuel :** créer **un compte Tailscale dédié** (offre gratuite « Personal ») avec un fournisseur d'identité protégé par une **passkey ou une clé de sécurité**. Ce compte devient un actif critique (§6).
- **Connexion interactive** sur chaque PC :
  - l'outil lance `tailscale up …` puis affiche l'URL de connexion **et un QR code** (`--qr`, [VÉRIFIÉ]). Vous pouvez donc vous authentifier **depuis votre téléphone**, sans saisir le mot de passe du compte sur le serveur ;
  - l'outil attend ensuite `BackendState = "Running"` dans `tailscale status --json` [VÉRIFIÉ — `ipn/ipnstate/ipnstate.go`].
  - L'URL n'est jamais journalisée (nouveau motif dans le filtre de masquage).
- **Clé d'authentification** (`--auth-key file:<chemin>`, [VÉRIFIÉ]) : **non retenue** par défaut. C'est un secret de plus à manipuler, alors que la connexion interactive n'en demande aucun.

### 2.4 Expiration de la clé du nœud — risque de verrouillage
- Côté serveur, Tailscale enregistre une date d'expiration de la clé du nœud (`Self.KeyExpiry`, [VÉRIFIÉ]). **[À VÉRIFIER]** la durée par défaut (180 jours selon la documentation, non consultable ici).
- **Si la clé du serveur expire, le serveur sort du tailnet et l'accès à distance est perdu jusqu'à une intervention à la console.**
- **Garde-fou :**
  - l'assistant impose une étape manuelle : console d'administration → *Machines* → serveur → **« Disable key expiry »** ;
  - `diagnose` et `report` lisent `Self.KeyExpiry` : une valeur présente est une **erreur** côté serveur, avec une alerte à J-30 ;
  - l'activation du 2FA (`enable-2fa`) est **refusée** tant que l'expiration du serveur n'est pas désactivée.
- Côté client, l'expiration est **conservée** : il suffit de se reconnecter depuis le PC personnel, sans aucun risque de verrouillage.

---

## 3. Appairage sans fichier

Les fichiers `.sdpair`, la phrase de passe, les PSK et les invitations **disparaissent** : Tailscale distribue lui-même les clés publiques.

En revanche, **l'appartenance au tailnet ne suffit pas pour atteindre RDP**. Le serveur **approuve chaque PC client un par un**, et le pare-feu n'autorise que les adresses approuvées (§4). C'est l'équivalent de l'ajout d'un `[Peer]` en v1.

### 3.1 Identité d'un pair
Pour chaque pair approuvé, `state.json` enregistre :
- l'identifiant stable du nœud (`ID`) ;
- sa clé publique (`PublicKey`, `nodekey:…`) ;
- son adresse IPv4 Tailscale (`TailscaleIPs`, plage `100.64.0.0/10`) ;
- son nom (`HostName`).

Tous ces champs viennent de `tailscale status --json` [VÉRIFIÉ — `ipnstate.PeerStatus`]. La sortie JSON est signalée « susceptible de changer » par Tailscale : la lecture est **tolérante** (champs facultatifs) et testée en CI sur la version épinglée.

### 3.2 Flux
1. **Serveur, `init` :**
   - installation, stratégies système, `tailscale up --unattended --hostname <server.hostname>`, connexion ;
   - pare-feu : RDP fermé à tous sauf aux pairs approuvés (aucun au départ) ;
   - affichage de l'**empreinte** du serveur ;
   - checklist : désactiver l'expiration de la clé du serveur, coller la politique d'accès (§5), **supprimer toute ancienne redirection de la box**.
2. **Client, `join` :**
   - installation, stratégies, `tailscale up --shields-up --hostname <client.hostname>`, connexion **avec le même compte** ;
   - recherche du serveur par son nom parmi les pairs. L'empreinte du serveur s'affiche et vous la comparez avec celle affichée sur le serveur ;
   - le client enregistre l'adresse et la clé du serveur, crée le `.rdp`, puis affiche **sa propre empreinte**.
3. **Serveur, `add-peer <nom>` :**
   - le pair doit être présent et connecté ; son empreinte s'affiche et vous la comparez avec celle du client ;
   - après confirmation : enregistrement du pair, mise à jour du pare-feu, puis, si Tailnet Lock est actif, signature du nœud (§5.2) ;
   - test de joignabilité (`tailscale ping`).
4. **Maintenance :**
   - `list-peers` ;
   - `revoke-peer <nom>` : retire **immédiatement** l'adresse du pare-feu. La révocation ne dépend donc pas de Tailscale. Elle est complétée par la suppression du nœud dans la console, une instruction affichée.
   - `rotate-keys` et `invite` **disparaissent** : Tailscale renouvelle les clés de nœud à chaque réauthentification. `--force-reauth` est **exclu** à distance, car il coupe la connexion en cours [VÉRIFIÉ — avertissement dans `up.go`].

### 3.3 Contrôle d'usurpation
Le pare-feu filtre par **adresse IP**, pas par clé. À chaque `diagnose`, et par une **tâche planifiée SYSTEM** toutes les 15 minutes (option, activée par défaut), le serveur vérifie que chaque adresse approuvée appartient toujours à la clé et à l'identifiant enregistrés.

En cas d'écart (nœud remplacé, adresse réattribuée dans la console) :
- la règle *allow* de cette adresse est **retirée** ;
- un événement est journalisé.

Côté client, `test` vérifie de la même façon la clé du serveur. Le certificat TLS de RDP, que mstsc vérifie, reste une seconde barrière.

**Réappairage d'un client réinstallé** : `revoke-peer`, puis `join` sur le client, puis `add-peer`. Plus de fichier ni de phrase de passe ; l'objectif reste moins de 10 minutes.

---

## 4. Pare-feu Windows du serveur

**Constat [VÉRIFIÉ — `wgengine/router/osrouter/router_windows.go`] :** sous Windows, Tailscale crée lui-même deux règles :
- **`Tailscale-In`** : autorise **tout** le trafic entrant vers l'adresse Tailscale locale, sur les profils privé et domaine ;
- **`Tailscale-Process`** : autorise l'UDP entrant vers `tailscaled.exe`.

Sans autre mesure, **tout appareil du tailnet** pourrait donc atteindre RDP, et TSplus sur 80 et 443. La stratégie v1 (règle *block* sur le complément, qui l'emporte toujours) répond exactement à ce cas. Seule la plage autorisée change :

| v1 | v2 |
|---|---|
| `SecureDesk-Allow-RDP-Tunnel` depuis `10.77.0.0/24` | `SecureDesk-Allow-RDP-Peers` depuis les **adresses `/32` des pairs approuvés** (aucune au départ) |
| `SecureDesk-Block-RDP-Others` : complément IPv4 + tout IPv6 | **Inchangé.** Il bloque aussi le reste du tailnet et les adresses IPv6 Tailscale (`fd7a:115c:a1e0::/48`). Le `.rdp` vise l'IPv4. |
| `SecureDesk-Allow-WireGuard-UDP` | **Supprimée** : rien à ouvrir en entrée. |
| Accès LAN en option | Inchangé. Le LAN ne doit pas chevaucher `100.64.0.0/10`. |

Si **aucun pair** n'est approuvé, RDP est fermé à tout le réseau, sauf au LAN si l'option est active. La console reste disponible. Les règles de Tailscale ne sont **jamais** modifiées : Tailscale les recrée lui-même. `diagnose` signale toute règle *allow* effective sur les ports protégés plus large que les pairs ou le LAN, comme en v1.

---

## 5. Défense en profondeur côté Tailscale

### 5.1 Politique d'accès du tailnet (manuelle)
La politique par défaut d'un tailnet autorise tout entre tous les appareils. `report` génère un extrait prêt à coller dans la console d'administration (*Access controls*), avec les vraies adresses :
- seuls les clients approuvés atteignent le serveur, uniquement sur le port RDP ;
- rien n'atteint les clients.

Ce n'est **pas** la protection principale (c'est le pare-feu du §4), mais cela réduit ce qu'un appareil indésirable du tailnet peut voir. **[À VÉRIFIER]** la syntaxe exacte (`grants`) et sa disponibilité dans l'offre gratuite : documentation inaccessible depuis ma session.

### 5.2 Tailnet Lock (recommandé)
Sans Tailnet Lock, le serveur de coordination, ou quiconque contrôle votre compte, peut **ajouter un nœud** au tailnet. Avec Tailnet Lock, **un nœud n'est accepté que s'il est signé par une clé de confiance détenue par vos propres PC**. C'est la parade à la compromission du compte ou de Tailscale lui-même.

**Commande prévue :** `lock-init` (serveur), qui exécute `tailscale lock init --gen-disablements 2 <clé du serveur> <clé du client>` [VÉRIFIÉ — `cmd/tailscale/cli/tailnet-lock.go`].
- **Codes de désactivation :** il en faut au moins un (on en génère deux). Ils s'affichent **une seule fois**, à noter sur papier comme les codes de secours multiOTP, et ne sont **jamais** journalisés.
- **Option de support :** `--gen-disablement-for-support` transmettrait un code de désactivation à Tailscale (récupération facilitée, mais Tailscale pourrait alors lever le verrou). **Non utilisé par défaut** ; décision à valider (§9).
- **Signature des pairs :** `add-peer` signe chaque nouveau pair (`tailscale lock sign nodekey:…`). `diagnose` lit `tailscale lock status --json` [VÉRIFIÉ].
- **[À VÉRIFIER]** la disponibilité dans l'offre gratuite et la version minimale requise.

### 5.3 Fonctions Tailscale à garder désactivées
Ces deux fonctions exposeraient un service local au tailnet, voire à Internet. `diagnose` vérifie que `tailscale serve status --json` et `tailscale funnel status --json` [VÉRIFIÉ — `serve_v2.go`] ne renvoient **aucune** configuration. Sinon, c'est une erreur.

---

## 6. Modèle de sécurité — ce qui change (à reporter dans `SECURITY.md`)

**Facteur 1, redéfini : « PC client approuvé ».** Pour atteindre RDP, il faut à la fois :
- un nœud du tailnet (clé privée WireGuard du nœud, **chiffrée par le TPM** si disponible) ;
- **et** une adresse explicitement approuvée par le pare-feu du serveur ;
- **et**, avec Tailnet Lock, une signature de vos propres clés.

Les facteurs 2 (mot de passe Windows, NLA) et 3 (TOTP multiOTP) sont **inchangés**.

| Attaquant | v2 |
|---|---|
| A1 Internet | **Rien n'est exposé** sur l'IP publique : aucune redirection. |
| A3 PC client volé | Clé du nœud chiffrée par le TPM et BitLocker. Révocation immédiate par `revoke-peer` (pare-feu), plus la suppression du nœud dans la console. |
| A4 Interception de l'appairage | **Sans objet** : aucun fichier ni secret à transférer. Restent la comparaison des empreintes et l'approbation explicite. |
| **A7 (nouveau) Compte Tailscale ou fournisseur d'identité compromis** | Il peut ajouter un appareil au tailnet, mais **son adresse n'est pas approuvée** par le pare-feu. Il peut aussi tenter de réattribuer l'adresse d'un pair [À VÉRIFIER : possible depuis la console] : le contrôle d'usurpation (§3.3) le détecte et ferme l'accès. **Tailnet Lock** l'empêche en amont. Il lui faudrait de toute façon encore le mot de passe et le TOTP. **Parade principale : passkey sur le compte.** |
| **A8 (nouveau) Tailscale Inc. (compromis ou contraint)** | Même analyse que A7 ; Tailnet Lock est conçu pour ce cas. Le contenu reste chiffré de bout en bout. Tailscale voit en revanche les **métadonnées** : quels nœuds, quand, depuis quelles IP publiques. |
| A6 LAN | Inchangé. |

**Nouveaux risques résiduels :**
- **Disponibilité** : une panne du service de coordination peut empêcher de nouvelles connexions.
- **Expiration de la clé du serveur** : verrouillage à distance si elle n'est pas désactivée (§2.4, garde-fous).
- **Mises à jour** : une mise à jour automatique défectueuse pourrait couper l'accès à distance.
- **Interface Tailscale dans les sessions TSplus** : **[À VÉRIFIER en recette]** qu'un utilisateur non administrateur, depuis sa session distante, ne peut ni déconnecter Tailscale ni changer de compte. La stratégie `UnattendedMode=always` va dans ce sens ; la stratégie `AlwaysOn.Enabled` existe mais est marquée **expérimentale** dans le code [VÉRIFIÉ — `pkey.go`] et n'est donc pas utilisée.
- **TSplus « Deny access from Outside »** : la documentation officielle dit seulement « only private IPs from LAN will be able to open a session », sans lister les plages (pages consultées le 31/10/2026 : `securing-a-terminal-service-plus-server`, `advanced-features-security`). Or `100.64.0.0/10` n'est **pas** une plage privée au sens de la RFC 1918. **[À VÉRIFIER en recette]** Si TSplus refuse les adresses 100.x, cette option doit rester **désactivée** ; le filtrage `/32` du pare-feu la remplace. L'instruction affichée par `tsplus-check` sera ajustée.

---

## 7. Impact sur le code

| Zone | Action |
|---|---|
| `Core/WireGuard/*`, `Core/Pairing/PairingFile.cs`, génération de clés et PSK dans `Core/Security/Keys.cs`, phrase de passe | **Supprimés** (environ 1 400 lignes avec leurs tests, `WireGuardOps.cs` compris). |
| `Core/Tailscale/` (nouveau) | Lecture tolérante de `status --json` et `lock status --json`, modèle de pair approuvé, plan des stratégies système, génération de l'extrait de politique d'accès, contrôle d'usurpation (logique pure, testée sous Linux). |
| `Windows/Tailscale/TailscaleOps.cs` (nouveau, remplace `WireGuardOps.cs`) | Installation (Authenticode, SHA-256), stratégies du registre, `up`, `status`, `ping`, `lock`, `serve` et `funnel status`, `logout`. |
| `Core/Firewall/FirewallPlan.cs` | Liste de `/32` au lieu d'un sous-réseau ; suppression de la règle UDP. |
| `ServerOps`, `ClientOps`, `Diagnostics`, `Uninstaller`, `Checks`, `Commands`, `MainForm` | Flux du §3.2, nouveaux contrôles, écrans « Réseau » et « Appairage » simplifiés (plus de port, d'endpoint DDNS ni de phrase de passe). |
| `Config`, `State` | `server.hostname`, `client.hostname`, `client.serverHostname`. Suppression de `endpointHost`, `listenPort`, `tunnelSubnet`, des invitations et des PSK. **Version de l'état portée à 2.** |
| `Logging/Redactor.cs` | Nouveaux motifs : `tskey-…` (clés d'authentification et d'API), URL de connexion, codes de désactivation de Tailnet Lock. |
| `installers.json`, `pin-installers.ps1` | Entrée `tailscale` à la place de `wireguard`. |
| CI `integration.yml`, `integration-e2e.ps1` | Voir §8. |
| Docs | `README` (étapes 1 à 3 réécrites, plus d'étape « Box »), `SECURITY.md`, `RECETTE.md`, fusion dans `PLAN.md`. |

**Migration depuis la v1.0.0.** Si `init` trouve un état v1 (tunnel WireGuard SecureDesk), il propose de le retirer : service, `.conf`, règle UDP, et WireGuard s'il a été installé par SecureDesk. Ce retrait n'a lieu **qu'à la fin**, une fois le client appairé et RDP testé via Tailscale. La migration se fait **à la console** du serveur : depuis une session RDP passant par le tunnel v1, l'outil refuse, comme pour `enable-2fa`.

**Version :** **v2.0.0** (changement incompatible de la configuration, de l'état et de la ligne de commande).

---

## 8. CI

- **Sans compte :** installation du MSI épinglé (signature et SHA-256), service `Tailscale` actif, chemin de `tailscale.exe`, écriture puis rollback des stratégies système, lecture de `status --json` (état `NeedsLogin`), règles de pare-feu avec des `/32` en `100.64.0.0/10`, idempotence, désinstallation complète et retour à l'état initial.
- **Avec un secret CI facultatif** `TS_CI_AUTHKEY` (clé éphémère, à usage multiple, dans un tailnet de test et non le vôtre) : vraie connexion d'un runner, lecture de `Self`, `KeyExpiry` et `TailscaleIPs`, puis `logout`. Sans ce secret, les étapes sont ignorées et signalées.
- **Test à deux nœuds** (serveur ↔ client réels) : **recette manuelle** sur vos PC. Un seul `tailscaled` tourne par machine, ce qui exclut l'astuce v1 des deux tunnels sur le même runner.

---

## 9. Décisions à valider

1. **Tailnet Lock** : activation recommandée (`lock-init`, deux codes de désactivation sur papier), **sans** code transmis au support de Tailscale. Avec le code au support, la récupération est plus simple mais la protection contre A8 plus faible.
2. **Mises à jour automatiques de Tailscale** (`InstallUpdates=always`) sur les deux PC : correctifs de sécurité rapides, contre un petit risque de régression à distance. Alternative : notification seulement (`CheckUpdates`), mises à jour à faire vous-même.
3. **Contrôle d'usurpation planifié** (tâche SYSTEM toutes les 15 minutes) activé par défaut.
4. **Expiration de la clé conservée côté client** (reconnexion périodique depuis le PC personnel), **désactivée côté serveur** (obligatoire).
5. **Migration v1 → v2** : ce qui est décrit au §7 suffit-il, ou n'avez-vous jamais installé la v1 sur vos PC (auquel cas le code de migration est inutile) ?
6. **Noms dans le tailnet** : `securedesk-serveur` et `securedesk-<nom du pair>` par défaut, modifiables dans la configuration.

## 10. Incréments prévus (une CI verte à chaque étape)
1. Core : modèle Tailscale, lecture JSON, plan des stratégies, pare-feu `/32`, contrôle d'usurpation, filtre de masquage, suppression du code WireGuard et de l'appairage. Tests unitaires.
2. Windows : `TailscaleOps`, épinglage du MSI, stratégies, intégration CI sans compte.
3. Commandes `init`, `join`, `add-peer`, `list-peers`, `revoke-peer`, `lock-init`, `test`, `diagnose`, `uninstall`, et la migration v1.
4. Assistant WinForms (écrans simplifiés).
5. Documentation (README, SECURITY, RECETTE, PLAN) et release **v2.0.0**.
