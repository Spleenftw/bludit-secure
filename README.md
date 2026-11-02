# bludit-secure

Plugin d’authentification pour **Bludit 3.22.0**. Version **0.1.0 expérimentale**, à valider sur une copie du site avant activation en production.

## Fonctionnalités

- Connexion locale avec le mot de passe Bludit.
- Bouton **Se connecter avec XYZ**, dont le nom est configurable, vers un fournisseur OIDC tel que Pocket ID.
- Liaison volontaire de l’identité SSO par chaque utilisateur connecté. Association sur **issuer + subject**, jamais automatiquement sur l’adresse e-mail. Aucun utilisateur ni rôle créé à partir des claims OIDC.
- TOTP par compte (SHA-1, six chiffres, 30 secondes), compatible avec le champ TOTP de Bitwarden. Activation après confirmation d’un code. Refus des codes déjà utilisés.
- Plusieurs passkeys par compte, avec nom et suppression individuelle. Compatible avec les passkeys synchronisées, dont celles conservées dans Bitwarden. Vérification utilisateur obligatoire.
- Choix personnel du second facteur : désactivé, TOTP, passkey, ou TOTP/passkey au choix. Possibilité de demander aussi ce facteur local après le SSO.
- Dix codes de récupération à usage unique, affichés une fois, renouvelables.

Les passkeys locales sont enregistrées pour le domaine **Bludit**. La passkey de Pocket ID reste attachée au domaine **Pocket ID**. Ce sont deux inscriptions distinctes. Les passkeys locales servent ici de **second facteur**, après le mot de passe ou le SSO, et non de connexion locale sans mot de passe.

## Prérequis

- PHP **8.2 ou supérieur**, extensions sodium, curl, mbstring et openssl, plus les prérequis habituels de Bludit.
- Site configuré avec son URL publique **HTTPS** exacte dans Bludit ; certificat valide. Aucun mode dégradé HTTP.
- Le serveur PHP doit pouvoir joindre l’issuer Pocket ID et ses endpoints de découverte, clés et jetons.
- Accès au stockage `bl-content/databases/plugins/bludit-secure/` en écriture pour PHP.
- Un reverse proxy doit transmettre une adresse client fiable à PHP via `REMOTE_ADDR`. Ne jamais faire confiance directement aux en-têtes fournis par le client.

## Installation

1. Sauvegarder les fichiers et `bl-content` et préparer un accès SSH de récupération.
2. Décompresser le ZIP dans `bl-plugins/` pour obtenir `bl-plugins/bludit-secure/plugin.php`. Le ZIP fourni inclut `vendor/`.
3. Activer **Bludit Secure** dans les plugins. Les sessions Bludit précédentes devront se reconnecter.
4. Ouvrir **Sécurité de mon compte** dans la barre d’administration.

Pour construire depuis les sources :

```sh
composer install --no-dev --prefer-dist --optimize-autoloader
```

Ne pas activer une copie source sans ses dépendances : les accès admin seront refusés tant que le plugin ne peut pas fonctionner.

## Configuration Pocket ID

Dans Pocket ID, créer un client OIDC confidentiel avec son secret et enregistrer exactement l’URI de retour affichée dans les paramètres du plugin :

```text
https://blog.example/admin/login?bs=oidc
```

Le chemin respecte le sous-répertoire et le chemin admin configurés dans Bludit. Reporter l’issuer exact (y compris sa convention de slash final), le Client ID et le Client secret dans le plugin. Choisir le nom du bouton, par exemple **Mon SSO**. Laisser le champ secret vide lors d’une modification conserve le secret existant.

Chaque utilisateur se connecte d’abord avec son compte Bludit, ouvre **Sécurité de mon compte**, puis clique sur **Lier mon compte à …**. Après validation chez Pocket ID, le compte est lié. Un même couple issuer/subject ne peut pas être associé à deux comptes Bludit.

Le plugin utilise le flux Authorization Code avec PKCE S256 et la bibliothèque jumbojett pour vérifier state, nonce, signature et claims. Les rôles restent ceux du compte Bludit. La déconnexion ferme la session Bludit, sans fermer la session Pocket ID ni celles des autres applications. Le logout OIDC global/back-channel n’est pas implémenté.

## Facteurs personnels

Dans **Sécurité de mon compte** :

- **TOTP** : préparer le secret, copier l’URI `otpauth://` dans Bitwarden, puis confirmer avec un code. Pas de service QR externe.
- **Passkey** : donner un nom, ajouter une passkey et choisir Bitwarden dans le navigateur, ou un autre authentificateur compatible.
- **Second facteur** : sélectionner le mode souhaité et décider s’il s’applique aussi après le SSO. Le mode « au choix » nécessite l’inscription des deux facteurs.
- **Récupération** : générer les codes et les conserver à part.

L’inscription du premier facteur active automatiquement son mode. Pour retirer un facteur exigé, sélectionner d’abord un mode compatible, ou désactiver le second facteur. Un facteur n’est jamais supprimé en désactivant implicitement la protection.

La gestion des facteurs nécessite une connexion complète datant de moins de cinq minutes. Au-delà, se déconnecter puis se reconnecter avec les facteurs existants. Les modifications invalident les autres sessions du plugin. Les utilisateurs choisissent leurs facteurs ; aucune obligation globale de MFA n’est imposée par cette version.

## Stockage et récupération

Les secrets TOTP, clés publiques, identités liées, empreintes des codes de récupération et limites de tentatives sont conservés dans un fichier chiffré et authentifié avec sodium. La clé de chiffrement est séparée, dans le même répertoire privé du plugin. Les fichiers sont protégés par un préambule PHP et des permissions 0600. **Ce chiffrement ne protège pas d’un attaquant ayant accès aux fichiers et à la clé du serveur.**

Sauvegarder ensemble `secure.key.php`, `secure.data.php` et les utilisateurs Bludit. Perdre la clé rend les facteurs irrécupérables. Ne pas réattribuer un ancien nom de compte à une autre personne sans retirer ses inscriptions de sécurité. Le client secret OIDC est stocké dans la configuration PHP habituelle du plugin : protéger également cette configuration et ses sauvegardes.

Les connexions incomplètes expirent après cinq minutes, les challenges WebAuthn après deux minutes. Les vérifications disposent d’un budget persistant par compte et par IP : dix tentatives sur cinq minutes, avec budgets séparés pour la gestion et l’inscription. Les sessions natives et cookies « se souvenir de moi » ne suffisent pas à passer la protection du plugin. L’accès AJAX est contrôlé avant le dispatch Bludit.

En cas de perte de tous les facteurs : utiliser un code de récupération. Sans code, un administrateur disposant de SSH peut désactiver temporairement le plugin en renommant son répertoire `bl-plugins/bludit-secure/` **hors de `bl-plugins`**. Cela rétablit l’authentification native pour tout le site : effectuer l’opération en maintenance avec l’accès `/admin` restreint, puis restaurer le plugin et réparer les inscriptions. Désinstaller le plugin depuis Bludit supprime ses données ; ne pas utiliser la désinstallation comme une simple désactivation.

Le plugin protège les **sessions web `/admin`**. Il ne modifie pas l’authentification de l’API Bludit, des autres plugins ou des services externes.

## Vérification

```sh
php tests/core.php
composer validate --no-check-publish
composer audit --no-dev
```

Les tests HTTP dans `tests/http_totp.py` et `tests/http_webauthn.py` nécessitent une **instance jetable** de Bludit 3.22.0, installée avec `admin / TestPassword123`, le plugin activé, une URL publique de fixture `https://127.0.0.1:18765/`, et un serveur PHP local sur `http://127.0.0.1:18765/`. Le transport HTTP est réservé à la fixture ; les assertions WebAuthn simulent l’origine HTTPS. Ils ne remplacent pas les essais navigateur HTTPS.

Variables : `TEST_PHP` (binaire PHP), `TEST_PHP_INI` (php.ini), `TEST_BLUDIT` (racine de la fixture). `TEST_BASE` est facultatif. Exécuter d’abord `http_totp.py` sur une fixture neuve, puis `http_webauthn.py`. **Le test WebAuthn efface les données de sécurité du plugin dans cette fixture**, jamais lui fournir un site réel.

Vérifié : syntaxe PHP 8.4, vecteurs RFC 6238, stockage chiffré et altération, limites persistantes, transactions, CSRF, connexion locale, blocage dashboard/AJAX avant MFA, refus du rejeu TOTP/récupération, inscription WebAuthn et signatures d’assertion, rejet d’une origine ou signature invalide et d’un challenge consommé. `composer audit` ne signale aucun avis au moment de la construction.

**À valider avant production** : connexion complète au Pocket ID réel, passkeys Bitwarden dans le navigateur avec HTTPS réel, reverse proxy, restauration de sauvegarde et compatibilité avec les autres plugins d’authentification. Aucune validation sur le site de production n’a été réalisée.
