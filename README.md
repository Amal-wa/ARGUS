# ARGUS — Zero Trust API Gateway

Passerelle API où chaque requête est authentifiée, scorée par un modèle de détection
d'anomalie (Isolation Forest), puis autorisée par un moteur de politique (OPA) qui combine
RBAC, score de risque ML et règles indépendantes du score. Chaque décision est journalisée
dans une chaîne de hash inviolable. Portfolio/démo, pas un déploiement de production — les
limites connues sont listées plus bas, pas cachées.

---

## Démarrage rapide

```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps
```

`postgres`, `redis`, `vault`, `opa`, `isolation-forest`, `behavioral-detector` doivent
afficher `(healthy)`. `api-gateway` et `dashboard` n'ont **aucun** `healthcheck:` défini
dans `docker-compose.yml` — `Up` suffit pour eux, n'attendez pas `(healthy)`.

| Service | URL locale | Notes |
|---|---|---|
| `api-gateway` | http://localhost:8000 | Swagger : `/docs` · ReDoc : `/redoc` — pas de healthcheck |
| `dashboard` (ARGUS-dashboard) | http://localhost:5173 | `admin1@zt.local` / `ChangeMe123!` — pas de healthcheck |
| `postgres` | localhost:5433 | user `postgres` / db `zt_db` |
| `redis` | localhost:6379 | `-a redis-dev-password` |
| `vault` | http://localhost:8200 | mode dev, token `dev-root-token` |
| `opa`, `isolation-forest` | interne uniquement | mTLS, jamais publiés sur l'hôte |

Arrêter : `docker compose -f docker/docker-compose.yml down` (les volumes survivent —
ajoutez `-v` pour tout effacer, y compris la base).

---

## Comment ça marche (l'essentiel)

Trois couches de décision, **indépendantes**, doivent toutes être franchies — un token
valide ne suffit jamais seul :

1. **RBAC** (`policies/authz/rbac.rego`) — rôle → action autorisée. `reader` lit,
   `editor`/`admin` écrivent, `admin` seul supprime ou touche `/users`.
2. **Score ML** (Isolation Forest) — comportement récent vs seuil calibré, absent en
   bootstrap (aucun modèle promu).
3. **Règles adaptatives** (`policies/risk/adaptive_access.rego`) — IPs distinctes,
   énumération de ressources, actions sensibles (`delete`, `/users`) : déclenchent un
   step-up ou un deny **même sans score ML**, par conception.

OPA combine les trois et journalise la décision dans `opa_decision_log`, chaîné par
SHA-256 (`scripts/verify_audit_integrity.py` — lecture seule, sûr à tout moment).

### Composants — un seul expose une API REST

| Composant | Nature | Rôle |
|---|---|---|
| `api-gateway` | **REST** (FastAPI, `/docs`) | Seul point d'entrée public. Auth, scoring, autorisation, audit. |
| `policies/` | Bundle OPA/Rego | RBAC + règles adaptatives + MFA, combinés dans `authz/decision.rego`. |
| `isolation-forest` | REST interne (mTLS) | `/score`, `/health` — jamais publié sur l'hôte, injoignable sans certificat client. |
| `ml-trainer` | Job batch | `docker compose run --rm ml-trainer` — entraîne un candidat, s'arrête. |
| `canary-validator` | Job batch | Compare un candidat au modèle en production sur du trafic réel, s'arrête. |
| `behavioral-detector` | Daemon (pas d'HTTP) | Boucle `scan; sleep(60)` sur les mêmes fenêtres Redis que le score ML. |
| `dashboard` (ARGUS-dashboard) | SPA React | Ne parle qu'au gateway, depuis le navigateur. |

**Remarque** : demander où sont les "endpoints" de `ml-trainer`/`canary-validator`/
`behavioral-detector` — ce sont des jobs/daemon, pas des services REST. Rien à documenter
en Swagger pour eux ; leur code se lit directement.

### Cycle de vie du modèle ML

```
ml-trainer → candidat (.joblib + Redis)
   → canary-validator (compare au modèle actif sur trafic réel)
      → révision humaine (dashboard, Confirm/Reject)
         → scripts/promote_model.py (acte humain, jamais automatique)
            → modèle actif (isolation-forest recharge en ≤30s)
```

`promote_model.py` refuse si le candidat n'a pas de distribution de scores calculée
(`score_distribution`), si ses dimensions ne correspondent plus au vecteur actuel, ou si un
humain a explicitement **rejeté** une comparaison canary pour cette version — mais une
confirmation humaine n'est pas obligatoire : un candidat resté `pending` (jamais revu) peut
être promu tel quel. Le rejet est un veto, pas la revue une condition.

---

## Sécurité — points clés

| Contrôle | Contre quoi |
|---|---|
| CORS allow-list stricte, jamais `*` | Vol de session cross-origin |
| Refresh token : cookie httpOnly, rotatif, usage unique | XSS ne peut pas le lire ; un token rejoué révoque toute la famille de sessions |
| Step-up sur action sensible (`delete`, `/users`), indépendant du score | Un compromis mot-de-passe seul ne suffit pas à supprimer des données ou créer un admin |
| mTLS Gateway↔OPA et Gateway↔Isolation Forest | Un pair interne compromis usurpant OPA ou faussant le score de risque |
| Authentification Redis (`requirepass`) | Un conteneur interne compromis forgeant un état MFA directement dans Redis |
| Chaîne de hash SHA-256 sur `opa_decision_log` | Falsification silencieuse du journal d'audit |
| En-têtes de sécurité HTTP (CSP, HSTS conditionnel, etc.) | Clickjacking, MIME-sniffing |

**Limites connues, assumées** :
- Vault en mode dev (mémoire, régénéré à chaque `docker compose up`) — pas pour la prod.
- Gateway↔{Vault, Postgres, Redis} reste en clair sur `internal_net` (réseau Docker privé) — le mTLS ne couvre que Gateway↔OPA et Gateway↔Isolation Forest.
- Redis : mot de passe partagé entre les 5 services connectés, pas d'ACL par service.
- `events` (échecs d'auth, rate-limits) n'est pas chaîné par hash — seul `opa_decision_log` l'est.
- Pas de scan de dépendances/SAST en CI (aucune CI pour l'instant).

---

## Commandes par service

### `api-gateway`

```bash
cd services/api-gateway
poetry install
poetry run pytest
poetry run alembic upgrade head            # migrations (déjà auto-exécuté au démarrage du conteneur)
```

Scripts opérationnels, dans le conteneur déjà démarré (`docker compose run --rm api-gateway`
peut échouer sur un désync Vault/mtls-certs — préférez `docker exec`) :

```bash
docker exec zt-api poetry run python scripts/verify_audit_integrity.py   # lecture seule
docker exec zt-api poetry run python scripts/promote_model.py <version>  # acte humain délibéré
docker exec zt-api poetry run python scripts/seed_users.py               # comptes + secrets MFA
docker exec zt-api poetry run python scripts/seed_business_data.py       # documents/orders + personas
```

### `isolation-forest`

```bash
cd services/isolation-forest && poetry install && poetry run pytest
```

### `ml-trainer` / `canary-validator` (jobs — pas de serveur)

```bash
docker compose -f docker/docker-compose.yml run --rm ml-trainer
docker compose -f docker/docker-compose.yml run --rm canary-validator
```

### `behavioral-detector` (daemon — rien à lancer)

Fait partie de `docker compose up` par défaut. Logs : `docker logs behavioral-detector`.

### `dashboard`

```bash
cd services/dashboard
npm install
npm run dev      # hors-conteneur ; déjà servi par docker compose up sinon
npm test
```

### `policies/` (OPA/Rego)

```bash
opa test policies/ -v
```

---

## Comptes de démo

Mot de passe commun : `ChangeMe123!`. Rôles : `reader1..15`, `editor1..8`, `admin1..2`
(`@zt.local`). Secrets TOTP dans `tools/traffic-generator/persona_secrets.json` (non
versionné, généré par `seed_users.py`/`seed_business_data.py`).

