# Audit read-only — Isolation Forest & canary-validator

Date : 2026-07-27
Méthode : audit statique en lecture seule (2 teammates indépendants + consolidation par le lead), aucune modification de code ni de données. Un teammate a exécuté une unique requête `SELECT` en lecture pure contre Postgres pour vérifier un doute de syntaxe SQL (voir section canary-validator, point vérifié n°4) — aucune écriture.

**Note opérationnelle** : les deux teammates ont signalé que les outils `TaskUpdate`/`TaskList` n'étaient pas exposés dans leur environnement d'exécution — ils n'ont donc pas pu s'auto-assigner les tâches #1/#2 sur la liste partagée comme demandé. Le lead a mis à jour ces statuts manuellement après réception de chaque rapport. Ça n'a eu aucun impact sur le contenu de l'audit lui-même.

---

## Sommaire des sévérités

| # | Composant | Sévérité | Catégorie | Titre |
|---|-----------|----------|-----------|-------|
| IF-1 | Isolation Forest | **HAUTE** | A+B | Squash logistique compresse tous les scores réels dans une bande étroite (~0,5–0,7) |
| IF-2 | Isolation Forest | **HAUTE** | A+B | Fenêtre de désync modèle/seuil pendant une promotion, sans garde-fou |
| CV-1 | canary-validator | **HAUTE** | B | Aucun garde-fou de taille d'échantillon + `review_status` jamais appliqué → promotion possible sans revue réelle |
| CV-2 | canary-validator | MOYENNE | A | Pas de contrainte d'unicité/verrou → exécutions concurrentes dupliquables |
| CV-3 | canary-validator | MOYENNE | A | Non-atomicité entre insertion des lignes de comparaison et écriture de la distribution |
| CV-4 | canary-validator | MOYENNE | A/C | Pas d'`ORDER BY` dans la sélection du lot + pas d'orchestrateur pour vider le backlog |
| IF-3 | Isolation Forest | MOYENNE | A/C | `contamination="auto"` est un hyperparamètre mort (jamais consommé par `score_samples`) |
| IF-4 | Isolation Forest | MOYENNE | C | Aucune mise à l'échelle des features avant fit/score |
| IF-5 | Isolation Forest | MOYENNE | C | `FALLBACK_STEP_UP_THRESHOLD=0.65` non justifié, aggravé par IF-1 |
| IF-6 | Isolation Forest | BASSE | C | Pannes de scoring indistinguables en observabilité (réseau vs erreur de schéma) |
| CV-5 | canary-validator | BASSE | C | Fichier modèle manquant : fail-closed correct mais pas d'alerte dédiée |
| CV-6 | canary-validator | BASSE | C | `write_score_distribution` ne vérifie pas le rowcount de l'UPDATE |
| CV-7 | canary-validator | BASSE | C | Pas d'index sur `(trace_id, candidate_model_version)` |

---

## 1. Isolation Forest (anomaly scoring)

*Fichiers lus : `services/isolation-forest/app/{model_store.py, main.py, settings.py}`, `tests/test_model_store.py` ; `services/canary-validator/app/score_mapping.py` ; `services/ml-trainer/app/{trainer.py, repository.py}` ; `services/api-gateway/app/services/{authorization.py, feature_vector.py}`, `app/core/{isolation_forest_client.py, opa_client.py, errors.py, settings.py}`, `app/middleware/gateway.py`, `app/schemas/authorization.py`, `scripts/promote_model.py`, `app/models/tables.py` ; `policies/authz/decision.rego`, `policies/risk/{adaptive_access.rego, mfa.rego}`, `policies/authz/rbac.rego` ; `tests/policies/README.md`.*

### HAUTE

**IF-1 — [A+B] Le squash logistique compresse tous les scores réels dans une bande étroite (~0,5–0,7), ce qui vide le seuil p98 de sa substance discriminante**

`services/isolation-forest/app/model_store.py:26-41`, dupliqué dans `services/canary-validator/app/score_mapping.py:14-24` :
```python
risk_score = 1 / (1 + exp(anomaly_score))
```
Le commentaire (`model_store.py:27`) affirme que `score_samples` est "unbounded" — c'est factuellement faux : par construction sklearn (`score = -2^(-depth/c(n))`), la sortie brute est mathématiquement bornée dans `(-1, 0)`, et empiriquement resserrée encore davantage (typiquement -0.3 à -0.7 pour un jeu de données "normal"). En appliquant `sigmoid(-x)` sans aucune calibration d'échelle/centrage sur cette plage déjà étroite, la quasi-totalité des scores — trafic légitime **et** anormal confondus — tombe dans une bande de 0,1-0,15 de large (anomaly_score=-0.35 → risk≈0.587 ; anomaly_score=-0.65 → risk≈0.657). Cohérent avec le p98 ~0.64-0.65 observé en pratique sur v1/v2/v3 : ce n'est pas une coïncidence, c'est la conséquence directe de ce squash mal calibré (confirmé via `compute_score_distribution` dans `canary-validator/app/repository.py`, qui calcule ses percentiles sur ce score déjà compressé).

**Impact** : la marge entre "trafic totalement normal" (p50) et "2% les plus atypiques" (p98) est de l'ordre de quelques centièmes seulement — pas une vraie séparation statistique. Deux conséquences dangereuses : (a) un nouvel entraînement (nouvelle graine, nouvel échantillon) peut décaler toute la distribution de 0,05-0,1 sans aucun changement réel de comportement utilisateur, faisant basculer massivement le taux de step-up d'une version à l'autre ; (b) le score n'a aucune valeur d'interprétation absolue pour un opérateur (dashboard Argus) — tout se lit "autour de 0,6", jamais proche de 0 ou de 1.

**Correctif** : calibrer le squash sur la distribution réelle observée par le canary-validator (min-max scaling ou z-score sur l'échantillon de calibration avant sigmoïde, ou mapping par rang/percentile plutôt qu'une formule fixe centrée à 0) ; documenter la vraie plage de `score_samples` au lieu de la qualifier d'"unbounded".

**IF-2 — [A+B] Fenêtre de désynchronisation modèle/seuil pendant une promotion, sans garde-fou côté Gateway**

`services/api-gateway/scripts/promote_model.py:125-126` écrit `model:active_version` puis `model:active_threshold` via deux `SET` Redis séparés (non transactionnels) — fenêtre de race où un lecteur concurrent voit la nouvelle version mais l'ancien seuil.

Plus large et plus systématique : `services/isolation-forest/app/settings.py:11` (`MODEL_POLL_INTERVAL_SECONDS=30` par défaut) + `app/model_store.py:95-98` (`poll_forever`) — isolation-forest ne recharge le nouveau modèle qu'au prochain sondage Redis, jusqu'à 30s+ après la promotion. Pendant cette fenêtre, `services/api-gateway/app/services/authorization.py:76-102` lit `model:active_threshold` (déjà mis à jour pour le **nouveau** modèle) dès que `model:active_version` est non-null, pendant qu'isolation-forest continue à scorer avec l'**ancien** modèle. Le code ne compare jamais `risk_ctx.model_version` (renvoyé par isolation-forest dans sa réponse `/score`) à la version que le Gateway pensait active avant d'utiliser le seuil — aucun cross-check n'existe.

**Impact** : pendant toute promotion, un score produit par l'ancienne distribution est comparé à un seuil calibré sur la nouvelle. Si les deux modèles ont des échelles différentes (cf. IF-1 — même une petite dérive du squash entre deux entraînements suffit), cela peut sur-déclencher du step-up sur du trafic normal, ou au contraire laisser passer du trafic anormal sans MFA — silencieusement, sans log d'alerte (contrairement au cas "threshold manquant", bien loggé en warning).

**Correctif** : (a) grouper les deux `SET` de `promote_model.py` dans une transaction Redis (`MULTI`/pipeline) ; (b) dans `AuthorizationService.authorize`, comparer `risk_ctx.model_version` à la version lue en début de fonction, et retomber sur `fallback_step_up_threshold` (+ warning) en cas de désaccord.

### MOYENNE

**IF-3 — [A/C] `contamination="auto"` est un hyperparamètre mort — aucun effet sur le score réellement utilisé**

`services/ml-trainer/app/trainer.py:97` : `IsolationForest(n_estimators=..., contamination="auto", random_state=...)`. Or le seul point d'appel du modèle entraîné (`model_store.py:71`, `canary-validator/app/repository.py:108`) est `.score_samples(...)` — jamais `.predict()` ni `.decision_function()`. En scikit-learn, `contamination` ne sert qu'à calculer `self.offset_`, uniquement consommé par `predict()`/`decision_function()` — jamais par `score_samples()`. Ce paramètre n'a donc strictement aucun impact sur le pipeline de production, quelle que soit sa valeur. Il est pourtant persisté dans `ml_model_registry.hyperparameters`, laissant croire à tort qu'il participe à la calibration du risque.

**Impact** : faible en soi, mais dette de compréhension — quiconque relit `hyperparameters` pour comprendre la sensibilité d'un modèle sera induit en erreur.

**Correctif** : retirer le paramètre (documenter que le mapping passe uniquement par `score_samples`), ou basculer sur `decision_function()`/un mapping basé sur `offset_` si l'intention était d'exploiter `contamination`.

**IF-4 — [C] Aucune mise à l'échelle des features avant fit/score, malgré un vecteur hétérogène**

`services/ml-trainer/app/trainer.py:95-99` et `services/isolation-forest/app/model_store.py:68-72` passent le vecteur brut sans normalisation. Le vecteur 16-dim (`app/services/feature_vector.py:28-40`) mélange one-hot (0/1), compteurs bornés par rate-limit (jusqu'à ~200), un ratio (0-1), des stats d'intervalles en secondes (0-300), et une latence en ms (potentiellement plusieurs centaines). Isolation Forest est réputé peu sensible à l'échelle, donc pas un bug net — mais le déséquilibre est réel : les dimensions one-hot quasi-constantes offrent peu de pouvoir de séparation face à `latency_ms` ou aux intervalles, qui varient sur plusieurs ordres de grandeur.

**Correctif** : documenter explicitement le choix de ne pas scaler, ou tester un `StandardScaler` par colonne persisté avec le modèle (`joblib.dump` du couple scaler+modèle).

**IF-5 — [C] `FALLBACK_STEP_UP_THRESHOLD=0.65` non justifié, aggravé par IF-1**

`services/api-gateway/app/core/settings.py:52`. Rien ne montre d'où vient `0.65` (le seul commentaire associé, `model_store.py:30`, "DEMO-PHASE CHOICE", reconnaît que le mapping lui-même est un placeholder). Compte tenu d'IF-1 (le trafic légitime score déjà ~0.55-0.65), ce fallback est soit quasiment toujours franchi (step-up permanent) soit quasiment jamais (aucune protection) selon la distribution réelle au moment du désync — un pari, pas un choix calibré.

**Correctif** : dériver ce fallback de la même logique de percentile que `promote_model.py` (ex. figer le p98 du premier modèle calibré comme défaut) plutôt qu'une constante en dur.

### BASSE

**IF-6 — [C] Toutes les pannes du service de scoring sont indistinguables en observabilité**

`services/api-gateway/app/core/isolation_forest_client.py:43-47` : `except (URLError, TimeoutError, json.JSONDecodeError)` capture aussi bien une panne réseau qu'une réponse HTTP 4xx (ex. vecteur de mauvaise longueur rejeté en 422 par isolation-forest, `main.py:24-26`) — `HTTPError` hérite de `URLError`, donc les deux finissent dans le même `ScoringUnavailableError`/`event_type="scoring_unavailable"`. Fail-closed correct dans les deux cas (pas de faille), mais un vrai bug de contrat de schéma serait masqué en "panne de service", retardant le diagnostic.

**Correctif** : distinguer `HTTPError` (avec son code) des erreurs réseau/timeout dans le log d'événement.

### Points contrôlés sans anomalie détectée

- **Fail-closed confirmé** : indisponibilité d'isolation-forest → `ScoringUnavailableError` → 503, jamais un accès accordé par défaut (`middleware/gateway.py:173-195`).
- **Bootstrap mode** : tant que `model:active_version` est absent, `risk_ctx` reste `{score: null}`, correctement distinct d'un `risk_ctx` manquant (`adaptive_access.rego:10-12`).
- **Anti-leakage training set** : écriture des training samples uniquement sur `ALLOW` et `not is_post_step_up`, hors routes `/monitoring/*` — cohérent avec la doc, aucune fuite trouvée.
- **Précédence RBAC > bootstrap > risk > MFA > step-up** : `policies/authz/decision.rego:12-53` correspond exactement à l'ordre documenté ; le défaut fail-closed (`malformed_input_deny`) couvre le cas où `risk_decision` est indéfini.
- **Contrôle de dimension à la promotion** : `promote_model.py:113-119` refuse un `feature_dims` incompatible (voir cependant IF-2 pour la fenêtre de transition).
- **Convention de signe** : "plus haut = plus anormal" cohérente de bout en bout, jusqu'à `adaptive_access.rego: score >= threshold → step_up`.

---

## 2. canary-validator

*Fichiers lus : `services/canary-validator/app/{main.py, validator.py, repository.py, score_mapping.py, settings.py}`, `tests/{test_validator.py, conftest.py}`, `Dockerfile` ; `services/isolation-forest/app/model_store.py` ; `services/ml-trainer/app/{trainer.py, settings.py}` ; `services/api-gateway/scripts/promote_model.py`, `app/models/tables.py`, `alembic/versions/0001_initial_mirror.py` ; `docker/docker-compose.yml`.*

Le teammate confirme que la description fournie en amont (sélection Mode A/B basée uniquement sur `model:active_version`/`model:candidate_version`, écrasement de `score_distribution` en Mode B, `review_status` jamais transitionné après insertion) correspond exactement au code actuel — aucune dérive constatée.

### HAUTE

**CV-1 — [B] Aucun garde-fou sur la taille d'échantillon + `review_status` non appliqué → promotion possible sur un seuil calculé sur un nombre d'échantillons arbitrairement faible, sans revue humaine réelle**

`services/canary-validator/app/validator.py:139-162` (`_run_calibration`) et `:165-206` (`_run_comparison`) ; `services/api-gateway/scripts/promote_model.py:106-119` ; comparer à `services/ml-trainer/app/trainer.py:112-118` + `settings.py:13` (`MIN_TRAINING_SAMPLES=1000`).

`ml-trainer` refuse d'entraîner si `len(samples) < min_training_samples` (garde-fou explicite, testé). Rien d'équivalent côté canary-validator : `_run_calibration`/`_run_comparison` acceptent n'importe quel nombre d'échantillons non nul et calculent un `p98` via `np.percentile` même sur 3-5 échantillons. `promote_model.py` ne vérifie que la présence de la clé `"p98"`, jamais `samples_scored`. Par ailleurs `review_status` est inséré en dur à `'pending'` (`repository.py:77`) et rien dans tout le dépôt (grep global) ne le fait jamais évoluer — aucune route API, aucun dashboard. « La revue » est une pure convention documentaire, pas un contrôle technique.

**Impact** : un opérateur (ou un script buggé) qui positionne `model:candidate_version` alors qu'il n'y a que quelques dizaines de lignes récentes obtient un `p98` non représentatif ; rien n'empêche d'enchaîner immédiatement `promote_model.py <version>`. Ce seuil devient `model:active_threshold`, consommé directement par `adaptive_access.rego` pour arbitrer ALLOW vs STEP_UP sur tout le trafic réel — un seuil mal calibré peut sur- ou sous-déclencher le step-up pour l'ensemble des utilisateurs.

**Correctif** : ajouter `MIN_CALIBRATION_SAMPLES`/`MIN_COMPARISON_SAMPLES` dans `ValidatorSettings`, refuser d'écrire `score_distribution` en dessous (comme `ml-trainer`), et faire vérifier `samples_scored` par `promote_model.py` en plus de `p98`. Envisager de rendre `review_status = 'approved'` un vrai pré-requis technique à la promotion (même via un simple flag consommé par `promote_model.py`), pas seulement documentaire.

### MOYENNE

**CV-2 — [A] Absence de contrainte d'unicité/verrou → exécutions concurrentes du job pouvant dupliquer des lignes et corrompre `score_distribution`**

`services/canary-validator/app/repository.py:28-55` (`load_unscored_comparison_samples`, `NOT EXISTS` corrélé) et `:67-90` (`insert_comparison_rows`) ; `services/api-gateway/app/models/tables.py:188-203` (`canary_validation_log_table`, aucun `UniqueConstraint`/`Index` sur `(trace_id, candidate_model_version)`).

L'idempotence repose entièrement sur le `NOT EXISTS`, sans contrainte DB ni verrou applicatif. Sous READ COMMITTED (défaut Postgres), deux exécutions concurrentes pour le même `candidate_version` (ex. relance manuelle pendant qu'une exécution planifiée traite encore un backlog de plusieurs milliers de lignes) peuvent chacune sélectionner les mêmes échantillons « non encore comparés » puis insérer chacune leur lot — sans erreur, faute de contrainte d'unicité.

**Impact** : doublons dans `canary_validation_log`, et surtout deux `write_score_distribution` concurrents où le dernier à committer écrase l'autre — le `p98` final reflète un sous-ensemble arbitraire plutôt que l'ensemble traité.

**Correctif** : ajouter `UNIQUE (trace_id, candidate_model_version)` sur `canary_validation_log` (protège aussi CV-3) et/ou un verrou consultatif Postgres (`pg_try_advisory_lock`) en tout début de `main()`.

**CV-3 — [A] Non-atomicité entre `insert_comparison_rows` et `write_score_distribution` → perte silencieuse et définitive d'échantillons en cas de crash mi-parcours**

`services/canary-validator/app/validator.py:185-193` ; `repository.py:57-65` et `:67-90` (deux blocs `engine.begin()` distincts).

Dans `_run_comparison`, `insert_comparison_rows(...)` committe sa transaction, puis `write_score_distribution(...)` en ouvre une seconde. Si le process est tué (OOM, kill container, coupure réseau) entre les deux, les lignes `canary_validation_log` sont déjà committées mais `score_distribution` ne reflète jamais ce lot. Comme la sélection en Mode B exclut via `NOT EXISTS` tout `trace_id` déjà présent dans `canary_validation_log` pour cette version, ce lot ne sera **plus jamais** re-scoré — perte permanente pour le calcul de distribution (l'audit trail, lui, les contient toujours).

**Impact** : `p98` peut rester basé sur un sous-ensemble incomplet, sans aucun signal d'erreur (le job suivant repart normalement, en apparence sain).

**Correctif** : faire partager la même transaction aux deux écritures (un seul `engine.begin()` enveloppant insert + update dans `_run_comparison`).

**CV-4 — [A/C] Absence de `ORDER BY` dans la sélection du lot + pas d'orchestrateur pour vider le backlog**

`services/canary-validator/app/repository.py:28-46` (pas de `ORDER BY` avant `LIMIT :batch_size`, contrairement à `load_calibration_samples:15-26` qui a `ORDER BY created_at DESC`) ; `docker/docker-compose.yml:275-280` (commentaire FR "planification hebdomadaire (scheduler externe ou cron interne au conteneur)" — vérifié : rien dans le dépôt n'implémente cette planification ni une boucle jusqu'à épuisement du backlog).

Sans `ORDER BY`, le sous-ensemble retourné par `LIMIT 5000` dépend du plan d'exécution Postgres — non garanti stable ni reproductible. Combiné à `CANARY_WINDOW_DAYS=30` et à l'absence confirmée d'automatisation qui relance le job jusqu'à épuisement, des échantillons éligibles peuvent sortir de la fenêtre glissante avant d'avoir jamais été traités si personne ne relance manuellement le job suffisamment de fois (confirmé en pratique : ~10 258 échantillons éligibles pour v3, un seul run n'en traite que 5000).

**Impact** : `score_distribution` peut être biaisée vers une portion arbitraire du trafic ; une partie du trafic réel peut n'être jamais comparée ni comptée dans le calibrage, silencieusement.

**Correctif** : ajouter `ORDER BY s.created_at` (cohérent avec `load_calibration_samples`) ; documenter/implémenter une boucle "jusqu'à épuisement" (dans `main.py` ou le scheduler externe évoqué en commentaire).

### BASSE

**CV-5 — [C] Fichier modèle manquant : fail-closed correct mais pas d'alerte dédiée**

`services/canary-validator/app/validator.py:100-104,130` ; `main.py:23-27`. `FileNotFoundError` (candidat déclaré dans Redis mais fichier absent du volume partagé) remonte au `try/except Exception` générique de `main()`, qui logge et sort en code 1. Fail-closed et sain (aucune écriture Redis/DB corrompue avant cet appel), mais rien ne surveille activement ce code de sortie (pas de CI/alerting trouvé) — `model:candidate_version` peut rester bloqué sur une version cassée jusqu'à consultation manuelle des logs.

**Correctif** : brancher une alerte sur l'exit code non nul (hors périmètre du code), ou logger un message orienté opérateur ("candidate model file missing — models-volume misconfigured?").

**CV-6 — [C] `write_score_distribution` ne vérifie pas le rowcount de l'UPDATE**

`services/canary-validator/app/repository.py:57-65`. Le `UPDATE ... WHERE model_version = :version` ne vérifie jamais `result.rowcount`. Neutralisé dans le flux normal (`ml-trainer` insère la ligne registry avant de positionner `model:candidate_version`), mais une manipulation manuelle erronée de cette clé Redis (faute de frappe, version orpheline) ferait reporter un succès (code 0) alors que l'UPDATE n'a affecté aucune ligne.

**Correctif** : vérifier `result.rowcount == 1` et lever une exception explicite sinon.

**CV-7 — [C] Aucun index sur `canary_validation_log(trace_id, candidate_model_version)`**

`services/api-gateway/app/models/tables.py:188-203`. Scan complet de table à chaque exécution pour évaluer le `NOT EXISTS` — pertinent puisque le job est destiné à tourner répétitivement sur un gros volume.

**Correctif** : ajouter un index composite `(trace_id, candidate_model_version)` (répond aussi partiellement à CV-2 si transformé en contrainte unique).

### Points vérifiés sans anomalie détectée

- **Duplication `risk_score_from_anomaly_score`** (`score_mapping.py` vs `isolation-forest/app/model_store.py`) : code strictement identique, aucune dérive.
- **Gestion des listes vides** dans les deux modes : retour anticipé confirmé, pas d'écriture DB déclenchée.
- **Mismatch `feature_dims`** (ex. v1 à 20 dims nourri d'un vecteur 16 dims) : `score_samples` lève une `ValueError` de forme, non interceptée localement, remonte à `main.py` → échec bruyant, code 1 ; le scoring a lieu en mémoire avant tout appel DB dans les deux modes, donc aucune écriture partielle n'est possible — fail-safe correct.
- **Idiome SQL `(:window_days || ' days')::interval`** : vérifié empiriquement (une requête `SELECT` en lecture pure) — fonctionne correctement.
- **Atomicité intra-appel** : chaque écriture individuelle est bien enveloppée dans `engine.begin()` (rollback auto en cas d'erreur mi-lot) — le problème identifié (CV-3) n'est que l'absence d'atomicité *entre* les deux appels.

---

## Synthèse des actions prioritaires (par ordre de sévérité)

1. **IF-1 / IF-2** — recalibrer le mapping anomaly_score → risk_score et fiabiliser la transition de modèle (cross-check `model_version` avant d'utiliser un seuil).
2. **CV-1** — introduire un seuil minimum d'échantillons pour calibrer/comparer, et faire de `review_status` un vrai gate technique avant promotion plutôt qu'une convention.
3. **CV-2 / CV-3 / CV-4** — verrou/contrainte d'unicité, transaction unique pour l'écriture comparaison+distribution, `ORDER BY` déterministe + boucle d'épuisement du backlog.
4. **IF-3 / IF-4 / IF-5** — nettoyage de dette (hyperparamètre mort, scaling des features, justification du fallback threshold).
5. **IF-6 / CV-5 / CV-6 / CV-7** — améliorations d'observabilité et de robustesse défensive, sans urgence.

Aucun fichier de code n'a été modifié dans le cadre de cet audit.
