.DEFAULT_GOAL := help
SHELL := /bin/bash

MVN       ?= ./mvnw
COMPOSE   ?= docker compose
PRODUCER  ?= http://localhost:8101
CONSUMER  ?= http://localhost:8102
DETECTOR  ?= http://localhost:8103
RESPONDER ?= http://localhost:8104

# Role-scoped keys. Reading alerts and locking an account are different capabilities.
VIEWER_KEY    ?= bh-viewer-key
ANALYST_KEY   ?= bh-analyst-key
RESPONDER_KEY ?= bh-responder-key

VENV   := analytics/.venv
PY     := $(VENV)/bin/python
PP     := python3 -m json.tool

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} \
		/^## / {printf "\n\033[1m%s\033[0m\n", substr($$0, 4); next} \
		/^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## Infrastructure

.PHONY: up
up: ## Start Redpanda, Postgres, Prometheus, Grafana
	$(COMPOSE) up -d
	@echo ""
	@echo "  Redpanda console  http://localhost:8090"
	@echo "  Grafana           http://localhost:3000"
	@echo "  Prometheus        http://localhost:9091"

.PHONY: up-search
up-search: ## Also start OpenSearch + Dashboards (needs ~1.5GB RAM)
	$(COMPOSE) --profile search up -d
	@echo "  OpenSearch Dashboards  http://localhost:5601"

.PHONY: up-lake
up-lake: ## Also start MinIO object storage
	$(COMPOSE) --profile lake up -d
	@echo "  MinIO console  http://localhost:9001  (bloodhound / bloodhound123)"

.PHONY: up-cloud
up-cloud: ## Also start LocalStack (AWS emulation)
	$(COMPOSE) --profile cloud up -d
	@echo "  LocalStack  http://localhost:4566"

.PHONY: up-auth
up-auth: ## Also start Keycloak (OIDC identity provider)
	$(COMPOSE) --profile auth up -d
	@echo "  Keycloak  http://localhost:8280  (admin / bloodhound)"
	@echo "  Then run the responder with: AUTH_MODE=oidc make responder"

.PHONY: up-airflow
up-airflow: ## Also start Airflow (scheduler + webserver)
	$(COMPOSE) --profile orchestrator --profile lake up -d
	@echo "  Airflow  http://localhost:8180  (admin / bloodhound)"

.PHONY: down
down: ## Stop everything (keeps data)
	$(COMPOSE) --profile search --profile lake --profile orchestrator --profile auth --profile cloud down

.PHONY: reset
reset: ## Stop everything and delete all data
	$(COMPOSE) --profile search --profile lake --profile orchestrator --profile auth --profile cloud down -v
	rm -rf bloodhound-detector/target/kafka-streams

.PHONY: logs
logs: ## Tail infrastructure logs
	$(COMPOSE) logs -f

.PHONY: psql
psql: ## Open a psql shell
	$(COMPOSE) exec postgres psql -U bloodhound -d bloodhound

.PHONY: topics
topics: ## List Kafka topics
	$(COMPOSE) exec redpanda rpk topic list --brokers redpanda:9092

.PHONY: tail-events
tail-events: ## Print raw events off the topic as they arrive
	$(COMPOSE) exec redpanda rpk topic consume security.events.raw --brokers redpanda:9092

.PHONY: tail-alerts
tail-alerts: ## Print alerts off the topic as they are detected
	$(COMPOSE) exec redpanda rpk topic consume security.alerts --brokers redpanda:9092

.PHONY: lag
lag: ## Show consumer group lag for all groups
	@for g in bloodhound-ingest bloodhound-responder bloodhound-detector; do \
		echo "--- $$g"; \
		$(COMPOSE) exec -T redpanda rpk group describe $$g --brokers redpanda:9092 2>/dev/null || echo "  (not running)"; \
	done

## Build and run

.PHONY: build
build: ## Compile and run tests
	$(MVN) -q clean install

.PHONY: install-common
install-common:
	@$(MVN) -q -pl bloodhound-common install -DskipTests

# No `-am` on these: spring-boot:run with also-make tries to run the aggregator POM and fails
# with "Unable to find a suitable main class".
.PHONY: producer
producer: install-common ## Run the event producer + lab IAM (8101)
	$(MVN) -q -pl bloodhound-producer spring-boot:run

.PHONY: consumer
consumer: install-common ## Run the Kafka -> Postgres consumer (8102)
	$(MVN) -q -pl bloodhound-consumer spring-boot:run

.PHONY: detector
detector: install-common ## Run the Kafka Streams detection engine (8103)
	$(MVN) -q -pl bloodhound-detector spring-boot:run

.PHONY: responder
responder: install-common ## Run alerting, incidents and response (8104)
	$(MVN) -q -pl bloodhound-responder spring-boot:run

## Simulation

.PHONY: status
status: ## Producer simulation status
	@curl -s $(PRODUCER)/sim/status | $(PP)

.PHONY: adversary-on
adversary-on: ## Turn on the continuous background adversary
	@curl -s -X POST "$(PRODUCER)/sim/adversary?enabled=true&intensity=$(or $(INTENSITY),0.3)" | $(PP)

.PHONY: adversary-off
adversary-off: ## Turn off the continuous adversary
	@curl -s -X POST "$(PRODUCER)/sim/adversary?enabled=false" | $(PP)

.PHONY: adversary-log
adversary-log: ## What the adversary has been doing
	@curl -s "$(PRODUCER)/sim/adversary/recent?limit=20" | $(PP)

.PHONY: brute-force
brute-force: ## Brute force one account (ATTEMPTS=30 SOURCES=1 SUCCEED=false)
	@curl -s -X POST "$(PRODUCER)/sim/attack/brute-force?attempts=$(or $(ATTEMPTS),30)&sources=$(or $(SOURCES),1)&succeed=$(or $(SUCCEED),false)" | $(PP)

.PHONY: cred-stuffing
cred-stuffing: ## Credential stuffing (USERS=150 SOURCES=3)
	@curl -s -X POST "$(PRODUCER)/sim/attack/credential-stuffing?targetUsers=$(or $(USERS),150)&sources=$(or $(SOURCES),3)" | $(PP)

.PHONY: password-spray
password-spray: ## Password spray (USERS=60 SOURCES=6)
	@curl -s -X POST "$(PRODUCER)/sim/attack/password-spray?targetUsers=$(or $(USERS),60)&sources=$(or $(SOURCES),6)" | $(PP)

.PHONY: impossible-travel
impossible-travel: ## Impossible travel (MINUTES=4)
	@curl -s -X POST "$(PRODUCER)/sim/attack/impossible-travel?minutesApart=$(or $(MINUTES),4)" | $(PP)

.PHONY: session-hijack
session-hijack: ## Stolen session used from elsewhere (CALLS=15)
	@curl -s -X POST "$(PRODUCER)/sim/attack/session-hijack?apiCalls=$(or $(CALLS),15)" | $(PP)

.PHONY: privilege-escalation
privilege-escalation: ## Authorization probing then a role change (PROBES=12)
	@curl -s -X POST "$(PRODUCER)/sim/attack/privilege-escalation?probes=$(or $(PROBES),12)" | $(PP)

.PHONY: api-key-abuse
api-key-abuse: ## Leaked API key exercised hard (CALLS=50)
	@curl -s -X POST "$(PRODUCER)/sim/attack/api-key-abuse?calls=$(or $(CALLS),50)" | $(PP)

.PHONY: attack-all
attack-all: ## Fire every scenario once
	@for s in brute-force cred-stuffing password-spray impossible-travel session-hijack privilege-escalation api-key-abuse; do \
		echo "--- $$s"; $(MAKE) -s $$s; done

## Ingest inspection

.PHONY: stats
stats: ## Ingest statistics
	@curl -s $(CONSUMER)/events/stats | $(PP)

.PHONY: recent
recent: ## Most recent stored events
	@curl -s "$(CONSUMER)/events/recent?limit=20" | $(PP)

.PHONY: suspects
suspects: ## Accounts with repeated login failures (raw SQL view)
	@curl -s "$(CONSUMER)/events/failed-logins?minutes=15&threshold=5" | $(PP)

.PHONY: sources
sources: ## Source IPs touching many accounts (raw SQL view)
	@curl -s "$(CONSUMER)/events/noisy-sources?minutes=15&threshold=10" | $(PP)

.PHONY: partitions
partitions: ## Table partitions and sizes
	@curl -s $(CONSUMER)/events/partitions | $(PP)

.PHONY: quality
quality: ## Data quality checks
	@curl -s -X POST $(CONSUMER)/ops/quality/run | $(PP)

.PHONY: dlq
dlq: ## Dead letter summary
	@curl -s $(CONSUMER)/dlq/summary | $(PP)
	@curl -s "$(CONSUMER)/dlq?limit=5" | $(PP)

.PHONY: dlq-replay
dlq-replay: ## Replay dead letters back onto their source topic
	@curl -s -X POST "$(CONSUMER)/dlq/replay?limit=$(or $(LIMIT),100)" | $(PP)

.PHONY: retention
retention: ## Preview retention (add APPLY=true to actually drop)
	@curl -s -X POST "$(CONSUMER)/ops/retention?retainDays=$(or $(DAYS),30)&dryRun=$(if $(filter true,$(APPLY)),false,true)" | $(PP)

## Detections

.PHONY: rules
rules: ## List loaded detection rules
	@curl -s $(DETECTOR)/rules | $(PP)

.PHONY: coverage
coverage: ## MITRE ATT&CK coverage of the rule set
	@curl -s $(DETECTOR)/rules/coverage | $(PP)

.PHONY: sigma
sigma: ## Export all rules as Sigma
	@curl -s $(DETECTOR)/rules/sigma

.PHONY: topology
topology: ## Kafka Streams topology state
	@curl -s $(DETECTOR)/rules/topology/state | $(PP)

.PHONY: topology-describe
topology-describe: ## Print the full Streams topology
	@curl -s $(DETECTOR)/rules/topology/describe

## SOC — alerts, risk, incidents, response

.PHONY: alerts
alerts: ## Open alerts
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" "$(RESPONDER)/alerts?limit=25&active=true" | $(PP)

.PHONY: rule-stats
rule-stats: ## Alert volume and precision per rule
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" $(RESPONDER)/alerts/rule-stats | $(PP)

.PHONY: risk
risk: ## Highest risk entities (decay applied)
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" "$(RESPONDER)/risk?limit=15" | $(PP)

.PHONY: incidents
incidents: ## Open incidents
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" "$(RESPONDER)/incidents?limit=20" | $(PP)

.PHONY: incident
incident: ## Full detail for one incident (ID=1)
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" $(RESPONDER)/incidents/$(or $(ID),1) | $(PP)

.PHONY: actions
actions: ## Proposed and executed response actions
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" "$(RESPONDER)/actions?limit=25" | $(PP)

.PHONY: pending
pending: ## Response actions waiting for a human
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" "$(RESPONDER)/actions?status=proposed&limit=25" | $(PP)

.PHONY: approve
approve: ## Approve and execute an action (ID=1). Needs the responder key.
	@curl -s -X POST -H "X-Api-Key: $(RESPONDER_KEY)" $(RESPONDER)/actions/$(ID)/approve | $(PP)

.PHONY: reject
reject: ## Reject a proposed action (ID=1)
	@curl -s -X POST -H "X-Api-Key: $(ANALYST_KEY)" "$(RESPONDER)/actions/$(ID)/reject?reason=$(or $(REASON),false%20positive)" | $(PP)

.PHONY: revert
revert: ## Undo an executed action (ID=1)
	@curl -s -X POST -H "X-Api-Key: $(RESPONDER_KEY)" $(RESPONDER)/actions/$(ID)/revert | $(PP)

.PHONY: triage
triage: ## Record an analyst verdict (ID=<alert-id> VERDICT=true_positive|false_positive|benign)
	@curl -s -X POST -H "X-Api-Key: $(ANALYST_KEY)" "$(RESPONDER)/alerts/$(ID)/triage?verdict=$(VERDICT)" | $(PP)

.PHONY: audit
audit: ## The audit trail
	@curl -s -H "X-Api-Key: $(VIEWER_KEY)" "$(RESPONDER)/audit?limit=30" | $(PP)

.PHONY: contained
contained: ## Accounts currently disabled by response automation
	@curl -s $(PRODUCER)/iam/accounts/disabled | $(PP)

## Analytics

$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q --upgrade pip
	# The local venv gets Iceberg too; the Airflow image deliberately does not.
	# See analytics/requirements-iceberg.txt for the SQLAlchemy conflict.
	$(VENV)/bin/pip install -q -r analytics/requirements-iceberg.txt

.PHONY: venv
venv: $(VENV) ## Create the Python virtualenv

.PHONY: baseline
baseline: $(VENV) ## Rebuild per-account behavioural baselines
	@cd analytics && ../$(PY) baseline.py --days $(or $(DAYS),7)

.PHONY: publish-baselines
publish-baselines: $(VENV) ## Publish baselines to the compacted Kafka topic for the detector
	@cd analytics && ../$(PY) publish_baselines.py

.PHONY: score
score: $(VENV) ## Score detections against simulated ground truth
	@cd analytics && ../$(PY) score_detections.py $(if $(MINUTES),--minutes $(MINUTES),--hours $(or $(HOURS),6)) $(if $(filter true,$(SAVE)),--save,)

## Lakehouse

.PHONY: archive
archive: $(VENV) ## Archive events to object storage as Parquet (DAYS=2)
	@cd analytics && ../$(PY) archive.py --backfill $(or $(DAYS),2) --verify

.PHONY: lake-stats
lake-stats: $(VENV) ## Compare Postgres vs object-storage cost per row
	@cd analytics && ../$(PY) lakehouse.py stats

.PHONY: lake-query
lake-query: $(VENV) ## Analyst queries over the Parquet archive
	@cd analytics && ../$(PY) lakehouse.py query

.PHONY: lake-pruning
lake-pruning: $(VENV) ## Measure partition pruning against a full scan
	@cd analytics && ../$(PY) lakehouse.py pruning --days $(or $(DAYS),60)

.PHONY: lake-small-files
lake-small-files: $(VENV) ## Load testing

.PHONY: load-ramp
load-ramp: $(VENV) ## Step through rates until the pipeline stops keeping up
	@cd analytics && ../$(PY) loadtest.py ramp --steps $(or $(STEPS),20,200,1000,2500,5000,10000) --seconds $(or $(SECONDS),35) --save

.PHONY: load-sustain
load-sustain: $(VENV) ## Hold one rate and watch whether lag grows (RATE=5000 MINUTES=5)
	@cd analytics && ../$(PY) loadtest.py sustain --rate $(or $(RATE),2000) --minutes $(or $(MINUTES),5)

.PHONY: load-report
load-report: $(VENV) ## Previous load test results
	@cd analytics && ../$(PY) loadtest.py report

## Demonstrate why many small files are a disaster
	@cd analytics && ../$(PY) lakehouse.py small-files

.PHONY: lake-compact
lake-compact: $(VENV) ## Compact a day's partition into one file (DATE=2026-09-12)
	@cd analytics && ../$(PY) lakehouse.py compact --date $(DATE)

.PHONY: iceberg
iceberg: $(VENV) ## Iceberg snapshots, time travel and schema evolution
	@cd analytics && ../$(PY) iceberg_table.py demo

.PHONY: iceberg-history
iceberg-history: $(VENV) ## List Iceberg table snapshots
	@cd analytics && ../$(PY) iceberg_table.py history

## Identity

KEYCLOAK ?= http://localhost:8280/realms/bloodhound/protocol/openid-connect/token

.PHONY: token
token: ## Fetch an access token (USER=viewer|analyst|responder|nobody)
	@curl -s -X POST "$(KEYCLOAK)" -d client_id=bloodhound-cli -d grant_type=password \
		-d "username=$(or $(USER),viewer)" -d "password=$(or $(USER),viewer)" \
		| python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"

.PHONY: whoami
whoami: ## Decode the claims in a token (USER=analyst)
	@$(MAKE) -s token USER=$(or $(USER),viewer) | python3 -c "\
import sys,json,base64; t=sys.stdin.read().strip(); p=t.split('.')[1]; p+='='*(-len(p)%4); \
c=json.loads(base64.urlsafe_b64decode(p)); \
print('  user: ', c['preferred_username']); print('  iss:  ', c['iss']); \
print('  aud:  ', c['aud']); \
print('  roles:', [r for r in c.get('realm_access',{}).get('roles',[]) if r.isupper()])"

.PHONY: authz-matrix
authz-matrix: ## Probe every role against every endpoint class
	@echo "  user         /alerts  triage   approve"; \
	echo "  ------------------------------------------"; \
	for u in viewer analyst responder nobody; do \
		T=$$($(MAKE) -s token USER=$$u); \
		printf "  %-12s %-8s %-8s %s\n" $$u \
		  "$$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $$T" '$(RESPONDER)/alerts?limit=1')" \
		  "$$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $$T" '$(RESPONDER)/alerts/none/triage?verdict=benign')" \
		  "$$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $$T" '$(RESPONDER)/actions/99999/approve')"; \
	done; \
	printf "  %-12s %-8s %-8s %s\n" "no token" \
	  "$$(curl -s -o /dev/null -w '%{http_code}' '$(RESPONDER)/alerts?limit=1')" \
	  "$$(curl -s -o /dev/null -w '%{http_code}' -X POST '$(RESPONDER)/alerts/none/triage?verdict=benign')" \
	  "$$(curl -s -o /dev/null -w '%{http_code}' -X POST '$(RESPONDER)/actions/99999/approve')"; \
	echo ""; echo "  200/404 allowed   401 authenticate first   403 authenticated but refused"

## Cloud

TF_IMAGE ?= hashicorp/terraform:1.9
TF_NET   ?= bloodhound_default
TF_DIR   ?= $(PWD)/infra/terraform
TF = docker run --rm --network $(TF_NET) -v $(TF_DIR):/work -w /work $(TF_IMAGE)
TF_VARS = -var 'localstack_endpoint=http://localstack:4566'

.PHONY: tf-validate
tf-validate: ## Terraform fmt, init and validate
	@$(TF) fmt -check -recursive && echo "  formatting clean"
	@$(TF) init -backend=false -input=false > /dev/null && echo "  init ok"
	@$(TF) validate

.PHONY: tf-plan
tf-plan: ## Plan against LocalStack
	@$(TF) init -input=false > /dev/null
	@$(TF) plan -input=false $(TF_VARS)

.PHONY: tf-apply
tf-apply: ## Apply against LocalStack
	@$(TF) init -input=false > /dev/null
	@$(TF) apply -input=false -auto-approve $(TF_VARS)

.PHONY: tf-destroy
tf-destroy: ## Destroy the LocalStack resources
	@$(TF) destroy -input=false -auto-approve $(TF_VARS)

.PHONY: tf-verify
tf-verify: ## Prove what actually exists in LocalStack
	@echo "  S3 buckets:"
	@$(COMPOSE) exec -T localstack awslocal s3 ls | sed 's/^/    /'
	@echo "  IAM roles:"
	@$(COMPOSE) exec -T localstack awslocal iam list-roles --query 'Roles[].RoleName' --output text | tr '\t' '\n' | sed 's/^/    /'
	@echo "  responder role — allowed vs denied:"
	@$(COMPOSE) exec -T localstack awslocal iam get-role-policy --role-name bloodhound-lab-responder \
		--policy-name contain-only --query PolicyDocument 2>/dev/null | python3 -c "\
import sys,json; d=json.load(sys.stdin); \
[print(f\"    {s['Effect']:6} {s['Sid']}: {', '.join(s['Action'] if isinstance(s['Action'],list) else [s['Action']])}\") for s in d['Statement']]"

## CloudTrail

CLOUDTRAIL ?= http://localhost:8105

.PHONY: cloudtrail
cloudtrail: install-common ## Run the CloudTrail ingestion service (8105)
	$(MVN) -q -pl bloodhound-cloudtrail spring-boot:run

.PHONY: cloudtrail-replay
cloudtrail-replay: ## Map the bundled CloudTrail sample into the pipeline
	@curl -s -X POST $(CLOUDTRAIL)/cloudtrail/replay-sample | $(PP)

.PHONY: cloudtrail-events
cloudtrail-events: ## Show the CloudTrail-derived events in Postgres
	@$(COMPOSE) exec -T postgres psql -U bloodhound -d bloodhound -c \
		"select user_id, event_action, event_outcome, host(source_ip) as src, \
		        labels->>'cloud_event_name' as aws_api \
		 from raw_events where labels->>'cloud_provider' = 'aws' order by ts limit 20;"

## Orchestration

.PHONY: dag-run
dag-run: ## Trigger the daily maintenance DAG (DAY=2026-09-12 to backfill one day)
	@$(COMPOSE) exec -T airflow-scheduler bash -lc \
		"airflow dags unpause bloodhound_daily >/dev/null; \
		 airflow dags trigger bloodhound_daily $(if $(DAY),--conf '{\"day\": \"$(DAY)\"}',)"

.PHONY: dag-status
dag-status: ## Task states for the most recent DAG run
	@RUN=$$($(COMPOSE) exec -T airflow-scheduler airflow dags list-runs -d bloodhound_daily -o plain 2>/dev/null | awk 'NR==2{print $$2}' | tr -d '\r'); \
	echo "run: $$RUN"; \
	$(COMPOSE) exec -T airflow-scheduler airflow tasks states-for-dag-run bloodhound_daily "$$RUN" -o plain 2>/dev/null | awk 'NR>1{printf "  %-20s %s\n", $$3, $$4}'

.PHONY: dag-tree
dag-tree: ## Show the DAG dependency tree
	@$(COMPOSE) exec -T airflow-scheduler bash -lc "airflow tasks list bloodhound_daily --tree" 2>/dev/null | grep -v '^\['

## Load testing

.PHONY: load-ramp
load-ramp: $(VENV) ## Step through rates until the pipeline stops keeping up
	@cd analytics && ../$(PY) loadtest.py ramp --steps $(or $(STEPS),20,200,1000,2500,5000,10000) --seconds $(or $(SECONDS),35) --save

.PHONY: load-sustain
load-sustain: $(VENV) ## Hold one rate and watch whether lag grows (RATE=5000 MINUTES=5)
	@cd analytics && ../$(PY) loadtest.py sustain --rate $(or $(RATE),2000) --minutes $(or $(MINUTES),5)

.PHONY: load-report
load-report: $(VENV) ## Previous load test results
	@cd analytics && ../$(PY) loadtest.py report

## Demo

.PHONY: demo
demo: ## Fire attacks, then show the full alert -> incident -> response chain
	@echo "=== firing scenarios ==="
	@$(MAKE) -s attack-all > /dev/null
	@echo "waiting for the pipeline to settle..."
	@curl -s -o /dev/null --retry 12 --retry-delay 5 --retry-all-errors $(RESPONDER)/actuator/health
	@echo ""
	@echo "=== alerts ===";    $(MAKE) -s alerts
	@echo "=== risk ===";      $(MAKE) -s risk
	@echo "=== incidents ==="; $(MAKE) -s incidents
	@echo "=== pending response actions ==="; $(MAKE) -s pending
