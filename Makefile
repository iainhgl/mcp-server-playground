SHELL := /bin/bash
COMPOSE := docker compose
CADDY_ROOT := certs/caddy-root.crt
HOSTS := idp gateway identity portal jira confluence

.PHONY: help env up down nuke ps logs trust untrust hosts check check0 check1 check2 check3 check4 check5 check6 bootstrap claude ledger consent-signal

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

RANDOM_KEYS := POSTGRES_PASSWORD PG_KEYCLOAK_PASSWORD PG_IDENTITY_PASSWORD PG_PORTAL_PASSWORD \
	KC_ADMIN_PASSWORD PORTAL_CLIENT_SECRET GATEWAY_SVC_CLIENT_SECRET MITM_WEB_PASSWORD \
	STUB_ADMIN_TOKEN JIRA_OAUTH_CLIENT_ID JIRA_OAUTH_CLIENT_SECRET CONFLUENCE_OAUTH_CLIENT_ID CONFLUENCE_OAUTH_CLIENT_SECRET \
	IDENTITY_ADMIN_TOKEN IDENTITY_WAT_KEY PORTAL_SVC_CLIENT_SECRET PORTAL_COOKIE_KEY LEDGER_WRITER_PASSWORD

env: ## Create .env, or add keys new phases need (existing values are kept)
	@test -f .env || { cp .env.example .env; echo "wrote .env"; }
	@./scripts/env_sync.sh $(RANDOM_KEYS)

up: env ## Start the stack and wait for the bootstrap jobs
	@mkdir -p certs/mitmproxy .secrets/identity
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory bootstrap

bootstrap: ## Wait for (or re-run) the DB, OpenBao, Keycloak and identity bootstrap jobs
	@$(COMPOSE) up -d db-init keycloak-init openbao-init identity-init >/dev/null 2>&1
	@for s in db-init openbao-init keycloak-init identity-init; do \
	  $(COMPOSE) wait $$s >/dev/null 2>&1; \
	  code=$$(docker inspect -f '{{.State.ExitCode}}' $$($(COMPOSE) ps -aq $$s)); \
	  if [ "$$code" != "0" ]; then echo "✗ $$s failed (exit $$code)"; \
	    $(COMPOSE) logs --no-log-prefix --since "$$(docker inspect -f '{{.State.StartedAt}}' $$($(COMPOSE) ps -aq $$s))" $$s | tail -20; exit 1; fi; \
	  echo "✓ $$s"; done

down: ## Stop the stack (keeps data)
	$(COMPOSE) down

nuke: ## Stop and delete all data volumes and OpenBao keys
	$(COMPOSE) down -v
	rm -rf .secrets

ps: ## Container status
	$(COMPOSE) ps -a

logs: ## Follow logs (make logs s=keycloak)
	$(COMPOSE) logs -f $(s)

trust: ## Export Caddy's root CA and trust it in your login keychain (prompts)
	@mkdir -p certs
	$(COMPOSE) cp caddy:/data/caddy/pki/authorities/local/root.crt $(CADDY_ROOT)
	security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db $(CADDY_ROOT)
	@echo "Trusted $(CADDY_ROOT). Firefox uses its own store; Node (Claude Code) needs NODE_EXTRA_CA_CERTS."

untrust: ## Remove the Caddy root CA from your keychain
	security remove-trusted-cert $(CADDY_ROOT) || true
	security delete-certificate -Z $$(openssl x509 -in $(CADDY_ROOT) -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :) ~/Library/Keychains/login.keychain-db || true

hosts: ## Offline fallback: add *.localtest.me to /etc/hosts (sudo)
	@for h in $(HOSTS); do grep -q " $$h.localtest.me$$" /etc/hosts || echo "127.0.0.1 $$h.localtest.me" | sudo tee -a /etc/hosts; done

certs-local:
	@test -f $(CADDY_ROOT) || $(COMPOSE) cp caddy:/data/caddy/pki/authorities/local/root.crt $(CADDY_ROOT)

check: check0 check1 check2 check3 check4 check5 check6 ## Run every phase's exit-criteria checks

check0: certs-local ## Phase 0 check: IdP, DCR, PKCE, audience scoping
	@set -a; source .env; set +a; uv run --script scripts/phase0_check.py

check1: certs-local ## Phase 1 check: gateway 401/PRM discovery, whoami, rejections (S1, S14)
	@set -a; source .env; set +a; uv run --script scripts/phase1_check.py

check2: certs-local ## Phase 2 check: Jira stub OAuth provider, REST filtering, rotation, faults
	@set -a; source .env; set +a; uv run --script scripts/phase2_check.py

check3: certs-local ## Phase 3 check: identity, token vault, 3LO consent, session binding (S9)
	@set -a; source .env; set +a; uv run --script scripts/phase3_check.py

check4: certs-local ## Phase 4 check: end to end via gateway + portal (S3 S5 S8 S12 S15 S18, C6, elicitation)
	@set -a; source .env; set +a; uv run --script scripts/phase4_check.py

check5: certs-local ## Phase 5 check: refresh/concurrency via gateway, verify mode, step-up deny, user disable, PKCE
	@set -a; source .env; set +a; uv run --script scripts/phase5_check.py

check6: certs-local ## Phase 6 check: Confluence persona + tools, separate consent, per-user spaces
	@set -a; source .env; set +a; uv run --script scripts/phase6_check.py

claude: certs-local ## Start Claude Code trusting the local CA (resume: make claude ARGS=--continue)
	NODE_EXTRA_CA_CERTS=$(CURDIR)/$(CADDY_ROOT) claude $(ARGS)

consent-signal: ## Switch how the gateway signals consent: make consent-signal MODE=auto|tool_error|url_elicitation
	GATEWAY_CONSENT_SIGNAL=$(MODE) $(COMPOSE) up -d --wait gateway
	@echo "gateway consentSignal=$(or $(MODE),auto (from gateway.yaml))"

ledger: ## Follow token-ledger events from all services
	@$(COMPOSE) logs -f --no-log-prefix 2>/dev/null | grep --line-buffered '^LEDGER ' | cut -c8- | jq -c .
