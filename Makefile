SHELL := /bin/bash
COMPOSE := docker compose
CADDY_ROOT := certs/caddy-root.crt
HOSTS := idp gateway identity portal jira confluence

.PHONY: help env up down nuke ps logs trust untrust hosts check check0 check1 check2 bootstrap claude ledger

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

RANDOM_KEYS := POSTGRES_PASSWORD PG_KEYCLOAK_PASSWORD PG_IDENTITY_PASSWORD PG_PORTAL_PASSWORD \
	KC_ADMIN_PASSWORD PORTAL_CLIENT_SECRET GATEWAY_SVC_CLIENT_SECRET MITM_WEB_PASSWORD \
	STUB_ADMIN_TOKEN JIRA_OAUTH_CLIENT_ID JIRA_OAUTH_CLIENT_SECRET

env: ## Create .env, or add keys new phases need (existing values are kept)
	@test -f .env || { cp .env.example .env; echo "wrote .env"; }
	@./scripts/env_sync.sh $(RANDOM_KEYS)

up: env ## Start the stack and wait for the bootstrap jobs
	@mkdir -p certs/mitmproxy .secrets
	$(COMPOSE) up -d
	@$(MAKE) --no-print-directory bootstrap

bootstrap: ## Wait for (or re-run) the Keycloak and OpenBao bootstrap jobs
	@$(COMPOSE) up -d keycloak-init openbao-init >/dev/null 2>&1
	@for s in openbao-init keycloak-init; do \
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

check: check0 check1 check2 ## Run every phase's exit-criteria checks

check0: certs-local ## Phase 0 check: IdP, DCR, PKCE, audience scoping
	@set -a; source .env; set +a; uv run --script scripts/phase0_check.py

check1: certs-local ## Phase 1 check: gateway 401/PRM discovery, whoami, rejections (S1, S14)
	@set -a; source .env; set +a; uv run --script scripts/phase1_check.py

check2: certs-local ## Phase 2 check: Jira stub OAuth provider, REST filtering, rotation, faults
	@set -a; source .env; set +a; uv run --script scripts/phase2_check.py

claude: certs-local ## Start Claude Code trusting the local CA (resume: make claude ARGS=--continue)
	NODE_EXTRA_CA_CERTS=$(CURDIR)/$(CADDY_ROOT) claude $(ARGS)

ledger: ## Follow token-ledger events from all services
	@$(COMPOSE) logs -f --no-log-prefix 2>/dev/null | grep --line-buffered '^LEDGER ' | cut -c8- | jq -c .
