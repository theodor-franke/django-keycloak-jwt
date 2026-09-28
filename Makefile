.PHONY: lint typecheck test e2e-up e2e e2e-down

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy src/django_keycloak_jwt

test:
	uv run pytest --cov --cov-report=term-missing

e2e-up:
	docker compose up -d
	@echo "Waiting for Keycloak to be ready..."
	@until curl -sf http://localhost:9000/health/ready >/dev/null 2>&1; do sleep 2; done
	@echo "Keycloak is ready."

e2e:
	uv run python example_project/manage.py migrate
	DJANGO_SETTINGS_MODULE=example_project.settings uv run pytest -m e2e e2e/

e2e-down:
	docker compose down -v
