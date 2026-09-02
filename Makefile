.PHONY: setup backend frontend test test-backend test-frontend seed build clean

setup:
	bash scripts/setup.sh

backend:
	bash scripts/run_backend.sh

frontend:
	bash scripts/run_frontend.sh

seed:
	python scripts/seed_demo.py

test-backend:
	cd backend && . .venv/bin/activate && python -m pytest tests/ -v

test-frontend:
	cd frontend && npm test

test: test-backend test-frontend

docker-up:
	docker compose up --build

docker-down:
	docker compose down

build:
	cd frontend && npm run build

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf frontend/dist
