.PHONY: up down logs rebuild shell

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

rebuild:
	docker compose down
	docker compose build --no-cache
	docker compose up -d

shell:
	docker compose exec backend /bin/bash
