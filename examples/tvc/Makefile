.PHONY: up smoke down

up:
	docker compose up --build --wait

smoke:
	docker compose exec -T mock-turnkey mock-turnkey smoke http://127.0.0.1:44021 http://tvc:44020

down:
	docker compose down
