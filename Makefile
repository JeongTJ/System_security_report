all:
	make up

up:
	docker-compose up --build -d

down:
	docker-compose down

re:
	docker-compose down
	docker-compose up --build -d