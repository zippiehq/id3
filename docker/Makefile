all:
	openssl genrsa -out drand1-priv.pem 1024
	openssl genrsa -out drand2-priv.pem 1024
	docker-compose -f docker-compose.yml build

run:
	docker-compose -f docker-compose.yml up
	
clean: 
	rm -rf drand1-data drand1-priv.pem drand2-data/ drand2-priv.pem tor-keys