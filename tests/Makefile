java8:
	docker run --rm \
		-v ${PWD}:/result \
		-w /result \
		-u $(shell id -u) \
		openjdk:8 bash ./generate.sh feature
java11:
	docker run --rm \
		-v ${PWD}:/result \
		-w /result \
		-u $(shell id -u) \
		openjdk:11 bash ./generate.sh feature/java11
