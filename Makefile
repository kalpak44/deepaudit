.PHONY: test demo check

test:
	python -m unittest discover -s tests -v

demo:
	python -m deepaudit demo

check:
	python -m compileall -q deepaudit tests
	python -m unittest discover -s tests -v
