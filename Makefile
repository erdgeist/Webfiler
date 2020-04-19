all: install

run:
	./venv/bin/python Filer.py -P 5000 &

venv:
	python3 -m venv ./venv

install: venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
