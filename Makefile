all: install

run: venv/bin/python3
	./venv/bin/python Filer.py -P 5000

venv/bin/python3:
	python3 -m venv ./venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
