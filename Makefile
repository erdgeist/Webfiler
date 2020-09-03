all: install

run: venv/bin/python3
	./venv/bin/python Filer.py -P 5000

translations/en/LC_MESSAGES/messages.mo:
	./venv/bin/pybabel compile -d translations

rebuild_po:
	./venv/bin/pybabel extract -F babel.cfg -o messages.pot .
	./venv/bin/pybabel update -i messages.pot -d translations

venv/bin/python3:
	python3 -m venv ./venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
