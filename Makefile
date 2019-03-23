lint:
	pylint sanic_oauth
	pycodestyle sanic_oauth
	# mypy --ignore-missing-imports sanic_oauth
pytest:
	pytest tests

install:
	pip uninstall -y sanic-oauth
	python setup.py install