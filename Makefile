all: lint pep8 docs test
	echo "All tests passed"

lint:
	# Pylint checks
	tox -e lint

pep8:
	# Check style consistency
	tox -e pep8py2
	tox -e pep8py3

clean:
	rm -fr build dist *.egg-info
	find ./ -name '*.pyc' -exec rm -f {} \;

cscope:
	git ls-files | xargs pycscope

test:
	rm -f .coverage
	tox -e py27
	tox -e py34 --skip-missing-interpreter
	tox -e py35 --skip-missing-interpreter

DOCS_DIR = docs
.PHONY: docs

docs:
	$(MAKE) -C $(DOCS_DIR) html
