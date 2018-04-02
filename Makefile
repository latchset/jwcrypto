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

testlong: export JWCRYPTO_TESTS_ENABLE_MMA=True
testlong: export TOX_TESTENV_PASSENV=JWCRYPTO_TESTS_ENABLE_MMA
testlong:
	rm -f .coverage
	tox -e py36

test:
	rm -f .coverage
	tox -e py27
	tox -e py34 --skip-missing-interpreter
	tox -e py35 --skip-missing-interpreter
	tox -e py36 --skip-missing-interpreter

DOCS_DIR = docs
.PHONY: docs

docs:
	$(MAKE) -C $(DOCS_DIR) html
