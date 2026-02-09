.PHONY: test lint clean install dev

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test:
	pytest test_scanner.py -v --tb=short

test-coverage:
	pytest test_scanner.py --cov=ip_scanner --cov-report=html

lint:
	flake8 ip_scanner.py --max-line-length=100 --ignore=E501
	bandit ip_scanner.py -f txt

security:
	bandit ip_scanner.py -f txt -o security_report.txt
	cat security_report.txt

format:
	black ip_scanner.py test_scanner.py

check:
	pytest test_scanner.py
	flake8 ip_scanner.py --max-line-length=100 --ignore=E501
	bandit ip_scanner.py -f txt

clean:
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -f security_report.txt

ci: test lint

dev: install test
