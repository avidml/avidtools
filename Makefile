.PHONY: all setup setup-submodules update-submodules install update clean test lint format help

# Default target
all: help

# Setup the project
setup: install

# Install dependencies
install:
	@echo "Installing dependencies..."
	poetry install
	@echo "Installation complete."

# Clean up generated files
clean:
	@echo "Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name "*.spec" -delete
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf build
	rm -rf dist
	rm -rf *.egg-info
	@echo "Cleanup complete."

# Run tests
test:
	@echo "Running tests..."
	poetry run pytest tests/
	@echo "Tests complete."


typecheck:
	@echo "Running mypy..."
	poetry run mypy --config-file ./mypy.ini avidtools
	@echo "mypy complete."

linting:
	@echo "Running ruff check..."
	poetry run ruff check avidtools
	@echo "ruff check complete"

# Run linter
lint: typecheck linting

# Format code
format:
	@echo "Formatting code..."
	poetry run ruff format .
	@echo "Formatting complete."

# Help command
help:
	@echo "Available commands:"
	@echo "  make setup            - Set up the project (initialize submodules and install dependencies)"
	@echo "  make setup-submodules - Initialize and update submodules"
	@echo "  make update-submodules - Update submodules"
	@echo "  make install          - Install project dependencies"
	@echo "  make update           - Update project dependencies and submodules"
	@echo "  make clean            - Clean up generated files"
	@echo "  make test             - Run tests"
	@echo "  make lint             - Run linter (Ruff and mypy)"
	@echo "  make format           - Format code using Ruff"
	@echo "  make help             - Show this help message"