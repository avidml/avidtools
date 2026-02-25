# Testing

This document describes how to run and contribute to the test suite for avidtools.

## Test Structure

The test suite is organized as follows:

```
tests/
├── conftest.py                    # Test configuration and fixtures
├── unit/                         # Unit tests
│   ├── datamodels/              # Tests for data models
│   │   ├── test_components.py   # Component data model tests
│   │   └── test_enums.py        # Enum tests
│   └── connectors/              # Tests for connectors
│       ├── test_atlas.py        # ATLAS connector tests
│       ├── test_cve.py          # CVE connector tests
│       └── test_inspect.py      # Inspect connector tests
└── integration/                 # Integration tests (future)
```

## Running Tests

### All Tests
```bash
make test
# or
poetry run pytest tests/
```

### Specific Test Categories
```bash
# Unit tests only
poetry run pytest tests/unit/

# Data model tests
poetry run pytest tests/unit/datamodels/

# Connector tests  
poetry run pytest tests/unit/connectors/

# Specific connector
poetry run pytest tests/unit/connectors/test_atlas.py
```

### With Coverage
```bash
poetry run pytest tests/ --cov=avidtools --cov-report=html
```

### Verbose Output
```bash
poetry run pytest tests/ -v
```

## Test Configuration

Tests are configured in `pyproject.toml` with the following settings:

- **Test paths**: `tests/` directory
- **Coverage**: Enabled with HTML, XML, and terminal reports
- **Markers**: `unit` and `integration` for categorizing tests
- **Coverage target**: 80%+ code coverage

## Writing Tests

### Test Fixtures

Common test fixtures are defined in `tests/conftest.py`:

- `sample_atlas_case_study`: Mock ATLAS case study data
- `sample_cve_data`: Mock CVE data  
- `mock_requests_get`: Mock HTTP requests
- `mock_nvdlib_search`: Mock NVD library calls

### Test Categories

Use pytest markers to categorize tests:

```python
import pytest

@pytest.mark.unit
def test_component_creation():
    """Unit test for component creation."""
    pass

@pytest.mark.integration  
def test_full_workflow():
    """Integration test for full workflow."""
    pass
```

### Mocking External Dependencies

Tests use `pytest-mock` and `responses` for mocking:

```python
from unittest.mock import Mock, patch
import responses

# Mock HTTP calls
@responses.activate
def test_api_call():
    responses.add(responses.GET, "https://api.example.com", json={"data": "test"})
    # Test code here

# Mock function calls
@patch('avidtools.module.function')
def test_function_call(mock_function):
    mock_function.return_value = "test"
    # Test code here
```

## CI/CD Integration

Tests are automatically run in GitHub Actions on:

- Pull requests to `main` branch
- The workflow includes:
  1. Python setup (3.12)
  2. Poetry installation and dependency setup
  3. Type checking with mypy
  4. Linting with ruff
  5. Test execution with coverage reporting

## Coverage Reports

After running tests with coverage, reports are generated in:

- **HTML**: `htmlcov/index.html` - Interactive web report
- **XML**: `coverage.xml` - For CI/CD systems
- **Terminal**: Displayed in console output

## Best Practices

1. **Test Naming**: Use descriptive names that explain what is being tested
2. **Arrange-Act-Assert**: Structure tests with clear setup, execution, and verification
3. **Mocking**: Mock external dependencies to ensure tests are isolated and fast
4. **Coverage**: Aim for high test coverage but focus on meaningful tests
5. **Documentation**: Add docstrings to test classes and complex test methods

## Debugging Tests

### Run with Debug Info
```bash
poetry run pytest tests/ -v -s --tb=long
```

### Run Specific Test
```bash
poetry run pytest tests/unit/datamodels/test_components.py::TestLangValue::test_lang_value_creation -v
```

### Drop into Debugger
```python
def test_something():
    import pdb; pdb.set_trace()
    # Test code here
```
