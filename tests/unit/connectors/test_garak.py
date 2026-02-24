"""Unit tests for Garak connector normalize helpers."""

from avidtools.connectors.garak import _normalize_metric_results


def test_normalize_metric_results_wraps_list_rows_in_dict():
    """List-based metric rows should be wrapped under results.rows."""
    report = {
        "metrics": [
            {
                "name": "score",
                "results": [
                    {"index": 1, "detector": "foo", "score": 10},
                    {"index": 2, "detector": "bar", "score": 20},
                ],
            }
        ]
    }

    _normalize_metric_results(report)

    results = report["metrics"][0]["results"]
    assert isinstance(results, dict)
    assert "rows" in results
    assert results["rows"][0] == {"detector": "foo", "score": 10}
    assert results["rows"][1] == {"detector": "bar", "score": 20}


def test_normalize_metric_results_transforms_columnar_dict_to_rows():
    """Columnar metric dicts should be transformed into ordered row dicts."""
    report = {
        "metrics": [
            {
                "name": "score",
                "results": {
                    "index": {"0": 0, "1": 1},
                    "detector": {"0": "foo", "1": "bar"},
                    "score": {"0": 50, "1": 80},
                },
            }
        ]
    }

    _normalize_metric_results(report)

    rows = report["metrics"][0]["results"]["rows"]
    assert rows == [
        {"detector": "foo", "score": 50},
        {"detector": "bar", "score": 80},
    ]
