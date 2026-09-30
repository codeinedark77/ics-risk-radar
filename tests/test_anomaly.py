import pytest

from ics_risk_radar.anomaly import RollingZScoreDetector


def test_invalid_window_rejected():
    with pytest.raises(ValueError):
        RollingZScoreDetector(window=1)


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        RollingZScoreDetector(threshold=0)


def test_no_flags_before_window_fills():
    d = RollingZScoreDetector(window=10, threshold=3.0)
    series = [1.0] * 5
    assert d.detect(series) == []


def test_flat_series_no_anomalies():
    d = RollingZScoreDetector(window=10, threshold=3.0)
    series = [5.0] * 50
    assert d.detect(series) == []


def test_spike_detected():
    d = RollingZScoreDetector(window=20, threshold=3.0)
    series = [10.0] * 30
    series[29] = 500.0  # obvious spike after baseline established
    anomalies = d.detect(series)
    assert len(anomalies) == 1
    assert anomalies[0].index == 29
    assert anomalies[0].value == 500.0


def test_gradual_drift_not_flagged_as_hard_spike():
    # slow linear drift shouldn't blow past a 3-sigma window jump
    d = RollingZScoreDetector(window=10, threshold=3.0)
    series = [float(i) for i in range(40)]
    anomalies = d.detect(series)
    # allow it to find at most a couple of borderline points, but it
    # must not flag the whole back half of a smooth ramp
    assert len(anomalies) < 5


def test_negative_spike_detected():
    d = RollingZScoreDetector(window=15, threshold=3.0)
    series = [100.0] * 20
    series[19] = -400.0
    anomalies = d.detect(series)
    assert any(a.index == 19 and a.z_score < 0 for a in anomalies)
