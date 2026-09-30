"""Lightweight statistical anomaly detection over OT telemetry time series.

Deliberately protocol-agnostic: takes numeric samples (e.g. packet
rate, connection count, PLC scan-cycle time) and flags points that
deviate from a rolling baseline. There is no protocol parsing or
packet crafting here -- callers are responsible for turning raw
network/telemetry capture into numeric series.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, pstdev


@dataclass(frozen=True)
class AnomalyPoint:
    index: int
    value: float
    z_score: float


class RollingZScoreDetector:
    """Flags samples more than `threshold` standard deviations from a
    trailing window's mean. Requires at least `window` prior samples
    before it will flag anything (cold-start safe -- no flags on the
    first `window` points)."""

    def __init__(self, window: int = 20, threshold: float = 3.0) -> None:
        if window < 2:
            raise ValueError("window must be >= 2")
        if threshold <= 0:
            raise ValueError("threshold must be > 0")
        self.window = window
        self.threshold = threshold

    def detect(self, series: list[float]) -> list[AnomalyPoint]:
        anomalies: list[AnomalyPoint] = []
        for i in range(len(series)):
            if i < self.window:
                continue
            baseline = series[i - self.window : i]
            mu = mean(baseline)
            # A perfectly flat baseline has sigma == 0. Floor it instead
            # of skipping: an unchanged value still yields z == 0, but a
            # real deviation from a flat baseline is exactly the case we
            # most want to catch, not silently drop.
            sigma = pstdev(baseline) or 1e-9
            z = (series[i] - mu) / sigma
            if abs(z) >= self.threshold:
                anomalies.append(
                    AnomalyPoint(index=i, value=series[i], z_score=round(z, 2))
                )
        return anomalies
