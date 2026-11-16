"""Detection and Correlation Engine Module for SOC-SIM."""
from .engine import DetectionEngine
from .correlation import EventCorrelator

__all__ = ["DetectionEngine", "EventCorrelator"]
