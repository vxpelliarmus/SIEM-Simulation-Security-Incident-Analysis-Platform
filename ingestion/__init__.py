"""Log Ingestion and Normalization Module for SOC-SIM."""
from .normalizer import EventNormalizer
from .log_collector import LogCollector

__all__ = ["EventNormalizer", "LogCollector"]
