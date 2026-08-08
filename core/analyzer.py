"""
core/analyzer.py

Coordinates packet analysis.
"""

from core.detector_engine import DetectorEngine


class Analyzer:

    def __init__(self, packets):
        self.packets = packets
        self.engine = DetectorEngine()

    def analyze(self):
        return self.engine.run(self.packets)

