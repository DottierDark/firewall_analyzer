from abc import ABC, abstractmethod
from typing import List

from ..core.models import FirewallRule, SecurityFinding


class BaseAnalyzer(ABC):
    """Abstract base class for all security analyzers."""

    @abstractmethod
    def analyze(self, rule: FirewallRule) -> List[SecurityFinding]:
        """Analyze a single firewall rule and return findings."""
        pass