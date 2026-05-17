from abc import ABC, abstractmethod
from app.utils.logger import setup_logger

class BaseScanner(ABC):
    """Abstract base class for all scanners."""
    
    def __init__(self):
        self.logger = setup_logger(self.__class__.__name__)
        self.findings = []
        
    @abstractmethod
    def scan(self):
        """Execute the scan and populate findings. Must be implemented by subclasses."""
        pass
        
    def add_finding(self, resource_id, issue, risk, remediation):
        """Standardized format for findings."""
        self.findings.append({
            "resource_id": resource_id,
            "issue": issue,
            "risk": risk,
            "remediation": remediation
        })
        
    def get_findings(self):
        return self.findings
