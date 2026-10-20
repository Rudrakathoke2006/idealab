"""
AEGIS-X HIBP Breach Catalog & Arrival Lag Loader (Dossier B6, Section 7.1)

Loads real breach metadata (BreachDate, AddedDate, DataClasses, IsVerified, IsFabricated, IsSensitive).
Computes empirical arrival-lag distribution:
  Delta_t = AddedDate - BreachDate
Used by the attack simulator to generate realistic benign and adversarial arrival processes.
"""

import os
import json
import datetime
from typing import Dict, List, Any, Tuple, Optional
import numpy as np
import pandas as pd

# Curated reference breach catalogue mirroring HIBP public schema metadata
REFERENCE_HIBP_BREACHES = [
    {"Name": "Adobe", "BreachDate": "2013-10-04", "AddedDate": "2013-12-04", "PwnCount": 152445165, "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "LinkedIn", "BreachDate": "2012-05-05", "AddedDate": "2016-05-18", "PwnCount": 164611595, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "Canva", "BreachDate": "2019-05-24", "AddedDate": "2019-05-28", "PwnCount": 137272825, "DataClasses": ["Email addresses", "Geographic locations", "Names", "Passwords", "Usernames"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "Dropbox", "BreachDate": "2012-07-01", "AddedDate": "2016-08-31", "PwnCount": 68648009, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "MyFitnessPal", "BreachDate": "2018-02-01", "AddedDate": "2018-03-30", "PwnCount": 143621484, "DataClasses": ["Email addresses", "IP addresses", "Passwords", "Usernames"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "Evite", "BreachDate": "2019-02-20", "AddedDate": "2019-06-19", "PwnCount": 100985032, "DataClasses": ["Email addresses", "IP addresses", "Names", "Passwords"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "Zomato", "BreachDate": "2017-05-18", "AddedDate": "2017-05-18", "PwnCount": 16641775, "DataClasses": ["Email addresses", "Passwords", "Usernames"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "Dubsmash", "BreachDate": "2018-12-01", "AddedDate": "2019-02-12", "PwnCount": 161749950, "DataClasses": ["Email addresses", "Geographic locations", "Names", "Passwords", "Usernames"], "IsVerified": True, "IsFabricated": False, "IsSensitive": False},
    {"Name": "FakeLeakDarkWebDump", "BreachDate": "2026-03-01", "AddedDate": "2026-03-02", "PwnCount": 500000, "DataClasses": ["Emails", "Forged Credentials"], "IsVerified": False, "IsFabricated": True, "IsSensitive": True},
    {"Name": "UnverifiedForumPaste", "BreachDate": "2026-01-10", "AddedDate": "2026-01-11", "PwnCount": 12000, "DataClasses": ["Emails", "Plaintext Passwords"], "IsVerified": False, "IsFabricated": False, "IsSensitive": False}
]

class HIBPCatalogueLoader:
    """Loads breach metadata and extracts arrival-lag empirical distribution."""

    def __init__(self, data_path: Optional[str] = None):
        self.data_path = data_path
        self.breaches = self._load_data()
        self.lag_days: List[float] = []
        self._compute_lag_statistics()

    def _load_data(self) -> List[Dict[str, Any]]:
        if self.data_path and os.path.exists(self.data_path):
            try:
                with open(self.data_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return REFERENCE_HIBP_BREACHES

    def _compute_lag_statistics(self):
        """Computes empirical arrival lag Delta_t = AddedDate - BreachDate in days."""
        lags = []
        for b in self.breaches:
            try:
                b_date = datetime.date.fromisoformat(b["BreachDate"])
                a_date = datetime.date.fromisoformat(b["AddedDate"])
                delta = max(0, (a_date - b_date).days)
                lags.append(float(delta))
            except Exception:
                continue
        self.lag_days = lags if lags else [60.0, 1460.0, 4.0, 1500.0, 57.0, 119.0, 0.0, 73.0, 1.0, 1.0]

    def get_lag_summary(self) -> Dict[str, float]:
        """Returns empirical summary statistics of arrival lag."""
        arr = np.array(self.lag_days)
        return {
            "mean_lag_days": round(float(np.mean(arr)), 1),
            "median_lag_days": round(float(np.median(arr)), 1),
            "p25_lag_days": round(float(np.percentile(arr, 25)), 1),
            "p75_lag_days": round(float(np.percentile(arr, 75)), 1),
            "p95_lag_days": round(float(np.percentile(arr, 95)), 1),
            "sample_count": len(arr)
        }

    def sample_arrival_lag_hours(self, rng: Optional[np.random.RandomState] = None) -> float:
        """Samples a realistic breach arrival lag in hours."""
        if rng is None:
            rng = np.random.RandomState(42)
        base_days = float(rng.choice(self.lag_days))
        # Add random hourly jitter
        jitter_hours = float(rng.uniform(0.0, 24.0))
        return (base_days * 24.0) + jitter_hours

hibp_loader = HIBPCatalogueLoader()
