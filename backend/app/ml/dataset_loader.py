"""Dataset Loader for SafeContain AI Machine Learning Pipeline.

Loads, validates, and provides structured access to enterprise cybersecurity
datasets (nodes, relationships, assets, vulnerabilities, alerts, evidence, etc.).
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd


# Default dataset directory relative to project root
DEFAULT_ML_DATASET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "synthetic_enterprise")
)

EXPECTED_DATASET_FILES = [
    "nodes.csv",
    "relationships.csv",
    "assets.csv",
    "users.csv",
    "vulnerabilities.csv",
    "security_alerts.csv",
    "evidence.csv",
    "attack_paths.csv",
    "interventions.csv",
    "asset_dependencies.csv",
    "business_impact.csv",
    "threat_scenarios.csv",
]


class DatasetLoader:
    """Loads and caches enterprise tabular and graph telemetry datasets."""

    def __init__(self, dataset_dir: Optional[str] = None):
        self.dataset_dir = os.path.abspath(dataset_dir or DEFAULT_ML_DATASET_DIR)
        self._cache: Dict[str, pd.DataFrame] = {}

    def get_available_files(self) -> List[str]:
        """Returns list of CSV filenames present in the dataset directory."""
        if not os.path.isdir(self.dataset_dir):
            return []
        return [
            f for f in os.listdir(self.dataset_dir)
            if f.endswith(".csv") and os.path.isfile(os.path.join(self.dataset_dir, f))
        ]

    def load_table(self, filename: str, force_reload: bool = False) -> pd.DataFrame:
        """Loads a specific CSV file into a Pandas DataFrame with caching."""
        if not filename.endswith(".csv"):
            filename = f"{filename}.csv"

        if not force_reload and filename in self._cache:
            return self._cache[filename].copy()

        filepath = os.path.join(self.dataset_dir, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dataset file '{filename}' not found at {filepath}")

        df = pd.read_csv(filepath)
        self._cache[filename] = df
        return df.copy()

    def load_all_tables(self, force_reload: bool = False) -> Dict[str, pd.DataFrame]:
        """Loads all available CSV tables in the dataset directory."""
        tables = {}
        for filename in self.get_available_files():
            tables[filename] = self.load_table(filename, force_reload=force_reload)
        return tables

    def get_inventory_summary(self) -> Dict[str, Any]:
        """Generates a complete summary inventory of all enterprise datasets."""
        available_files = self.get_available_files()
        tables_summary = {}
        total_records = 0

        for filename in sorted(available_files):
            df = self.load_table(filename)
            null_counts = {col: int(df[col].isnull().sum()) for col in df.columns}
            tables_summary[filename] = {
                "records": len(df),
                "features_count": len(df.columns),
                "columns": list(df.columns),
                "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
                "null_counts": null_counts,
                "total_nulls": int(df.isnull().sum().sum()),
                "duplicate_rows": int(df.duplicated().sum()),
            }
            total_records += len(df)

        missing_expected = [f for f in EXPECTED_DATASET_FILES if f not in available_files]

        return {
            "dataset_directory": self.dataset_dir,
            "total_files": len(available_files),
            "total_records": total_records,
            "expected_files_count": len(EXPECTED_DATASET_FILES),
            "missing_expected_files": missing_expected,
            "tables": tables_summary,
        }
