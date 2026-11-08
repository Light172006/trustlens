"""
TrustLens Web Security Analyzer - Model Artifact Registry & Checksum Integrity
Saves, registers, and loads model artifacts, preprocessors, and metadata with cryptographic SHA-256 verification.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import joblib

logger = logging.getLogger("model_registry")

BASE_DIR = Path(__file__).resolve().parent.parent


def compute_file_sha256(filepath: Path) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def save_model_artifacts(
    model: Any,
    preprocessor: Any,
    metadata: Dict[str, Any],
    output_dir: Optional[Path] = None,
) -> Path:
    if output_dir is None:
        output_dir = BASE_DIR / "models" / "best_model"
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "model.joblib"
    preprocessor_path = output_dir / "preprocessor.joblib"

    logger.info(f"Serializing model to {model_path}...")
    joblib.dump(model, model_path)

    logger.info(f"Serializing preprocessor pipeline to {preprocessor_path}...")
    joblib.dump(preprocessor, preprocessor_path)

    # Compute checksums
    model_sha256 = compute_file_sha256(model_path)
    prep_sha256 = compute_file_sha256(preprocessor_path)

    metadata["artifacts"] = {
        "model_file": str(model_path.name),
        "model_sha256": model_sha256,
        "model_size_bytes": model_path.stat().st_size,
        "preprocessor_file": str(preprocessor_path.name),
        "preprocessor_sha256": prep_sha256,
        "preprocessor_size_bytes": preprocessor_path.stat().st_size,
    }

    meta_path = BASE_DIR / "models" / "model_metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Wrote model metadata with SHA-256 checksums to {meta_path}")
    return output_dir


def load_model_artifacts(
    models_dir: Optional[Path] = None,
    verify_checksums: bool = True,
) -> Tuple[Any, Any, Dict[str, Any]]:
    if models_dir is None:
        models_dir = BASE_DIR / "models" / "best_model"
    meta_path = BASE_DIR / "models" / "model_metadata.json"

    if not meta_path.exists():
        raise FileNotFoundError(f"Model metadata not found at {meta_path}")

    with open(meta_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    model_path = models_dir / metadata["artifacts"]["model_file"]
    preprocessor_path = models_dir / metadata["artifacts"]["preprocessor_file"]

    if not model_path.exists():
        raise FileNotFoundError(f"Model artifact not found at {model_path}")
    if not preprocessor_path.exists():
        raise FileNotFoundError(f"Preprocessor artifact not found at {preprocessor_path}")

    if verify_checksums:
        actual_model_sha = compute_file_sha256(model_path)
        expected_model_sha = metadata["artifacts"]["model_sha256"]
        if actual_model_sha != expected_model_sha:
            raise ValueError(
                f"Model artifact SHA-256 mismatch! Expected: {expected_model_sha}, Actual: {actual_model_sha}"
            )

        actual_prep_sha = compute_file_sha256(preprocessor_path)
        expected_prep_sha = metadata["artifacts"]["preprocessor_sha256"]
        if actual_prep_sha != expected_prep_sha:
            raise ValueError(
                f"Preprocessor artifact SHA-256 mismatch! Expected: {expected_prep_sha}, Actual: {actual_prep_sha}"
            )

    model = joblib.load(model_path)
    preprocessor = joblib.load(preprocessor_path)

    logger.info(f"Successfully loaded and verified model artifact '{metadata['model_name']}' (v{metadata['model_version']})")
    return model, preprocessor, metadata

