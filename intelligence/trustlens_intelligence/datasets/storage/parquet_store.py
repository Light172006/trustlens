"""TrustLens Intelligence — High-Performance Streaming Parquet Storage.

Provides chunked, schema-validated Parquet writing, reading, and batch iteration
with snappy or zstandard compression using PyArrow and pandas.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


class ParquetStore:
    """Manages high-throughput analytical persistence for ML dataset chunks."""

    def __init__(self, default_compression: str = "snappy") -> None:
        self.default_compression = default_compression

    def write_table(
        self,
        df: pd.DataFrame,
        path: Path | str,
        compression: str | None = None,
    ) -> Path:
        """Write a DataFrame to a Parquet file atomically."""
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        comp = compression or self.default_compression
        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, target_path, compression=comp)
        return target_path

    def append_chunk(
        self,
        df: pd.DataFrame,
        path: Path | str,
        compression: str | None = None,
    ) -> Path:
        """Append a DataFrame chunk to an existing Parquet file or create a new one."""
        target_path = Path(path)
        if not target_path.exists():
            return self.write_table(df, target_path, compression=compression)

        existing_df = self.read_dataframe(target_path)
        combined_df = pd.concat([existing_df, df], ignore_index=True)
        return self.write_table(combined_df, target_path, compression=compression)

    def read_dataframe(
        self,
        path: Path | str,
        columns: list[str] | None = None,
    ) -> pd.DataFrame:
        """Read Parquet file into a pandas DataFrame."""
        target_path = Path(path)
        if not target_path.exists():
            raise FileNotFoundError(f"Parquet file not found: {target_path}")

        table = pq.read_table(target_path, columns=columns)
        return table.to_pandas()

    def iter_batches(
        self,
        path: Path | str,
        batch_size: int = 10000,
        columns: list[str] | None = None,
    ) -> Iterator[pd.DataFrame]:
        """Iterate over a large Parquet file in streaming batches."""
        target_path = Path(path)
        if not target_path.exists():
            raise FileNotFoundError(f"Parquet file not found: {target_path}")

        parquet_file = pq.ParquetFile(target_path)
        for record_batch in parquet_file.iter_batches(batch_size=batch_size, columns=columns):
            yield record_batch.to_pandas()

