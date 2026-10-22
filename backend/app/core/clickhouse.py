import logging
from typing import Optional, List, Dict, Any
import clickhouse_connect
from clickhouse_connect.driver.client import Client
from app.core.config import settings

logger = logging.getLogger(__name__)


import time

class ClickHouseService:
    def __init__(self):
        self._client: Optional[Client] = None
        self._last_failed_at: Optional[float] = None

    def get_client(self) -> Optional[Client]:
        if self._client is not None:
            return self._client
        if self._last_failed_at and (time.time() - self._last_failed_at) < 30.0:
            return None
        try:
            self._client = clickhouse_connect.get_client(
                host=settings.CLICKHOUSE_HOST,
                port=settings.CLICKHOUSE_PORT,
                username=settings.CLICKHOUSE_USER,
                password=settings.CLICKHOUSE_PASSWORD,
                database=settings.CLICKHOUSE_DB,
                connect_timeout=1,
                send_receive_timeout=2,
            )
            return self._client
        except Exception as e:
            self._last_failed_at = time.time()
            logger.warning("ClickHouse connection not available: %s", str(e))
            return None

    def is_connected(self) -> bool:
        client = self.get_client()
        if not client:
            return False
        try:
            res = client.command("SELECT 1")
            return res == 1
        except Exception:
            self._client = None
            self._last_failed_at = time.time()
            return False

    def query(self, sql: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return []
        try:
            result = client.query(sql, parameters=parameters)
            column_names = result.column_names
            rows = []
            for row in result.result_rows:
                rows.append(dict(zip(column_names, row)))
            return rows
        except Exception as e:
            logger.error("ClickHouse query error: %s (SQL: %s)", str(e), sql)
            return []

    def insert_records(self, table: str, records: List[Dict[str, Any]]) -> bool:
        client = self.get_client()
        if not client or not records:
            return False
        try:
            columns = list(records[0].keys())
            data = [[rec.get(col) for col in columns] for rec in records]
            client.insert(table, data, column_names=columns)
            return True
        except Exception as e:
            logger.error("ClickHouse insert error on table %s: %s", table, str(e))
            return False


clickhouse_service = ClickHouseService()
