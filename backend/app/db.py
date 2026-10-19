from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import trace
from .config import settings

app_pool: ConnectionPool | None = None


def open_pools() -> None:
    global app_pool
    app_pool = ConnectionPool(settings.app_dsn, min_size=2, max_size=20,
                              kwargs={"row_factory": dict_row}, open=True)


def close_pools() -> None:
    if app_pool:
        app_pool.close()


@contextmanager
def session(user_id: str | None = None, role: str | None = None) -> Iterator[psycopg.Connection]:
    """One DB transaction as wallet_app, with the caller's identity bound for RLS.

    set_config(..., true) is SET LOCAL: it disappears at COMMIT/ROLLBACK, so the
    pooled connection cannot leak this identity into the next request.
    """
    assert app_pool is not None
    with app_pool.connection() as conn:
        with conn.transaction():
            if user_id:
                conn.execute("SELECT set_config('app.user_id', %s, true), set_config('app.role', %s, true)",
                             (str(user_id), role or "customer"))
                trace.step("Bind request identity for row-level security", lane="Database", layer="L3",
                           data=[("SQL", f"SET LOCAL app.user_id = '{user_id}'"),
                                 ("SQL ", f"SET LOCAL app.role = '{role or 'customer'}'"),
                                 ("connection role", "wallet_app (not owner, NOBYPASSRLS)")],
                           explain="Postgres policies compare every row against this identity. "
                                   "It is transaction-local, so a pooled connection never keeps it.")
            yield conn


@contextmanager
def owner_conn() -> Iterator[psycopg.Connection]:
    """Owner connection. Used only for migrations, seeding and the demo lab's DDL."""
    with psycopg.connect(settings.owner_dsn, row_factory=dict_row, autocommit=True) as conn:
        yield conn
