import os
from pathlib import Path
from typing import Iterator
from sqlmodel import SQLModel, Session, create_engine

_DATA_DIR = Path(os.environ.get("PA_DATA_DIR", "./data"))
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_DB_PATH = _DATA_DIR / "app.db"

engine = create_engine(
    f"sqlite:///{_DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    # Import models so SQLModel sees them before create_all
    from .auth import models as _auth_models  # noqa: F401
    from .targets import models as _target_models  # noqa: F401
    try:
        from .llm import models as _llm_models  # noqa: F401
    except ImportError:
        pass  # community edition may not have llm/models.py
    from .audit import models as _audit_models  # noqa: F401
    from .uploads import models as _upload_models  # noqa: F401
    from .agents import models as _agent_models  # noqa: F401  # includes AgentAuditScan
    from .tools import zap_models as _zap_models  # noqa: F401
    # Knowledge subpackages live outside backend/ but their tables share app.db.
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from knowledge_base.cwe import models as _cwe_models  # noqa: F401
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
