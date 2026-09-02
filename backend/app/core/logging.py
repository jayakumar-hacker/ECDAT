import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    stream=sys.stdout,
)

logger = logging.getLogger("ecdat")
audit_logger = logging.getLogger("ecdat.audit")


def audit(action: str, actor: str, detail: str = ""):
    """Lightweight audit trail. In production this would go to a
    tamper-evident append-only store; for the MVP it goes to stdout/logfile."""
    audit_logger.info("AUDIT action=%s actor=%s detail=%s", action, actor, detail)
