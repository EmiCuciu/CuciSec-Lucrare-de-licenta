from typing import List, Optional

from fastapi import APIRouter, Query
from loguru import logger

from api.schemas import LogResponse
from repository.log_repository import LogRepository

router = APIRouter(prefix="/api/logs", tags=["Logs"])
log_repo = LogRepository()


@router.get("/", response_model=List[LogResponse])
def get_logs(
        limit: int = Query(default=50, le=1000),
        skip: int = Query(default=0, ge=0),
        protocol: Optional[str] = Query(default=None),
        action: Optional[str] = Query(default=None),
        ip_src: Optional[str] = Query(default=None)):
    """
    Retrieves paginated Logs from DB, using optional filters
    :param skip: Paginated
    :param limit: Maximum 1000 logs
    :param protocol: Filter by protocol
    :param action: Filter by action
    :param ip_src: Filter by source ip
    :return: List of LogResponse
    """
    logger.debug(f"[LogRoute] getting paginated logs from db: current skip: {skip}")
    logs = log_repo.get_filtered_logs(
        limit=limit,
        offset=skip,
        protocol=protocol,
        action=action,
        ip_src=ip_src
    )

    return logs
