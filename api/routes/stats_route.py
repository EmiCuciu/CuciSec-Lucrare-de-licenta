from fastapi import APIRouter
from loguru import logger

from api.schemas import StatsResponse
from infrastructure.nftables_manager import NftablesManager
from repository.stats_repository import StatsRepository
from service.stats_service import StatsService

router = APIRouter(prefix="/api/stats", tags=["Stats"])
stats_repo = StatsRepository()



@router.get("/", response_model=StatsResponse)
def get_stats():
    """
    Combined statistics: DB + Kernel (nftables)
    return: StatsResponse
    """

    db_stats = stats_repo.get_db_stats()
    recent_bans = stats_repo.get_recent_bans()

    nft_json = NftablesManager.get_stats()

    flood_counters = StatsService.parse_flood_counters(nft_json)

    return StatsResponse(
        total_logs=db_stats["total_logs"],
        accepted=db_stats["accepted"],
        dropped=db_stats["dropped"],
        banned_ips=db_stats["banned_ips"],
        flood_counters=flood_counters,
        recent_bans=recent_bans
    )
