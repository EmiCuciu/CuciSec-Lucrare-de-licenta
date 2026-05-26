from fastapi import APIRouter, Depends

from api.dependencies import get_kernel_baseline
from api.schemas import StatsResponse
from infrastructure.nftables_manager import NftablesManager
from repository.stats_repository import StatsRepository
from service.stats_service import StatsService

router = APIRouter(prefix="/api/stats", tags=["Stats"])
stats_repo = StatsRepository()


@router.get("/", response_model=StatsResponse)
def get_stats(baseline: dict = Depends(get_kernel_baseline)):
    """
    Combined statistics: DB + kernel (nftables).
    flood_counters = previous sessions (baseline from DB at startup) + current session (live nftables).
    """

    db_stats = stats_repo.get_db_stats()
    recent_bans = stats_repo.get_recent_bans()
    dpi_drops = stats_repo.get_dpi_drops()

    nft_json = NftablesManager.get_stats()
    live = StatsService.parse_flood_counters(nft_json)

    # persistent (all previous sessions) + real-time (current session, no lag)
    combined = {k: baseline.get(k, 0) + live.get(k, 0) for k in live}

    kernel_only_drops = (
        combined["tcp_syn_flood_dropped"] +
        combined["icmp_flood_dropped"]    +
        combined["udp_flood_dropped"]     +
        combined["blacklist_dropped"]
    )
    total_intercepted = db_stats["total_logs"] + kernel_only_drops

    return StatsResponse(
        total_logs=db_stats["total_logs"],
        accepted=db_stats["accepted"],
        dropped=db_stats["dropped"],
        banned_ips=db_stats["banned_ips"],
        total_intercepted=total_intercepted,
        flood_counters=combined,
        dpi_drops=dpi_drops,
        recent_bans=recent_bans
    )