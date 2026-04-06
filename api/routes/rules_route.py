from typing import List

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger

from api.dependencies import get_rule_engine
from api.schemas import RuleResponse, RuleCreate
from domain.models import RuleModel
from repository.rule_repository import RuleRepository
from service.rule_engine import RuleEngine

router = APIRouter(prefix="/api/rules", tags=["Rules"])
rule_repo = RuleRepository()


@router.get("/", response_model=List[RuleResponse])
def get_rules():
    """
    Retrieves all rules from database
    :return: List of rules
    """
    logger.debug("[RuleRoute] getting all rules...")
    rules = rule_repo.get_all()

    return rules


@router.post("/", response_model=RuleResponse, status_code=201)
def create_rule(
        rule_data: RuleCreate,
        rule_engine: RuleEngine = Depends(get_rule_engine)):
    """
    Create a new rule and hot-reloads it in RAM
    :param rule_data: RuleCreate
    :param rule_engine: RuleEngine dependency
    :return: RuleResponse
    """
    new_rule = RuleModel(
        ip_src=rule_data.ip_src,
        port=rule_data.port,
        protocol=rule_data.protocol,
        action=rule_data.action,
        description=rule_data.description,
        enabled=rule_data.enabled
    )
    logger.debug(f"[RuleRoute] creating new rule {new_rule}")

    rule_id = rule_repo.insert(new_rule)

    if rule_id is None:
        raise HTTPException(status_code=500,
                            detail="Failed to insert rule into database")

    rule_engine.reload_rules()

    new_rule.id = rule_id

    return RuleResponse(
        id=rule_id,
        ip_src=new_rule.ip_src,
        port=new_rule.port,
        protocol=new_rule.protocol,
        action=new_rule.action,
        description=new_rule.description,
        enabled=new_rule.enabled
    )


@router.delete("/{rule_id}", status_code=204)
def delete_rule(
        rule_id: int,
        rule_engine: RuleEngine = Depends(get_rule_engine)):
    """
    Delete a rule
    :param rule_id: id rule to delete
    :param rule_engine: RuleEngine
    :return: None
    """
    deleted = rule_repo.delete(rule_id)

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    logger.debug(f"[RuleRoute] rule {rule_id} deleted")

    rule_engine.reload_rules()


@router.patch("/{rule_id}/toggle", response_model=dict)
def toggle_rule(
        rule_id: int,
        enabled: int,
        rule_engine: RuleEngine = Depends(get_rule_engine)):
    """
    Activate/Deactivate a rule
    :param rule_id: id rule to toggle
    :param enabled: operation
    :param rule_engine: RuleEngine
    :return: dictionary with patched rule
    """
    if enabled not in (0, 1):
        raise HTTPException(status_code=400, detail="Bad req, enabled must be 0 or 1")

    operation = rule_repo.toggle(rule_id, enabled)

    if not operation:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    rule_engine.reload_rules()

    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "reloaded": True
    }
