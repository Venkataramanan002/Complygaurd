"""Rule Simulation API."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from utils.simulation_engine import RuleSimulator

router = APIRouter(prefix="/api/simulate", tags=["Simulation"])


class AddRuleRequest(BaseModel):
    device_name: str
    proposed_rule: dict


@router.post("/add-rule")
async def simulate_add(req: AddRuleRequest, db: AsyncSession = Depends(get_db)):
    sim = RuleSimulator()
    result = await sim.simulate_add_rule(req.proposed_rule, req.device_name, db)
    return result
