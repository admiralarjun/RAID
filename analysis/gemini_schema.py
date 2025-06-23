from pydantic import BaseModel
from typing import Literal, Optional, Union

class AILogicGroup(BaseModel):
    logic: Literal["and", "or"]
    children: list[Union['AIRule', 'AILogicGroup']]

class AIRule(BaseModel):
    field: str
    operator: Literal["contains", "equals", "startswith"]
    value: str
    severity: Literal["low", "medium", "high", "critical"]
    tags: Optional[list[str]]

AILogicGroup.model_rebuild()
