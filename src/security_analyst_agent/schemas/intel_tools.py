from pydantic import BaseModel


class IntelLookupRequest(BaseModel):
    indicator: str
    indicator_type: str

