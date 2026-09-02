from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class ScanCreateRequest(BaseModel):
    target: str = Field(..., description="Absolute path to a directory or file to scan, or 'demo'")
    target_type: str = "directory"  # directory | file | demo
    scanners: list[str] = Field(default_factory=lambda: ["source", "dependency", "certificate", "binary", "container"])


class MoscaSimulateRequest(BaseModel):
    asset_id: str
    x_data_lifetime_years: float
    y_migration_time_years: float
    z_threat_horizon_years: float


class MigrationSimulateRequest(BaseModel):
    current_algorithm: str
    proposed_algorithm: str
    user_supplied: dict | None = None


class ReportRequest(BaseModel):
    scan_id: str
    format: str = "json"  # json | csv | pdf


class AIChatRequest(BaseModel):
    question: str
    scan_id: str | None = None
