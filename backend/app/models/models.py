"""
ECDAT database models.

These are intentionally normalized but pragmatic for an MVP: every
displayed number in the dashboard traces back to rows in these tables,
which are populated either by real scanners or by the labelled demo
seed script (scripts/seed_demo.py) - never hard-coded in the API layer.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship
from app.core.database import Base


def gen_id() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_id)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # "admin" | "user" (structured for future RBAC)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=True)
    created_at = Column(DateTime, default=now)
    is_active = Column(Boolean, default=True)


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=now)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_id)
    target = Column(String, nullable=False)
    target_type = Column(String, default="directory")  # directory | file | demo
    scanners_requested = Column(JSON, default=list)  # ["source","dependency",...]
    status = Column(String, default="pending")  # pending|running|completed|failed
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    files_scanned = Column(Integer, default=0)
    artefacts_found = Column(Integer, default=0)
    errors = Column(JSON, default=list)
    created_at = Column(DateTime, default=now)
    created_by = Column(String, nullable=True)

    targets = relationship("ScanTarget", back_populates="scan", cascade="all, delete-orphan")
    artefacts = relationship("CryptographicArtefact", back_populates="scan", cascade="all, delete-orphan")
    evidence = relationship("ScanEvidence", back_populates="scan", cascade="all, delete-orphan")


class ScanTarget(Base):
    __tablename__ = "scan_targets"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"))
    path = Column(String, nullable=False)
    kind = Column(String, default="file")  # file | dependency_manifest | certificate | binary | container

    scan = relationship("Scan", back_populates="targets")


class BusinessAsset(Base):
    """A logical system/application, e.g. 'Payment API'."""
    __tablename__ = "business_assets"
    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    owner = Column(String, default="")
    environment = Column(String, default="production")
    business_criticality = Column(String, default="MEDIUM")  # LOW|MEDIUM|HIGH|CRITICAL
    data_sensitivity = Column(String, default="INTERNAL")  # PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED
    internet_exposed = Column(Boolean, default=False)
    data_retention_years = Column(Integer, default=5)
    estimated_migration_years = Column(Float, default=1.0)

    assets = relationship("Asset", back_populates="business_asset")


class DataAsset(Base):
    """Represents a data flow/store associated with a business asset (e.g. cardholder data)."""
    __tablename__ = "data_assets"
    id = Column(String, primary_key=True, default=gen_id)
    business_asset_id = Column(String, ForeignKey("business_assets.id"))
    name = Column(String, nullable=False)
    sensitivity = Column(String, default="INTERNAL")
    required_lifetime_years = Column(Integer, default=5)


class Algorithm(Base):
    """Crypto knowledge-base entry (seeded from knowledge-base/ JSON)."""
    __tablename__ = "algorithms"
    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, unique=True, nullable=False)
    category = Column(String, nullable=False)  # key_establishment|signature|symmetric|hash|mac|protocol
    purpose = Column(String, default="")
    classical_security_bits = Column(Integer, nullable=True)
    quantum_vulnerable = Column(Boolean, default=True)
    quantum_impact = Column(String, default="")  # description
    recommended_pqc = Column(String, default="")
    recommended_hybrid = Column(String, default="")
    migration_complexity = Column(String, default="MEDIUM")  # LOW|MEDIUM|HIGH
    performance_notes = Column(Text, default="")
    compatibility_notes = Column(Text, default="")


class Library(Base):
    __tablename__ = "libraries"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    name = Column(String, nullable=False)
    version = Column(String, default="unknown")
    ecosystem = Column(String, default="")  # pypi|npm|maven|go|cargo|os
    source_file = Column(String, default="")
    crypto_capable = Column(Boolean, default=False)
    known_algorithms = Column(JSON, default=list)
    confidence = Column(Float, default=0.5)


class Protocol(Base):
    __tablename__ = "protocols"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    name = Column(String, nullable=False)  # TLS 1.2, TLS 1.3, SSH, mTLS...
    file = Column(String, default="")
    line = Column(Integer, nullable=True)
    evidence = Column(Text, default="")
    confidence = Column(Float, default=0.5)


class Certificate(Base):
    __tablename__ = "certificates"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    file = Column(String, nullable=False)
    subject = Column(String, default="")
    issuer = Column(String, default="")
    serial_number = Column(String, default="")
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)
    expired = Column(Boolean, default=False)
    days_remaining = Column(Integer, nullable=True)
    public_key_algorithm = Column(String, default="")
    key_size = Column(Integer, nullable=True)
    signature_algorithm = Column(String, default="")
    san = Column(JSON, default=list)
    weak_key = Column(Boolean, default=False)
    weak_signature = Column(Boolean, default=False)
    parse_error = Column(String, nullable=True)


class Dependency(Base):
    __tablename__ = "dependencies"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    name = Column(String, nullable=False)
    version = Column(String, default="unknown")
    ecosystem = Column(String, default="")
    source_file = Column(String, default="")
    crypto_related = Column(Boolean, default=False)
    known_algorithms = Column(JSON, default=list)
    confidence = Column(Float, default=0.5)
    is_transitive = Column(Boolean, default=False)
    depth = Column(Integer, default=0)
    parent_dependency = Column(String, default="")
    provenance_chain = Column(JSON, default=list)


class Asset(Base):
    """A discovered cryptographic *unit of concern* grouping one or more artefacts
    (e.g. 'RSA-2048 used for Payment API auth'). Risk/Mosca/Recommendations attach here."""
    __tablename__ = "assets"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=True)
    business_asset_id = Column(String, ForeignKey("business_assets.id"), nullable=True)
    name = Column(String, nullable=False)
    asset_type = Column(String, default="crypto_usage")  # crypto_usage|certificate|library|protocol
    algorithm_name = Column(String, nullable=True)
    key_size = Column(Integer, nullable=True)
    purpose = Column(String, default="")
    component = Column(String, default="")
    location = Column(String, default="")  # file:line
    confidence = Column(Float, default=0.5)
    created_at = Column(DateTime, default=now)

    business_asset = relationship("BusinessAsset", back_populates="assets")
    risk_assessment = relationship("RiskAssessment", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    mosca_assessment = relationship("MoscaAssessment", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    recommendation = relationship("Recommendation", back_populates="asset", uselist=False, cascade="all, delete-orphan")


class CryptographicArtefact(Base):
    """Raw finding from a scanner - one row per detected usage. Feeds CBOM + Asset creation."""
    __tablename__ = "crypto_artefacts"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"))
    asset_id = Column(String, ForeignKey("assets.id"), nullable=True)
    artefact_type = Column(String, default="source")  # source|dependency|certificate|binary|container
    algorithm = Column(String, nullable=False)
    file = Column(String, default="")
    line = Column(Integer, nullable=True)
    language = Column(String, default="")
    usage = Column(String, default="")
    key_size = Column(Integer, nullable=True)
    purpose = Column(String, default="")  # key_establishment|digital_signature|encryption|hashing|mac
    confidence = Column(Float, default=0.5)
    evidence = Column(Text, default="")
    component = Column(String, default="")
    library = Column(String, default="")
    protocol = Column(String, default="")
    certificate_id = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="artefacts")


class ScanEvidence(Base):
    """Free-form scanner errors/warnings (e.g. failed to parse a file)."""
    __tablename__ = "scan_evidence"
    id = Column(String, primary_key=True, default=gen_id)
    scan_id = Column(String, ForeignKey("scans.id"))
    scanner = Column(String, default="")
    level = Column(String, default="info")  # info|warning|error
    message = Column(Text, default="")
    file = Column(String, default="")

    scan = relationship("Scan", back_populates="evidence")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id"), unique=True)
    score = Column(Integer, default=0)
    severity = Column(String, default="LOW")  # LOW|MEDIUM|HIGH|CRITICAL
    factors = Column(JSON, default=list)  # [{"name":..., "impact":...}]
    computed_at = Column(DateTime, default=now)

    asset = relationship("Asset", back_populates="risk_assessment")


class MoscaAssessment(Base):
    __tablename__ = "mosca_assessments"
    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id"), unique=True)
    x_data_lifetime_years = Column(Float, default=5)
    y_migration_time_years = Column(Float, default=1)
    z_threat_horizon_years = Column(Float, default=10)
    x_plus_y = Column(Float, default=0)
    exceeds_horizon = Column(Boolean, default=False)
    result = Column(String, default="MONITOR")  # URGENT MIGRATION|PLAN MIGRATION|MONITOR|LOW PRIORITY
    computed_at = Column(DateTime, default=now)

    asset = relationship("Asset", back_populates="mosca_assessment")


class Recommendation(Base):
    __tablename__ = "recommendations"
    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id"), unique=True)
    current_algorithm = Column(String, default="")
    category = Column(String, default="")  # key_establishment|signature
    recommended_algorithm = Column(String, default="")
    recommended_type = Column(String, default="")  # pqc_standard|hybrid|legacy|experimental
    hybrid_option = Column(String, default="")
    reason = Column(Text, default="")
    compatibility = Column(Text, default="")
    migration_complexity = Column(String, default="MEDIUM")
    priority = Column(String, default="MEDIUM")
    confidence = Column(Float, default=0.7)

    asset = relationship("Asset", back_populates="recommendation")


class MigrationPlan(Base):
    __tablename__ = "migration_plans"
    id = Column(String, primary_key=True, default=gen_id)
    asset_id = Column(String, ForeignKey("assets.id"))
    priority = Column(String, default="MEDIUM")  # CRITICAL|HIGH|MEDIUM|LOW
    rationale = Column(Text, default="")
    blockers = Column(JSON, default=list)
    replacement = Column(String, default="")
    affected_dependencies = Column(JSON, default=list)
    risk_before = Column(Integer, nullable=True)
    risk_after_estimate = Column(String, default="Estimated")  # "Not measured"|"Estimated"|"User supplied"
    created_at = Column(DateTime, default=now)

    asset = relationship("Asset")
