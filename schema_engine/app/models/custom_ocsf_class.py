import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, JSON, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base

class CustomOcsfClass(Base):
    __tablename__ = 'custom_ocsf_classes'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(String(255), nullable=False, index=True)
    class_uid = Column(Integer, nullable=False)
    class_name = Column(String(255), nullable=False)
    category_uid = Column(Integer, nullable=False)
    attributes = Column(JSON, nullable=False, default={})
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        onupdate=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        UniqueConstraint('organization_id', 'class_uid', name='uix_org_class_uid'),
    )