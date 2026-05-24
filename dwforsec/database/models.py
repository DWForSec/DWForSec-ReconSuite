import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Table, Text
from sqlalchemy.orm import relationship
from dwforsec.database.db import Base

# Association table for subdomains and open ports
subdomain_ports = Table(
    'subdomain_ports',
    Base.metadata,
    Column('subdomain_id', Integer, ForeignKey('subdomains.id', ondelete='CASCADE')),
    Column('port_number', Integer)
)

class Target(Base):
    __tablename__ = 'targets'
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id', ondelete='CASCADE'))
    status = Column(String, default="running")  # running, completed, failed
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    target = relationship("Target", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    ssl_findings = relationship("SSLFinding", back_populates="scan", cascade="all, delete-orphan")
    crawl_results = relationship("CrawlResult", back_populates="scan", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="scan", cascade="all, delete-orphan")

class Subdomain(Base):
    __tablename__ = 'subdomains'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'))
    subdomain = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    is_live = Column(Boolean, default=False)
    status_code = Column(Integer, nullable=True)
    title = Column(String, nullable=True)
    
    scan = relationship("Scan", back_populates="subdomains")

class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'))
    tool = Column(String, nullable=False)
    template_id = Column(String, nullable=True)
    matched_url = Column(String, nullable=True)
    host = Column(String, nullable=True)
    severity = Column(String, nullable=False)  # critical, high, medium, low, info
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    scan = relationship("Scan", back_populates="findings")

class SSLFinding(Base):
    __tablename__ = 'ssl_findings'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'))
    host = Column(String, nullable=False)
    tls_version = Column(String, nullable=True)
    weak_ciphers = Column(Text, nullable=True)
    hsts_enabled = Column(Boolean, nullable=True)
    self_signed = Column(Boolean, nullable=True)
    expiry_date = Column(String, nullable=True)
    issuer = Column(String, nullable=True)
    san = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    
    scan = relationship("Scan", back_populates="ssl_findings")

class CrawlResult(Base):
    __tablename__ = 'crawl_results'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'))
    url = Column(String, nullable=False)
    content_type = Column(String, nullable=True)
    is_js = Column(Boolean, default=False)
    source_map_found = Column(Boolean, default=False)
    admin_route_found = Column(Boolean, default=False)
    staging_url_found = Column(Boolean, default=False)
    secrets_found = Column(Text, nullable=True)  # JSON or comma-separated masked secrets
    
    scan = relationship("Scan", back_populates="crawl_results")

class Technology(Base):
    __tablename__ = 'technologies'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'))
    host = Column(String, nullable=False)
    tech_name = Column(String, nullable=False)
    
    scan = relationship("Scan", back_populates="technologies")
