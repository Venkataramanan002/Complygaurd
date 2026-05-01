"""
Database models — compatible with both SQLite (dev/default) and PostgreSQL (production).

SQLite-safe column types are used throughout. JSON columns use SQLAlchemy's
built-in JSON type which maps to TEXT on SQLite and JSONB on PostgreSQL.
UUID primary keys are stored as String(36) on SQLite, UUID on PostgreSQL.
"""

import os
import uuid
import datetime

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, BigInteger,
    Text, ForeignKey, Numeric, Boolean, JSON
)
from sqlalchemy.orm import declarative_base, relationship

# ---------------------------------------------------------------------------
# Detect dialect so we can use native PG types in production
# ---------------------------------------------------------------------------
# UUID, IP, CIDR columns — identical for both SQLite and PostgreSQL
# Using String types avoids dialect-specific binding issues (asyncpg UUID objects)
def _uuid_col(pk=False, fk=None):
    if pk:
        return Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), nullable=False)
    if fk:
        return Column(String(36), ForeignKey(fk), nullable=True)
    return Column(String(36), nullable=True)

def _inet_col():
    return Column(String(45), nullable=True)

def _cidr_col():
    return Column(String(50), nullable=True)

Base = declarative_base()


# ---------------------------------------------------------------------------
# Connection log
# ---------------------------------------------------------------------------
class Connection(Base):
    __tablename__ = 'connections'

    id               = _uuid_col(pk=True)
    timestamp        = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    session_end      = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    src_ip           = Column(String(45), index=True, nullable=False)
    dst_ip           = Column(String(45), index=True, nullable=False)
    src_port         = Column(Integer, nullable=False)
    dst_port         = Column(Integer, nullable=False)
    protocol         = Column(String(10), nullable=False)

    bytes_sent       = Column(BigInteger, default=0, nullable=False)
    bytes_received   = Column(BigInteger, default=0, nullable=False)
    packets_sent     = Column(BigInteger, default=0, nullable=False)
    packets_received = Column(BigInteger, default=0, nullable=False)
    tcp_flags        = Column(String(50), nullable=True)

    rule_id          = Column(String(100), nullable=True)
    action           = Column(String(20), nullable=False)
    interface_in     = Column(String(50), nullable=True)
    interface_out    = Column(String(50), nullable=True)
    zone_from        = Column(String(50), nullable=True)
    zone_to          = Column(String(50), nullable=True)

    app_name         = Column(String(100), nullable=True)
    app_category     = Column(String(100), nullable=True)
    url              = Column(Text, nullable=True)
    domain           = Column(String(255), nullable=True)
    user_agent       = Column(Text, nullable=True)
    http_method      = Column(String(10), nullable=True)

    username         = Column(String(100), nullable=True)
    device_name      = Column(String(100), nullable=True)
    device_mac       = Column(String(17), nullable=True)
    device_os        = Column(String(50), nullable=True)

    geo_src_country  = Column(String(100), nullable=True)
    geo_src_city     = Column(String(100), nullable=True)
    geo_dst_country  = Column(String(100), nullable=True)
    geo_dst_city     = Column(String(100), nullable=True)

    nat_src_ip       = Column(String(45), nullable=True)
    nat_src_port     = Column(Integer, nullable=True)
    nat_dst_ip       = Column(String(45), nullable=True)
    nat_dst_port     = Column(Integer, nullable=True)

    decryption_status = Column(String(20), nullable=True)
    threat_detected   = Column(Boolean, default=False, nullable=False)
    source            = Column(String(20), default="config_projection", nullable=False)  # config_projection | syslog | csv_import


# ---------------------------------------------------------------------------
# Threat log
# ---------------------------------------------------------------------------
class Threat(Base):
    __tablename__ = 'threats'

    id          = _uuid_col(pk=True)
    timestamp   = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    device_name = Column(String(100), nullable=True)
    src_ip      = Column(String(45), nullable=False)
    dst_ip      = Column(String(45), nullable=False)

    threat_type = Column(String(50), nullable=False)
    threat_name = Column(String(255), nullable=False)
    severity    = Column(String(20), nullable=False)
    risk_score  = Column(Integer, nullable=True)

    file_name   = Column(String(255), nullable=True)
    file_size   = Column(BigInteger, nullable=True)
    file_type   = Column(String(50), nullable=True)
    file_hash   = Column(String(128), nullable=True)
    source      = Column(String(20), default="config_projection", nullable=False)  # config_projection | syslog | csv_import


# ---------------------------------------------------------------------------
# User accounts (persistent)
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = 'users'

    id              = _uuid_col(pk=True)
    username        = Column(String(100), unique=True, index=True, nullable=False)
    email           = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role            = Column(String(30), default='viewer', nullable=False)
    created_at      = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# System health metrics
# ---------------------------------------------------------------------------
class SystemHealth(Base):
    __tablename__ = 'system_health'

    id                   = _uuid_col(pk=True)
    timestamp            = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    device_name          = Column(String(100), nullable=False)

    cpu_usage_percent    = Column(Float, nullable=False)
    memory_usage_percent = Column(Float, nullable=False)
    active_sessions      = Column(Integer, nullable=False)

    interface_status     = Column(String(20), nullable=True)
    link_speed_mbps      = Column(Integer, nullable=True)
    errors_in            = Column(BigInteger, default=0, nullable=False)
    errors_out           = Column(BigInteger, default=0, nullable=False)


# ---------------------------------------------------------------------------
# Admin audit trail
# ---------------------------------------------------------------------------
class AdminAudit(Base):
    __tablename__ = 'admin_audit'

    id            = _uuid_col(pk=True)
    timestamp     = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    device_name   = Column(String(100), nullable=False)

    admin_username = Column(String(100), nullable=False)
    action_type    = Column(String(100), nullable=False)
    change_before  = Column(Text, nullable=True)
    change_after   = Column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Network topology
# ---------------------------------------------------------------------------
class NetworkTopology(Base):
    __tablename__ = 'network_topology'

    id           = _uuid_col(pk=True)
    device_name  = Column(String(100), nullable=False)
    device_type  = Column(String(50), nullable=False)   # firewall / router / switch / server / endpoint
    zone         = Column(String(50), index=True, nullable=True)
    ip_address   = _inet_col()
    ports_open   = Column(JSON, default=list, nullable=False)
    connected_to = Column(JSON, default=list, nullable=False)
    vlan_id      = Column(Integer, nullable=True)
    subnet       = _cidr_col()
    is_entry_point = Column(Boolean, default=False, nullable=False)
    last_updated = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    # ── Switch-specific fields ──────────────────────────────────────────
    vlans          = Column(JSON, default=list, nullable=True)      # [{id, name, subnet, status}]
    trunk_ports    = Column(JSON, default=list, nullable=True)      # [{port, allowed_vlans, native_vlan, neighbor}]
    access_ports   = Column(JSON, default=list, nullable=True)      # [{port, vlan_id, port_security, status}]
    stp_mode       = Column(String(30), nullable=True)              # rstp / pvst / mstp
    stp_root_for   = Column(JSON, default=list, nullable=True)      # VLANs this switch is root bridge for
    port_security  = Column(JSON, default=list, nullable=True)      # [{port, max_mac, violation_mode, sticky}]

    # ── Router-specific fields ──────────────────────────────────────────
    interfaces     = Column(JSON, default=list, nullable=True)      # [{name, ip, subnet, status, speed, description}]
    routing_protocol = Column(String(30), nullable=True)            # ospf / bgp / eigrp / static / rip
    ospf_area      = Column(String(20), nullable=True)              # OSPF area ID
    bgp_asn        = Column(Integer, nullable=True)                 # BGP autonomous system number
    bgp_neighbors  = Column(JSON, default=list, nullable=True)      # [{neighbor_ip, remote_asn, state, description}]
    static_routes  = Column(JSON, default=list, nullable=True)      # [{network, mask, next_hop, interface, metric}]
    nat_rules      = Column(JSON, default=list, nullable=True)      # [{type, inside_ip, outside_ip, port}]
    acls           = Column(JSON, default=list, nullable=True)       # [{name, rules: [{action, protocol, src, dst, port}]}]

    # ── Inter-device link fields ────────────────────────────────────────
    link_type      = Column(String(30), nullable=True)              # trunk / access / routed / wan / vpn
    link_speed     = Column(String(20), nullable=True)              # 1G / 10G / 100M / etc.
    neighbor_device = Column(String(100), nullable=True)            # directly connected device name
    neighbor_port  = Column(String(50), nullable=True)              # port on the neighbor device


# ---------------------------------------------------------------------------
# Firewall rules
# ---------------------------------------------------------------------------
class FirewallRule(Base):
    __tablename__ = 'firewall_rules'

    id            = _uuid_col(pk=True)
    device_name   = Column(String(100), index=True, nullable=False)
    rule_name     = Column(String(255), nullable=True)
    rule_position = Column(Integer, nullable=True)
    source_ip     = Column(String(100), nullable=False)
    source_port   = Column(String(100), nullable=True)
    dest_ip       = Column(String(100), nullable=False)
    dest_port     = Column(String(100), nullable=True)
    protocol      = Column(String(10), nullable=False)
    action        = Column(String(20), index=True, nullable=False)
    service_name  = Column(String(100), nullable=True)
    hit_count     = Column(Integer, default=0, nullable=False)
    last_hit      = Column(DateTime, nullable=True)
    is_enabled    = Column(Boolean, default=True, index=True, nullable=False)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Rule risk analysis
# ---------------------------------------------------------------------------
class RuleRiskAnalysis(Base):
    __tablename__ = 'rule_risk_analysis'

    id            = _uuid_col(pk=True)
    rule_id       = _uuid_col(fk='firewall_rules.id')
    risk_score    = Column(Numeric(4, 1), index=True, nullable=False)
    risk_level    = Column(String(20), index=True, nullable=False)
    risk_category = Column(String(50), nullable=True)
    reason        = Column(Text, nullable=True)
    cvss_color    = Column(String(20), nullable=True)
    recommendation = Column(Text, nullable=True)
    calculated_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    rule = relationship("FirewallRule")


# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------
class AttackPath(Base):
    __tablename__ = 'attack_paths'

    id                       = _uuid_col(pk=True)
    entry_point              = Column(String(100), index=True, nullable=False)
    target                   = Column(String(100), nullable=False)
    path_hops                = Column(JSON, default=list, nullable=False)
    total_risk_score         = Column(Numeric(4, 1), nullable=False)
    risk_level               = Column(String(20), index=True, nullable=False)
    attack_difficulty        = Column(Numeric(4, 1), nullable=True)
    vulnerable_ports_in_path = Column(JSON, default=list, nullable=False)
    weakest_link             = Column(String(255), nullable=True)
    calculated_at            = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Config uploads
# ---------------------------------------------------------------------------
class ConfigUpload(Base):
    __tablename__ = 'config_uploads'

    id                = _uuid_col(pk=True)
    filename          = Column(String(255), nullable=False)
    upload_time       = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    file_size         = Column(BigInteger, nullable=False)
    vendor            = Column(String(50), nullable=True)
    ingestion_status  = Column(String(20), default='pending', nullable=False)
    progress_percent  = Column(Integer, default=0, nullable=False)
    configs_processed = Column(Integer, default=0, nullable=False)
    errors_count      = Column(Integer, default=0, nullable=False)
    warnings_count    = Column(Integer, default=0, nullable=False)
    unsupported_count = Column(Integer, default=0, nullable=False)
    error_messages    = Column(JSON, default=list, nullable=False)
    completed_at      = Column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# Config backups (SSH/CLI collected)
# ---------------------------------------------------------------------------
class ConfigBackup(Base):
    __tablename__ = 'config_backups'

    id              = _uuid_col(pk=True)
    device_name     = Column(String(100), index=True, nullable=False)
    timestamp       = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    file_path       = Column(String(500), nullable=False)
    file_hash       = Column(String(64), nullable=False)   # SHA-256
    file_size       = Column(BigInteger, nullable=False)
    version_number  = Column(Integer, nullable=False)
    change_detected = Column(Boolean, default=False, nullable=False)
    change_summary  = Column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Rule owners (lifecycle management)
# ---------------------------------------------------------------------------
class RuleOwner(Base):
    __tablename__ = 'rule_owners'

    id                    = _uuid_col(pk=True)
    rule_id               = _uuid_col(fk='firewall_rules.id')
    owner_name            = Column(String(100), nullable=False)
    owner_email           = Column(String(255), nullable=False)
    department            = Column(String(100), nullable=True)
    assigned_date         = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_certified_date   = Column(DateTime, nullable=True)
    certification_due_date = Column(DateTime, nullable=True)
    status                = Column(String(30), default='active', nullable=False)  # active|pending_review|expired|decommissioned

    rule = relationship("FirewallRule")


# ---------------------------------------------------------------------------
# Certification reviews
# ---------------------------------------------------------------------------
class CertificationReview(Base):
    __tablename__ = 'certification_reviews'

    id               = _uuid_col(pk=True)
    rule_id          = _uuid_col(fk='firewall_rules.id')
    reviewer_name    = Column(String(100), nullable=False)
    review_date      = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    decision         = Column(String(30), nullable=False)  # certify|modify|decommission
    justification    = Column(Text, nullable=True)
    risk_accepted    = Column(Boolean, default=False, nullable=False)
    next_review_date = Column(DateTime, nullable=True)

    rule = relationship("FirewallRule")


# ---------------------------------------------------------------------------
# Threat intelligence cache
# ---------------------------------------------------------------------------
class ThreatIntelCache(Base):
    __tablename__ = 'threat_intel_cache'

    id          = _uuid_col(pk=True)
    ip          = Column(String(45), index=True, nullable=False)
    source      = Column(String(50), nullable=False)  # abuseipdb | otx | virustotal
    result_json = Column(JSON, default=dict, nullable=False)
    queried_at  = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    ttl_hours   = Column(Integer, default=24, nullable=False)


# ---------------------------------------------------------------------------
# Change requests (workflow)
# ---------------------------------------------------------------------------
class ChangeRequest(Base):
    __tablename__ = 'change_requests'

    id               = _uuid_col(pk=True)
    title            = Column(String(255), nullable=False)
    description      = Column(Text, nullable=True)
    requester_name   = Column(String(100), nullable=False)
    requester_email  = Column(String(255), nullable=True)
    request_date     = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    status           = Column(String(30), default='draft', nullable=False)
    priority         = Column(String(20), default='medium', nullable=False)
    device_name      = Column(String(100), nullable=True)
    change_type      = Column(String(30), nullable=False)
    proposed_changes = Column(JSON, default=list, nullable=False)
    risk_score       = Column(Float, default=0, nullable=False)
    risk_assessment  = Column(JSON, default=dict, nullable=False)
    reviewer_name    = Column(String(100), nullable=True)
    review_date      = Column(DateTime, nullable=True)
    review_notes     = Column(Text, nullable=True)
    deployment_date  = Column(DateTime, nullable=True)
    rollback_data    = Column(JSON, default=dict, nullable=False)


class ChangeComment(Base):
    __tablename__ = 'change_comments'

    id                = _uuid_col(pk=True)
    change_request_id = _uuid_col(fk='change_requests.id')
    author            = Column(String(100), nullable=False)
    comment           = Column(Text, nullable=False)
    created_at        = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    change_request = relationship("ChangeRequest")


# ---------------------------------------------------------------------------
# Drift events
# ---------------------------------------------------------------------------
class DriftEvent(Base):
    __tablename__ = 'drift_events'

    id                 = _uuid_col(pk=True)
    device_name        = Column(String(100), index=True, nullable=False)
    detected_at        = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    severity           = Column(String(20), nullable=False)  # critical|medium|low
    drift_summary      = Column(Text, nullable=True)
    diff_json          = Column(JSON, default=dict, nullable=False)
    baseline_backup_id = Column(String(36), nullable=True)
    acknowledged       = Column(Boolean, default=False, nullable=False)
    acknowledged_by    = Column(String(100), nullable=True)
    remediation_action = Column(String(30), default='none', nullable=False)  # none|auto_rollback|manual


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
class Alert(Base):
    __tablename__ = 'alerts'

    id              = _uuid_col(pk=True)
    alert_type      = Column(String(50), nullable=False)  # drift|threat|compliance|health
    severity        = Column(String(20), nullable=False)
    title           = Column(String(255), nullable=False)
    message         = Column(Text, nullable=True)
    source_device   = Column(String(100), nullable=True)
    created_at      = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    acknowledged    = Column(Boolean, default=False, nullable=False)
    acknowledged_by = Column(String(100), nullable=True)
