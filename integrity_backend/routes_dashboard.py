import os
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Request, Query
from .routes_reports import verify_auth_for_tenant
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter()

# Helper function to get db path
def get_db_path():
    return str(Path(__file__).parent.parent / 'data' / 'integ.db')

@router.get("/dashboard/{tenant_id}")
async def get_dashboard(tenant_id: str, request: Request, days: int = Query(7, ge=1, le=90)):
    # Require authentication
    if not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Query database for reports in date range
        db_path = get_db_path()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Summary by report type
            c.execute("""
                SELECT 
                    report_type,
                    COUNT(*) as count,
                    SUM(findings_count) as total_findings,
                    SUM(injections_count) as total_injections,
                    SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical_reports,
                    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk_reports
                FROM reports 
                WHERE tenant = ? AND at >= ? AND at <= ?
                GROUP BY report_type
            """, (tenant_id, start_date.isoformat(), end_date.isoformat()))
            summary = [dict(row) for row in c.fetchall()]
            
            # Browser statistics
            c.execute("""
                SELECT 
                    browser,
                    browser_version,
                    COUNT(*) as count,
                    SUM(CASE WHEN risk_level IN ('critical', 'high') THEN 1 ELSE 0 END) as high_risk_count
                FROM reports 
                WHERE tenant = ? AND at >= ? AND at <= ?
                GROUP BY browser, browser_version
                ORDER BY count DESC
                LIMIT 20
            """, (tenant_id, start_date.isoformat(), end_date.isoformat()))
            browsers = [dict(row) for row in c.fetchall()]
            
            # Client IP statistics
            c.execute("""
                SELECT 
                    client_ip,
                    COUNT(*) as total_reports,
                    COUNT(DISTINCT user_agent) as user_agents_count,
                    SUM(CASE WHEN risk_level IN ('critical', 'high') THEN 1 ELSE 0 END) as risk_reports,
                    MAX(at) as last_seen
                FROM reports 
                WHERE tenant = ? AND at >= ? AND at <= ? AND client_ip IS NOT NULL
                GROUP BY client_ip
                ORDER BY total_reports DESC
                LIMIT 20
            """, (tenant_id, start_date.isoformat(), end_date.isoformat()))
            client_statistics = [dict(row) for row in c.fetchall()]
            
            # High risk reports
            c.execute("""
                SELECT 
                    id, tenant, report_type, page_url, client_ip, browser, browser_version,
                    platform as os, user_agent, findings_count, injections_count, 
                    risk_level, at, payload
                FROM reports 
                WHERE tenant = ? AND at >= ? AND at <= ? AND risk_level IN ('critical', 'high')
                ORDER BY at DESC
                LIMIT 50
            """, (tenant_id, start_date.isoformat(), end_date.isoformat()))
            high_risk_reports = []
            for row in c.fetchall():
                report = dict(row)
                # Parse payload JSON if available
                if report.get('payload'):
                    try:
                        payload = json.loads(report['payload'])
                        if 'findings' in payload:
                            report['findings'] = payload['findings']
                        if 'injections' in payload:
                            report['injections'] = payload['injections']
                    except:
                        pass
                high_risk_reports.append(report)
            
            return {
                "tenant": tenant_id,
                "period_days": days,
                "summary": summary,
                "browsers": browsers,
                "client_statistics": client_statistics,
                "high_risk_reports": high_risk_reports
            }
    except Exception as e:
        logger.exception(f"Dashboard error: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard error: {str(e)}")

@router.get("/ip-correlation/{tenant_id}")
async def get_ip_correlation(tenant_id: str, request: Request, days: int = Query(7, ge=1, le=90)):
    # Require authentication
    if not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Query database for IP incidents
        db_path = get_db_path()
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get IPs with high-risk incidents
            c.execute("""
                SELECT 
                    client_ip,
                    COUNT(*) as total_incidents,
                    GROUP_CONCAT(DISTINCT report_type) as attack_types_str,
                    MIN(at) as first_seen,
                    MAX(at) as last_seen
                FROM reports 
                WHERE tenant = ? AND at >= ? AND at <= ? 
                  AND client_ip IS NOT NULL
                  AND risk_level IN ('critical', 'high')
                GROUP BY client_ip
                HAVING COUNT(*) > 1
                ORDER BY total_incidents DESC
                LIMIT 20
            """, (tenant_id, start_date.isoformat(), end_date.isoformat()))
            
            ip_incidents = []
            for row in c.fetchall():
                incident = dict(row)
                # Calculate a risk score (simple algorithm - can be refined)
                risk_score = min(10, 3 + incident['total_incidents'] * 0.5)
                incident['risk_score'] = round(risk_score, 1)
                
                # Parse attack types into list
                attack_types = []
                if incident.get('attack_types_str'):
                    attack_types = incident['attack_types_str'].split(',')
                incident['attack_types'] = attack_types
                del incident['attack_types_str']
                
                ip_incidents.append(incident)
                
            return {
                "tenant": tenant_id,
                "period_days": days,
                "ip_incidents": ip_incidents
            }
    except Exception as e:
        logger.exception(f"IP correlation error: {e}")
        raise HTTPException(status_code=500, detail=f"IP correlation error: {str(e)}")