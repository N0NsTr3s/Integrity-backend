import os
import json
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Request, Query
from .routes_reports import verify_auth_for_tenant
from .db import get_db_connection
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/dashboard/{tenant_id}")
async def get_dashboard(tenant_id: str, request: Request, days: int = Query(7, ge=1, le=90)):
    # Check for admin authentication
    admin_secret = os.environ.get('ADMIN_SECRET')
    provided_secret = request.headers.get('x-admin-secret')
    
    if not (admin_secret and provided_secret == admin_secret) and not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get PostgreSQL connection
        conn = get_db_connection()
        
        # Use RealDictCursor for easy dictionary access
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            
            # Summary by report type
            c.execute("""
                SELECT 
                    report_type,
                    COUNT(*) as count,
                    COALESCE(SUM(findings_count), 0) as total_findings,
                    COALESCE(SUM(injections_count), 0) as total_injections,
                    SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical_reports,
                    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk_reports
                FROM reports 
                WHERE tenant = %s AND at >= %s AND at <= %s
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
                WHERE tenant = %s AND at >= %s AND at <= %s
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
                WHERE tenant = %s AND at >= %s AND at <= %s AND client_ip IS NOT NULL
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
                WHERE tenant = %s AND at >= %s AND at <= %s AND risk_level IN ('critical', 'high')
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
        
        # Make sure to close the connection
        conn.close()
        
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
    # Check for admin authentication
    admin_secret = os.environ.get('ADMIN_SECRET')
    provided_secret = request.headers.get('x-admin-secret')
    
    if not (admin_secret and provided_secret == admin_secret) and not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get PostgreSQL connection
        conn = get_db_connection()
        
        # Use RealDictCursor for easy dictionary access
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            
            # Get IPs with high-risk incidents
            # Replace SQLite's GROUP_CONCAT with PostgreSQL's string_agg
            c.execute("""
                SELECT 
                    client_ip,
                    COUNT(*) as total_incidents,
                    string_agg(DISTINCT report_type, ',') as attack_types_str,
                    MIN(at) as first_seen,
                    MAX(at) as last_seen
                FROM reports 
                WHERE tenant = %s AND at >= %s AND at <= %s 
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
        
        # Make sure to close the connection
        conn.close()
        
        return {
            "tenant": tenant_id,
            "period_days": days,
            "ip_incidents": ip_incidents
        }
    except Exception as e:
        logger.exception(f"IP correlation error: {e}")
        raise HTTPException(status_code=500, detail=f"IP correlation error: {str(e)}")

@router.get("/file-integrity/{tenant_id}")
async def get_file_integrity_details(tenant_id: str, request: Request, days: int = Query(7, ge=1, le=90)):
    # Check for admin authentication
    admin_secret = os.environ.get('ADMIN_SECRET')
    provided_secret = request.headers.get('x-admin-secret')
    
    if not (admin_secret and provided_secret == admin_secret) and not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Query database for file integrity reports
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as c:
                
                # Get file integrity reports
                c.execute("""
                    SELECT 
                        id, tenant, report_type, page_url, client_ip, browser, browser_version,
                        platform as os, findings_count, risk_level, at, payload
                    FROM reports 
                    WHERE tenant = %s AND at >= %s AND at <= %s 
                      AND report_type = 'file_integrity'
                    ORDER BY at DESC
                    LIMIT 100
                """, (tenant_id, start_date.isoformat(), end_date.isoformat()))
                
                integrity_reports = []
                for row in c.fetchall():
                    report = dict(row)
                    # Parse payload JSON if available
                    if report.get('payload'):
                        try:
                            payload = json.loads(report['payload'])
                            if 'findings' in payload:
                                report['findings'] = payload['findings']
                        except:
                            pass
                    integrity_reports.append(report)
                
                logger.info(f"Found {len(integrity_reports)} file integrity reports for tenant {tenant_id}")
                
                # For affected files summary, we need to parse the payload JSON
                affected_files = {}
                
                for report in integrity_reports:
                    findings = report.get('findings', [])
                    if isinstance(findings, list):
                        for finding in findings:
                            url = finding.get('url')
                            if url:
                                if url not in affected_files:
                                    affected_files[url] = {
                                        'count': 0,
                                        'issues': set(),
                                        'risk_levels': set()
                                    }
                                affected_files[url]['count'] += 1
                                affected_files[url]['issues'].add(finding.get('issue', 'unknown'))
                                affected_files[url]['risk_levels'].add(finding.get('risk_level', 'unknown'))
                
                # Convert sets to lists for JSON serialization
                for url in affected_files:
                    affected_files[url]['issues'] = list(affected_files[url]['issues'])
                    affected_files[url]['risk_levels'] = list(affected_files[url]['risk_levels'])
                
                logger.info(f"Found {len(affected_files)} affected files for tenant {tenant_id}")
                
                return {
                    "tenant": tenant_id,
                    "period_days": days,
                    "total_reports": len(integrity_reports),
                    "affected_files": [
                        {"url": url, **details}
                        for url, details in affected_files.items()
                    ],
                    "recent_reports": integrity_reports[:20]  # Limit to 20 most recent
                }
        finally:
            conn.close()
    except Exception as e:
        logger.exception(f"File integrity details error: {e}")
        raise HTTPException(status_code=500, detail=f"File integrity details error: {str(e)}")