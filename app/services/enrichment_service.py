import aiohttp
import asyncio
import json
from typing import Dict, Optional, List
from sqlalchemy.orm import Session
from app.models import IOC, IOCType
from app.config import get_settings

settings = get_settings()


class EnrichmentService:
    """
    Threat intelligence enrichment service.
    
    Queries multiple TI providers concurrently to determine IOC reputation.
    Supports VirusTotal, AbuseIPDB, and IP geolocation.
    """
    
    # API endpoints
    VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
    IPAPI_BASE = "https://ipapi.co"
    
    @staticmethod
    async def enrich_ip(ip: str) -> Dict:
        """
        Enrich IP address with reputation and geolocation data.
        
        Queries:
        - VirusTotal for IP reputation
        - AbuseIPDB for abuse reports
        - ipapi.co for geolocation
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dict with enrichment data from all sources
        """
        enrichment_data = {}
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            # VirusTotal IP lookup
            if settings.VIRUSTOTAL_API_KEY:
                tasks.append(EnrichmentService._query_virustotal_ip(session, ip))
            
            # AbuseIPDB lookup
            if settings.ABUSEIPDB_API_KEY:
                tasks.append(EnrichmentService._query_abuseipdb(session, ip))
            
            # Geolocation (no key required)
            tasks.append(EnrichmentService._query_ip_geolocation(session, ip))
            
            # Run all queries concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Parse results
            for result in results:
                if isinstance(result, dict):
                    enrichment_data.update(result)
        
        return enrichment_data
    
    @staticmethod
    async def enrich_domain(domain: str) -> Dict:
        """Enrich domain with VirusTotal reputation data"""
        enrichment_data = {}
        
        if not settings.VIRUSTOTAL_API_KEY:
            return enrichment_data
        
        async with aiohttp.ClientSession() as session:
            result = await EnrichmentService._query_virustotal_domain(session, domain)
            if result:
                enrichment_data.update(result)
        
        return enrichment_data
    
    @staticmethod
    async def enrich_hash(file_hash: str) -> Dict:
        """Enrich file hash with VirusTotal malware detection data"""
        enrichment_data = {}
        
        if not settings.VIRUSTOTAL_API_KEY:
            return enrichment_data
        
        async with aiohttp.ClientSession() as session:
            result = await EnrichmentService._query_virustotal_hash(session, file_hash)
            if result:
                enrichment_data.update(result)
        
        return enrichment_data
    
    # ========== Private API Query Methods ==========
    
    @staticmethod
    async def _query_virustotal_ip(session: aiohttp.ClientSession, ip: str) -> Dict:
        """Query VirusTotal IP address report"""
        url = f"{EnrichmentService.VIRUSTOTAL_BASE}/ip_addresses/{ip}"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        
        try:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    
                    return {
                        "virustotal": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0)
                        }
                    }
        except Exception as e:
            print(f"VirusTotal IP query failed: {e}")
        
        return {}
    
    @staticmethod
    async def _query_virustotal_domain(session: aiohttp.ClientSession, domain: str) -> Dict:
        """Query VirusTotal domain report"""
        url = f"{EnrichmentService.VIRUSTOTAL_BASE}/domains/{domain}"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        
        try:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    
                    return {
                        "virustotal": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0)
                        }
                    }
        except Exception as e:
            print(f"VirusTotal domain query failed: {e}")
        
        return {}
    
    @staticmethod
    async def _query_virustotal_hash(session: aiohttp.ClientSession, file_hash: str) -> Dict:
        """Query VirusTotal file hash report"""
        url = f"{EnrichmentService.VIRUSTOTAL_BASE}/files/{file_hash}"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        
        try:
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    
                    return {
                        "virustotal": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                            "file_type": attrs.get("type_description", "Unknown"),
                            "first_seen": attrs.get("first_submission_date")
                        }
                    }
                elif response.status == 404:
                    # Hash not found in VirusTotal database
                    return {
                        "virustotal": {
                            "status": "not_found",
                            "message": "Hash not in VirusTotal database"
                        }
                    }
        except Exception as e:
            print(f"VirusTotal hash query failed: {e}")
        
        return {}
    
    @staticmethod
    async def _query_abuseipdb(session: aiohttp.ClientSession, ip: str) -> Dict:
        """Query AbuseIPDB for IP abuse reports"""
        url = f"{EnrichmentService.ABUSEIPDB_BASE}/check"
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        
        try:
            async with session.get(url, headers=headers, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    ip_data = data.get("data", {})
                    
                    return {
                        "abuseipdb": {
                            "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
                            "total_reports": ip_data.get("totalReports", 0),
                            "country_code": ip_data.get("countryCode"),
                            "isp": ip_data.get("isp"),
                            "is_whitelisted": ip_data.get("isWhitelisted", False)
                        }
                    }
        except Exception as e:
            print(f"AbuseIPDB query failed: {e}")
        
        return {}
    
    @staticmethod
    async def _query_ip_geolocation(session: aiohttp.ClientSession, ip: str) -> Dict:
        """Query ipapi.co for IP geolocation (free, no API key)"""
        url = f"{EnrichmentService.IPAPI_BASE}/{ip}/json/"
        
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    return {
                        "geolocation": {
                            "city": data.get("city"),
                            "region": data.get("region"),
                            "country": data.get("country_name"),
                            "country_code": data.get("country_code"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                            "org": data.get("org")
                        }
                    }
        except Exception as e:
            print(f"Geolocation query failed: {e}")
        
        return {}
    
    # ========== Database Update Methods ==========
    
    @staticmethod
    def determine_malicious_status(enrichment_data: Dict) -> bool:
        """
        Analyze enrichment data to determine if IOC is malicious.
        
        Criteria:
        - VirusTotal: 2+ vendors flag as malicious
        - AbuseIPDB: Confidence score > 75
        """
        is_malicious = False
        
        # Check VirusTotal
        vt_data = enrichment_data.get("virustotal", {})
        if vt_data.get("malicious", 0) >= 2:
            is_malicious = True
        
        # Check AbuseIPDB
        abuse_data = enrichment_data.get("abuseipdb", {})
        if abuse_data.get("abuse_confidence_score", 0) > 75:
            is_malicious = True
        
        return is_malicious
    
    @staticmethod
    async def enrich_ioc(db: Session, ioc: IOC) -> IOC:
        """
        Enrich a single IOC and update database record.
        
        Args:
            db: Database session
            ioc: IOC object to enrich
            
        Returns:
            Updated IOC object
        """
        enrichment_data = {}
        
        # Route to appropriate enrichment method
        if ioc.type == IOCType.IP:
            enrichment_data = await EnrichmentService.enrich_ip(ioc.value)
        elif ioc.type == IOCType.DOMAIN:
            enrichment_data = await EnrichmentService.enrich_domain(ioc.value)
        elif ioc.type in [IOCType.MD5, IOCType.SHA256]:
            enrichment_data = await EnrichmentService.enrich_hash(ioc.value)
        
        # Update IOC record
        if enrichment_data:
            ioc.enrichment_data = json.dumps(enrichment_data)
            ioc.is_malicious = EnrichmentService.determine_malicious_status(enrichment_data)
            db.commit()
            db.refresh(ioc)
        
        return ioc
    
    @staticmethod
    async def enrich_incident_iocs(db: Session, incident_id: int) -> List[IOC]:
        """
        Enrich all IOCs for an incident concurrently.
        
        Args:
            db: Database session
            incident_id: Incident ID
            
        Returns:
            List of enriched IOC objects
        """
        # Get all IOCs for incident
        iocs = db.query(IOC).filter(IOC.incident_id == incident_id).all()
        
        # Enrich each IOC concurrently
        tasks = [EnrichmentService.enrich_ioc(db, ioc) for ioc in iocs]
        enriched_iocs = await asyncio.gather(*tasks)
        
        return enriched_iocs