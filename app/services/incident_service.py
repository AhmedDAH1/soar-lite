from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import Optional, List
from datetime import datetime, timedelta

from app.models import Incident, IOC, Action, SeverityEnum, StatusEnum
from app.schemas.incident import IncidentUpdate


class IncidentService:
    """
    Business logic for incident case management.
    """
    
    # Valid status transitions (state machine)
    VALID_TRANSITIONS = {
        StatusEnum.NEW: [StatusEnum.INVESTIGATING],
        StatusEnum.INVESTIGATING: [StatusEnum.INVESTIGATING, StatusEnum.CONTAINED],
        StatusEnum.CONTAINED: [StatusEnum.RESOLVED],
        StatusEnum.RESOLVED: []  # Final state, no transitions
    }
    
    @staticmethod
    def validate_status_transition(current_status: StatusEnum, new_status: StatusEnum) -> bool:
        """
        Validate if status transition is allowed.
        
        Args:
            current_status: Current incident status
            new_status: Desired new status
            
        Returns:
            True if transition is valid
        """
        if current_status == new_status:
            return True  # No change is always valid
        
        valid_next_states = IncidentService.VALID_TRANSITIONS.get(current_status, [])
        return new_status in valid_next_states
    
    @staticmethod
    def update_incident(
        db: Session,
        incident_id: int,
        updates: IncidentUpdate,
        analyst_username: str = "analyst"
    ) -> Optional[Incident]:
        """
        Update incident with validation and audit logging.
        
        Args:
            db: Database session
            incident_id: Incident to update
            updates: Update data
            analyst_username: Who is making the update
            
        Returns:
            Updated incident or None if not found
        """
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return None
        
        changes_made = []
        
        # Update title
        if updates.title is not None and updates.title != incident.title:
            old_title = incident.title
            incident.title = updates.title
            changes_made.append(f"Title changed from '{old_title}' to '{updates.title}'")
        
        # Update description
        if updates.description is not None and updates.description != incident.description:
            incident.description = updates.description
            changes_made.append("Description updated")
        
        # Update severity
        if updates.severity is not None:
            new_severity = SeverityEnum[updates.severity.upper()]
            if new_severity != incident.severity:
                old_severity = incident.severity.value
                incident.severity = new_severity
                changes_made.append(f"Severity changed from {old_severity} to {updates.severity}")
                
                # Log severity change
                action = Action(
                    incident_id=incident.id,
                    action_type="severity_updated",
                    description=f"Severity manually updated from {old_severity} to {updates.severity}",
                    performed_by=analyst_username
                )
                db.add(action)
        
        # Update status (with validation)
        if updates.status is not None:
            new_status = StatusEnum[updates.status.upper()]
            
            # Validate transition
            if not IncidentService.validate_status_transition(incident.status, new_status):
                # Invalid transition - don't update, but log attempt
                action = Action(
                    incident_id=incident.id,
                    action_type="status_update_rejected",
                    description=f"Invalid status transition from {incident.status.value} to {updates.status} - rejected",
                    performed_by=analyst_username
                )
                db.add(action)
            elif new_status != incident.status:
                old_status = incident.status.value
                incident.status = new_status
                changes_made.append(f"Status changed from {old_status} to {updates.status}")
                
                # Log status change
                action = Action(
                    incident_id=incident.id,
                    action_type="status_updated",
                    description=f"Status updated from {old_status} to {updates.status}",
                    performed_by=analyst_username
                )
                db.add(action)
        
        # If any changes were made, create a summary action
        if changes_made:
            summary_action = Action(
                incident_id=incident.id,
                action_type="incident_updated",
                description=f"Incident updated: {', '.join(changes_made)}",
                performed_by=analyst_username
            )
            db.add(summary_action)
        
        db.commit()
        db.refresh(incident)
        
        return incident
    
    @staticmethod
    def search_incidents(
        db: Session,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        ioc_value: Optional[str] = None,
        days: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Incident]:
        """
        Search and filter incidents.
        
        Args:
            db: Database session
            severity: Filter by severity (low/medium/high/critical)
            status: Filter by status (new/investigating/contained/resolved)
            search: Search in title and description
            ioc_value: Find incidents containing this IOC
            days: Only incidents from last N days
            limit: Max results
            offset: Pagination offset
            
        Returns:
            List of matching incidents
        """
        query = db.query(Incident)
        
        # Filter by severity
        if severity:
            try:
                severity_enum = SeverityEnum[severity.upper()]
                query = query.filter(Incident.severity == severity_enum)
            except KeyError:
                pass  # Invalid severity, ignore filter
        
        # Filter by status
        if status:
            try:
                status_enum = StatusEnum[status.upper()]
                query = query.filter(Incident.status == status_enum)
            except KeyError:
                pass
        
        # Text search in title/description
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                or_(
                    Incident.title.ilike(search_pattern),
                    Incident.description.ilike(search_pattern)
                )
            )
        
        # Filter by IOC value
        if ioc_value:
            # Join with IOCs table
            query = query.join(Incident.iocs).filter(
                IOC.value.ilike(f"%{ioc_value}%")
            )
        
        # Filter by date range
        if days:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Incident.created_at >= cutoff_date)
        
        # Order by most recent first
        query = query.order_by(Incident.created_at.desc())
        
        # Pagination
        query = query.limit(limit).offset(offset)
        
        return query.all()
    
    @staticmethod
    def get_statistics(db: Session) -> dict:
        """
        Get incident statistics for dashboard.
        
        Returns:
            Dict with counts by severity, status, etc.
        """
        total_incidents = db.query(Incident).count()
        
        # Count by status
        status_counts = {}
        for status in StatusEnum:
            count = db.query(Incident).filter(Incident.status == status).count()
            status_counts[status.value] = count
        
        # Count by severity
        severity_counts = {}
        for severity in SeverityEnum:
            count = db.query(Incident).filter(Incident.severity == severity).count()
            severity_counts[severity.value] = count
        
        # Recent incidents (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_count = db.query(Incident).filter(
            Incident.created_at >= seven_days_ago
        ).count()
        
        # Unresolved incidents
        unresolved_count = db.query(Incident).filter(
            Incident.status != StatusEnum.RESOLVED
        ).count()
        
        # Critical unresolved
        critical_unresolved = db.query(Incident).filter(
            and_(
                Incident.severity == SeverityEnum.CRITICAL,
                Incident.status != StatusEnum.RESOLVED
            )
        ).count()
        
        return {
            "total_incidents": total_incidents,
            "by_status": status_counts,
            "by_severity": severity_counts,
            "recent_7_days": recent_count,
            "unresolved": unresolved_count,
            "critical_unresolved": critical_unresolved
        }