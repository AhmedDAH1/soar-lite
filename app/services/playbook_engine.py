import yaml
import os
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from sqlalchemy.orm import Session

from app.models import Incident, IOC, Action, SeverityEnum


class PlaybookEngine:
    """
    Playbook execution engine for automated incident response.
    
    Loads YAML playbook definitions and executes actions when conditions match.
    """
    
    PLAYBOOKS_DIR = Path("playbooks")
    
    @staticmethod
    def load_playbooks() -> List[Dict]:
        """
        Load all enabled playbooks from YAML files.
        
        Returns:
            List of playbook definitions (dict)
        """
        playbooks = []
        
        if not PlaybookEngine.PLAYBOOKS_DIR.exists():
            return playbooks
        
        for yaml_file in PlaybookEngine.PLAYBOOKS_DIR.glob("*.yml"):
            try:
                with open(yaml_file, 'r') as f:
                    playbook = yaml.safe_load(f)
                    
                    # Only load enabled playbooks
                    if playbook.get("enabled", True):
                        playbook["_filename"] = yaml_file.name
                        playbooks.append(playbook)
            except Exception as e:
                print(f"Error loading playbook {yaml_file}: {e}")
        
        return playbooks
    
    @staticmethod
    def evaluate_condition(condition: Dict, context: Dict) -> bool:
        """
        Evaluate a single condition against context data.
        
        Args:
            condition: Dict with 'field', 'operator', 'value'
            context: Dict with incident, ioc, enrichment data
            
        Returns:
            True if condition matches, False otherwise
        """
        field_path = condition.get("field", "")
        operator = condition.get("operator", "")
        expected_value = condition.get("value")
        
        # Navigate nested field path (e.g., "ioc.type" or "enrichment_data.abuseipdb.abuse_confidence_score")
        field_value = PlaybookEngine._get_nested_value(context, field_path)
        
        # Evaluate operator
        if operator == "equals":
            return field_value == expected_value
        
        elif operator == "in":
            return field_value in expected_value
        
        elif operator == "greater_than":
            return isinstance(field_value, (int, float)) and field_value > expected_value
        
        elif operator == "greater_than_or_equal":
            return isinstance(field_value, (int, float)) and field_value >= expected_value
        
        elif operator == "less_than":
            return isinstance(field_value, (int, float)) and field_value < expected_value
        
        elif operator == "contains":
            return expected_value in str(field_value)
        
        return False
    
    @staticmethod
    def _get_nested_value(data: Dict, path: str) -> Any:
        """
        Get value from nested dict using dot notation.
        
        Example: _get_nested_value({"ioc": {"type": "ip"}}, "ioc.type") -> "ip"
        """
        keys = path.split(".")
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        
        return value
    
    @staticmethod
    def evaluate_playbook(playbook: Dict, context: Dict) -> bool:
        """
        Check if ALL conditions in playbook are met.
        
        Args:
            playbook: Playbook definition
            context: Execution context (incident, ioc data)
            
        Returns:
            True if all conditions match
        """
        conditions = playbook.get("conditions", [])
        
        # All conditions must be true (AND logic)
        for condition in conditions:
            if not PlaybookEngine.evaluate_condition(condition, context):
                return False
        
        return True
    
    @staticmethod
    def execute_action(
        action: Dict,
        incident: Incident,
        db: Session,
        playbook_name: str
    ) -> Optional[Action]:
        """
        Execute a single playbook action.
        
        Args:
            action: Action definition from playbook
            incident: Incident to act upon
            db: Database session
            playbook_name: Name of triggering playbook
            
        Returns:
            Action record (timeline entry)
        """
        action_type = action.get("type")
        params = action.get("params", {})
        
        action_record = None
        
        # ========== Action: Update Severity ==========
        if action_type == "update_severity":
            new_severity = params.get("severity")
            only_if_lower = params.get("only_if_lower", False)
            
            # Convert string to enum
            severity_map = {
                "low": SeverityEnum.LOW,
                "medium": SeverityEnum.MEDIUM,
                "high": SeverityEnum.HIGH,
                "critical": SeverityEnum.CRITICAL
            }
            
            new_severity_enum = severity_map.get(new_severity.lower())
            
            if new_severity_enum:
                # Check if we should update
                should_update = True
                
                if only_if_lower:
                    # Only escalate, never downgrade
                    severity_order = {
                        SeverityEnum.LOW: 1,
                        SeverityEnum.MEDIUM: 2,
                        SeverityEnum.HIGH: 3,
                        SeverityEnum.CRITICAL: 4
                    }
                    
                    current_level = severity_order.get(incident.severity, 0)
                    new_level = severity_order.get(new_severity_enum, 0)
                    
                    should_update = new_level > current_level
                
                if should_update:
                    old_severity = incident.severity.value
                    incident.severity = new_severity_enum
                    
                    action_record = Action(
                        incident_id=incident.id,
                        action_type="severity_updated",
                        description=f"Severity updated from {old_severity} to {new_severity}",
                        playbook_name=playbook_name,
                        performed_by="system",
                        action_metadata=json.dumps({
                            "old_severity": old_severity,
                            "new_severity": new_severity
                        })
                    )
        
        # ========== Action: Add Tag ==========
        elif action_type == "add_tag":
            tag = params.get("tag")
            
            # For now, store tags in incident description
            # In production, you'd have a separate tags table
            if tag:
                tag_marker = f"[TAG:{tag}]"
                if tag_marker not in (incident.description or ""):
                    incident.description = f"{incident.description or ''} {tag_marker}".strip()
                    
                    action_record = Action(
                        incident_id=incident.id,
                        action_type="tag_added",
                        description=f"Tag added: {tag}",
                        playbook_name=playbook_name,
                        performed_by="system",
                        action_metadata=json.dumps({"tag": tag})
                    )
        
        # ========== Action: Create Timeline Entry ==========
        elif action_type == "create_timeline_entry":
            description = params.get("description", "Playbook action executed")
            
            action_record = Action(
                incident_id=incident.id,
                action_type="timeline_entry",
                description=description,
                playbook_name=playbook_name,
                performed_by="system"
            )
        
        # Save action to database
        if action_record:
            db.add(action_record)
        
        return action_record
    
    @staticmethod
    def execute_playbook(
        playbook: Dict,
        incident: Incident,
        ioc: Optional[IOC],
        db: Session
    ) -> List[Action]:
        """
        Execute a playbook against an incident/IOC.
        
        Args:
            playbook: Playbook definition
            incident: Incident object
            ioc: IOC object (optional, for IOC-specific playbooks)
            db: Database session
            
        Returns:
            List of executed actions
        """
        # Build context for condition evaluation
        context = {
            "incident": {
                "id": incident.id,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "malicious_ioc_count": sum(1 for i in incident.iocs if i.is_malicious)
            }
        }
        
        # Add IOC context if provided
        if ioc:
            context["ioc"] = {
                "id": ioc.id,
                "type": ioc.type.value,
                "value": ioc.value,
                "is_malicious": ioc.is_malicious
            }
            
            # Parse enrichment data
            if ioc.enrichment_data:
                try:
                    context["enrichment_data"] = json.loads(ioc.enrichment_data)
                except json.JSONDecodeError:
                    pass
        
        # Evaluate conditions
        if not PlaybookEngine.evaluate_playbook(playbook, context):
            return []
        
        # Execute actions
        executed_actions = []
        playbook_name = playbook.get("name", "Unknown Playbook")
        
        for action in playbook.get("actions", []):
            action_record = PlaybookEngine.execute_action(
                action, incident, db, playbook_name
            )
            if action_record:
                executed_actions.append(action_record)
        
        # Commit all changes
        if executed_actions:
            db.commit()
            print(f"✅ Playbook '{playbook_name}' executed {len(executed_actions)} actions")
        
        return executed_actions
    
    @staticmethod
    def run_playbooks_for_incident(incident_id: int, db: Session) -> Dict:
        """
        Run all enabled playbooks against an incident.
        
        This is typically called after enrichment completes.
        
        Args:
            incident_id: Incident ID
            db: Database session
            
        Returns:
            Summary of executed playbooks and actions
        """
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        
        if not incident:
            return {"error": "Incident not found"}
        
        playbooks = PlaybookEngine.load_playbooks()
        
        results = {
            "incident_id": incident_id,
            "playbooks_evaluated": len(playbooks),
            "playbooks_triggered": 0,
            "total_actions": 0,
            "executed_playbooks": []
        }
        
        # Run playbooks for each IOC (IOC-specific playbooks)
        for ioc in incident.iocs:
            for playbook in playbooks:
                actions = PlaybookEngine.execute_playbook(playbook, incident, ioc, db)
                
                if actions:
                    results["playbooks_triggered"] += 1
                    results["total_actions"] += len(actions)
                    results["executed_playbooks"].append({
                        "playbook": playbook.get("name"),
                        "ioc": ioc.value,
                        "actions": len(actions)
                    })
        
        # Run incident-level playbooks (e.g., multi-IOC detection)
        for playbook in playbooks:
            # Check if this is an incident-level playbook (no IOC-specific conditions)
            conditions = playbook.get("conditions", [])
            is_incident_level = all(
                not cond.get("field", "").startswith("ioc.")
                for cond in conditions
            )
            
            if is_incident_level:
                actions = PlaybookEngine.execute_playbook(playbook, incident, None, db)
                
                if actions:
                    results["playbooks_triggered"] += 1
                    results["total_actions"] += len(actions)
                    results["executed_playbooks"].append({
                        "playbook": playbook.get("name"),
                        "ioc": None,
                        "actions": len(actions)
                    })
        
        return results