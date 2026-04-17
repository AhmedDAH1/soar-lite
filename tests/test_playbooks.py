from app.services.playbook_engine import PlaybookEngine


def test_evaluate_condition_equals():
    """Test equals operator"""
    condition = {
        "field": "ioc.type",
        "operator": "equals",
        "value": "ip"
    }
    context = {"ioc": {"type": "ip"}}
    
    assert PlaybookEngine.evaluate_condition(condition, context) is True


def test_evaluate_condition_in():
    """Test 'in' operator"""
    condition = {
        "field": "ioc.type",
        "operator": "in",
        "value": ["md5", "sha256"]
    }
    context = {"ioc": {"type": "md5"}}
    
    assert PlaybookEngine.evaluate_condition(condition, context) is True


def test_evaluate_condition_greater_than():
    """Test greater_than operator"""
    condition = {
        "field": "enrichment_data.abuseipdb.abuse_confidence_score",
        "operator": "greater_than",
        "value": 75
    }
    context = {
        "enrichment_data": {
            "abuseipdb": {
                "abuse_confidence_score": 90
            }
        }
    }
    
    assert PlaybookEngine.evaluate_condition(condition, context) is True


def test_get_nested_value():
    """Test nested value extraction"""
    data = {
        "enrichment_data": {
            "virustotal": {
                "malicious": 10
            }
        }
    }
    
    value = PlaybookEngine._get_nested_value(data, "enrichment_data.virustotal.malicious")
    assert value == 10


def test_load_playbooks():
    """Test loading playbooks from YAML files"""
    playbooks = PlaybookEngine.load_playbooks()
    
    # Should load at least the 3 playbooks we created
    assert len(playbooks) >= 3
    
    # Check playbook structure
    for playbook in playbooks:
        assert "name" in playbook
        assert "conditions" in playbook
        assert "actions" in playbook