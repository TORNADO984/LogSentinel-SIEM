from datetime import timedelta
from hashlib import sha256

from .models import Alert, Event


def detect(event: Event, store):
    rule = None
    evidence = [event.id]
    if event.event_type in ('login_failure', 'login_success') and event.source_ip:
        failures = store.query(event_type='login_failure', hostname=event.hostname,
                               source_ip=event.source_ip, start=event.timestamp - timedelta(minutes=5),
                               end=event.timestamp, limit=1000)
        if failures['total'] >= 5:
            evidence = [item['id'] for item in failures['items']]
            if event.event_type == 'login_success':
                rule = ('success_after_failures', 'Successful login after repeated failures', 'critical',
                        'T1078', 'Valid Accounts', 'A successful login followed at least five failures from this IP on this host within five minutes. Investigate possible account compromise.')
                evidence.append(event.id)
            else:
                rule = ('failed_login_spike', 'Failed login spike', 'high', 'T1110', 'Brute Force',
                        'At least five failed logins from the same IP on one host within five minutes.')
    elif event.event_type in ('account_created', 'privilege_change'):
        rule = (event.event_type, 'Account created' if event.event_type == 'account_created' else 'Privilege change observed',
                'high', 'T1136' if event.event_type == 'account_created' else 'T1098',
                'Create Account' if event.event_type == 'account_created' else 'Account Manipulation',
                'Review this account or privilege change against approved administration activity.')
    if rule:
        key, title, severity, technique, technique_name, description = rule
        # Fixed five-minute buckets suppress repeated spike alerts. Other rules are per event.
        scope = str(int(event.timestamp.timestamp()) // 300) if key == 'failed_login_spike' else event.id
        alert_id = sha256(f'{key}:{event.hostname}:{event.source_ip}:{scope}'.encode()).hexdigest()
        store.save('alerts', Alert(id=alert_id, timestamp=event.timestamp, title=title, severity=severity,
                   hostname=event.hostname, source_ip=event.source_ip, username=event.username,
                   technique_id=technique, technique_name=technique_name, description=description, event_ids=evidence))
