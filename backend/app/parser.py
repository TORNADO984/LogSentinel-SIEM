import re
from ipaddress import ip_address

from .models import Event, LogInput


def normalize(log: LogInput) -> Event:
    kind, severity = 'system', 'info'
    user, ip = log.username, log.source_ip
    if log.source == 'linux':
        if re.search(r'Failed (password|publickey)|authentication failure', log.raw, re.I):
            kind, severity = 'login_failure', 'medium'
        elif re.search(r'Accepted (password|publickey)|session opened for user', log.raw, re.I):
            kind = 'login_success'
        elif re.search(r'new user:|useradd\[', log.raw, re.I):
            kind, severity = 'account_created', 'high'
        elif re.search(r'usermod.*(?:sudo|wheel|admin)|COMMAND=.*(?:usermod|visudo)', log.raw, re.I):
            kind, severity = 'privilege_change', 'high'
        elif re.search(r'sudo.*COMMAND=', log.raw):
            kind, severity = 'sudo_command', 'low'
        match = re.search(r'(?:for (?:invalid user )?|user=|name=)([\w.\-]+)', log.raw)
        if match and not user:
            user = match[1]
        if not user:
            match = re.search(r"(?:add|delete) '([^']+)' (?:to|from) group", log.raw)
            if match:
                user = match[1]
        match = re.search(r'(?:from |rhost=)([\da-fA-F.:]+)', log.raw)
        if match and not ip:
            try:
                ip = str(ip_address(match[1]))
            except ValueError:
                pass
    else:
        kind, severity = {
            4625: ('login_failure', 'medium'),
            4624: ('login_success', 'info'),
            4720: ('account_created', 'high'),
            4728: ('privilege_change', 'high'),
            4732: ('privilege_change', 'high'),
            4756: ('privilege_change', 'high'),
        }.get(log.event_id, ('process_created' if log.source == 'sysmon' and log.event_id == 1 else 'system', 'info'))
    return Event(id=str(log.id), timestamp=log.timestamp, hostname=log.hostname, source=log.source,
                 event_type=kind, severity=severity, username=user, source_ip=ip, raw=log.raw)
