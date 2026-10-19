#!/usr/bin/env python3
"""Check supported AWS ingress rules in Terraform plan JSON; no cloud access."""
import argparse
import ipaddress
import json
import sys
from pathlib import Path

AWS = 'registry.terraform.io/hashicorp/aws'
SUPPORTED = {'aws_security_group', 'aws_security_group_rule',
             'aws_vpc_security_group_ingress_rule'}
PORTS = {22: 'SSH', 3389: 'RDP'}


def unknown(value):
    if isinstance(value, dict):
        return any(unknown(v) for v in value.values())
    if isinstance(value, list):
        return any(unknown(v) for v in value)
    return value is True


def evaluate(rule, modern=False):
    """Return (exposed service names, review reason)."""
    protocol = rule.get('ip_protocol' if modern else 'protocol')
    if protocol is None:
        return [], 'Protocol is missing'
    protocol = str(protocol).lower()
    if protocol not in {'tcp', '6', '-1', 'all'}:
        return [], None
    cidrs = []
    if modern:
        cidrs = [rule[k] for k in ('cidr_ipv4', 'cidr_ipv6') if rule.get(k)]
    else:
        for key in ('cidr_blocks', 'ipv6_cidr_blocks'):
            values = rule.get(key) or []
            if not isinstance(values, list):
                return [], 'CIDR collection is malformed'
            cidrs.extend(values)
    public = False
    for cidr in cidrs:
        try:
            public |= ipaddress.ip_network(cidr, strict=False).prefixlen == 0
        except (ValueError, TypeError):
            return [], 'CIDR value is malformed'
    if not public:
        return [], None
    if protocol in {'-1', 'all'}:
        return list(PORTS.values()), None
    start, end = rule.get('from_port'), rule.get('to_port')
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
        return [], 'TCP port range is missing or invalid'
    return [name for port, name in PORTS.items() if start <= port <= end], None


def scan(plan):
    if not isinstance(plan, dict) or str(plan.get('format_version', '')).split('.')[0] != '1':
        raise ValueError('Expected Terraform plan JSON format_version 1.x')
    changes = plan.get('resource_changes')
    if not isinstance(changes, list):
        raise ValueError('Expected resource_changes list; use terraform show -json on a saved plan')
    result = {'findings': [], 'review_required': [], 'supported_resources': 0,
              'evaluated_rules': 0, 'ignored_resources': 0}
    for item in changes:
        if not isinstance(item, dict):
            raise ValueError('Malformed resource change')
        kind, address = item.get('type'), item.get('address', '<unknown>')
        if item.get('mode') != 'managed' or item.get('provider_name') != AWS or kind not in SUPPORTED:
            result['ignored_resources'] += 1
            continue
        change = item.get('change')
        if not isinstance(change, dict) or not isinstance(change.get('actions'), list):
            raise ValueError('Malformed change for supported resource')
        if change['actions'] == ['delete']:
            result['ignored_resources'] += 1
            continue
        result['supported_resources'] += 1
        after = change.get('after')
        if not isinstance(after, dict):
            result['review_required'].append({'address': address, 'reason': 'Planned values are unavailable'})
            continue
        # Conservative: any unknown on a supported resource requires review.
        if unknown(change.get('after_unknown', {})):
            result['review_required'].append({'address': address, 'reason': 'Resource contains values unknown until apply'})
            continue
        if kind == 'aws_security_group_rule':
            if after.get('type') == 'egress':
                continue
            if after.get('type') != 'ingress':
                result['review_required'].append({'address': address, 'reason': 'Rule direction is missing'})
                continue
        rules = after.get('ingress') if kind == 'aws_security_group' else [after]
        if rules is None or not isinstance(rules, list):
            result['review_required'].append({'address': address, 'reason': 'Ingress collection is unavailable'})
            continue
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError('Malformed ingress rule')
            services, reason = evaluate(rule, kind == 'aws_vpc_security_group_ingress_rule')
            if reason:
                result['review_required'].append({'address': address, 'rule_index': index, 'reason': reason})
                continue
            result['evaluated_rules'] += 1
            if services:
                result['findings'].append({'rule_id': 'NET001', 'severity': 'HIGH',
                    'address': address, 'rule_index': index, 'services': services,
                    'message': 'Administrative port permits an IPv4 or IPv6 default route',
                    'remediation': 'Remove public administrative ingress; use an approved private access path.'})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    args = parser.parse_args()
    try:
        result = scan(json.loads(args.plan.read_text()))
    except (OSError, ValueError, TypeError) as exc:
        # Do not print input content: real Terraform plans may contain secrets.
        print('Input error: supply readable, valid Terraform plan JSON (format 1.x).', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if result['findings']:
        return 1
    if result['review_required'] or result['evaluated_rules'] == 0:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
