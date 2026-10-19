import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from network_guard import scan
ROOT = Path(__file__).resolve().parents[1]


def plan(kind='aws_security_group_rule', **attrs):
    values = {'type': 'ingress', 'protocol': 'tcp', 'from_port': 22,
              'to_port': 22, 'cidr_blocks': ['0.0.0.0/0']}
    values.update(attrs)
    return {'format_version': '1.2', 'resource_changes': [{
        'address': kind + '.demo', 'mode': 'managed', 'type': kind,
        'provider_name': 'registry.terraform.io/hashicorp/aws',
        'change': {'actions': ['create'], 'after': values, 'after_unknown': {}}}]}


class GuardTests(unittest.TestCase):
    def test_public_ssh(self):
        self.assertEqual(scan(plan())['findings'][0]['services'], ['SSH'])
    def test_ipv6_rdp(self):
        p = plan(cidr_blocks=[], ipv6_cidr_blocks=['::/0'], from_port=3389, to_port=3389)
        self.assertEqual(scan(p)['findings'][0]['services'], ['RDP'])
    def test_private_ssh(self):
        self.assertFalse(scan(plan(cidr_blocks=['10.0.0.0/8']))['findings'])
    def test_https(self):
        self.assertFalse(scan(plan(from_port=443, to_port=443))['findings'])
    def test_port_range(self):
        self.assertEqual(scan(plan(from_port=1, to_port=4000))['findings'][0]['services'], ['SSH', 'RDP'])
    def test_all_protocols_ignore_ports(self):
        self.assertEqual(scan(plan(protocol='-1', from_port=0, to_port=0))['findings'][0]['services'], ['SSH', 'RDP'])
    def test_udp(self):
        self.assertFalse(scan(plan(protocol='udp'))['findings'])
    def test_egress(self):
        self.assertEqual(scan(plan(type='egress'))['evaluated_rules'], 0)
    def test_inline(self):
        rule = plan()['resource_changes'][0]['change']['after']
        self.assertEqual(len(scan(plan('aws_security_group', ingress=[rule]))['findings']), 1)
    def test_modern_ipv6(self):
        p = plan('aws_vpc_security_group_ingress_rule', ip_protocol='6', cidr_ipv6='::/0')
        self.assertEqual(len(scan(p)['findings']), 1)
    def test_unknown_requires_review(self):
        p = plan(); p['resource_changes'][0]['change']['after_unknown'] = {'cidr_blocks': [True]}
        self.assertEqual(len(scan(p)['review_required']), 1)
        self.assertFalse(scan(p)['findings'])
    def test_false_unknown_marker(self):
        p = plan(); p['resource_changes'][0]['change']['after_unknown'] = {'cidr_blocks': [False]}
        self.assertEqual(len(scan(p)['findings']), 1)
    def test_delete_ignored(self):
        p = plan(); p['resource_changes'][0]['change']['actions'] = ['delete']
        self.assertEqual(scan(p)['supported_resources'], 0)
    def test_replacement_checked(self):
        p = plan(); p['resource_changes'][0]['change']['actions'] = ['delete', 'create']
        self.assertEqual(len(scan(p)['findings']), 1)
    def test_unchanged_checked(self):
        p = plan(); p['resource_changes'][0]['change']['actions'] = ['no-op']
        self.assertEqual(len(scan(p)['findings']), 1)
    def test_wrong_provider_ignored(self):
        p = plan(); p['resource_changes'][0]['provider_name'] = 'example/other'
        self.assertEqual(scan(p)['supported_resources'], 0)
    def test_missing_ports_requires_review(self):
        self.assertEqual(len(scan(plan(from_port=None))['review_required']), 1)
    def test_invalid_cidr_requires_review(self):
        self.assertEqual(len(scan(plan(cidr_blocks=['invalid']))['review_required']), 1)
    def test_bad_version(self):
        with self.assertRaises(ValueError): scan({'format_version': '2.0', 'resource_changes': []})
    def test_wrong_input(self):
        with self.assertRaises(ValueError): scan({'format_version': '1.0'})
    def test_cli_exit_codes(self):
        for obj, expected in [(plan(), 1), (plan(cidr_blocks=['10.0.0.0/8']), 0),
                              ({'format_version': '1.0', 'resource_changes': []}, 2), ({}, 2)]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'input.json'; path.write_text(json.dumps(obj))
                result = subprocess.run([sys.executable, str(ROOT / 'network_guard.py'), str(path)], capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr)

if __name__ == '__main__': unittest.main()
