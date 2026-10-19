# Terraform Network Guard

A small, offline Python check for AWS security group rules that permit SSH (TCP 22) or Remote Desktop (TCP 3389) from an IPv4 or IPv6 default route. It reads Terraform plan JSON and returns a machine-readable report suitable for a CI gate.

## Project context and contribution

This is a new, AI-assisted portfolio demonstration prepared for Niyi Adegoke. It uses synthetic examples and contains no employer code or infrastructure data. It is not a production deployment, a discovered vulnerability, a CVE, or evidence of work performed for a client.

Niyi supplied the career context and requested a repository-ready security example. The AI assistant selected the implementation approach, wrote the scanner, fixtures, tests, workflow, and documentation, and executed local tests. Niyi's review, modifications, and independent validation are not asserted here. Update this section with specific personal changes after making and reviewing them. HashiCorp and AWS documentation informed the input format and rule rationale; their implementations are not reproduced here.

## Why this check exists

An administrative ingress rule can be broader than intended even when it appears inside a valid Terraform plan. Checking the proposed rule before deployment gives reviewers a concrete opportunity to remove public administrative access. This demonstration intentionally focuses on one policy rather than claiming comprehensive cloud security coverage.

## Quick start

Requires Python 3.10 or later; no third-party Python packages or AWS credentials are needed for the supplied examples.

```sh
python3 network_guard.py examples/safe.json
# Exit 0: evaluated supported rules, no selected-policy findings or review items

python3 network_guard.py examples/unsafe.json
# Exit 1: public SSH finding NET001

python3 -m unittest discover -s tests -v
```

The unsafe fixture permits SSH from `0.0.0.0/0`. The safe fixture restricts the same rule to `10.20.0.0/16`. They are hand-authored, minimal plan-format fixtures, not output captured from a live deployment.

## Use with a real plan

From an existing, authorized Terraform workspace:

```sh
terraform plan -out=review.tfplan
terraform show -json review.tfplan > plan.json
python3 /path/to/terraform-network-guard/network_guard.py plan.json
```

Creating a real plan may require credentials and contact cloud APIs. The scanner itself only reads a local file. Terraform plan JSON can contain secrets even for values marked sensitive. Keep real plans out of repositories, public CI artifacts, and application submissions. Only publish the synthetic fixtures in this project.

## Rule and supported resources

`NET001` reports a HIGH finding when known rule values permit TCP 22 or TCP 3389 from a prefix-length-zero CIDR (`0.0.0.0/0` or `::/0`). It handles port ranges, TCP protocol number `6`, and all-protocol rules. Egress rules are ignored.

Supported HashiCorp AWS provider resource representations:

- `aws_security_group` with inline ingress blocks
- `aws_security_group_rule` with `type = ingress`
- `aws_vpc_security_group_ingress_rule`

The scanner examines `resource_changes[].change.after`, including no-op and replacement entries. Pure deletions, data resources, other providers, and unsupported resource types are ignored. Module-qualified addresses are preserved in findings.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | At least one supported rule evaluated; no findings or review-required entries |
| 1 | At least one policy finding; also inspect any review-required entries |
| 2 | Invalid input, unresolved review items without findings, or no supported rules evaluated |

Only exit 0 passes a CI gate. The JSON includes findings, review items, evaluated-rule count, supported-resource count, and ignored-resource count. An exit 0 applies only to the selected check and supported entries, not the entire plan.

Unknown values are handled conservatively: any unknown value on a supported resource causes that resource to require review, including unrelated computed attributes such as an ID. This avoids pretending to have evaluated an incomplete resource, but can block otherwise harmless plans. A future improvement would inspect only policy-relevant unknown paths.

## Limitations and design tradeoffs

- This is a focused prototype, not a replacement for mature IaC scanners or security review.
- It checks direct default-route exposure only. Multiple narrower CIDRs that together cover the internet are outside scope.
- It does not determine actual network reachability, routing, NACL effects, security group references, prefix list contents, IAM access, or application authentication.
- It does not parse HCL, inspect current AWS state, resolve Terraform expressions, or assess resources omitted from the plan's resource changes.
- It does not implement a full Terraform JSON schema validator. Malformed input must not be treated as a security result.
- A private CIDR is not automatically trustworthy. The safe example only passes this one policy.
- Tests use synthetic data. No cloud resources were deployed; no real Terraform-generated plan or hosted GitHub Actions run was validated during creation.

Python's standard library keeps the example easy to inspect and run. JSON output makes it usable by other automation without printing full resource values.

## Verification

At creation, 21 local unittest cases passed, including subprocess checks for all three exit codes. The GitHub workflow runs those tests and the safe/unsafe examples on pushes and pull requests. A successful hosted run should be verified after upload.

## Read and extend

Start with `evaluate` for the rule logic, `scan` for plan traversal, and `main` for reporting and exit codes. To extend this project, add a failing test for the intended behavior first, implement the change, and document its scope. Useful next steps include policy-specific unknown handling and integration fixtures generated using Terraform and the AWS provider.

## References

- [HashiCorp Terraform JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
- [HashiCorp sensitive data guidance](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
- [AWS security group rules by use case](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html)

The test workflow belongs at the repository root in `.github/workflows/terraform-network-guard.yml`. Run the quick-start commands from this project folder.
