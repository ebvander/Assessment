# Security Review: SSM Automation and RDS Access Policies

**Scope:** Annexures A and B (SSM automation), Annexures C and D (RDS access)
**Region:** eu-west-1
**Assumption:** The organisation wide SCP `DenyAllOutsideEUWest1` stays in place.

**What the SCP does and does not cover**

* It denies actions outside eu-west-1, with an exemption list (`NotAction`) for global services. `iam:*` and `sts:*` are fully exempt, so IAM and role assumption activity is not restricted by region.
* S3 is exempt only for four account level actions. Object actions such as `s3:GetObject` and `s3:PutObject` are not exempt and fall under the regional deny. This does not reduce the A1 risk within eu-west-1.
* AWS service principals and the `BreakGlassAdmin` role are excluded from the deny. Use of that role should be alerted on (see C10).
* The SCP sets no limit on what is permitted within eu-west-1, so it does not offset the findings below.

---

## 1. Summary

I recommend that neither request is approved in its current form.

**SSM automation.** The policy lets a pipeline identity read and write every S3 bucket, tag any instance as eligible for automation and run arbitrary shell commands on it. If the Azure DevOps agent is compromised, the impact reaches all three accounts.

**RDS access.** The three IAM policies control RDS management, not database access. The CRUB role carries the same `rds:*` rights as Admin, and none of the policies includes `rds-db:connect`, so the flow described in Annexure D would not work as designed.

Both requests can be resubmitted once the points below are addressed.

---

## 2. SSM Automation (Annexures A and B)

**Use case:** An Azure DevOps agent, running as an EKS Fargate pod with IRSA, assumes a role in each of three accounts and starts SSM automation to deploy to EC2 instances.

### Policy findings

| # | Finding | Rating | Impact | Mitigation |
|---|---|---|---|---|
| A1 | `s3:GetObject` and `s3:PutObject` apply to `arn:aws:s3:::*/*`. | Critical | Any bucket can be read or overwritten, including backups and deployment artefacts. | Limit to the named deployment buckets and prefixes. Enforce encryption and versioning. |
| A2 | `ec2:CreateTags` is allowed on all instances, and `SendCommand` relies on the `AutomationAllowed` and `Application` tags. | High | The role can tag any instance as eligible, then run commands on it. The tag control offers no protection. | Remove `CreateTags`, or block changes to those tag keys. Back this with an SCP. |
| A3 | `AWS-RunShellScript` and `AWS-RunPowerShellScript` are permitted. | High | Arbitrary commands with full operating system privileges on tagged instances. | Replace with approved custom documents that accept validated parameters. Control changes to them. |
| A4 | `customer-*` documents are executable from account 839864138277, which differs from the instance account. | High | Anyone who can create a matching document name in that account can run it here. | Name exact document ARNs. Restrict document creation in that account. |
| A5 | `StartInstances`, `StopInstances` and `RebootInstances` have no tag or environment condition. | High | Unrelated workloads can be disrupted. | Apply the same tag conditions as `SendCommand`. Separate production from non production. |
| A6 | Account IDs are inconsistent and some ARNs are malformed (an 11 digit account ID in the EC2 statement, a space in the S3 bucket ARN, a different account in the log group ARN). | High | Statements may not match their intended resources, and fixes tend to arrive as wildcards. | Correct the identifiers and validate with IAM Access Analyzer before resubmission. |
| A7 | The deny list does not cover `CreateAssociation`, `CreateDocument`, `DeleteDocument` or `StartAssociationsOnce`, and there is no explicit deny on destructive EC2 actions. | Medium | A later policy attachment could open persistence or destructive paths. | Add explicit denies and a permission boundary as a second layer. |
| A8 | The caller role has no `iam:PassRole` or `ssm:StartAutomationExecution`, although Annexure B shows automation being started. | Medium | Likely to be fixed later with broad permissions. | Grant both narrowly, with `iam:PassRole` limited to the execution role. |
| A9 | Command output and document content are readable, and log encryption is not specified. | Medium | Secrets passed to commands could leak into logs. | Keep secrets out of parameters and use Secrets Manager. Encrypt log groups and set retention. |

### Architecture findings

| # | Finding | Rating | Impact | Mitigation |
|---|---|---|---|---|
| B1 | One agent identity assumes roles in three accounts. | High | A compromised pipeline or agent gives execution across all three accounts. | Use a separate role per account and environment. Require approval and protected branches for production. |
| B2 | The IRSA trust scope is not shown. | High | If the trust policy does not pin namespace and service account, other pods could assume the role. | Pin both in the trust policy and use a dedicated agent pool. |
| B3 | Cross account trust conditions and monitoring are not described. | Medium | Pipeline activity is hard to attribute and misuse may go unnoticed. | Name the exact source role in each target trust policy. Enable CloudTrail and alert on shell document use, tag changes and unexpected S3 writes. |

---

## 3. RDS Access (Annexures C and D)

**Use case:** SailPoint manages Entra ID group membership, which maps to IAM Identity Center permission sets giving ReadOnly, CRUB (presumed CRUD) and Admin access through IAM database authentication.

### Core issue

IAM policies control RDS management actions. SQL privileges such as SELECT or DDL are granted inside the database. IAM database authentication depends on `rds-db:connect` scoped to a named database user, and `rds:*` does not include it. None of the submitted policies contains it, so users could not connect as described. If it is added later with a wildcard, any user could authenticate as the administrative database user.

For reference, the intended pattern is below. Placeholders must be replaced with the real account ID, database resource ID and username.

```json
{
  "Effect": "Allow",
  "Action": "rds-db:connect",
  "Resource": "arn:aws:rds-db:eu-west-1:ACCOUNT:dbuser:DB-RESOURCE-ID/readonly_user"
}
```

### Findings

| # | Finding | Rating | Impact | Mitigation |
|---|---|---|---|---|
| C1 | CRUB grants `rds:*` on all resources. | Critical | A read and write user can modify, delete, snapshot or restore databases. Role separation is nominal. | Remove management actions from CRUB. Grant `rds-db:connect` for the CRUB database user only. |
| C2 | Admin grants `rds:*` on all resources. | Critical | Includes deletion, snapshot sharing and master password changes, which bypass IAM authentication. | Scope to specific ARNs and the minimum actions. Require MFA for destructive actions and use deletion protection. |
| C3 | `rds-db:connect` is missing and nothing is limited to specific instances or database users. | High | The proposed flow fails, and a careless fix could grant access to every database user. | Add it per database user and per instance. |
| C4 | Admin can delete CloudWatch alarms, publish to SNS and read logs, all on `*`. | High | Monitoring can be weakened and unrelated logs read. | Scope to RDS resources and protect alarms with an SCP. |
| C5 | Three shared database users serve all humans. | High | Individual accountability is weak without database level audit logging. | Enable database audit logging and correlate it with Identity Center sessions. |
| C6 | Removal of access passes through SailPoint, Entra ID and Identity Center. Tokens last 15 minutes, but open connections persist. | High | A leaver can keep working access after removal. | Use short session durations and idle timeouts, and define how sessions are terminated. |
| C7 | Admin has full DDL and DML. | High | An admin can create users or grants outside the IAM model. | Make Admin time limited with approval and MFA, and keep a monitored break glass account. |
| C8 | Incorrect SailPoint group assignment. | Medium | A user could receive Admin access in error. | Approval workflows, periodic access reviews and alerts on Admin group changes. |
| C9 | Environment separation, data classification and network path are not stated. | Medium | ReadOnly scope and database exposure cannot be assessed. | Separate permission sets per account and environment. Keep instances private and enforce TLS. |
| C10 | No fallback if SailPoint, Entra ID or Identity Center is unavailable. | Medium | Operational lockout during an incident. | Document a break glass procedure with a vaulted credential and alerting on use. |

The ReadOnly policy is narrow and suitable for management visibility. It does not grant database SELECT on its own.

---

## 4. Path to Approval
1. **SSM:** fix A1 to A3, correct the identifiers (A6) and split caller and execution role duties (A8).
2. **RDS:** rebuild around scoped `rds-db:connect` per database user, rewrite CRUB and Admin with least privilege, and define the SQL grants separately.
3. **Both:** add monitoring, session limits and approval gates before production use.
4. **Resubmit** with IAM Access Analyzer output and the trust policies, and test permitted and denied access.