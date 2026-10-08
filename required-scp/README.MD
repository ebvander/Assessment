## SCP Design Rationale

The SCP ensures that AWS resources can only be created and managed in `eu-west-1` (Ireland). It blocks activity in other regions while allowing essential global services, such as IAM and Route 53, to continue working.

A dedicated `BreakGlassAdmin` role provides emergency access if something goes wrong. Access to this role must be tightly controlled and monitored.
