# Lint Delta

## ADDED Requirements

### Requirement: Shared via site IDs are advice

Lint SHALL report one `autoapprover-siteid-collision` advice finding when
two or more `autoApprovers.routes` via prefixes share a site ID and their
embedded IPv4 prefixes differ. The finding SHALL name each of those routes
and SHALL ask the reader to confirm they are the same site. It SHALL NOT
call the control plane, and it SHALL NOT use warn or error severity.

#### Scenario: One site ID covers two subnets

- **WHEN** two via prefixes share a site ID and decode to different IPv4
  prefixes
- **THEN** lint reports one advice finding that names both routes and asks
  to confirm they are the same site

#### Scenario: Different site IDs are quiet

- **WHEN** two via prefixes have different site IDs
- **THEN** lint reports no `autoapprover-siteid-collision` finding

#### Scenario: Ordinary routes are quiet

- **WHEN** the route keys are ordinary IPv4 CIDRs
- **THEN** lint reports no `autoapprover-siteid-collision` finding
