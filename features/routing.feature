Feature: Routing capture
  Owned BTKN iptables objects must be idempotent and never flush foreign policy.

  @BTKN-ROUT-001 @P0 @routing
  Scenario: UDP path order is restore exclusions socket MARK save TPROXY
    Given a hybrid plan
    Then UDP restore precedes exclusions MARK save and TPROXY

  @BTKN-ROUT-002 @P0 @routing
  Scenario: Expected Xray owner of 11820 is not a collision
    Given ss output for our xray pid
    When preflight runs
    Then port 11820 is allowed

  @BTKN-ROUT-003 @P0 @routing
  Scenario: Foreign Xray owner of 11820 is a collision
    Given ss output for /opt/sbin/xray
    When preflight runs
    Then Apply is rejected

  @BTKN-ROUT-004 @P0 @routing
  Scenario: Preflight tool failure is ErrPreflightProbe
    Given iptables probe error
    When preflight runs
    Then the error is ErrPreflightProbe

  @BTKN-ROUT-005 @P0 @routing
  Scenario: Fail-open incomplete when leftover hooks remain
    Given detach failure and leftover PREROUTING jumps
    When FailOpen runs
    Then ErrCleanupIncomplete is returned

  @BTKN-ROUT-006 @P0 @routing
  Scenario: Partial apply rolls back owned hooks
    Given an injected mutation failure
    When Apply runs
    Then applied is false and Remove ran

  @BTKN-ROUT-007 @P0 @routing
  Scenario: Reconcile from clean desired system Applies after absent Remove
    Given no BTKN state and a valid expected Xray listener
    When Reconcile desired true
    Then it does not stop on ErrCleanupIncomplete and Apply succeeds

  @BTKN-ROUT-008 @P0 @routing
  Scenario: Reconcile removes stale leftover BTKN then Applies
    Given leftover jumps mark and table
    When Reconcile desired true
    Then stale objects are removed and Apply runs

  @BTKN-ROUT-031 @P0 @failure @routing
  Scenario: Removing an already absent owned rule is idempotent
    Given CombinedOutput "iptables: Bad rule (does a matching rule exist in that chain?)."
    And err "exit status 1"
    When cleanup classifies the result
    Then it is treated as absent
    And Permission denied plus exit status 1 is ErrCleanupIncomplete
    And double Remove on a clean system returns nil
