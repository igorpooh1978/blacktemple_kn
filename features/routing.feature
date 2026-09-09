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

  @BTKN-ROUT-009 @P0 @routing
  Scenario: Capture is selected-client only
    Given a hybrid plan
    Then unmarked foreign clients are not captured

  @BTKN-ROUT-010 @P0 @routing
  Scenario: Private and local destinations stay DIRECT
    Given a hybrid plan
    Then RFC1918 and local CIDRs are excluded from capture

  @BTKN-ROUT-011 @P0 @routing
  Scenario: TCP path uses REDIRECT to 11820
    Given a hybrid plan
    Then nat PREROUTING REDIRECT targets 11820

  @BTKN-ROUT-012 @P0 @routing
  Scenario: XKeen detected allows Plan and refuses Apply
    Given XKeen coexistence evidence
    When Plan and Apply run
    Then Plan succeeds and Apply is rejected

  @BTKN-ROUT-013 @P0 @routing
  Scenario: Mark and table collisions fail preflight
    Given a foreign fwmark or table 4254
    When Preflight runs
    Then Apply is refused without auto-picking another mark

  @BTKN-ROUT-014 @P0 @routing
  Scenario: No OUTPUT capture of Xray outbound
    Given a hybrid plan
    Then OUTPUT is not used to recapture proxy traffic

  @BTKN-ROUT-015 @P0 @routing
  Scenario: No foreign or global flush
    Given Apply and Remove
    Then iptables -F of foreign chains is forbidden

  @BTKN-ROUT-016 @P0 @routing
  Scenario: IPv6 capture remains untouched
    Given a hybrid plan
    Then ip6tables capture is not installed

  @BTKN-ROUT-017 @P0 @routing
  Scenario: Partial Apply joins cleanup errors
    Given Apply failure plus Remove failure
    Then both errors are reported
