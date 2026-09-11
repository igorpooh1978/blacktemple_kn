Feature: R6-I live selected-client routing
  Live KN-1011 acceptance. Unit tests prove invariants. Hardware PASS is
  recorded separately and must not be faked.

  @BTKN-R6I-LIVE-001 @P0 @routing
  Scenario: Selected client TCP is captured by BTKN only
    Given capture.enabled is true
    And one selected LAN client
    When hybrid Apply runs beside live XKeen
    Then BTKN PREROUTING is inserted first
    And only that client is redirected to 11820

  @BTKN-R6I-LIVE-002 @P0 @routing
  Scenario: Non-selected clients are not captured
    Given a selected-client ipset
    Then sources outside btkn_clients_v4 RETURN
    And whole-LAN CIDR capture is absent

  @BTKN-R6I-LIVE-003 @P0 @routing
  Scenario: Router-local traffic is never captured
    Given a hybrid plan
    Then OUTPUT is not used
    And BTKN_OUT is not attached

  @BTKN-R6I-LIVE-004 @P0 @routing
  Scenario: XKeen mark table ports and PID remain untouched
    Given live XKeen on 1181 mark 0x111 table 111
    When BTKN Apply runs
    Then XKeen objects are not deleted or rewritten

  @BTKN-R6I-LIVE-005 @P0 @routing
  Scenario: Disable removes only BTKN capture state
    Given installed BTKN hooks beside XKeen
    When capture.enabled is false and Remove runs
    Then BTKN jumps mark table and ipsets are gone
    And XKeen remains

  @BTKN-R6I-LIVE-006 @P0 @routing
  Scenario: Partial Apply invokes BTKN-only cleanup
    Given an injected mutation failure during Apply
    Then applied is false and Remove ran
    And XKeen is not mutated

  @BTKN-R6I-LIVE-007 @P0 @routing
  Scenario: OUR Xray failure cannot mutate XKeen
    Given OUR Xray stop or Apply rollback
    Then /opt/sbin/xray is not killed
    And mark 0x111 table 111 and port 1181 are not modified

  @BTKN-R6I-LIVE-008 @P0 @routing
  Scenario: capture.enabled=false is final post-acceptance state
    Given live acceptance has finished
    Then capture.enabled is persisted false
    And netfilter-reconcile desired is absent
