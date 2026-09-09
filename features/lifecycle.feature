Feature: Service lifecycle
  Supervisor and init must fail closed without live routing mutations.

  @BTKN-LIFE-001 @P0 @lifecycle
  Scenario: Supervisor transitions are explicit
    Given supervisor states
    When illegal transitions are requested
    Then they are rejected

  @BTKN-LIFE-002 @P0 @lifecycle
  Scenario: Reconcile without xray requests desired-absent
    Given missing or dead xray
    When platform Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-003 @P0 @lifecycle
  Scenario: Network not ready keeps capture desired-absent
    Given platform network not ready
    When Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-004 @P0 @lifecycle
  Scenario: Missing Xray keeps capture desired-absent
    Given no xray binary
    When Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-005 @P0 @lifecycle
  Scenario: Network wait is bounded
    Given network never ready
    When WaitNetworkReady runs
    Then it times out without hanging

  @BTKN-LIFE-006 @P0 @lifecycle
  Scenario: Healthy running does not capture OUTPUT
    Given ready xray
    When Reconcile desired-present is evaluated
    Then OUTPUT is not captured and iptables is not called from this path

  @BTKN-LIFE-007 @P0 @lifecycle
  Scenario: Corrupt config keeps capture desired-absent
    Given a corrupt xray config
    When Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-008 @P0 @lifecycle
  Scenario: Xray backoff keeps capture desired-absent
    Given xray restart backoff
    When Reconcile runs
    Then capture is not applied

  @BTKN-LIFE-009 @P0 @lifecycle
  Scenario: netfilter-reconcile CLI drives Hybrid Reconcile
    Given blacktempled netfilter-reconcile
    When the manager CLI runs
    Then HybridIptablesEngine.Reconcile is invoked
    And the daemon does not stop XKeen

  @BTKN-LIFE-010 @P0 @lifecycle
  Scenario: netfilter-reconcile stop removes owned BTKN
    Given stop argv
    When netfilter-reconcile stop runs
    Then desired capture is absent and RemoveOwned runs

  @BTKN-LIFE-011 @P0 @lifecycle
  Scenario: NDM hook delegates reconcile to the manager only
    Given packaging/keenetic/netfilter.d/blacktemple-kn.sh
    Then it execs blacktempled netfilter-reconcile
    And it contains no iptables ip rule ip route or XKeen commands

  @BTKN-LIFE-012 @P0 @lifecycle
  Scenario: Package stop and uninstall clean BTKN before the manager disappears
    Given S99 stop and packaging/control/prerm
    Then netfilter-reconcile stop runs while blacktempled is still executable

  @BTKN-LIFE-013 @P0 @lifecycle
  Scenario: Manager restart removes owned capture then reconciles fresh
    Given blacktempled restart
    Then RemoveOwned runs before a new Apply
    And duplicate BTKN jumps are not installed

  @BTKN-LIFE-014 @P0 @lifecycle
  Scenario: OUR Xray death fail-opens capture
    Given BTKN capture active
    When OUR Xray is stopped through the manager CLI
    Then desired capture is absent and the selected client returns DIRECT
