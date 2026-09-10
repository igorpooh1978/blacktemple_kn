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

  @BTKN-LIFE-015 @P0 @lifecycle
  Scenario: HTTP UI binds the LAN DHCP address not loopback or WAN
    Given S99blacktemple-kn and auto-lan
    Then the manager listens on br0 RFC1918
    And it does not bind 0.0.0.0 or WAN
    And loopback is only the fallback when no LAN bridge IP exists

  @BTKN-LIFE-016 @P0 @lifecycle
  Scenario: Reconcile desired-absent reports reason and removes BTKN
    Given netfilter-reconcile with desired false
    Then stderr includes origin decision reason desired client our_xray_alive action=remove
    And Hybrid Reconcile is invoked with desired false

  @BTKN-LIFE-017 @P0 @lifecycle
  Scenario: Reconcile desired-present reports reason and attempts Apply
    Given netfilter-reconcile with desired true
    Then stderr includes origin decision reason desired client our_xray_alive action=apply
    And Hybrid Reconcile is invoked with desired true

  @BTKN-LIFE-018 @P0 @lifecycle
  Scenario: Manual and NDM reconcile share one exclusive lock
    Given netfilter-reconcile lock path
    Then the lock is under run/netfilter-reconcile.lock
    And only one exclusive holder is taken per invocation

  @BTKN-LIFE-019 @P0 @lifecycle
  Scenario: Reconcile origin is observable as manual or ndm
    Given BTKN_NDM_HOOK
    Then NDM hook exports BTKN_NDM_HOOK=1 before exec
    And CLI origin is ndm when the env is set otherwise manual

  @BTKN-LIFE-020 @P0 @lifecycle
  Scenario: Independent rescue watchdog recovers after smoke death
    Given scripts/btkn-rescue.sh
    Then arm starts a watch that recovers unless disarmed before deadline

  @BTKN-LIFE-021 @P0 @lifecycle
  Scenario: Rescue cleanup touches only the BTKN namespace
    Given rescue recover
    Then only BTKN_ chains btkn_ sets mark 0x42544b4e table 4254 and OUR Xray are mutated

  @BTKN-LIFE-022 @P0 @lifecycle
  Scenario: Rescue never kills or deletes foreign XKeen objects
    Given rescue recover
    Then it does not killall pkill iptables -F ip flush rmmod or delete xkeen chains

  @BTKN-LIFE-023 @P0 @lifecycle
  Scenario: XKeen restore uses bounded polling not a single sleep
    Given restore-xkeen
    Then it polls until TCP and UDP 1181 or a bounded deadline

  @BTKN-LIFE-024 @P0 @lifecycle
  Scenario: Hardware smoke refuses mutation unless rescue is armed
    Given router-smoke-app.sh
    Then stop-xkeen and apply require an armed rescue watchdog

  @BTKN-LIFE-025 @P0 @lifecycle
  Scenario: Smoke does not capture the controller SSH client by default
    Given resolve-client
    Then SSH_CONNECTION is not used as the capture client
    And the SSH source address is refused unless BTKN_ALLOW_CONTROLLER_CLIENT=1

  @BTKN-LIFE-026 @P0 @lifecycle
  Scenario: Fresh install defaults capture.enabled false
    Given no persisted capture config
    When the manager ensures the canonical config
    Then capture.enabled is false

  @BTKN-LIFE-027 @P0 @lifecycle
  Scenario: Missing capture setting is interpreted as false
    Given a config file without capture.enabled
    When Reconcile loads the master switch
    Then capture is disabled

  @BTKN-LIFE-028 @P0 @lifecycle
  Scenario: Disabled capture never Applies while OUR Xray is running
    Given capture.enabled is false
    And OUR Xray is alive
    When netfilter-reconcile runs
    Then Hybrid Reconcile is invoked with desired false

  @BTKN-LIFE-029 @P0 @lifecycle
  Scenario: Disabled capture never Applies with a selected client
    Given capture.enabled is false
    And selected-client is present
    When netfilter-reconcile runs
    Then Hybrid Reconcile is invoked with desired false

  @BTKN-LIFE-030 @P0 @lifecycle
  Scenario: NDM hook with capture disabled never Applies
    Given BTKN_NDM_HOOK=1
    And capture.enabled is false
    When netfilter-reconcile runs
    Then origin is ndm and action is remove

  @BTKN-LIFE-031 @P0 @lifecycle
  Scenario: Manager restart with capture disabled never Applies
    Given capture.enabled is false
    When netfilter-reconcile runs after manager restart
    Then Hybrid Reconcile is invoked with desired false

  @BTKN-LIFE-032 @P0 @lifecycle
  Scenario: Disabled capture may Remove stale BTKN-owned state
    Given capture.enabled is false
    And leftover BTKN chains exist
    When Reconcile runs
    Then action is remove-owned-only

  @BTKN-LIFE-033 @P0 @lifecycle
  Scenario: Disabled Remove never touches the XKeen namespace
    Given capture.enabled is false
    When RemoveOwned runs
    Then XKeen chains mark 0x111 table 111 and port 1181 are not mutated

  @BTKN-LIFE-034 @P0 @lifecycle
  Scenario: Production BlackTemple never stops XKeen
    Given src/cmd packaging/init and packaging/keenetic
    Then they do not stop S05xkeen or kill /opt/sbin/xray

  @BTKN-LIFE-035 @P0 @lifecycle
  Scenario: Corrupt capture config fails closed to disabled
    Given invalid capture.enabled JSON
    When the master switch is loaded
    Then capture.enabled is false

  @BTKN-LIFE-036 @P0 @lifecycle
  Scenario: Environment variables cannot silently enable capture
    Given BTKN_CAPTURE_ENABLED or similar env is set
    When production Reconcile runs
    Then capture remains disabled unless the persisted JSON boolean is true

  @BTKN-LIFE-037 @P0 @lifecycle
  Scenario: Safe coexistence allows Web UI and OUR Xray without netfilter Apply
    Given capture.enabled is false
    Then auto-lan Web UI may bind the LAN bridge
    And OUR Xray may be running
    And netfilter-reconcile does not Apply

  @BTKN-LIFE-038 @P0 @lifecycle
  Scenario: Production-router mutation smoke requires an explicit network-loss ACK
    Given router-smoke.ps1 and router-smoke-app.sh
    Then live mutation requires BTKN_ALLOW_ROUTING_MUTATION BTKN_ALLOW_XKEEN_STOP and BTKN_PRODUCTION_ROUTER_MUTATION_ACK
    And the harness does not hardcode those values

  @BTKN-LIFE-039 @P0 @lifecycle
  Scenario: Exclusive reconcile lock failure prevents all netfilter mutation
    Given netfilter-reconcile cannot acquire run/netfilter-reconcile.lock
    Then stderr reports reason=lock-failed result=failure
    And Hybrid Reconcile is not invoked
    And neither Apply nor Remove run

  @BTKN-LIFE-040 @P0 @lifecycle
  Scenario: Stale rescue watcher cannot recover a newer run
    Given watcher A is armed
    And a newer run B arms
    Then watcher A must not recover

  @BTKN-LIFE-041 @P0 @lifecycle
  Scenario: Disarm for run B cannot control run A
    Given run A and run B are distinct rescue tokens
    When disarm B is requested
    Then run A remains independently armed

  @BTKN-LIFE-042 @P0 @lifecycle
  Scenario: Only the current armed rescue token may execute recovery
    Given a rescue recover invocation
    Then recover rereads the current token
    And recovery is skipped when the token does not match

  @BTKN-LIFE-043 @P0 @lifecycle
  Scenario: Rescue does not start XKeen when already healthy
    Given /opt/sbin/xray is running
    And TCP and UDP 1181 are listening
    When rescue restore runs
    Then it reports ALREADY_HEALTHY
    And S05xkeen start is not invoked

  @BTKN-LIFE-044 @P0 @lifecycle
  Scenario: Packaged daemon uses an absolute data directory
    Given Entware init S99blacktemple-kn
    When blacktempled starts
    Then ARGS includes -data-dir /opt/blacktemple-kn/data
    And the process does not depend on the working directory for profiles.json
