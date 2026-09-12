Feature: R6-I UDP TPROXY via full iproute2
  BusyBox ip cannot install table 4254. Entware ip-full can.
  TCP REDIRECT must keep working without policy routing.

  @BTKN-R6I-UDP-001 @P0 @routing
  Scenario: Full iproute2 is selected instead of BusyBox ip
    Given PATH ip is BusyBox
    And /opt/libexec/ip-full is capable of table 4254
    When ResolveIPRoute2 runs
    Then the selected binary is /opt/libexec/ip-full
    And BusyBox is not used for BTKN policy routing

  @BTKN-R6I-UDP-002 @P0 @routing
  Scenario: BTKN fwmark installs into table 4254 with full iproute2
    Given full iproute2 is selected
    When Apply runs
    Then ip rule fwmark 0x42544b4e lookup 4254 is installed
    And local default dev lo table 4254 is installed
    And XKeen mark 0x111 is not deleted

  @BTKN-R6I-UDP-003 @P0 @routing
  Scenario: Missing full iproute2 fails UDP routing explicitly
    Given only BusyBox ip is available
    When Apply runs
    Then TCP REDIRECT 11820 is installed
    And UDP TPROXY and table 4254 commands are absent
    And Preflight reports IPROUTE2_FULL_REQUIRED

  @BTKN-R6I-UDP-004 @P0 @routing
  Scenario: Missing addrtype uses deterministic exclusion fallback
    Given ADDRTYPE_SUPPORTED is false
    When Plan is generated
    Then addrtype rules are absent
    And btkn_exclude_v4 still contains RFC1918 prefixes
    And TCP REDIRECT 11820 remains

  @BTKN-R6I-UDP-005 @P0 @routing
  Scenario: XKeen table 111 and mark 0x111 are never changed
    Given live XKeen on mark 0x111 table 111
    When BTKN Apply or Remove runs
    Then no command deletes 0x111 or table 111

  @BTKN-R6I-UDP-006 @P0 @routing
  Scenario: UDP TPROXY selected-client traffic reaches OUR Xray
    Given full iproute2 and policy routing
    When hybrid Plan is built
    Then mangle TPROXY redirects UDP to 11820 with mark 0x42544b4e
    And hardware LIVE evidence is recorded separately

  @BTKN-R6I-UDP-007 @P0 @routing
  Scenario: Foreign mangle rewrite does not leave UDP capture detached
    Given NAT BTKN TCP REDIRECT still present
    And mangle PREROUTING has been rewritten to xkeen-only
    When Reconcile desired true runs
    Then mangle BTKN_PRE is inserted at PREROUTING head
    And UDP TPROXY 11820 with mark 0x42544b4e is installed
    And XKeen mark 0x111 is not deleted

  @BTKN-R6I-UDP-008 @P0 @lifecycle
  Scenario: NDM hook re-applies after XKeen proxy.sh
    Given packaging/keenetic/netfilter.d
    Then zz-blacktemple-kn.sh sorts after proxy.sh
    And the primary hook exports BTKN_IPROUTE2 when ip-full exists
    And neither hook runs iptables directly
