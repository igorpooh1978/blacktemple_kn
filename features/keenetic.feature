Feature: Bare Keenetic bootstrap
  Detect/Prepare/Verify must not mutate routing and must reject unsafe module paths.

  @BTKN-KEEN-001 @P0 @keenetic
  Scenario: Hybrid ready does not require XKeen
    Given userland tools and iptables targets
    When Detect runs without XKeen
    Then engine is HYBRID_READY

  @BTKN-KEEN-002 @P0 @keenetic
  Scenario: Prepare does not apply capture rules
    Given HYBRID_READY
    When Prepare runs
    Then no iptables or ip rule add commands are issued

  @BTKN-KEEN-003 @P0 @keenetic
  Scenario: Module path root boundary rejects prefix siblings
    Given candidate paths
    Then /lib/modules/4.9-ndm-5/xt_TPROXY.ko is allowed
    And /lib/modules-evil/xt_TPROXY.ko is rejected
    And /tmp/xt_TPROXY.ko is rejected
    And /opt/lib/modules/../../tmp/xt_TPROXY.ko is rejected
    And a symlink to /tmp/evil.ko is rejected
    And a non-regular file is rejected
    And a wrong module basename is rejected

  @BTKN-KEEN-004 @P0 @keenetic
  Scenario: Prepare without modprobe fails without insmod guess
    Given HYBRID_PREPARE_REQUIRED and no modprobe
    When Prepare runs
    Then INSMOD PREPARE DEPENDENCY_ORDER_UNVERIFIED
    And no routing sysctl opkg or rmmod commands run

  @BTKN-KEEN-005 @P0 @keenetic
  Scenario: XKeen presence does not imply hybrid capability
    Given XKeen installed without TPROXY
    When Detect runs
    Then the engine is not HYBRID_READY

  @BTKN-KEEN-006 @P0 @keenetic
  Scenario: TUN device is TUN_CANDIDATE not ready
    Given /dev/net/tun without hybrid targets
    When Detect runs
    Then engine is TUN_CANDIDATE

  @BTKN-KEEN-007 @P0 @keenetic
  Scenario: Required packages come from routing requirements
    Given HybridRequirements
    Then userland tools include ip iptables ipset

  @BTKN-KEEN-008 @P0 @keenetic
  Scenario: Missing loaded TPROXY with module file is HYBRID_PREPARE_REQUIRED
    Given xt_TPROXY.ko on disk and TPROXY absent from targets
    When Detect runs
    Then engine is HYBRID_PREPARE_REQUIRED

  @BTKN-KEEN-009 @P0 @keenetic
  Scenario: Absent tools and TUN is NO_USABLE_ENGINE
    Given an empty runner
    When Detect runs
    Then engine is NO_USABLE_ENGINE

  @BTKN-KEEN-010 @P0 @keenetic
  Scenario: Successful Prepare never changes sysctl or packages
    Given HYBRID_READY
    When Prepare runs
    Then sysctl opkg install and insmod are not issued
