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
