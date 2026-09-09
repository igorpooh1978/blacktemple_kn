Feature: Packaging
  IPK must stay MIPSLE softfloat without kernel modules or XKeen dependency.

  @BTKN-PKG-001 @P0 @packaging
  Scenario: Control Depends stay userland only
    Given packaging/control/control
    Then Depends are ip-full, iptables, ipset
    And ca-bundle is absent
    And NDM hook is not listed as an IPK payload in this wave
