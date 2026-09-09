Feature: Packaging
  IPK must stay MIPSLE softfloat without kernel modules or XKeen dependency.

  @BTKN-PKG-001 @P0 @packaging
  Scenario: Control Depends stay userland only
    Given packaging/control/control
    Then Depends are ip-full, iptables, ipset
    And ca-bundle is absent
    And NDM hook is staged in the IPK payload

  @BTKN-PKG-002 @P0 @packaging
  Scenario: Control records mipsel softfloat without ko or Node
    Given packaging/control/control
    Then Architecture is mipsel-3.4_kn
    And the description records softfloat
    And .ko and Node runtime are absent

  @BTKN-PKG-003 @P0 @packaging
  Scenario: IPK stages the NDM netfilter hook
    Given build.ps1 and packaging/keenetic
    Then the hook is copied to /opt/etc/ndm/netfilter.d/blacktemple-kn.sh

  @BTKN-PKG-004 @P0 @packaging
  Scenario: Entware opkg accepts gzip-tar IPK
    Given tools/ipkpack
    Then the outer package is gzip ustar with ./debian-binary ./data.tar.gz ./control.tar.gz
    And it is not a raw ar archive

  @BTKN-PKG-005 @P0 @packaging
  Scenario: Control stanza keeps Architecture in the first paragraph
    Given packaging/control/control
    Then the first Debian control paragraph includes Architecture
    And it has no blank or whitespace-only lines before Architecture

  @BTKN-PKG-006 @P0 @packaging
  Scenario: Control maintainer scripts are LF-only
    Given tools/ipkpack
    Then packed shebang scripts do not contain CR
