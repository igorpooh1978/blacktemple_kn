Feature: Hardware tooling
  The KN-1011 probe is diagnostic infrastructure: single-instance, bounded, self-terminating.

  @BTKN-TOOL-001 @P0 @hardware
  Scenario: Probe script is read-only for routing and packages
    Given scripts/router-probe.sh
    Then it must not contain iptables mutation or opkg install

  @BTKN-TOOL-011 @P0 @hardware
  Scenario: SSH cat upload completes after receiving EOF
    Given Copy-ScriptViaSshCat
    When stdin bytes are written
    Then EndWrite flush and close happen so remote cat sees EOF
    And unread stdout/stderr pipes are not used
    And timeout kills the ssh process tree

  @BTKN-TOOL-012 @P0 @hardware @failure
  Scenario: Only one router capability probe may run at a time
    Given a first probe holds the lock
    When a second probe starts
    Then it exits immediately with ALREADY_RUNNING
    And no second diagnostic workload starts
    And this is proven by executable shell acceptance on Linux /proc

  @BTKN-TOOL-013 @P0 @failure
  Scenario: A stale probe lock does not permanently block diagnostics
    Given a lock whose owning process no longer exists
    When a new probe starts
    Then stale ownership metadata is removed
    And the new probe starts
    And a reused PID of a foreign process is not killed

  @BTKN-TOOL-014 @P0 @failure
  Scenario: Router probe exceeding its maximum runtime is terminated safely
    Given a probe past its hard deadline
    When the watchdog fires
    Then owned descendants are TERM then KILL
    And lock metadata is removed
    And the status is TIMEOUT
    And no owned sh sed awk grep remain

  @BTKN-TOOL-015 @P0 @failure
  Scenario: Probe failure cannot leave a CPU consuming process storm
    Given an isolated child that would not exit
    When the hard timeout fires
    Then the owned tree is gone
    And the lock is removed
    And a subsequent probe can run

  @BTKN-TOOL-016 @P0 @hardware
  Scenario: Probe redaction is one-pass and does not treat arbitrary hex as IPv6
    Given redactor fixtures
    Then public IPv4 is redacted
    And private IPv4 may remain
    And global IPv6 is redacted
    And timestamps SHA and iptables tokens are preserved
    And the probe must not spawn sed plus two awk per command

  @BTKN-TOOL-017 @P0 @hardware
  Scenario: Probe self-cleanup never kills Xray XKeen or arbitrary awk
    Given cleanup of an owned probe tree
    Then xray xkeen ndnproxy nginx are never kill targets
    And killall awk or pkill sh is forbidden
    And a foreign process whose cmdline only resembles the probe script survives
    And this is proven by executable shell acceptance on Linux /proc
