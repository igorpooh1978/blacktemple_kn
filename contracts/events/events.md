# Internal events (documentation freeze)

These are in-process events, not a message broker.

| Event | Payload |
| --- | --- |
| connection.changed | state |
| xray.state | supervisor state |
| profile.activated | profile id (not secret) |
| geodata.updated | version |
| list.updated | list id |
| policy.applied | key names only |
| manager.restart.requested | reason |
