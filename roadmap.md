## Milestone 1: Foundation
- [x] Read audit records from the kernel via netlink socket
- [x] Parse raw audit record lines into semi-structured data
- [x] Correlate related records into events
- [x] Daemonize the process and manage its lifecycle
- [x] Basic CLI for starting/stopping the daemon and viewing logs
- [ ] Define readable JSON schema for outputted events
- [ ] Write events to log files in JSON and legacy formats

## Milestone 2: Configuration, Rotation & Rule Management
- [x] Implement configuration system for process settings and log policies
- [x] Implement log rotation mechanism for file size and retention management
- [x] Allow users to read, write, and list audit rules through CLI
- [-] Support audit rules defined from rules files for compatibility
- [-] Create installation script for auditd replacement and permissions setup

--- At this point, we should be near feature parity with auditd ---

## Milestone 3: Performance and Compatibility
- [ ] Comprehensive testing suite for comparing with legacy tools
    - [ ] Output similarity and correctness validation
    - [ ] Performance benchmarks against auditd
- [ ] Achieve satisfactory performance and compatibility scores
- Note: General testing should occur throughout development. This milestone focuses on legacy tool comparison.

## Milestone 4: Filtering & Enrichment
- [ ] Implement basic filtering system for event logging criteria
- [ ] Enhance data enrichment capabilities
- [ ] Build ausearch replacement using filtering system
- [ ] Build aureport replacement

--- This should achieve feature parity with most of the legacy toolset ---

## Milestone 5: Stretch Goals
- [ ] Create user-friendly wrapper for audit rule management
- [ ] Refine filtering system and provide comprehensive documentation
- [ ] Integration with popular audit tooling frameworks (SIEM, log aggregators)