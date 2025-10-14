# Project Structure

## Directory Organization

```
packet-tracer/
├── .git/                    # Git version control
├── .kiro/                   # Kiro AI assistant configuration
│   ├── specs/               # Feature specifications
│   │   └── packet-tracer/   # Project requirements and design docs
│   └── steering/            # AI assistant guidance rules
├── .vscode/                 # VSCode editor settings
├── src/                     # Source code files
├── include/                 # Header files (if using C/C++)
├── tests/                   # Test files and test scripts
├── docs/                    # Documentation
├── Makefile                 # Build configuration
└── README.md               # Project overview and usage
```

## File Naming Conventions
- Source files: `packet-tracer.c` (main program)
- Header files: `packet-tracer.h`, `network-utils.h`
- Test files: `test_*.c` or `*_test.c`
- Documentation: Use lowercase with hyphens

## Code Organization
- **Main Program**: Single executable `packet-tracer`
- **Modular Design**: Separate functions for:
  - Command-line argument parsing
  - Network interface validation
  - IP address validation
  - Packet capture logic
  - Packet analysis and display
  - Signal handling
  - Resource cleanup

## Specifications Location
- Requirements and design documents in `.kiro/specs/packet-tracer/`
- Use specs for feature planning and implementation tracking

## Development Workflow
1. Update requirements in `.kiro/specs/` first
2. Implement in `src/` directory
3. Test functionality before committing
4. Update documentation as needed

## Key Files
- **Main executable**: `src/packet-tracer.c`
- **Build file**: `Makefile`
- **Documentation**: `README.md`
- **Requirements**: `.kiro/specs/packet-tracer/requirements.md`