# Dependency Graph — API Key Leakage Scanner

This file contains a visual dependency graph (Mermaid) of the main Python modules in the project. Open this file in VS Code and use Markdown preview to render the diagram.

```mermaid
flowchart TD
    subgraph App
        M[main.py]
        LR[scanner/report_generator.py]
        FF[scanner/file_finder.py]
        LS[scanner/live_scanner.py]
        SS[scanner/secret_scanner.py]
        RP[scanner/regex_patterns.py]
    end

    subgraph Core
        A[core/analyzer.py]
        D[detectors/jwt_detectors.py]
        V[validators/jwt_validators.py]
        E[scoring/entropy.py]
        C[scoring/context.py]
        F[filters/vendor_filter.py]
    end

    %% Main entry
    M -->|uses| LS
    M -->|uses| FF
    M -->|uses| SS
    M -->|writes reports to| LR

    %% Scanner internals
    LS -->|calls| SS
    SS -->|reads patterns from| RP
    SS -->|calls| A

    %% Analyzer internals
    A -->|uses| D
    A -->|uses| V
    A -->|uses| E
    A -->|uses| C
    A -->|uses| F

    %% Output
    LR -->|outputs| Reports[(reports/scan_report.html \n reports/scan_report.json)]

    style M fill:#fef3c7,stroke:#b58900
    style SS fill:#e6f7ff,stroke:#2b7a78
    style A fill:#fff0f6,stroke:#b30059
```

Plain-text adjacency (for quick copy):
- `main.py` -> `scanner/live_scanner.py`, `scanner/file_finder.py`, `scanner/secret_scanner.py`, `scanner/report_generator.py`
- `scanner/live_scanner.py` -> `scanner/secret_scanner.py`
- `scanner/secret_scanner.py` -> `scanner/regex_patterns.py`, `core/analyzer.py`, `filters/vendor_filter.py`
- `core/analyzer.py` -> `detectors/jwt_detectors.py`, `validators/jwt_validators.py`, `scoring/entropy.py`, `scoring/context.py`, `filters/vendor_filter.py`

Rendering tips:
- In VS Code: open `dependency_graph.md` and press `Ctrl+Shift+V` or use the Markdown preview to render the Mermaid diagram.
- Alternative: convert Mermaid to PNG/SVG with Mermaid CLI if installed.

If you want, I can also generate a DOT file or render a PNG here (if you want me to install tools and run rendering).