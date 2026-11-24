# Third-party notices

**CMMC Level 2 requirement text and NIST SP 800-171A assessment objectives** are U.S. Government works
(DoD CIO *CMMC Assessment Guide – Level 2* v2.13; NIST SP 800-171 Rev. 2 and SP 800-171A) and are not
subject to copyright in the United States.

The machine-readable extraction of that text used by `backend/tools/build_cmmc_catalog.py` was taken from
**nealfennimore/cmmc at tag 1.0.0**, released under the MIT License:

> MIT License — Copyright (c) 2024 Neal Fennimore. Permission is hereby granted, free of charge, to any person
> obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software
> without restriction... THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

Later releases of that project are under the Elastic License 2.0 and are **not** used. No code from that project
is included. Scoring point values were transcribed independently from 32 CFR 170.24 (eCFR) and only
cross-checked against that project's data.

Runtime dependencies (FastAPI, SQLAlchemy, Alembic, MCP Python SDK, pypdf, python-docx, openpyxl, psycopg) are
used under their own licenses; CI produces a CycloneDX SBOM.
