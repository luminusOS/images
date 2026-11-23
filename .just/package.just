set dotenv-load := true
set positional-arguments := true

import 'common.just'

default: workstation

workstation format="all": (_workstation format)

[no-cd]
_workstation format:
    python3 tools/package-workstation.py "$1"
