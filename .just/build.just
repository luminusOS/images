set dotenv-load := true

import 'common.just'

default: workstation

[private]
[no-cd]
_core-stamp:
    python3 tools/core-stamp.py "$IMAGES_BASE" "$IMAGES_FEDORA" "$IMAGES_TAG" "$IMAGES_VERSION" "$IMAGES_NAME" "$IMAGES_PRETTY"

[no-cd]
core:
    python3 tools/build-images.py core

[no-cd]
workstation:
    python3 tools/build-images.py workstation

[no-cd]
workstation-iso:
    python3 tools/build-images.py workstation-iso
