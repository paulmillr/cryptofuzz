#!/usr/bin/env bash

# Native dependency lock file for the supported build in build.sh.
# Update revisions deliberately, then run the full adapter and fuzz smoke tests.

readonly LIBRESSL_VERSION="v4.3.2"
readonly LIBRESSL_REVISION="05fc4bad4ea5211549cc8289e56b39f44022129f"
readonly LIBRESSL_OPENBSD_REVISION="cbcdd558e87dfc1c24eb6a47c1fb660d41c2a56f"

readonly CRYPTOPP_REVISION="782425901d36fe0944b16aae37801b8ec2fa9000"
readonly BLST_REVISION="de54cd4684a3adba193a6c50ca5861c8c32c3b8a"

readonly QUICKJS_REVISION="04be246001599f5995fa2f2d8c91a0f198d3f34c"

readonly MPDECIMAL_VERSION="4.0.1"
readonly MPDECIMAL_SHA256="96d33abb4bb0070c7be0fed4246cd38416188325f820468214471938545b1ac8"
