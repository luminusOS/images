validate_boot_feature() {
  local feature="${BOOT_TEST_FEATURE:-}" unit="${BOOT_TEST_FEATURE_UNIT:-}" channel="${BOOT_TEST_CHANNEL:-testing}"
  local reserved=" features sysext discovery probe core workstation "
  if ! [[ "${feature}" =~ ^[a-z][a-z0-9]{1,30}$ && "${reserved}" != *" ${feature} "* ]]; then
    echo "Invalid BOOT_TEST_FEATURE: expected a non-reserved feature ID" >&2
    return 1
  fi
  if ! [[ "${unit}" =~ ^luminusos-${feature}-[A-Za-z0-9][A-Za-z0-9_.-]*\.service$ ]]; then
    echo "Invalid BOOT_TEST_FEATURE_UNIT: expected a service named for ${feature}" >&2
    return 1
  fi
  case "${channel}" in
    stable)
      if [ "${feature}" = dummy ]; then
        echo "Stable candidates cannot use dummy" >&2
        return 1
      fi
      ;;
    testing) ;;
    *) echo "Invalid BOOT_TEST_CHANNEL: expected testing or stable" >&2; return 1 ;;
  esac
}
