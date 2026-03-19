# NIST 800-53 CM-2: BASELINE CONFIGURATION TESTS
# Purpose: Unit tests for 05-require-resource-limits.rego
# Usage: opa test GP-Copilot/opa-package/ -v

package main

# 1. TEST: Missing CPU limits is DENIED
test_deny_missing_cpu_limits {
  msg := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "test-app"},
    "spec": {"template": {"spec": {"containers": [
      {
        "name": "test-container",
        "resources": {"limits": {"memory": "256Mi"}}
      }
    ]}}}
  }
  count(msg) == 1
  contains(msg[_], "must have CPU limits defined")
}

# 2. TEST: Missing Memory limits is DENIED
test_deny_missing_memory_limits {
  msg := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "test-app"},
    "spec": {"template": {"spec": {"containers": [
      {
        "name": "test-container",
        "resources": {"limits": {"cpu": "100m"}}
      }
    ]}}}
  }
  count(msg) == 1
  contains(msg[_], "must have memory limits defined")
}

# 3. TEST: Fully compliant pod is ALLOWED
test_allow_compliant_limits {
  msg := deny with input as {
    "kind": "Deployment",
    "metadata": {"name": "test-app"},
    "spec": {"template": {"spec": {"containers": [
      {
        "name": "test-container",
        "resources": {
          "limits": {"cpu": "100m", "memory": "256Mi"},
          "requests": {"cpu": "10m", "memory": "128Mi"}
        }
      }
    ]}}}
  }
  count(msg) == 0
}

# 4. TEST: Missing CPU requests triggers WARNING
test_warn_missing_cpu_requests {
  msg := warn with input as {
    "kind": "Deployment",
    "metadata": {"name": "test-app"},
    "spec": {"template": {"spec": {"containers": [
      {
        "name": "test-container",
        "resources": {
          "limits": {"cpu": "100m", "memory": "256Mi"}
        }
      }
    ]}}}
  }
  count(msg) == 1
  contains(msg[_], "should have CPU requests defined")
}
