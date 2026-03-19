# NIST 800-53 SC-7: BOUNDARY PROTECTION TESTS
# Purpose: Unit tests for 03-prohibit-insecure-services.rego
# Usage: opa test GP-Copilot/opa-package/ -v

package main

# 1. TEST: NodePort Service is DENIED
test_deny_nodeport {
  msg := deny with input as {
    "kind": "Service",
    "metadata": {"name": "test-nodeport"},
    "spec": {"type": "NodePort"}
  }
  count(msg) == 1
  contains(msg[_], "prohibited type 'NodePort'")
}

# 2. TEST: Unauthorized LoadBalancer is DENIED
test_deny_loadbalancer_unauthorized {
  msg := deny with input as {
    "kind": "Service",
    "metadata": {"name": "test-lb"},
    "spec": {"type": "LoadBalancer"}
  }
  count(msg) == 1
  contains(msg[_], "without explicit authorization")
}

# 3. TEST: Authorized LoadBalancer is ALLOWED
test_allow_loadbalancer_authorized {
  msg := deny with input as {
    "kind": "Service",
    "metadata": {
      "name": "test-lb-auth",
      "annotations": {"anthra.io/authorized-loadbalancer": "true"}
    },
    "spec": {"type": "LoadBalancer"}
  }
  count(msg) == 0
}

# 4. TEST: Standard ClusterIP is ALLOWED
test_allow_clusterip {
  msg := deny with input as {
    "kind": "Service",
    "metadata": {"name": "test-clusterip"},
    "spec": {"type": "ClusterIP"}
  }
  count(msg) == 0
}

# 5. TEST: Service without selector triggers WARNING
test_warn_no_selector {
  msg := warn with input as {
    "kind": "Service",
    "metadata": {"name": "test-no-selector"},
    "spec": {"type": "ClusterIP"}
  }
  count(msg) == 1
  contains(msg[_], "no selector defined")
}
