// Browser stub for node-rsa
// This module is Node.js only - use WebCrypto for browser RSA operations

class NodeRSA {
  constructor() {
    throw new Error("node-rsa is not available in browser - use WebCrypto instead");
  }
}

export default NodeRSA;
