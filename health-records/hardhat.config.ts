import hardhatToolboxMochaEthersPlugin from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import { configVariable, defineConfig } from "hardhat/config";

// One exact compiler version everywhere (contracts use `pragma solidity 0.8.37;`).
const SOLC_VERSION = "0.8.37";
// Optional: path to a pre-downloaded solc binary of that exact version, for offline or
// firewalled machines. Leave unset and Hardhat downloads (and verifies) the compiler itself.
const SOLC_PATH = process.env.SOLC_PATH || undefined;

export default defineConfig({
  plugins: [hardhatToolboxMochaEthersPlugin],
  solidity: {
    profiles: {
      default: {
        version: SOLC_VERSION,
        path: SOLC_PATH,
      },
      production: {
        version: SOLC_VERSION,
        path: SOLC_PATH,
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
  networks: {
    // Local development chain simulated in-process by Hardhat.
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
    },
    // Final demo network. Values come from environment variables or the Hardhat
    // keystore (`npx hardhat keystore set SEPOLIA_PRIVATE_KEY`) and are never committed.
    sepolia: {
      type: "http",
      chainType: "l1",
      url: configVariable("SEPOLIA_RPC_URL"),
      accounts: [configVariable("SEPOLIA_PRIVATE_KEY")],
    },
  },
});
