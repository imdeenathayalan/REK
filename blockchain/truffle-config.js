require('dotenv').config({ path: __dirname + '/.env' });
const HDWalletProvider = require('@truffle/hdwallet-provider');

module.exports = {
  networks: {

    development: {
      host: "127.0.0.1",
      port: 7545,
      network_id: "*"
    },

    sepolia: {
      provider: () => {
        return new HDWalletProvider({
          privateKeys: [process.env.DEPLOYER_KEY],
          providerOrUrl: process.env.SEPOLIA_RPC,
          pollingInterval: 15000,
          chainId: 11155111
        });
      },
      network_id: 11155111,
      confirmations: 1,
      timeoutBlocks: 1000,
      skipDryRun: true,
      gas: 5000000,
    }

  },

  compilers: {
    solc: {
      version: "0.8.21",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  }
};

