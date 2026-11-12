import { mountUI } from "./controller.mjs";

export const METEOR_WALLET_ID = "meteor-wallet";
export const METEOR_EXECUTOR_URL = "https://raw.githubusercontent.com/Meteor-Wallet/meteor_wallet_sdk/6369ad789d2f3aaf8e6ccb065021723111027174/storage/meteor-near-connect-latest.js";
export const METEOR_ICON_URL = "https://raw.githubusercontent.com/Meteor-Wallet/meteor_wallet_sdk/main/assets/meteor-logo-svg.svg";

const METEOR_WALLET_MANIFEST = Object.freeze({
  id: METEOR_WALLET_ID,
  platform: Object.freeze(["web"]),
  name: "Meteor Wallet",
  icon: METEOR_ICON_URL,
  description: "Meteor Wallet for the local NEAR Testnet transfer demo",
  website: "https://meteorwallet.app",
  version: "6369ad789d2f3aaf8e6ccb065021723111027174",
  executor: METEOR_EXECUTOR_URL,
  type: "sandbox",
  permissions: Object.freeze({
    storage: true,
    allowsOpen: Object.freeze([
      "https://wallet.meteorwallet.app",
      "https://meteorwallet.app",
    ]),
    external: Object.freeze(["meteorCom", "meteorComV2"]),
  }),
  features: Object.freeze({
    signMessage: false,
    signTransaction: false,
    signAndSendTransaction: true,
    signAndSendTransactions: false,
    signInWithoutAddKey: true,
    signInAndSignMessage: false,
    signInWithFunctionCallKey: false,
    signDelegateActions: false,
    mainnet: false,
    testnet: true,
  }),
});

const METEOR_ONLY_CONNECTOR_READY = true;

function removeInjectedProviderListeners(windowObject, injectedListener, messageListener) {
  windowObject.removeEventListener("near-wallet-injected", injectedListener, true);
  windowObject.removeEventListener("message", messageListener, true);
}

export function createGuardedMeteorConnector({ NearConnector, windowObject = globalThis.window, cspNonce }) {
  if (typeof NearConnector !== "function") {
    throw new TypeError("The NEAR Connect module did not provide NearConnector.");
  }
  if (!windowObject || typeof windowObject.addEventListener !== "function"
    || typeof windowObject.removeEventListener !== "function") {
    throw new TypeError("A browser window is required to enforce the Meteor-only provider boundary.");
  }

  let injectedProviderSeen = false;
  const blockInjectedProvider = (event) => {
    injectedProviderSeen = true;
    event.stopImmediatePropagation?.();
    event.preventDefault?.();
  };
  const blockInjectedProviderMessage = (event) => {
    if (event?.data?.type === "near-wallet-injected") blockInjectedProvider(event);
  };

  // Install capture-phase guards before NearConnector registers its own handlers.
  // This blocks both its CustomEvent and parent-frame message injection paths.
  windowObject.addEventListener("near-wallet-injected", blockInjectedProvider, true);
  windowObject.addEventListener("message", blockInjectedProviderMessage, true);

  let connector;
  try {
    connector = new NearConnector({
      network: "testnet",
      autoConnect: false,
      cspNonce,
      manifest: {
        version: "1.0.0",
        wallets: [METEOR_WALLET_MANIFEST],
      },
    });
  } catch (error) {
    removeInjectedProviderListeners(windowObject, blockInjectedProvider, blockInjectedProviderMessage);
    throw error;
  }

  if (!connector || connector.network !== "testnet"
    || typeof connector.connect !== "function" || typeof connector.on !== "function") {
    removeInjectedProviderListeners(windowObject, blockInjectedProvider, blockInjectedProviderMessage);
    throw new TypeError("NEAR Connect did not create a testnet connector with the required API.");
  }

  return {
    network: "testnet",
    on(event, callback) {
      return connector.on(event, callback);
    },
    async connect() {
      if (injectedProviderSeen) {
        throw new Error("A wallet-injected provider was blocked; only the pinned Meteor Wallet executor is allowed.");
      }
      const wallet = await connector.connect({ walletId: METEOR_WALLET_ID });
      if (injectedProviderSeen) {
        throw new Error("A wallet-injected provider was blocked; only the pinned Meteor Wallet executor is allowed.");
      }
      if (!wallet || wallet.manifest !== METEOR_WALLET_MANIFEST
        || typeof wallet.getAccounts !== "function") {
        throw new Error("NEAR Connect returned an unexpected provider; the Meteor-only connection was rejected.");
      }
      return wallet;
    },
  };
}

export function mountLocalUI({
  document,
  loadConnector = () => import("@hot-labs/near-connect"),
  windowObject = globalThis.window,
}) {
  const appScript = document.querySelector?.('script[type="module"][nonce]')
    ?? document.querySelector?.("script[nonce]");
  const cspNonce = appScript?.nonce || appScript?.getAttribute?.("nonce") || undefined;
  return mountUI({
    document,
    connectionEnabled: METEOR_ONLY_CONNECTOR_READY,
    createConnector: async () => {
      const { NearConnector } = await loadConnector();
      return createGuardedMeteorConnector({ NearConnector, windowObject, cspNonce });
    },
  });
}

if (typeof document !== "undefined") mountLocalUI({ document });
