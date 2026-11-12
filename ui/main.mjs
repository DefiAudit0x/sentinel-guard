import { actionCreators } from "@near-js/transactions";
import { mountUI } from "./controller.mjs";
import {
  TESTNET_SELF_TRANSFER_ACCOUNT,
  TESTNET_SELF_TRANSFER_AMOUNT_YOCTO,
  SELF_TRANSFER_REVIEW_TTL_MS,
} from "./self_transfer.mjs";

export const METEOR_TESTNET_TARGET = Object.freeze({ blockchain: "near", network: "testnet" });
const SELF_TRANSFER_SIGNING_PARAMS = Object.freeze({
  network: "testnet",
  signerId: TESTNET_SELF_TRANSFER_ACCOUNT,
  receiverId: TESTNET_SELF_TRANSFER_ACCOUNT,
  actions: Object.freeze([Object.freeze({
    type: "Transfer",
    params: Object.freeze({ deposit: TESTNET_SELF_TRANSFER_AMOUNT_YOCTO }),
  })]),
});

function isAccountForTarget(account, accountId) {
  const identifier = account?.identifier;
  return identifier?.blockchain === METEOR_TESTNET_TARGET.blockchain
    && identifier.network === METEOR_TESTNET_TARGET.network
    && typeof identifier.accountId === "string"
    && identifier.accountId.length > 0
    && (accountId === undefined || identifier.accountId === accountId);
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function assertFixedTransferParams(params) {
  if (!exactKeys(params, ["network", "signerId", "receiverId", "actions"])
    || params.network !== SELF_TRANSFER_SIGNING_PARAMS.network
    || params.signerId !== SELF_TRANSFER_SIGNING_PARAMS.signerId
    || params.receiverId !== SELF_TRANSFER_SIGNING_PARAMS.receiverId
    || !Array.isArray(params.actions) || params.actions.length !== 1) {
    throw new Error("Only the fixed reviewed Testnet self-transfer can be requested.");
  }
  const [action] = params.actions;
  if (!exactKeys(action, ["type", "params"]) || action.type !== "Transfer"
    || !exactKeys(action.params, ["deposit"])
    || action.params.deposit !== TESTNET_SELF_TRANSFER_AMOUNT_YOCTO) {
    throw new Error("The requested action differs from the fixed reviewed Testnet transfer.");
  }
}

export function createMeteorConnectAdapter({
  MeteorConnect,
  webpage_local_storage: storage,
  windowObject = globalThis.window,
  transferActionCreators = actionCreators,
  clock = () => Date.now(),
  monotonicClock = () => globalThis.performance?.now?.(),
}) {
  if (typeof MeteorConnect !== "function") {
    throw new TypeError("The Meteor SDK did not provide MeteorConnect.");
  }
  if (!storage || typeof storage !== "object") {
    throw new TypeError("The Meteor SDK browser storage adapter is unavailable.");
  }
  if (typeof clock !== "function") throw new TypeError("A wall review clock is required.");
  if (typeof monotonicClock !== "function") throw new TypeError("A monotonic review clock is required.");
  const originUrl = windowObject?.location?.origin;
  if (typeof originUrl !== "string" || !/^https?:\/\//.test(originUrl)) {
    throw new TypeError("A browser origin is required for Meteor SDK identity.");
  }

  const meteorConnect = new MeteorConnect();
  let initializePromise = null;
  let signedInIdentifier = null;

  const initialize = () => {
    if (!initializePromise) {
      initializePromise = meteorConnect.initialize({
        storage,
        mobileBridge: {
          enabled: false,
          autoOpenPairedWallet: false,
          partnerMetadata: {
            name: "Sentinel Guard Local Testnet Demo",
            description: "NEAR Testnet account sign-in and fixed-transfer review",
            originUrl,
          },
          transferAccounts: { enabled: false },
          newKeyTransfer: { enabled: false },
        },
      }).catch((error) => {
        initializePromise = null;
        throw error;
      });
    }
    return initializePromise;
  };

  const getStoredSignedInAccount = async () => {
    if (!signedInIdentifier) return null;
    const account = await meteorConnect.getAccount(signedInIdentifier);
    return isAccountForTarget(account, signedInIdentifier.accountId) ? account : null;
  };

  const wallClockHighWaterByDeadline = new WeakMap();
  const assertReviewDeadline = (deadline = {}) => {
    if (!deadline || typeof deadline !== "object") {
      throw new Error("Transfer review expired before the wallet prompt could open.");
    }
    const { createdAt, expiresAt, monotonicCreatedAt, monotonicExpiresAt, isLifecycleActive } = deadline;
    const wallNow = clock();
    const monotonicNow = monotonicClock();
    const wallClockHighWater = wallClockHighWaterByDeadline.get(deadline)
      ?? deadline.wallClockHighWater ?? createdAt;
    if (!Number.isSafeInteger(createdAt) || createdAt < 0
      || !Number.isSafeInteger(expiresAt) || expiresAt - createdAt !== SELF_TRANSFER_REVIEW_TTL_MS
      || !Number.isSafeInteger(wallClockHighWater) || !Number.isSafeInteger(wallNow)
      || wallNow < wallClockHighWater || wallNow < createdAt || wallNow >= expiresAt
      || !Number.isFinite(monotonicCreatedAt) || monotonicCreatedAt < 0
      || !Number.isFinite(monotonicExpiresAt) || monotonicExpiresAt <= monotonicCreatedAt
      || monotonicExpiresAt !== monotonicCreatedAt + SELF_TRANSFER_REVIEW_TTL_MS
      || !Number.isFinite(monotonicNow) || monotonicNow < monotonicCreatedAt || monotonicNow >= monotonicExpiresAt) {
      throw new Error("Transfer review expired before the wallet prompt could open.");
    }
    wallClockHighWaterByDeadline.set(deadline, wallNow);
    if (typeof isLifecycleActive === "function" && !isLifecycleActive()) {
      throw new Error("The page lifecycle changed before the wallet prompt could open.");
    }
  };

  const wallet = {
    async getAccounts({ network } = {}) {
      if (network !== METEOR_TESTNET_TARGET.network || !signedInIdentifier) return [];
      const account = await getStoredSignedInAccount();
      return account ? [{ accountId: account.identifier.accountId }] : [];
    },

    async signAndSendTransaction(params, reviewDeadline = {}) {
      assertFixedTransferParams(params);
      assertReviewDeadline(reviewDeadline);
      if (!signedInIdentifier || params.signerId !== signedInIdentifier.accountId) {
        throw new Error("The selected account differs from the signed-in Testnet account.");
      }
      const account = await getStoredSignedInAccount();
      assertReviewDeadline(reviewDeadline);
      if (!account || !isAccountForTarget(account, params.signerId)) {
        throw new Error("The signed-in NEAR Testnet account is no longer available in Meteor SDK storage.");
      }
      const action = await meteorConnect.createAction({
        id: "near::sign_transactions",
        input: {
          target: {
            blockchain: account.identifier.blockchain,
            network: account.identifier.network,
            accountId: account.identifier.accountId,
          },
          transactions: [{
            receiverId: params.receiverId,
            actions: [transferActionCreators.transfer(BigInt(params.actions[0].params.deposit))],
          }],
          useFunctionCallKey: false,
        },
      });
      assertReviewDeadline(reviewDeadline);
      return action.promptForExecution();
    },
  };

  return {
    network: METEOR_TESTNET_TARGET.network,

    async connect() {
      await initialize();
      const signInAction = await meteorConnect.createAction({
        id: "near::sign_in",
        input: { target: METEOR_TESTNET_TARGET },
      });
      const account = await signInAction.promptForExecution();
      if (!isAccountForTarget(account)) {
        throw new Error("Meteor did not return a NEAR Testnet account for ordinary sign-in.");
      }
      signedInIdentifier = {
        blockchain: account.identifier.blockchain,
        network: account.identifier.network,
        accountId: account.identifier.accountId,
      };
      if (!await getStoredSignedInAccount()) {
        signedInIdentifier = null;
        throw new Error("Meteor SDK did not retain the signed-in Testnet account.");
      }
      return wallet;
    },
  };
}

export function mountLocalUI({
  document,
  loadMeteorSdk = () => import("@meteorwallet/sdk"),
  windowObject = globalThis.window,
}) {
  return mountUI({
    document,
    connectionEnabled: true,
    windowObject,
    createConnector: async () => createMeteorConnectAdapter({
      ...(await loadMeteorSdk()),
      windowObject,
    }),
  });
}

if (typeof document !== "undefined") mountLocalUI({ document });
