import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import QRCode from "qrcode";
import { encodeAmount } from "./utils";

function requireElement<T extends HTMLElement>(id: string): T {
    const el = document.getElementById(id);
    if (!el) {
        throw new Error(`Missing required element: ${id}`);
    }
    return el as T;
}

// DOM Elements - Auth Panels
const authContainer = requireElement<HTMLElement>("auth-container");
const panels = ["init-panel", "login-panel", "selection-panel", "create-pw-panel", "backup-panel", "import-panel"];

// Initialize default data directory from backend
window.addEventListener("DOMContentLoaded", async () => {
    try {
        const defaultDir: string = await invoke("get_default_data_dir");
        const dataDirInput = document.getElementById("data-dir") as HTMLInputElement;
        if (dataDirInput) dataDirInput.value = defaultDir;
    } catch (e) {
        console.error("Failed to resolve default data directory:", e);
    }
});

// Dashboard Elements
const dashboard = requireElement<HTMLElement>("main-dashboard");
const balanceEl = requireElement<HTMLElement>("balance-amount");
const addressEl = requireElement<HTMLElement>("address-text");
const blockHeightEl = requireElement<HTMLElement>("block-height");
const peerCountEl = requireElement<HTMLElement>("peer-count");
const assetAeraVal = requireElement<HTMLElement>("asset-aera-val");
const activityList = requireElement<HTMLElement>("activity-list");

// Form Elements
const dataDirInput = requireElement<HTMLInputElement>("data-dir");
const createPwInput = requireElement<HTMLInputElement>("create-pw");
const importPhraseInput = requireElement<HTMLTextAreaElement>("import-phrase");
const importPwInput = requireElement<HTMLInputElement>("import-pw");
const loginPwInput = requireElement<HTMLInputElement>("login-pw");
const mnemonicDisplay = requireElement<HTMLElement>("mnemonic-display");

// Buttons
const btnInit = requireElement<HTMLElement>("btn-init");
const btnGoCreate = requireElement<HTMLElement>("btn-go-create");
const btnGoImport = requireElement<HTMLElement>("btn-go-import");
const btnDoCreate = requireElement<HTMLElement>("btn-do-create");
const btnDoImport = requireElement<HTMLElement>("btn-do-import");
const btnBackupConfirm = requireElement<HTMLElement>("btn-backup-confirm");
const btnDoLogin = requireElement<HTMLElement>("btn-do-login");
const btnSettings = requireElement<HTMLElement>("btn-settings");
const btnLogout = requireElement<HTMLElement>("btn-logout");
const btnCloseSettings = requireElement<HTMLElement>("btn-close-settings");
const settingsModal = requireElement<HTMLElement>("settings-modal");
const btnSwitchWallet = requireElement<HTMLElement>("btn-switch-wallet");
const loginAddressInput = requireElement<HTMLInputElement>("login-address-input");
const sendPasswordModal = requireElement<HTMLElement>("send-password-modal");
const sendPasswordInput = requireElement<HTMLInputElement>("send-password-input");
const btnSendPasswordConfirm = requireElement<HTMLElement>("btn-send-password-confirm");
const btnSendPasswordCancel = requireElement<HTMLElement>("btn-send-password-cancel");

// Global State
let currentAddress = "";
let idleTimer: number | null = null;
let statsInterval: number | null = null;
let activityInterval: number | null = null;
let dashboardListenersAttached = false;
let pendingSend: { to: string; amount: number; network: string; source: "main" | "bridge" } | null = null;
/** Idle lock timeout: lock wallet after this many ms without activity */
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;

// Multi-Network State
let currentNetwork = "aera";
let networkAddresses: { [key: string]: string } = {
    aera: "",
    eth: "",       // Native ETH
    bridge_eth: "", // USDT ERC-20
    tron: "",      // USDT TRC-20
    aera_usdt: ""   // Native USDT on AERA
};

function resetNetworkAddresses() {
    networkAddresses = {
        aera: "",
        eth: "",
        bridge_eth: "",
        tron: "",
        aera_usdt: ""
    };
}

const networkSelectors: { [key: string]: string } = {
    aera: "AERA Network",
    eth: "Ethereum (Native)",
    tron_native: "TRON (Native)",
    bridge_eth: "Ethereum (ERC-20)",
    tron: "TRON (TRC-20)",
    aera_usdt: "AERA (USDT)"
};

const networkCurrencies: { [key: string]: string } = {
    aera: "AERA",
    eth: "ETH",
    tron_native: "TRX",
    bridge_eth: "USDT",
    tron: "USDT",
    aera_usdt: "USDT"
};

const lastBalances: { [key: string]: string } = {
    aera: "0.00 AERA",
    eth: "0.00 ETH",
    tron_native: "0.00 TRX",
    bridge_eth: "0.00 USDT",
    tron: "0.00 USDT",
    aera_usdt: "0.00 USDT"
};

const lastFeeBalances: { [key: string]: string } = {
    eth: "0.00 ETH",
    tron: "0.00 TRX"
};
let lastFeeFetchAt = 0;
const FEE_REFRESH_MS = 30_000;

// Helper: Fetch balance for a network and update DOM element
async function fetchAndUpdateBalance(
    invokeCmd: string,
    address: string,
    elementId: string,
    cacheKey: string,
    cache: { [key: string]: string }
): Promise<string | null> {
    if (!address || address === "Address not generated") return null;
    try {
        const bal: string = await invoke(invokeCmd, { address });
        cache[cacheKey] = bal;
        const el = document.getElementById(elementId);
        if (el) el.textContent = bal;
        return bal;
    } catch (e) {
        console.error(`${invokeCmd} failed`, e);
        return null;
    }
}

// Helper: Navigation
function showPanel(id: string) {
    panels.forEach(p => {
        const el = document.getElementById(p);
        if (el) el.style.display = (p === id) ? "flex" : "none";
    });
    if (id !== "backup-panel") {
        clearInputs();
        clearMnemonicDisplay();
    }
}

// Helper: Security - Clear all sensitive inputs
function clearInputs() {
    const inputs = [createPwInput, importPwInput, loginPwInput, importPhraseInput];
    inputs.forEach(input => {
        if (input) {
            input.value = "";
        }
    });
}

// Helper: Clear mnemonic from DOM (no recovery phrase left in memory)
function clearMnemonicDisplay() {
    if (mnemonicDisplay) {
        mnemonicDisplay.textContent = "";
    }
}

function renderMnemonic(words: string[]) {
    if (!mnemonicDisplay) return;
    mnemonicDisplay.textContent = "";
    const fragment = document.createDocumentFragment();
    words.forEach((word, i) => {
        const item = document.createElement("div");
        item.className = "mnemonic-word";
        const idx = document.createElement("span");
        idx.className = "mnemonic-index";
        idx.textContent = `${i + 1}.`;
        item.appendChild(idx);
        item.appendChild(document.createTextNode(` ${word}`));
        fragment.appendChild(item);
    });
    mnemonicDisplay.appendChild(fragment);
}

function renderActivityMessage(message: string) {
    activityList.textContent = "";
    const div = document.createElement("div");
    div.style.textAlign = "center";
    div.style.padding = "20px";
    div.style.opacity = "0.5";
    div.textContent = message;
    activityList.appendChild(div);
}

function renderActivities(activities: any[], addrLower: string) {
    activityList.textContent = "";
    const fragment = document.createDocumentFragment();
    activities.forEach(tx => {
        const isSent = (tx.from || "").toLowerCase() === addrLower;
        const date = new Date(tx.timestamp * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

        const amountBase = BigInt(tx.amount);
        const decimals = BigInt(10) ** BigInt(18);
        const whole = amountBase / decimals;
        const frac = amountBase % decimals;
        const fracStr = frac.toString().padStart(18, "0").substring(0, 4);
        const amountFormatted = `${whole}.${fracStr}`;

        const item = document.createElement("div");
        item.className = "activity-item";

        const left = document.createElement("div");
        left.className = "activity-left";
        const type = document.createElement("div");
        type.className = "activity-type";
        type.textContent = `${isSent ? "Sent" : "Received"} ${tx.chain}`;
        const dateEl = document.createElement("div");
        dateEl.className = "activity-date";
        dateEl.textContent = date;
        left.appendChild(type);
        left.appendChild(dateEl);

        const right = document.createElement("div");
        right.className = "activity-right";
        const amount = document.createElement("div");
        amount.className = `activity-amount ${isSent ? "sent" : "received"}`;
        amount.textContent = `${isSent ? "-" : "+"}${amountFormatted} ${tx.chain}`;
        const status = document.createElement("div");
        const statusText = (tx.status || "").toString();
        status.className = `activity-status status-${statusText.toLowerCase()}`;
        status.textContent = statusText;
        right.appendChild(amount);
        right.appendChild(status);

        item.appendChild(left);
        item.appendChild(right);
        fragment.appendChild(item);
    });
    activityList.appendChild(fragment);
}

async function lockWallet() {
    if (!dashboard.style.display || dashboard.style.display === "none") return;

    console.log("Locking wallet session...");

    // 1. Immediate UI Transition
    const settingsMod = document.getElementById("settings-modal");
    if (settingsMod) settingsMod.classList.remove("active");

    dashboard.style.display = "none";
    authContainer.style.display = "flex";
    if (loginAddressInput) loginAddressInput.value = "";

    // Reset dashboard visuals to blank state
    balanceEl.textContent = "0.00 AERA";
    addressEl.textContent = "aera1...";
    renderActivityMessage("No activity found");
    setActiveTab("assets");

    clearInputs();
    clearMnemonicDisplay();
    currentNetwork = "aera";
    resetNetworkAddresses();
    goToLogin(false); // Do NOT pre-fill on explicit logout/lock

    // 2. Background cleanup
    clearSessionIntervals();
    stopIdleTimer();

    try {
        console.log("Requesting backend session lock...");
        await invoke("lock_session");
        console.log("Backend session locked.");
        // Refresh available wallets on logout to see any new local files
        await loadAvailableWallets();
    } catch (e) {
        console.error("Logout IPC failed", e);
    }
}

async function loadAvailableWallets() {
    try {
        console.log("Refreshing available wallets...");
        const addresses: string[] = await invoke("refresh_wallets");
        const datalist = document.getElementById("available-addresses");
        if (datalist) {
            datalist.textContent = "";
            const fragment = document.createDocumentFragment();
            addresses.forEach(addr => {
                const option = document.createElement("option");
                option.value = addr;
                fragment.appendChild(option);
            });
            datalist.appendChild(fragment);
            console.log(`Loaded ${addresses.length} addresses into datalist.`);
        }
    } catch (e) {
        console.error("Failed to refresh wallets:", e);
    }
}

async function goToLogin(autoFill: boolean = true) {
    try {
        await loadAvailableWallets();
        const wallets: string[] = await invoke("list_wallets");

        if (wallets && wallets.length > 0) {
            if (autoFill) {
                const address: string = await invoke("get_address");
                if (loginAddressInput) {
                    loginAddressInput.value = address.trim();
                }
            } else if (loginAddressInput) {
                loginAddressInput.value = "";
            }
            showPanel("login-panel");
        } else {
            // No wallets found in the list, go to selection
            showPanel("selection-panel");
        }
    } catch (e) {
        console.error("Navigation to login failed:", e);
        showPanel("selection-panel");
    }
}

function clearSessionIntervals() {
    if (statsInterval) {
        clearInterval(statsInterval);
        statsInterval = null;
    }
    if (activityInterval) {
        clearInterval(activityInterval);
        activityInterval = null;
    }
}

function startIdleTimer() {
    stopIdleTimer();
    idleTimer = window.setTimeout(lockWallet, IDLE_TIMEOUT_MS);
}

function stopIdleTimer() {
    if (idleTimer) {
        clearTimeout(idleTimer);
        idleTimer = null;
    }
}

function resetIdleTimer() {
    if (dashboard.style.display === "flex") {
        startIdleTimer();
    }
}

// Global Activity Listeners
window.addEventListener("mousemove", resetIdleTimer);
window.addEventListener("keydown", resetIdleTimer);
window.addEventListener("click", resetIdleTimer);
window.addEventListener("scroll", resetIdleTimer);

// Expose to window for inline onclicks
(window as any).showPanel = showPanel;
(window as any).switchNetwork = switchNetwork;

function initAssetSectionToggles() {
    const sections = document.querySelectorAll(".asset-section");
    sections.forEach(section => {
        const toggle = section.querySelector(".asset-section-toggle") as HTMLButtonElement | null;
        if (!toggle) return;
        toggle.addEventListener("click", () => {
            section.classList.toggle("collapsed");
            const expanded = !section.classList.contains("collapsed");
            toggle.setAttribute("aria-expanded", String(expanded));
        });
    });
}

initAssetSectionToggles();

function getAddressForNetwork(net: string): string {
    if (net === "tron_native") return networkAddresses.tron;
    return networkAddresses[net] || "";
}

async function switchNetwork(net: string) {
    currentNetwork = net;

    // Update Send Indicator
    const indicator = document.getElementById("active-network-indicator");
    if (indicator) indicator.textContent = networkSelectors[net] || "Unknown Network";

    const currencyLabel = document.getElementById("currency-label");
    if (currencyLabel) currencyLabel.textContent = networkCurrencies[net] || "TOKENS";

    // Fetch network-specific address if not cached
    if ((net === "tron" || net === "tron_native") && !networkAddresses.tron) {
        try { networkAddresses.tron = await invoke("get_tron_address"); } catch (e) { console.error(e); }
    } else if (net === "eth" && !networkAddresses.eth) {
        try { networkAddresses.eth = await invoke("get_eth_address"); } catch (e) { console.error(e); }
    } else if (net === "bridge_eth") {
        try {
            const addr: string = await invoke("get_eth_usdt_address");
            networkAddresses.bridge_eth = addr;
            if (!networkAddresses.eth) networkAddresses.eth = addr;
        } catch (e) {
            console.error(e);
        }
    } else if (net === "aera_usdt") {
        networkAddresses.aera_usdt = currentAddress;
    } else if (net === "aera") {
        networkAddresses.aera = currentAddress;
    }

    // Update Address Display
    updateAddressDisplay();
    updateFeeHints(currentNetwork);

    // Immediate Refresh
    updateStats();
    updateActivity();
}

function updateAddressDisplay() {
    let addr = getAddressForNetwork(currentNetwork);

    if (!addr || addr.trim() === "" || addr === "0x" || addr.includes("...")) {
        addressEl.textContent = "Address not generated";
        addressEl.setAttribute("title", "No address found");
    } else {
        if (addr.length > 20) {
            addressEl.textContent = addr.substring(0, 8) + "..." + addr.substring(addr.length - 4);
        } else {
            addressEl.textContent = addr;
        }
        addressEl.setAttribute("title", addr);
    }
}

function updateFeeHints(network: string) {
    const feeEl = document.getElementById("fee-hint");
    const bridgeFeeEl = document.getElementById("bridge-fee-hint");

    const setHint = (el: HTMLElement | null, text: string, warn: boolean) => {
        if (!el) return;
        el.textContent = text;
        el.classList.toggle("warn", warn);
    };

    if (network === "eth" || network === "bridge_eth") {
        const fee = lastFeeBalances.eth;
        const warn = fee.startsWith("0.00");
        setHint(feeEl, `Network fee balance: ${fee}`, warn);
        setHint(bridgeFeeEl, `Network fee balance: ${fee}`, warn);
    } else if (network === "tron" || network === "tron_native") {
        const fee = lastFeeBalances.tron;
        const warn = fee.startsWith("0.00");
        setHint(feeEl, `Network fee balance: ${fee}`, warn);
        setHint(bridgeFeeEl, `Network fee balance: ${fee}`, warn);
    } else {
        setHint(feeEl, "Network fee balance: —", false);
        setHint(bridgeFeeEl, "Network fee balance: —", false);
    }
}

function parseFeeValue(text: string): number {
    const n = parseFloat((text || "").split(" ")[0]);
    return isNaN(n) ? 0 : n;
}

function getFeeBalanceForNetwork(network: string): number {
    if (network === "eth" || network === "bridge_eth") return parseFeeValue(lastFeeBalances.eth);
    if (network === "tron" || network === "tron_native") return parseFeeValue(lastFeeBalances.tron);
    return 0;
}

// 1. Init Node
btnInit.addEventListener("click", async () => {
    const dataDir = dataDirInput.value;
    btnInit.textContent = "Launching Node...";
    (btnInit as HTMLButtonElement).disabled = true;

    try {
        await invoke("init_node", { dataDir });
        const walletExists: boolean = await invoke("has_wallet");
        if (walletExists) {
            goToLogin();
        } else {
            showPanel("selection-panel");
        }
    } catch (e) {
        alert("Node Init Failed: " + e);
        btnInit.textContent = "Initialize Node";
        (btnInit as HTMLButtonElement).disabled = false;
    }
});

// 2. Selection
btnGoCreate.addEventListener("click", () => showPanel("create-pw-panel"));
btnGoImport.addEventListener("click", () => showPanel("import-panel"));

// 3a. Create Wallet
btnDoCreate.addEventListener("click", async () => {
    const password = createPwInput.value;
    if (!password) return alert("Please enter a password");

    btnDoCreate.textContent = "Generating...";
    try {
        const wallet: any = await invoke("create_mnemonic_wallet", { password });
        currentAddress = wallet.address;

        // Display mnemonic words
        const words = wallet.mnemonic.split(" ");
        renderMnemonic(words);

        showPanel("backup-panel");
    } catch (e) {
        alert("Creation Failed: " + e);
        btnDoCreate.textContent = "Generate Wallet";
    }
});

// 3b. Confirm Backup
btnBackupConfirm.addEventListener("click", () => {
    clearMnemonicDisplay();
    enterDashboard();
});

// 3c. Import Wallet
btnDoImport.addEventListener("click", async () => {
    const phrase = importPhraseInput.value.trim();
    const password = importPwInput.value;

    if (!phrase || !password) return alert("Please enter phrase and password");

    btnDoImport.textContent = "Importing...";
    try {
        const wallet: any = await invoke("import_mnemonic_wallet", { phrase, password });
        currentAddress = wallet.address;
        networkAddresses.aera = currentAddress; // Sync primary network
        enterDashboard();
    } catch (e) {
        alert("Import Failed: " + e);
        btnDoImport.textContent = "Import & Unlock";
    }
});

// 3d. Fast Login
btnDoLogin.addEventListener("click", async () => {
    const address = loginAddressInput.value.trim().toLowerCase();
    const password = loginPwInput.value;

    if (!address) return alert("Please enter wallet address");
    if (!password) return alert("Enter password");

    // Validate address format
    if (!address.startsWith("aera1")) {
        return alert("Invalid address format. AERA addresses must start with 'aera1'");
    }

    btnDoLogin.textContent = "Unlocking...";
    try {
        const wallet: any = await invoke("unlock_wallet", { address, password });
        currentAddress = wallet.address;
        networkAddresses.aera = currentAddress; // Sync primary network
        enterDashboard();
    } catch (e) {
        alert("Login Failed: " + e);
    } finally {
        btnDoLogin.textContent = "Unlock AERA";
    }
});


// 4. Copy Address to Clipboard (single handler; copies displayed network address)
addressEl.addEventListener("click", async () => {
    const full = addressEl.getAttribute("title") || (networkAddresses[currentNetwork] || currentAddress);
    if (!full || full === "Address not generated" || full.includes("...")) return;
    try {
        await navigator.clipboard.writeText(full);
        const orig = addressEl.textContent;
        addressEl.textContent = "Copied!";
        addressEl.style.color = "var(--accent)";
        setTimeout(() => {
            addressEl.textContent = orig;
            addressEl.style.color = "";
        }, 2000);
    } catch (err) {
        console.error("Failed to copy address", err);
    }
});


// 5. Enter Dashboard
function enterDashboard() {
    authContainer.style.display = "none";
    dashboard.style.display = "flex";
    setActiveTab("assets");

    // 1. Clear any old intervals just in case
    clearSessionIntervals();

    // 2. Start Security Timer
    startIdleTimer();

    // 3. Reset network state for the new session
    currentNetwork = "aera";
    resetNetworkAddresses();
    networkAddresses.aera = currentAddress;
    networkAddresses.aera_usdt = currentAddress;
    updateAddressDisplay();

    // 4. Start updates (and store refs)
    statsInterval = window.setInterval(updateStats, 5000);
    activityInterval = window.setInterval(updateActivity, 10000);

    updateStats();
    updateActivity();

    // Setup Receive Modal (once per dashboard session to avoid duplicate listeners)
    if (!dashboardListenersAttached) {
        dashboardListenersAttached = true;
    }

    const btnReceive = requireElement<HTMLElement>("btn-receive");
    const receiveModal = requireElement<HTMLElement>("receive-modal");
    const btnCloseReceive = requireElement<HTMLElement>("btn-close-receive");
    if (!(btnReceive as any)._receiveListenerAttached) {
        (btnReceive as any)._receiveListenerAttached = true;
        btnReceive.addEventListener("click", async () => {
            const netName = networkSelectors[currentNetwork];
            let addr = currentNetwork === "aera" || currentNetwork === "aera_usdt"
                ? currentAddress
                : getAddressForNetwork(currentNetwork);

            const qrCanvas = document.getElementById("qr-canvas") as HTMLCanvasElement;
            if (!addr || !addr.trim() || addr === "Address not generated" || addr.includes("...")) {
                addr = "Address not generated";
                if (qrCanvas) qrCanvas.style.display = "none";
            } else {
                if (qrCanvas) {
                    qrCanvas.style.display = "block";
                    try {
                        await QRCode.toCanvas(qrCanvas, addr, {
                            width: 180,
                            margin: 2,
                            color: { dark: "#000000", light: "#FFFFFF" },
                        });
                    } catch (err) {
                        console.error("QR Code generation failed", err);
                    }
                }
            }
            const netNameEl = document.getElementById("receive-network-name");
            const addrEl = document.getElementById("receive-address-full");
            if (netNameEl) netNameEl.textContent = netName;
            if (addrEl) addrEl.textContent = addr;
            receiveModal.classList.add("active");
        });
        btnCloseReceive.addEventListener("click", () => receiveModal.classList.remove("active"));
    }

    updateFeeHints(currentNetwork);
}

function setActiveTab(tabName: string) {
    document.querySelectorAll(".tab-link").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    const tab = document.querySelector(`.tab-link[data-tab="${tabName}"]`);
    const pane = document.getElementById(tabName);
    if (tab) tab.classList.add("active");
    if (pane) pane.classList.add("active");
}

async function updateActivity() {
    if (!currentAddress) return;
    const addrLower = (currentAddress || "").toLowerCase();

    try {
        const activities: any[] = await invoke("get_activity", { address: addrLower });

        if (activities.length === 0) {
            renderActivityMessage("No activity found");
            return;
        }

        renderActivities(activities, addrLower);

    } catch (e) {
        console.error("Activity update failed", e);
    }
}

async function updateStats() {
    try {
        const netInfo: any = await invoke("get_network_info");
        blockHeightEl.textContent = netInfo.block_height.toString();
        peerCountEl.textContent = netInfo.peer_count.toString();

        // Update AERA asset balance always
        try {
            const aeraInfo: any = await invoke("get_balance", { address: currentAddress });
            assetAeraVal.textContent = aeraInfo.balance_formatted;
            lastBalances.aera = aeraInfo.balance_formatted;
        } catch (e) {
            console.error("AERA balance fetch failed", e);
        }

        const now = Date.now();
        const shouldRefreshFees = now - lastFeeFetchAt > FEE_REFRESH_MS;
        
        // Track if we already fetched these balances in this cycle
        let ethFetched = false;
        let trxFetched = false;
        
        if (shouldRefreshFees) {
            // Refresh native fee balances for ETH/TRX (if addresses available)
            await fetchAndUpdateBalance("get_eth_balance", networkAddresses.eth, "asset-native-eth-val", "eth", lastFeeBalances);
            await fetchAndUpdateBalance("get_trx_balance", networkAddresses.tron, "asset-trx-val", "tron", lastFeeBalances);
            lastFeeFetchAt = now;
            ethFetched = true;
            trxFetched = true;
        }

        // Update main balance display based on network
        if (currentNetwork === "aera") {
            balanceEl.textContent = lastBalances.aera;
        } else if (currentNetwork === "eth") {
            const bal = await fetchAndUpdateBalance("get_eth_balance", networkAddresses.eth, "asset-native-eth-val", "eth", lastBalances);
            if (bal) {
                balanceEl.textContent = bal;
                if (!ethFetched) lastFeeBalances.eth = bal;
            } else {
                balanceEl.textContent = lastBalances.eth;
            }
            updateFeeHints(currentNetwork);
        } else if (currentNetwork === "tron_native") {
            const bal = await fetchAndUpdateBalance("get_trx_balance", networkAddresses.tron, "asset-trx-val", "tron_native", lastBalances);
            if (bal) {
                balanceEl.textContent = bal;
                if (!trxFetched) lastFeeBalances.tron = bal;
            } else {
                balanceEl.textContent = lastBalances.tron_native;
            }
            updateFeeHints(currentNetwork);
        } else if (currentNetwork === "tron") {
            const bal = await fetchAndUpdateBalance("get_tron_balance", networkAddresses.tron, "asset-tron-val", "tron", lastBalances);
            if (bal) {
                balanceEl.textContent = bal;
                if (!trxFetched) {
                    await fetchAndUpdateBalance("get_trx_balance", networkAddresses.tron, "asset-trx-val", "tron", lastFeeBalances);
                }
            } else {
                balanceEl.textContent = lastBalances.tron;
            }
            updateFeeHints(currentNetwork);
        } else if (currentNetwork === "bridge_eth") {
            if (!networkAddresses.bridge_eth && networkAddresses.eth) {
                networkAddresses.bridge_eth = networkAddresses.eth;
            }
            const bal = await fetchAndUpdateBalance("get_eth_usdt_balance", networkAddresses.bridge_eth, "asset-eth-val", "bridge_eth", lastBalances);
            if (bal) {
                balanceEl.textContent = bal;
            } else {
                balanceEl.textContent = lastBalances.bridge_eth;
            }
            updateFeeHints(currentNetwork);
        } else if (currentNetwork === "aera_usdt") {
            balanceEl.textContent = lastBalances.aera_usdt;
            const usdtVal = document.getElementById("asset-aera-usdt-val");
            if (usdtVal) usdtVal.textContent = lastBalances.aera_usdt;
            updateFeeHints(currentNetwork);
        } else {
            balanceEl.textContent = "Checking...";
        }

    } catch (e) {
        console.error("Stats update failed", e);
    }
}

// Tab Switching (+ load mining status when Mining tab opened)
document.querySelectorAll(".tab-link").forEach(button => {
    button.addEventListener("click", async () => {
        const tabName = (button as HTMLElement).dataset.tab!;
        document.querySelectorAll(".tab-link").forEach(b => b.classList.remove("active"));
        button.classList.add("active");
        document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
        const pane = document.getElementById(tabName);
        if (pane) pane.classList.add("active");

        if (tabName === "bridge") {
            updateFeeHints(currentNetwork);
        }

        if (tabName === "mining") {
            try {
                const st: any = await invoke("get_mining_status");
                mineHashrate.textContent = `${(st.hashrate / 1000).toFixed(2)} KH/s`;
                mineReward.textContent = `${st.current_reward.toFixed(2)} AERA`;
                mineBlocks.textContent = st.blocks_mined.toString();
                if (mineDifficulty) mineDifficulty.textContent = st.difficulty.toString();
                if (mineNodeStatus) {
                    mineNodeStatus.textContent = st.is_active ? "Mining active" : "Idle";
                    mineNodeStatus.classList.toggle("success", !!st.is_active);
                }
                btnStartMining.style.display = st.is_active ? "none" : "block";
                btnStopMining.style.display = st.is_active ? "block" : "none";
        } catch (e) {
            console.warn("Failed to load mining status:", e);
        }
        }
    });
});

// Send Transaction Toggle
const btnSendToggle = requireElement<HTMLElement>("btn-send-toggle");
const sendSection = requireElement<HTMLElement>("send-section");
const btnSendCancel = requireElement<HTMLElement>("btn-send-cancel");

btnSendToggle.addEventListener("click", () => sendSection.classList.add("active"));
btnSendCancel.addEventListener("click", () => sendSection.classList.remove("active"));

// Send Execution (secure password modal, no prompt())
const btnSendExecute = requireElement<HTMLElement>("btn-send-execute");
const sendToInput = document.getElementById("send-to") as HTMLInputElement;
const sendAmountInput = document.getElementById("send-amount") as HTMLInputElement;

function closeSendPasswordModal() {
    pendingSend = null;
    if (sendPasswordInput) sendPasswordInput.value = "";
    sendPasswordModal.classList.remove("active");
}

btnSendExecute.addEventListener("click", () => {
    const to = sendToInput.value?.trim();
    const amount = parseFloat(sendAmountInput.value);

    if (currentNetwork === "tron_native") {
        return alert("Native transfers are not supported yet. Please select a USDT or AERA network.");
    }

    if (!to || isNaN(amount) || amount <= 0) {
        return alert("Please enter valid address and amount");
    }
    pendingSend = { to, amount, network: currentNetwork, source: "main" };
    if (sendPasswordInput) sendPasswordInput.value = "";
    sendPasswordModal.classList.add("active");
    sendPasswordInput?.focus();
});

btnSendPasswordCancel.addEventListener("click", () => {
    closeSendPasswordModal();
});

sendPasswordModal.addEventListener("click", (e) => {
    if (e.target === sendPasswordModal) closeSendPasswordModal();
});

btnSendPasswordConfirm.addEventListener("click", async () => {
    const password = sendPasswordInput?.value ?? "";
    if (!pendingSend || !password) {
        return alert("Enter password to sign.");
    }
    const { to, amount, network, source } = pendingSend;
    btnSendPasswordConfirm.textContent = "Signing...";
    (btnSendPasswordConfirm as HTMLButtonElement).disabled = true;

    try {
        const feeNeeded = getFeeBalanceForNetwork(network);
        if (network === "eth" || network === "bridge_eth") {
            if (feeNeeded <= 0) {
                return alert("Insufficient ETH for network fee. Please top up your ETH balance.");
            }
        } else if (network === "tron") {
            if (feeNeeded <= 0) {
                return alert("Insufficient TRX for network fee. Please top up your TRX balance.");
            }
            }
        let result: any;
        if (network === "aera" || network === "aera_usdt") {
            const assetType = network === "aera" ? "aera" : "usdt";
            result = await invoke("send_aera_transaction", {
                from: currentAddress,
                recipient: to,
                amount: encodeAmount(amount, network),
                asset: assetType,
                password
            });
        } else {
            const usesNativeDecimals = network === "eth" || network === "tron_native";
            const encoded = usesNativeDecimals ? encodeAmount(amount, network) : encodeAmount(amount, "aera");
            // Cross-chain: USDT uses 18 decimals (AERA base units), backend converts to target chain
            result = await invoke("cross_chain_transfer", {
                from: currentAddress,
                to,
                amount: encoded,
                chain: network,
                password
            });
        }
        closeSendPasswordModal();
        if (result.success) {
            alert(`Transaction Sent! Hash: ${result.tx_hash}`);
            if (source === "main") {
                sendSection.classList.remove("active");
                sendToInput.value = "";
                sendAmountInput.value = "";
            } else {
                const bridgeTo = document.getElementById("bridge-send-to") as HTMLInputElement | null;
                const bridgeAmount = document.getElementById("bridge-send-amount") as HTMLInputElement | null;
                if (bridgeTo) bridgeTo.value = "";
                if (bridgeAmount) bridgeAmount.value = "";
            }
            updateStats();
            updateActivity();
        } else {
            alert("Transaction Failed: " + (result.error ?? "Unknown"));
        }
    } catch (e) {
        alert("IPC Error: " + String(e));
    } finally {
        btnSendPasswordConfirm.textContent = "Sign & Send";
        (btnSendPasswordConfirm as HTMLButtonElement).disabled = false;
    }
});

// Settings & Logout (Node Status / Network from get_network_info)
btnSettings.addEventListener("click", async () => {
    const nodeEl = document.getElementById("settings-node-status");
    const netEl = document.getElementById("settings-network");
    try {
        const ni: any = await invoke("get_network_info");
        if (nodeEl) {
            const status = ni.peer_count > 0 ? "Connected" : (ni.block_height > 0 ? "Running" : "Initialized");
            nodeEl.textContent = status;
            nodeEl.className = "value " + (ni.peer_count > 0 ? "success" : "");
        }
        if (netEl) netEl.textContent = `AERA Chain ${ni.chain_id} · Block ${ni.block_height} · Peers ${ni.peer_count}`;
    } catch {
        if (nodeEl) nodeEl.textContent = "Not initialized";
        if (netEl) netEl.textContent = "—";
    }
    settingsModal.classList.add("active");
});
btnCloseSettings.addEventListener("click", () => settingsModal.classList.remove("active"));

btnSwitchWallet.addEventListener("click", async () => {
    if (loginAddressInput) loginAddressInput.value = "";
    clearInputs();
    await invoke("lock_session");
    showPanel("import-panel"); // Direct navigation to Import as requested
});

btnLogout.addEventListener("click", () => {
    lockWallet();
});

// btnLoginForgot removed for security.

// Mining Controls
const btnStartMining = requireElement<HTMLElement>("btn-start-mining");
const btnStopMining = requireElement<HTMLElement>("btn-stop-mining");
const mineHashrate = requireElement<HTMLElement>("mine-hashrate");
const mineReward = requireElement<HTMLElement>("mine-reward");
const mineBlocks = requireElement<HTMLElement>("mine-blocks");
const mineDifficulty = requireElement<HTMLElement>("mine-difficulty");

const mineNodeStatus = document.getElementById("mine-node-status");

// Real-time Mining Updates (Tauri Events)
listen("mining-tick", (event: any) => {
    const stats = event.payload;
    mineHashrate.textContent = `${(stats.hashrate / 1000).toFixed(2)} KH/s`;
    mineReward.textContent = `${stats.current_reward.toFixed(2)} AERA`;
    mineBlocks.textContent = stats.blocks_mined.toString();
    if (mineDifficulty) mineDifficulty.textContent = stats.difficulty.toString();
    if (mineNodeStatus) {
        mineNodeStatus.textContent = stats.is_active ? "Mining active" : "Idle";
        mineNodeStatus.classList.toggle("success", !!stats.is_active);
    }
    if (stats.is_active) {
        btnStartMining.style.display = "none";
        btnStopMining.style.display = "block";
    } else {
        btnStartMining.style.display = "block";
        btnStopMining.style.display = "none";
    }
});

btnStartMining.addEventListener("click", async () => {
    try {
        await invoke("start_mining", { address: currentAddress });
        btnStartMining.style.display = "none";
        btnStopMining.style.display = "block";
    } catch (e) {
        alert("Failed to start mining: " + e);
    }
});

btnStopMining.addEventListener("click", async () => {
    try {
        await invoke("stop_mining");
        btnStartMining.style.display = "block";
        btnStopMining.style.display = "none";
        if (mineNodeStatus) {
            mineNodeStatus.textContent = "Idle";
            mineNodeStatus.classList.remove("success");
        }
    } catch (e) {
        alert("Failed to stop mining: " + e);
    }
});
