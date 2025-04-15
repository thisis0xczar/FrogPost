/**
 * FrogPost Extension
 * Originally Created by thisis0xczar/Lidor JFrog AppSec Team
 * Refined on: 2025-04-15
 */
const STORAGE_KEYS = {
    sinks: 'customSinks',
    checks: 'customChecks'
};

const sinkForm = document.getElementById('addSinkForm');
const checkForm = document.getElementById('addCheckForm');
const sinksTableBody = document.getElementById('customSinksTableBody');
const checksTableBody = document.getElementById('customChecksTableBody');
const statusDiv = document.getElementById('statusMessage');

function showStatus(message, isError = false) {
    statusDiv.textContent = message;
    statusDiv.className = isError ? 'status error' : 'status success';
    setTimeout(() => {
        statusDiv.textContent = '';
        statusDiv.className = 'status';
    }, 3000);
}

function validateRegex(pattern) {
    try {
        new RegExp(pattern);
        return true;
    } catch (e) {
        return false;
    }
}

function renderTable(definitions, tableBody, type) {
    tableBody.innerHTML = '';
    if (!definitions || definitions.length === 0) {
        const row = tableBody.insertRow();
        const cell = row.insertCell();
        cell.colSpan = type === 'sink' ? 5 : 4;
        cell.textContent = `No custom ${type}s defined.`;
        cell.style.textAlign = 'center';
        cell.style.fontStyle = 'italic';
        return;
    }

    definitions.forEach((def, index) => {
        const row = tableBody.insertRow();
        row.insertCell().textContent = def.name;
        row.insertCell().textContent = def.pattern;
        row.insertCell().textContent = def.severity;
        if (type === 'sink') {
            row.insertCell().textContent = def.category || '';
        }
        const deleteCell = row.insertCell();
        const deleteBtn = document.createElement('button');
        deleteBtn.textContent = 'Delete';
        deleteBtn.className = 'delete-btn';
        deleteBtn.dataset.index = index;
        deleteBtn.dataset.type = type;
        deleteBtn.addEventListener('click', handleDeleteClick);
        deleteCell.appendChild(deleteBtn);
    });
}

async function loadDefinitions() {
    try {
        const data = await chrome.storage.sync.get([STORAGE_KEYS.sinks, STORAGE_KEYS.checks]);
        renderTable(data[STORAGE_KEYS.sinks], sinksTableBody, 'sink');
        renderTable(data[STORAGE_KEYS.checks], checksTableBody, 'check');
    } catch (e) {
        console.error("Error loading definitions:", e);
        showStatus("Error loading definitions.", true);
    }
}

async function addDefinition(type) {
    const isSink = type === 'sink';
    const form = isSink ? sinkForm : checkForm;
    const nameInput = document.getElementById(isSink ? 'sinkName' : 'checkName');
    const patternInput = document.getElementById(isSink ? 'sinkPattern' : 'checkPattern');
    const severityInput = document.getElementById(isSink ? 'sinkSeverity' : 'checkSeverity');
    const categoryInput = isSink ? document.getElementById('sinkCategory') : null;
    const storageKey = isSink ? STORAGE_KEYS.sinks : STORAGE_KEYS.checks;

    const name = nameInput.value.trim();
    const pattern = patternInput.value.trim();
    const severity = severityInput.value;
    const category = isSink ? (categoryInput.value.trim() || undefined) : undefined; // Store undefined if empty

    if (!name || !pattern || !severity) {
        showStatus("Name, Pattern, and Severity are required.", true);
        return;
    }

    if (!validateRegex(pattern)) {
        showStatus("Invalid Regex pattern.", true);
        return;
    }

    const newDefinition = { name, pattern, severity };
    if (isSink && category) {
        newDefinition.category = category;
    }

    try {
        const data = await chrome.storage.sync.get([storageKey]);
        const definitions = data[storageKey] || [];
        definitions.push(newDefinition);
        await chrome.storage.sync.set({ [storageKey]: definitions });
        form.reset();
        showStatus(`Custom ${type} added successfully.`);
        loadDefinitions(); // Refresh tables
    } catch (e) {
        console.error(`Error adding definition:`, e);
        showStatus(`Error adding custom ${type}.`, true);
    }
}

async function handleDeleteClick(event) {
    const button = event.target;
    const index = parseInt(button.dataset.index, 10);
    const type = button.dataset.type;
    const storageKey = type === 'sink' ? STORAGE_KEYS.sinks : STORAGE_KEYS.checks;

    if (isNaN(index) || !type) return;

    if (confirm(`Are you sure you want to delete this custom ${type}?`)) {
        try {
            const data = await chrome.storage.sync.get([storageKey]);
            let definitions = data[storageKey] || [];
            if (index >= 0 && index < definitions.length) {
                definitions.splice(index, 1);
                await chrome.storage.sync.set({ [storageKey]: definitions });
                showStatus(`Custom ${type} deleted.`);
                loadDefinitions(); // Refresh tables
            } else {
                showStatus(`Error: Invalid index for deletion.`, true);
            }
        } catch (e) {
            console.error(`Error deleting definition:`, e);
            showStatus(`Error deleting custom ${type}.`, true);
        }
    }
}

document.addEventListener('DOMContentLoaded', loadDefinitions);
sinkForm.addEventListener('submit', (e) => {
    e.preventDefault();
    addDefinition('sink');
});
checkForm.addEventListener('submit', (e) => {
    e.preventDefault();
    addDefinition('check');
});
