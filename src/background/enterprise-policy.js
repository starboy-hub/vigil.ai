/**
 * VIGIL Chrome Enterprise Policy Engine
 * Integrates with chrome.storage.managed so IT Administrators can push
 * pre-configured policies (Vault entries, trusted organizations, enforce mode)
 * across corporate fleets via ADMX / Group Policy / Google Admin Console.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_ENTERPRISE = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  async function loadManagedPolicy() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.managed) {
      return null;
    }
    return new Promise((resolve) => {
      chrome.storage.managed.get(null, (items) => {
        if (chrome.runtime.lastError || !items || !Object.keys(items).length) {
          resolve(null);
        } else {
          resolve(items);
        }
      });
    });
  }

  async function syncEnterprisePolicy(vaultInstance) {
    const policy = await loadManagedPolicy();
    if (!policy) return { active: false };

    const updates = {};
    if (policy.managedPreset) {
      updates.vigil_preset = policy.managedPreset;
    }
    if (policy.managedEnforceMode !== undefined) {
      updates.vigil_enforced = Boolean(policy.managedEnforceMode);
    }
    if (Array.isArray(policy.managedTrustedSites)) {
      updates.vigil_enterprise_trusted_sites = policy.managedTrustedSites;
    }

    if (Object.keys(updates).length > 0) {
      await new Promise((res) => chrome.storage.local.set(updates, res));
    }

    // Push managed vault entries if provided by corporate policy
    if (Array.isArray(policy.managedVaultEntries) && vaultInstance && typeof vaultInstance.add === 'function') {
      for (const entry of policy.managedVaultEntries) {
        if (entry && entry.kind && entry.value) {
          try {
            await vaultInstance.add(entry.kind, entry.value);
          } catch (e) {
            console.warn('[VIGIL] Enterprise: Error adding managed vault item:', e.message);
          }
        }
      }
    }

    return { active: true, policy };
  }

  function initPolicyListener(vaultInstance) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === 'managed') {
          syncEnterprisePolicy(vaultInstance).catch(() => {});
        }
      });
    }
  }

  return {
    loadManagedPolicy,
    syncEnterprisePolicy,
    initPolicyListener
  };
}));
