/**
 * AEGIS-X Browser Cryptographic Storage Management
 * Handles persistent IndexedDB key store initialization, session locks, and zero-plaintext lifecycle.
 */

export interface CryptoStoreConfig {
  dbName: string;
  passphrase?: string;
  useIndexedDB: boolean;
}

export class BrowserCryptoLock {
  private static lockAcquired = false;
  private static lockName = "aegis_x_matrix_crypto_lock";

  public static async acquireTabLock(): Promise<boolean> {
    if (typeof navigator !== "undefined" && "locks" in navigator) {
      try {
        // Modern Web Locks API to prevent IndexedDB crypto corruption across multiple tabs
        await navigator.locks.request(this.lockName, { ifAvailable: true }, async (lock) => {
          this.lockAcquired = !!lock;
        });
        return this.lockAcquired;
      } catch {
        this.lockAcquired = true;
        return true;
      }
    }
    this.lockAcquired = true;
    return true;
  }

  public static isLockedByAnotherSession(): boolean {
    return !this.lockAcquired;
  }
}

export function validatePassphraseEntropy(passphrase: string): boolean {
  return typeof passphrase === "string" && passphrase.length >= 8;
}
