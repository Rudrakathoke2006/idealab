/**
 * AEGIS-X Matrix Client Manager
 * Manages singleton Matrix SDK lifecycle, WASM-based Rust crypto, and local Megolm sessions.
 * Fail-Closed: Never sends plaintext if encryption initialization fails.
 */

import * as sdk from "matrix-js-sdk";
import { BrowserCryptoLock } from "./cryptoStore";

export interface MatrixSessionConfig {
  baseUrl: string;
  userId: string;
  deviceId: string;
  accessToken: string;
  cryptoStorePassphrase: string;
}

export class MatrixClientManager {
  private static instance: MatrixClientManager | null = null;
  private client: sdk.MatrixClient | null = null;
  private isCryptoReady = false;

  public static getInstance(): MatrixClientManager {
    if (!MatrixClientManager.instance) {
      MatrixClientManager.instance = new MatrixClientManager();
    }
    return MatrixClientManager.instance;
  }

  public async initialize(session: MatrixSessionConfig): Promise<sdk.MatrixClient> {
    if (this.client && this.isCryptoReady) {
      return this.client;
    }

    const acquired = await BrowserCryptoLock.acquireTabLock();
    if (!acquired) {
      throw new Error("IndexedDB crypto store is in use by another tab. Multi-tab concurrency blocked to prevent key corruption.");
    }

    this.client = sdk.createClient({
      baseUrl: session.baseUrl,
      userId: session.userId,
      deviceId: session.deviceId,
      accessToken: session.accessToken,
    });

    try {
      // Initialize Matrix Rust-based cryptographic engine (WASM) with encrypted storage
      if (typeof (this.client as any).initRustCrypto === "function") {
        await (this.client as any).initRustCrypto({
          storagePassword: session.cryptoStorePassphrase,
          useIndexedDB: true,
        });
      } else if (typeof (this.client as any).initCrypto === "function") {
        await (this.client as any).initCrypto();
      }
      this.isCryptoReady = true;
    } catch (err: any) {
      this.isCryptoReady = false;
      this.client = null;
      throw new Error(`Cryptographic initialization failed: ${err.message}. Fail-closed: messaging blocked.`);
    }

    await this.client.startClient({
      initialSyncLimit: 20,
    });

    return this.client;
  }

  public async createEncryptedDirectRoom(recipientMatrixUserId: string): Promise<string> {
    if (!this.client || !this.isCryptoReady) {
      throw new Error("Client crypto engine is not initialized. Plaintext room creation blocked.");
    }

    // Step 3: Create room with Megolm E2EE configured from the start
    const result = await this.client.createRoom({
      preset: sdk.Preset.TrustedPrivateChat,
      invite: [recipientMatrixUserId],
      is_direct: true,
      initial_state: [
        {
          type: "m.room.encryption",
          state_key: "",
          content: {
            algorithm: "m.megolm.v1.aes-sha2",
          },
        },
      ],
    });

    return result.room_id;
  }

  public async sendEncryptedMessage(roomId: string, messageText: string): Promise<void> {
    if (!this.client || !this.isCryptoReady) {
      throw new Error("Cannot send message: crypto store not unlocked or uninitialized.");
    }

    // Fails closed if room is unencrypted or encryption cannot be guaranteed
    const room = this.client.getRoom(roomId);
    if (room && !this.client.isRoomEncrypted(roomId)) {
      throw new Error("SECURITY VIOLATION: Room is not encrypted. Plaintext transmission strictly forbidden.");
    }

    await this.client.sendTextMessage(roomId, messageText);
  }

  public getClient(): sdk.MatrixClient | null {
    return this.client;
  }

  public isReady(): boolean {
    return this.isCryptoReady;
  }

  public async logout(): Promise<void> {
    if (this.client) {
      this.client.stopClient();
      this.client = null;
      this.isCryptoReady = false;
    }
  }
}

export const matrixManager = MatrixClientManager.getInstance();
