/**
 * AEGIS-X Secure Messaging API Client
 * Manages authorization, recipient discovery, and incident-room linking.
 * CRITICAL RULE: NEVER sends message plaintext, encryption keys, or crypto passwords to FastAPI.
 */

export interface BootstrapConfig {
  enabled: boolean;
  homeserver_url: string;
  matrix_user_id: string;
  encryption_required: boolean;
  require_device_verification: boolean;
  policy_version: string;
}

export interface RecipientItem {
  user_id: string;
  display_name: string;
  matrix_user_id: string;
  email?: string;
}

export interface RoomAuthorizationDecision {
  allowed: boolean;
  recipient_matrix_user_id: string;
  recipient_user_id: string;
  encryption_required: boolean;
  require_device_verification: boolean;
  policy_version: string;
}

export interface LinkedRoomMetadata {
  link_id: string;
  matrix_room_id: string;
  incident_id: string;
  room_type: string;
  policy_version: string;
  encryption_required: boolean;
  require_device_verification: boolean;
  created_at?: string;
}

export class MessagingApi {
  private baseUrl: string;
  private token: string;

  constructor(token: string, baseUrl: string = "/api/v1") {
    this.token = token;
    this.baseUrl = baseUrl;
  }

  private async fetchJson<T>(url: string, options: RequestInit = {}): Promise<T> {
    const headers = {
      "Authorization": `Bearer ${this.token}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    };

    const res = await fetch(`${this.baseUrl}${url}`, { ...options, headers });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Request failed with status ${res.status}`);
    }
    return res.json();
  }

  public async getBootstrap(): Promise<BootstrapConfig> {
    return this.fetchJson<BootstrapConfig>("/messaging/bootstrap");
  }

  public async searchRecipients(query: string = ""): Promise<RecipientItem[]> {
    const qParam = query ? `?q=${encodeURIComponent(query)}` : "";
    const data = await this.fetchJson<{ items: RecipientItem[] }>(`/messaging/recipients${qParam}`);
    return data.items || [];
  }

  public async authorizeDirectRoom(recipientUserId: string): Promise<RoomAuthorizationDecision> {
    return this.fetchJson<RoomAuthorizationDecision>("/messaging/rooms/authorize", {
      method: "POST",
      body: JSON.stringify({ recipient_user_id: recipientUserId })
    });
  }

  public async linkIncidentRoom(matrixRoomId: string, incidentId: string): Promise<LinkedRoomMetadata> {
    return this.fetchJson<LinkedRoomMetadata>("/messaging/rooms/link", {
      method: "POST",
      body: JSON.stringify({
        matrix_room_id: matrixRoomId,
        room_type: "INCIDENT",
        incident_id: incidentId
      })
    });
  }

  public async getIncidentRoom(incidentId: string): Promise<LinkedRoomMetadata> {
    return this.fetchJson<LinkedRoomMetadata>(`/incidents/${incidentId}/messaging-room`);
  }

  public async getSecurityEvents(): Promise<any[]> {
    return this.fetchJson<any[]>("/messaging/security-events");
  }
}
