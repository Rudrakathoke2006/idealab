import React, { useState, useEffect } from "react";
import { MessagingApi, BootstrapConfig, RecipientItem } from "./MessagingApi";
import { matrixManager } from "./MatrixClientManager";
import { ConversationList, ConversationSummary } from "./ConversationList";
import { ConversationView, DecryptedMessage } from "./ConversationView";
import { MessageComposer } from "./MessageComposer";
import { DeviceVerification, DeviceInfo } from "./DeviceVerification";

interface MessagingPageProps {
  token: string;
  currentUserId: string;
}

export const MessagingPage: React.FC<MessagingPageProps> = ({ token, currentUserId }) => {
  const [api] = useState(() => new MessagingApi(token));
  const [bootstrap, setBootstrap] = useState<BootstrapConfig | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Directory and conversation state
  const [recipients, setRecipients] = useState<RecipientItem[]>([]);
  const [selectedRecipient, setSelectedRecipient] = useState<string>("");
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [selectedRoomId, setSelectedRoomId] = useState<string | null>(null);
  const [messages, setMessages] = useState<DecryptedMessage[]>([]);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [showNewChatModal, setShowNewChatModal] = useState(false);
  const [linkIncidentId, setLinkIncidentId] = useState("");

  // 1. Fetch bootstrap on mount
  useEffect(() => {
    async function loadBootstrap() {
      try {
        setLoading(true);
        const data = await api.getBootstrap();
        setBootstrap(data);
        const recs = await api.searchRecipients();
        setRecipients(recs);
      } catch (err: any) {
        setError(err.message || "Failed to load secure messaging configuration.");
      } finally {
        setLoading(false);
      }
    }
    loadBootstrap();
  }, [api]);

  // 2. Unlock local crypto store
  const handleUnlockCrypto = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase || !bootstrap) return;

    try {
      setError(null);
      await matrixManager.initialize({
        baseUrl: bootstrap.homeserver_url,
        userId: bootstrap.matrix_user_id,
        deviceId: `WEB_${currentUserId.slice(-6)}`,
        accessToken: `simulated_matrix_oidc_${currentUserId}`,
        cryptoStorePassphrase: passphrase
      });

      setIsUnlocked(true);
      // Sample mock initial verified device
      setDevices([
        {
          deviceId: `WEB_${currentUserId.slice(-6)}`,
          displayName: "Current Browser Session",
          fingerprint: "ed25519:Ag97a...F39a0",
          isVerified: true
        }
      ]);
    } catch (err: any) {
      setError(err.message || "Cryptographic unlock failed. Check your passphrase.");
    }
  };

  // 3. Start a new authorized direct room
  const handleCreateRoom = async () => {
    if (!selectedRecipient) return;
    try {
      setError(null);
      // Step A: Request authorization from AEGIS-X FastAPI
      const authDecision = await api.authorizeDirectRoom(selectedRecipient);
      if (!authDecision.allowed) {
        throw new Error("Conversation was not authorized by security policy.");
      }

      // Step B: Initialize private encrypted room via client SDK
      const roomId = await matrixManager.createEncryptedDirectRoom(authDecision.recipient_matrix_user_id);

      // Optional: Link to incident if specified
      if (linkIncidentId.trim()) {
        await api.linkIncidentRoom(roomId, linkIncidentId.trim());
      }

      const rec = recipients.find(r => r.user_id === selectedRecipient);
      const newConv: ConversationSummary = {
        roomId,
        name: rec?.display_name || authDecision.recipient_matrix_user_id,
        roomType: linkIncidentId ? "INCIDENT" : "DIRECT",
        incidentId: linkIncidentId.trim() || undefined,
        isEncrypted: true,
        hasUnverifiedDevices: false,
        lastMessagePreview: "Room initialized with Megolm encryption"
      };

      setConversations(prev => [newConv, ...prev]);
      setSelectedRoomId(roomId);
      setShowNewChatModal(false);
      setSelectedRecipient("");
      setLinkIncidentId("");
    } catch (err: any) {
      setError(err.message || "Failed to create encrypted room.");
    }
  };

  // 4. Send encrypted message
  const handleSendMessage = async (text: string) => {
    if (!selectedRoomId) return;

    // Send through Matrix SDK in local memory
    await matrixManager.sendEncryptedMessage(selectedRoomId, text);

    const newMsg: DecryptedMessage = {
      id: `msg_${Date.now()}`,
      sender: bootstrap?.matrix_user_id || "@analyst:chat.aegis-x.internal",
      senderName: "You (SOC Analyst)",
      body: text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      isSelf: true,
      algorithm: "m.megolm.v1.aes-sha2",
      verificationStatus: "VERIFIED"
    };

    setMessages(prev => [...prev, newMsg]);
  };

  if (loading) {
    return (
      <div style={{ padding: "40px", color: "#8b949e", textAlign: "center" }}>
        Loading AEGIS-X Secure Incident Messaging...
      </div>
    );
  }

  // Cryptographic Lock Screen
  if (!isUnlocked) {
    return (
      <div style={{
        maxWidth: "460px",
        margin: "60px auto",
        background: "#161b22",
        border: "1px solid #30363d",
        borderRadius: "8px",
        padding: "24px",
        color: "#f0f6fc"
      }}>
        <div style={{ textAlign: "center", marginBottom: "20px" }}>
          <div style={{ fontSize: "36px", marginBottom: "8px" }}>🔐</div>
          <h2 style={{ margin: "0 0 6px 0", fontSize: "18px" }}>Unlock Browser Cryptographic Key Store</h2>
          <p style={{ color: "#8b949e", fontSize: "12px", margin: 0 }}>
            AEGIS-X End-to-End Encryption (E2EE) requires entering your client passphrase to decrypt the local IndexedDB key store.
          </p>
        </div>

        {error && (
          <div style={{
            background: "rgba(248, 81, 73, 0.15)",
            border: "1px solid #f85149",
            color: "#f85149",
            padding: "8px 12px",
            borderRadius: "6px",
            fontSize: "12px",
            marginBottom: "16px"
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleUnlockCrypto}>
          <div style={{ marginBottom: "16px" }}>
            <label style={{ display: "block", fontSize: "12px", color: "#8b949e", marginBottom: "6px" }}>
              Key Store Passphrase
            </label>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Enter secure device passphrase..."
              required
              style={{
                width: "100%",
                background: "#0d1117",
                border: "1px solid #30363d",
                borderRadius: "6px",
                padding: "8px 12px",
                color: "#f0f6fc",
                fontSize: "14px",
                outline: "none"
              }}
            />
          </div>

          <div style={{
            background: "#0d1117",
            padding: "10px 12px",
            borderRadius: "6px",
            fontSize: "11px",
            color: "#8b949e",
            marginBottom: "16px",
            lineHeight: "1.4"
          }}>
            🔒 <strong>Zero-Plaintext Guarantee:</strong> Your passphrase and private encryption keys never leave this browser tab. All encryption and decryption occurs locally in WebAssembly.
          </div>

          <button
            type="submit"
            style={{
              width: "100%",
              background: "#238636",
              color: "#ffffff",
              border: "none",
              borderRadius: "6px",
              padding: "10px",
              fontWeight: 600,
              fontSize: "14px",
              cursor: "pointer"
            }}
          >
            Unlock & Initialize Cryptography
          </button>
        </form>
      </div>
    );
  }

  const selectedConv = conversations.find(c => c.roomId === selectedRoomId);

  return (
    <div style={{
      display: "flex",
      height: "750px",
      background: "#0d1117",
      border: "1px solid #30363d",
      borderRadius: "8px",
      overflow: "hidden"
    }}>
      {/* Left Sidebar: Conversations */}
      <ConversationList
        conversations={conversations}
        selectedRoomId={selectedRoomId}
        onSelectConversation={(rId) => setSelectedRoomId(rId)}
        onNewConversationClick={() => setShowNewChatModal(true)}
      />

      {/* Main Chat Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {selectedConv ? (
          <>
            <ConversationView
              roomName={selectedConv.name}
              isEncrypted={selectedConv.isEncrypted}
              incidentId={selectedConv.incidentId}
              messages={messages}
            />
            <MessageComposer onSendMessage={handleSendMessage} />
          </>
        ) : (
          <div style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            color: "#8b949e",
            padding: "32px",
            textAlign: "center"
          }}>
            <div style={{ fontSize: "48px", marginBottom: "16px" }}>🔒</div>
            <h3 style={{ color: "#f0f6fc", margin: "0 0 8px 0" }}>Zero-Plaintext Incident Messaging Active</h3>
            <p style={{ maxWidth: "420px", fontSize: "13px", lineHeight: "1.5" }}>
              Select an encrypted channel on the left or initialize a new authorized incident room to collaborate securely.
            </p>
            <button
              onClick={() => setShowNewChatModal(true)}
              style={{
                marginTop: "16px",
                background: "#238636",
                color: "#ffffff",
                border: "none",
                borderRadius: "6px",
                padding: "8px 16px",
                fontWeight: 600,
                cursor: "pointer"
              }}
            >
              + Start Authorized Conversation
            </button>
          </div>
        )}
      </div>

      {/* Right Sidebar: Cryptographic Device Verification */}
      <div style={{ width: "320px", borderLeft: "1px solid #30363d", padding: "16px", overflowY: "auto" }}>
        <DeviceVerification
          devices={devices}
          requireVerification={bootstrap?.require_device_verification ?? true}
          onVerifyDevice={(devId) => {
            setDevices(prev => prev.map(d => d.deviceId === devId ? { ...d, isVerified: true } : d));
          }}
        />
      </div>

      {/* New Room Modal */}
      {showNewChatModal && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: "rgba(0,0,0,0.7)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 1000
        }}>
          <div style={{
            background: "#161b22",
            border: "1px solid #30363d",
            borderRadius: "8px",
            padding: "24px",
            width: "420px",
            color: "#f0f6fc"
          }}>
            <h3 style={{ margin: "0 0 16px 0", fontSize: "16px" }}>Authorize New Encrypted Conversation</h3>

            {error && (
              <div style={{ color: "#f85149", fontSize: "12px", marginBottom: "12px" }}>
                {error}
              </div>
            )}

            <div style={{ marginBottom: "14px" }}>
              <label style={{ display: "block", fontSize: "12px", color: "#8b949e", marginBottom: "6px" }}>
                Select Authorized Tenant Recipient
              </label>
              <select
                value={selectedRecipient}
                onChange={(e) => setSelectedRecipient(e.target.value)}
                style={{
                  width: "100%",
                  background: "#0d1117",
                  border: "1px solid #30363d",
                  borderRadius: "6px",
                  padding: "8px",
                  color: "#f0f6fc",
                  fontSize: "13px"
                }}
              >
                <option value="">-- Choose Analyst --</option>
                {recipients.map(r => (
                  <option key={r.user_id} value={r.user_id}>
                    {r.display_name} ({r.matrix_user_id})
                  </option>
                ))}
              </select>
            </div>

            <div style={{ marginBottom: "16px" }}>
              <label style={{ display: "block", fontSize: "12px", color: "#8b949e", marginBottom: "6px" }}>
                Optional: Link to Incident ID
              </label>
              <input
                type="text"
                value={linkIncidentId}
                onChange={(e) => setLinkIncidentId(e.target.value)}
                placeholder="e.g. inc-2026-0881"
                style={{
                  width: "100%",
                  background: "#0d1117",
                  border: "1px solid #30363d",
                  borderRadius: "6px",
                  padding: "8px",
                  color: "#f0f6fc",
                  fontSize: "13px"
                }}
              />
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
              <button
                onClick={() => setShowNewChatModal(false)}
                style={{
                  background: "transparent",
                  border: "1px solid #30363d",
                  color: "#c9d1d9",
                  borderRadius: "6px",
                  padding: "6px 12px",
                  cursor: "pointer"
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleCreateRoom}
                disabled={!selectedRecipient}
                style={{
                  background: "#238636",
                  color: "#ffffff",
                  border: "none",
                  borderRadius: "6px",
                  padding: "6px 14px",
                  fontWeight: 600,
                  cursor: selectedRecipient ? "pointer" : "not-allowed",
                  opacity: selectedRecipient ? 1 : 0.6
                }}
              >
                Authorize & Create Room
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
