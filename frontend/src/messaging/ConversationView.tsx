import React from "react";

export interface DecryptedMessage {
  id: string;
  sender: string;
  senderName: string;
  body: string;
  timestamp: string;
  isSelf: boolean;
  algorithm: string;
  verificationStatus: "VERIFIED" | "UNVERIFIED";
}

interface ConversationViewProps {
  roomName: string;
  isEncrypted: boolean;
  incidentId?: string;
  messages: DecryptedMessage[];
}

export const ConversationView: React.FC<ConversationViewProps> = ({
  roomName,
  isEncrypted,
  incidentId,
  messages
}) => {
  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      flex: 1,
      height: "100%",
      background: "#0d1117"
    }}>
      {/* Header Banner */}
      <div style={{
        padding: "12px 16px",
        borderBottom: "1px solid #30363d",
        background: "#161b22",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center"
      }}>
        <div>
          <div style={{ fontWeight: 600, color: "#f0f6fc", fontSize: "14px" }}>
            {roomName}
          </div>
          <div style={{ fontSize: "12px", color: "#8b949e", display: "flex", gap: "12px", marginTop: "2px" }}>
            <span style={{ color: "#3fb950" }}>
              🔒 End-to-End Encrypted (Megolm v1 AES-256)
            </span>
            {incidentId && (
              <span style={{ color: "#58a6ff" }}>
                Linked Incident: {incidentId}
              </span>
            )}
          </div>
        </div>

        <div style={{
          fontSize: "11px",
          padding: "4px 8px",
          background: "rgba(56, 139, 253, 0.1)",
          color: "#58a6ff",
          border: "1px solid #388bfd",
          borderRadius: "4px"
        }}>
          Zero-Plaintext Boundary Active: Messages Decrypted Locally on Device
        </div>
      </div>

      {/* Messages Scroll View */}
      <div style={{
        flex: 1,
        overflowY: "auto",
        padding: "16px",
        display: "flex",
        flexDirection: "column",
        gap: "12px"
      }}>
        {messages.length === 0 ? (
          <div style={{ textAlign: "center", color: "#8b949e", padding: "40px 0", fontSize: "13px" }}>
            🔒 This room is end-to-end encrypted. Messages sent here are encrypted on your device and cannot be read by the server.
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              style={{
                alignSelf: msg.isSelf ? "flex-end" : "flex-start",
                maxWidth: "70%",
                background: msg.isSelf ? "#1f6feb" : "#21262d",
                color: "#f0f6fc",
                borderRadius: "8px",
                padding: "8px 12px",
                fontSize: "13px",
                lineHeight: "1.4"
              }}
            >
              <div style={{
                fontSize: "11px",
                color: msg.isSelf ? "#c9d1d9" : "#8b949e",
                marginBottom: "4px",
                display: "flex",
                justifyContent: "space-between",
                gap: "8px"
              }}>
                <span>{msg.senderName}</span>
                <span>{msg.timestamp}</span>
              </div>

              {/* Render safely as plain text to eliminate XSS */}
              <div style={{ wordBreak: "break-word", whiteSpace: "pre-wrap" }}>
                {msg.body}
              </div>

              <div style={{
                fontSize: "10px",
                color: msg.isSelf ? "rgba(255,255,255,0.7)" : "#8b949e",
                marginTop: "4px",
                textAlign: "right"
              }}>
                {msg.verificationStatus === "VERIFIED" ? "✓ Verified Device" : "⚠️ Unverified Device"} · {msg.algorithm}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
