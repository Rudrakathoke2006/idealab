import React from "react";

export interface ConversationSummary {
  roomId: string;
  name: string;
  roomType: "DIRECT" | "INCIDENT";
  incidentId?: string;
  lastMessagePreview?: string;
  timestamp?: string;
  isEncrypted: boolean;
  hasUnverifiedDevices: boolean;
}

interface ConversationListProps {
  conversations: ConversationSummary[];
  selectedRoomId: string | null;
  onSelectConversation: (roomId: string) => void;
  onNewConversationClick: () => void;
}

export const ConversationList: React.FC<ConversationListProps> = ({
  conversations,
  selectedRoomId,
  onSelectConversation,
  onNewConversationClick
}) => {
  return (
    <div style={{
      width: "300px",
      background: "#0d1117",
      borderRight: "1px solid #30363d",
      display: "flex",
      flexDirection: "column",
      height: "100%"
    }}>
      <div style={{
        padding: "16px",
        borderBottom: "1px solid #30363d",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center"
      }}>
        <h3 style={{ margin: 0, fontSize: "15px", color: "#f0f6fc", display: "flex", alignItems: "center", gap: "8px" }}>
          <span>🔐</span> Secure Channels
        </h3>
        <button
          onClick={onNewConversationClick}
          style={{
            background: "#238636",
            color: "#ffffff",
            border: "none",
            borderRadius: "6px",
            padding: "6px 12px",
            fontSize: "12px",
            fontWeight: 600,
            cursor: "pointer"
          }}
        >
          + New Chat
        </button>
      </div>

      <div style={{ overflowY: "auto", flex: 1, padding: "8px" }}>
        {conversations.length === 0 ? (
          <div style={{ textAlign: "center", padding: "32px 16px", color: "#8b949e", fontSize: "13px" }}>
            No active conversations. Start an authorized room above.
          </div>
        ) : (
          conversations.map((c) => {
            const isSelected = c.roomId === selectedRoomId;
            return (
              <div
                key={c.roomId}
                onClick={() => onSelectConversation(c.roomId)}
                style={{
                  padding: "10px 12px",
                  borderRadius: "6px",
                  marginBottom: "4px",
                  cursor: "pointer",
                  background: isSelected ? "rgba(56, 139, 253, 0.15)" : "transparent",
                  border: isSelected ? "1px solid #388bfd" : "1px solid transparent",
                  transition: "background 0.2s"
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                  <span style={{ fontWeight: 600, color: "#f0f6fc", fontSize: "13px" }}>
                    {c.roomType === "INCIDENT" ? "🚨 " : "👤 "}
                    {c.name}
                  </span>
                  <span style={{ fontSize: "11px", color: "#8b949e" }}>
                    {c.isEncrypted ? "🔒 E2EE" : "⚠️ Plain"}
                  </span>
                </div>
                {c.incidentId && (
                  <div style={{ fontSize: "11px", color: "#58a6ff", marginBottom: "2px" }}>
                    Incident: {c.incidentId}
                  </div>
                )}
                <div style={{
                  fontSize: "12px",
                  color: "#8b949e",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis"
                }}>
                  {c.lastMessagePreview || "Encrypted message envelope"}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
