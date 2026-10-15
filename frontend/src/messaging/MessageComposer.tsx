import React, { useState } from "react";

interface MessageComposerProps {
  onSendMessage: (text: string) => Promise<void>;
  disabled?: boolean;
}

export const MessageComposer: React.FC<MessageComposerProps> = ({
  onSendMessage,
  disabled = false
}) => {
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSend = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!text.trim() || sending || disabled) return;

    setSending(true);
    setError(null);
    try {
      await onSendMessage(text.trim());
      setText("");
    } catch (err: any) {
      setError(err.message || "Failed to encrypt and transmit message.");
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div style={{
      borderTop: "1px solid #30363d",
      padding: "12px 16px",
      background: "#161b22"
    }}>
      {error && (
        <div style={{
          background: "rgba(248, 81, 73, 0.15)",
          color: "#f85149",
          border: "1px solid #f85149",
          padding: "6px 12px",
          borderRadius: "4px",
          fontSize: "12px",
          marginBottom: "8px"
        }}>
          ⚠️ {error}
        </div>
      )}

      <form onSubmit={handleSend} style={{ display: "flex", gap: "10px", alignItems: "flex-end" }}>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={disabled ? "Crypto uninitialized or room locked..." : "Type an encrypted message... (Enter to send, Shift+Enter for newline)"}
          disabled={disabled || sending}
          rows={2}
          style={{
            flex: 1,
            background: "#0d1117",
            border: "1px solid #30363d",
            borderRadius: "6px",
            color: "#f0f6fc",
            padding: "8px 12px",
            fontSize: "13px",
            resize: "none",
            outline: "none",
            fontFamily: "inherit"
          }}
        />

        <button
          type="submit"
          disabled={disabled || sending || !text.trim()}
          style={{
            background: "#238636",
            color: "#ffffff",
            border: "none",
            borderRadius: "6px",
            padding: "10px 18px",
            fontWeight: 600,
            fontSize: "13px",
            cursor: (disabled || sending || !text.trim()) ? "not-allowed" : "pointer",
            opacity: (disabled || sending || !text.trim()) ? 0.6 : 1,
            display: "flex",
            alignItems: "center",
            gap: "6px"
          }}
        >
          <span>🔒</span>
          {sending ? "Encrypting..." : "Send"}
        </button>
      </form>
    </div>
  );
};
