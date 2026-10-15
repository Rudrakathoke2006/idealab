import React, { useState } from "react";

export interface DeviceInfo {
  deviceId: string;
  displayName: string;
  fingerprint: string;
  isVerified: boolean;
  lastSeenTs?: number;
}

interface DeviceVerificationProps {
  devices: DeviceInfo[];
  requireVerification: boolean;
  onVerifyDevice?: (deviceId: string) => void;
}

export const DeviceVerification: React.FC<DeviceVerificationProps> = ({
  devices,
  requireVerification,
  onVerifyDevice
}) => {
  const [verifyingId, setVerifyingId] = useState<string | null>(null);

  const handleVerify = (devId: string) => {
    setVerifyingId(devId);
    setTimeout(() => {
      onVerifyDevice?.(devId);
      setVerifyingId(null);
    }, 600);
  };

  return (
    <div style={{
      background: "#0d1117",
      border: "1px solid #30363d",
      borderRadius: "8px",
      padding: "16px",
      color: "#c9d1d9",
      fontSize: "13px"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <h4 style={{ margin: 0, color: "#58a6ff", display: "flex", alignItems: "center", gap: "8px" }}>
          <span>🛡️</span> Cryptographic Device Trust & Verification
        </h4>
        <span style={{
          fontSize: "11px",
          padding: "3px 8px",
          borderRadius: "12px",
          background: requireVerification ? "rgba(210, 153, 34, 0.15)" : "rgba(56, 139, 253, 0.15)",
          color: requireVerification ? "#e3b341" : "#58a6ff",
          border: `1px solid ${requireVerification ? "#d29922" : "#388bfd"}`
        }}>
          {requireVerification ? "Strict: Verification Required" : "Permissive: Warning Only"}
        </span>
      </div>

      <p style={{ margin: "0 0 12px 0", color: "#8b949e", fontSize: "12px" }}>
        Matrix E2EE requires verifying the cryptographic keys of recipient devices to guarantee protection against homeserver key-substitution attacks.
      </p>

      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {devices.map((dev) => (
          <div
            key={dev.deviceId}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "10px 12px",
              background: "#161b22",
              border: `1px solid ${dev.isVerified ? "#238636" : "#da3633"}`,
              borderRadius: "6px"
            }}
          >
            <div>
              <div style={{ fontWeight: 600, color: "#f0f6fc", display: "flex", alignItems: "center", gap: "6px" }}>
                <span>{dev.isVerified ? "✅" : "⚠️"}</span>
                {dev.displayName || dev.deviceId}
                <span style={{
                  fontSize: "10px",
                  padding: "2px 6px",
                  borderRadius: "4px",
                  background: dev.isVerified ? "#238636" : "#da3633",
                  color: "#ffffff"
                }}>
                  {dev.isVerified ? "VERIFIED" : "UNVERIFIED"}
                </span>
              </div>
              <div style={{ fontFamily: "monospace", fontSize: "11px", color: "#8b949e", marginTop: "4px" }}>
                Key: {dev.fingerprint}
              </div>
            </div>

            {!dev.isVerified && (
              <button
                onClick={() => handleVerify(dev.deviceId)}
                disabled={verifyingId === dev.deviceId}
                style={{
                  background: "#1f6feb",
                  color: "#ffffff",
                  border: "none",
                  borderRadius: "4px",
                  padding: "6px 12px",
                  cursor: "pointer",
                  fontSize: "12px",
                  fontWeight: 600
                }}
              >
                {verifyingId === dev.deviceId ? "Verifying..." : "Verify Device"}
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
