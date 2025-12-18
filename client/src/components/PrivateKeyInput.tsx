import { useState, useRef, useCallback } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Key, Upload, Loader2, AlertCircle } from "lucide-react";

interface PrivateKeyInputProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (privateKey: string, passphrase?: string) => void;
  serverName: string;
  username: string;
  isConnecting?: boolean;
  error?: string | null;
}

const SESSION_STORAGE_KEY = "ssh_private_key";

export function PrivateKeyInput({
  open,
  onOpenChange,
  onSubmit,
  serverName,
  username,
  isConnecting = false,
  error = null,
}: PrivateKeyInputProps) {
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [rememberKey, setRememberKey] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Try to load key from session storage on mount
  useState(() => {
    const savedKey = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (savedKey) {
      setPrivateKey(savedKey);
      setRememberKey(true);
    }
  });

  const validateKey = (key: string): boolean => {
    const trimmed = key.trim();

    // Check for common PEM markers
    const validMarkers = [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----BEGIN DSA PRIVATE KEY-----",
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ];

    const hasValidStart = validMarkers.some((marker) =>
      trimmed.startsWith(marker)
    );
    const hasValidEnd = trimmed.includes("-----END");

    return hasValidStart && hasValidEnd;
  };

  const handleKeyChange = (value: string) => {
    setPrivateKey(value);
    setValidationError(null);
  };

  const handleFileUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setPrivateKey(content);
        setValidationError(null);
      };
      reader.onerror = () => {
        setValidationError("Failed to read file");
      };
      reader.readAsText(file);

      // Reset input so same file can be selected again
      event.target.value = "";
    },
    []
  );

  const handleSubmit = () => {
    const trimmedKey = privateKey.trim();

    if (!trimmedKey) {
      setValidationError("Please enter or upload a private key");
      return;
    }

    if (!validateKey(trimmedKey)) {
      setValidationError(
        "Invalid private key format. Key should be in PEM format (starting with -----BEGIN ... PRIVATE KEY-----)"
      );
      return;
    }

    // Save to session storage if requested
    if (rememberKey) {
      sessionStorage.setItem(SESSION_STORAGE_KEY, trimmedKey);
    } else {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }

    onSubmit(trimmedKey, passphrase || undefined);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && e.ctrlKey) {
      handleSubmit();
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg" onKeyDown={handleKeyDown}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            SSH Private Key
          </DialogTitle>
          <DialogDescription>
            Enter your private key to connect as <strong>{username}</strong> to{" "}
            <strong>{serverName}</strong>. Your key stays in the browser and is
            never sent to our servers.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {(error || validationError) && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error || validationError}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="privateKey">Private Key (PEM format)</Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => fileInputRef.current?.click()}
                disabled={isConnecting}
              >
                <Upload className="h-4 w-4 mr-2" />
                Upload File
              </Button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".pem,.key,id_rsa,id_ed25519,id_ecdsa,id_dsa"
                onChange={handleFileUpload}
                className="hidden"
              />
            </div>
            <Textarea
              id="privateKey"
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
              value={privateKey}
              onChange={(e) => handleKeyChange(e.target.value)}
              className="font-mono text-xs h-48 resize-none"
              disabled={isConnecting}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="passphrase">
              Passphrase (optional, for encrypted keys)
            </Label>
            <Input
              id="passphrase"
              type="password"
              placeholder="Enter passphrase if key is encrypted"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              disabled={isConnecting}
            />
          </div>

          <div className="flex items-center space-x-2">
            <Checkbox
              id="rememberKey"
              checked={rememberKey}
              onCheckedChange={(checked) => setRememberKey(checked === true)}
              disabled={isConnecting}
            />
            <Label
              htmlFor="rememberKey"
              className="text-sm font-normal cursor-pointer"
            >
              Remember key for this session (cleared when tab closes)
            </Label>
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isConnecting}
          >
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isConnecting || !privateKey}>
            {isConnecting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Connecting...
              </>
            ) : (
              "Connect"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
