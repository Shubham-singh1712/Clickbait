import { useRef, useState } from "react";
import {
  FileImage,
  Link as LinkIcon,
  MessageSquareText,
  Upload,
  X,
} from "lucide-react";

function VerificationInput({
  onVerify,
  loading,
}) {
  const [mode, setMode] = useState("message");
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);

  const fileInputRef = useRef(null);

  const modes = [
    {
      id: "message",
      label: "Message",
      icon: MessageSquareText,
    },
    {
      id: "url",
      label: "URL",
      icon: LinkIcon,
    },
    {
      id: "screenshot",
      label: "Screenshot",
      icon: FileImage,
    },
  ];

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (mode === "message") {
      if (!message.trim()) return;

      await onVerify({
        type: "message",
        payload: {
          text: message,
        },
      });

      return;
    }

    if (mode === "url") {
      if (!url.trim()) return;

      await onVerify({
        type: "url",
        payload: {
          url,
        },
      });

      return;
    }

    if (mode === "screenshot") {
      if (!file) return;

      await onVerify({
        type: "screenshot",
        file,
      });
    }
  };

  const removeFile = () => {
    setFile(null);

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="verification-panel">

      <div className="mode-tabs">
        {modes.map((item) => {
          const Icon = item.icon;

          return (
            <button
              key={item.id}
              type="button"
              className={
                mode === item.id
                  ? "mode-tab active"
                  : "mode-tab"
              }
              onClick={() => setMode(item.id)}
            >
              <Icon size={18} />
              {item.label}
            </button>
          );
        })}
      </div>

      <form onSubmit={handleSubmit}>

        {mode === "message" && (
          <div className="input-section">
            <label>
              Paste the communication
            </label>

            <textarea
              value={message}
              onChange={(event) =>
                setMessage(event.target.value)
              }
              placeholder="Paste an internship offer, scholarship notice, exam circular, fee message or other communication here..."
              rows={9}
            />

            <div className="input-footer">
              <span>
                {message.length} characters
              </span>
            </div>
          </div>
        )}

        {mode === "url" && (
          <div className="input-section">
            <label>
              Enter the notice URL
            </label>

            <div className="url-input-wrapper">
              <LinkIcon size={19} />

              <input
                type="url"
                value={url}
                onChange={(event) =>
                  setUrl(event.target.value)
                }
                placeholder="https://example.com/notice"
              />
            </div>
          </div>
        )}

        {mode === "screenshot" && (
          <div className="input-section">
            <label>
              Upload a notice screenshot
            </label>

            {!file ? (
              <button
                type="button"
                className="upload-zone"
                onClick={() =>
                  fileInputRef.current?.click()
                }
              >
                <div className="upload-icon">
                  <Upload size={30} />
                </div>

                <strong>
                  Choose screenshot
                </strong>

                <span>
                  PNG, JPG or JPEG
                </span>
              </button>
            ) : (
              <div className="file-preview">
                <div className="file-info">
                  <FileImage size={25} />

                  <div>
                    <strong>{file.name}</strong>

                    <span>
                      {(file.size / 1024).toFixed(1)} KB
                    </span>
                  </div>
                </div>

                <button
                  type="button"
                  className="icon-button"
                  onClick={removeFile}
                >
                  <X size={18} />
                </button>
              </div>
            )}

            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/jpg"
              hidden
              onChange={(event) =>
                setFile(event.target.files?.[0] || null)
              }
            />
          </div>
        )}

        <button
          type="submit"
          className="verify-button"
          disabled={
            loading ||
            (mode === "message" && !message.trim()) ||
            (mode === "url" && !url.trim()) ||
            (mode === "screenshot" && !file)
          }
        >
          <ShieldCheck size={20} />

          {loading
            ? "Analyzing Communication..."
            : "Verify Communication"}
        </button>
      </form>
    </div>
  );
}

export default VerificationInput;