import { useRef, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Upload,
  FileText,
  CheckCircle2,
  AlertTriangle,
  X,
  Loader2,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import {
  uploadConfig,
  type UploadConfigBatchItem,
  type UploadConfigBatchResponse,
  type UploadConfigResponse,
} from "@/lib/api";

interface UploadModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUploadComplete?: () => void;
}

const ACCEPTED = ".xml,.conf,.csv,.json,.xlsx,.xls";

const VENDOR_GUIDE = [
  { vendor: "Palo Alto (PAN-OS)", ext: ".xml", hint: "Export from Panorama or device running config." },
  { vendor: "Cisco ASA / Router / Switch", ext: ".conf", hint: "Upload several device configs together for one pass." },
  { vendor: "FortiGate", ext: ".conf", hint: "Keep 'forti' in the filename so detection stays explicit." },
  { vendor: "Traffic / Log Data", ext: ".csv / .json / .xlsx", hint: "Traffic and threat datasets can be uploaded in the same batch." },
];

type Phase = "idle" | "uploading" | "done" | "error";

function formatFileSize(size: number) {
  return size >= 1e6 ? `${(size / 1e6).toFixed(1)} MB` : `${(size / 1024).toFixed(1)} KB`;
}

function normalizeUploadResults(
  response: UploadConfigResponse | UploadConfigBatchResponse
): UploadConfigBatchItem[] {
  if ("results" in response) {
    return response.results;
  }
  return [
    {
      upload_id: response.upload_id,
      vendor: response.vendor,
      filename: response.filename ?? "Uploaded file",
      message: response.message ?? null,
      processed_rows: response.processed_rows ?? null,
      errors_count: response.errors_count ?? null,
    },
  ];
}

export function UploadModal({ open, onOpenChange, onUploadComplete }: UploadModalProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");
  const [results, setResults] = useState<UploadConfigBatchItem[]>([]);
  const [guideOpen, setGuideOpen] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  function reset() {
    setFiles([]);
    setPhase("idle");
    setProgress(0);
    setErrorMsg("");
    setResults([]);
    setGuideOpen(false);
  }

  function handleClose(nextOpen: boolean) {
    onOpenChange(nextOpen);
    if (!nextOpen) reset();
  }

  function mergeFiles(incoming: FileList | File[]) {
    const next = Array.isArray(incoming) ? incoming : Array.from(incoming);
    const byKey = new Map<string, File>();
    for (const file of [...files, ...next]) {
      byKey.set(`${file.name}:${file.size}:${file.lastModified}`, file);
    }
    setFiles(Array.from(byKey.values()));
    setPhase("idle");
    setErrorMsg("");
  }

  function handleFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files?.length) {
      mergeFiles(e.target.files);
    }
    e.target.value = "";
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    if (e.dataTransfer.files.length) {
      mergeFiles(e.dataTransfer.files);
    }
  }

  function removeFile(target: File) {
    setFiles((current) =>
      current.filter(
        (file) =>
          !(file.name === target.name && file.size === target.size && file.lastModified === target.lastModified)
      )
    );
  }

  async function handleUpload() {
    if (!files.length) return;
    setPhase("uploading");
    setProgress(0);
    setErrorMsg("");
    setResults([]);

    let p = 0;
    const tick = setInterval(() => {
      p = Math.min(p + Math.max(2, Math.round(18 / Math.max(files.length, 1))), 92);
      setProgress(p);
    }, 180);

    try {
      const response = await uploadConfig(files);
      clearInterval(tick);
      setResults(normalizeUploadResults(response));
      setProgress(100);
      setPhase("done");
      onUploadComplete?.();
      window.dispatchEvent(new CustomEvent("firewall-upload-complete"));
    } catch (err) {
      clearInterval(tick);
      setErrorMsg((err as Error).message || "Upload failed");
      setPhase("error");
    }
  }

  const totalSize = files.reduce((sum, file) => sum + file.size, 0);

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-2xl bg-card border-border">
        <DialogHeader>
          <DialogTitle className="text-sm font-semibold flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            Upload Firewall Data
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 mt-1">
          <div className="bg-primary/5 border border-primary/20 rounded-lg p-3">
            <p className="text-xs text-muted-foreground">
              Upload one file or a full batch. The backend will parse each file, detect the device type or data format,
              and run the same analysis pipeline across the uploaded set.
            </p>
          </div>

          <div className="bg-secondary/30 rounded-lg overflow-hidden">
            <button
              onClick={() => setGuideOpen(!guideOpen)}
              className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-medium text-foreground hover:bg-secondary/50 transition-smooth"
            >
              Supported formats
              {guideOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
            <div className={`overflow-hidden transition-all duration-200 ${guideOpen ? "max-h-72" : "max-h-0"}`}>
              <div className="px-4 pb-3 space-y-2">
                {VENDOR_GUIDE.map(({ vendor, ext, hint }) => (
                  <div key={vendor} className="flex gap-3">
                    <span className="text-xs font-mono bg-secondary px-1.5 py-0.5 rounded shrink-0 self-start">{ext}</span>
                    <div>
                      <p className="text-xs font-medium text-foreground">{vendor}</p>
                      <p className="text-xs text-muted-foreground">{hint}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {phase !== "done" && (
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileRef.current?.click()}
              className="border-2 border-dashed border-muted hover:border-primary/50 transition-smooth bg-secondary/20 rounded-xl p-8 text-center cursor-pointer select-none"
            >
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                accept={ACCEPTED}
                multiple
                onChange={handleFileInput}
              />
              <Upload className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-foreground font-medium">
                {files.length ? "Add or replace files" : "Choose files or drag them here"}
              </p>
              <p className="text-xs text-muted-foreground mt-1">Multi-file upload enabled for configs and datasets</p>
            </div>
          )}

          {files.length > 0 && phase === "idle" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>{files.length} file{files.length === 1 ? "" : "s"} selected</span>
                <span>{formatFileSize(totalSize)}</span>
              </div>

              <div className="max-h-60 overflow-y-auto space-y-2 pr-1">
                {files.map((file) => (
                  <div key={`${file.name}:${file.size}:${file.lastModified}`} className="flex items-center gap-3 bg-secondary/30 rounded-lg p-3">
                    <FileText className="h-5 w-5 text-primary shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-foreground truncate">{file.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {formatFileSize(file.size)} - {file.name.split(".").pop()?.toUpperCase()}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0 shrink-0"
                      onClick={(e) => {
                        e.stopPropagation();
                        removeFile(file);
                      }}
                    >
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {files.length > 0 && phase === "idle" && (
            <Button className="w-full" onClick={handleUpload}>
              <Upload className="h-4 w-4 mr-2" />
              Upload & Analyze {files.length} File{files.length === 1 ? "" : "s"}
            </Button>
          )}

          {phase === "uploading" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Uploading {files.length} file{files.length === 1 ? "" : "s"} and starting analysis...
                </span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-1.5" />
              <p className="text-xs text-muted-foreground text-center">
                Validating batch -&gt; ingesting files -&gt; parsing rules -&gt; building topology -&gt; calculating attack paths
              </p>
            </div>
          )}

          <AnimatePresence>
            {phase === "done" && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="space-y-3"
              >
                <div className="rounded-lg border border-success/30 bg-success/10 p-3">
                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="h-4 w-4 text-success mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-success">Upload complete</p>
                      <p className="text-xs text-muted-foreground">
                        {results.length} file{results.length === 1 ? "" : "s"} accepted and sent into the pipeline.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                  {results.map((result) => (
                    <div key={`${result.filename}:${result.upload_id}:${result.vendor}`} className="rounded-lg border border-border bg-secondary/20 p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-xs font-medium text-foreground truncate">{result.filename}</p>
                          <p className="text-xs text-muted-foreground">
                            {result.type === "data" ? "Data import" : "Config analysis"} - vendor: {result.vendor}
                          </p>
                        </div>
                        <CheckCircle2 className="h-4 w-4 text-success shrink-0 mt-0.5" />
                      </div>
                      {(result.message || result.processed_rows != null) && (
                        <p className="text-xs text-muted-foreground mt-2 break-words">
                          {result.message ?? "Upload accepted."}
                          {result.processed_rows != null ? ` Rows processed: ${result.processed_rows}.` : ""}
                          {result.errors_count ? ` Errors: ${result.errors_count}.` : ""}
                        </p>
                      )}
                    </div>
                  ))}
                </div>

                <Button variant="outline" className="w-full" onClick={reset}>
                  <Upload className="h-4 w-4 mr-2" />
                  Upload Another Batch
                </Button>
              </motion.div>
            )}

            {phase === "error" && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="space-y-3"
              >
                <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-destructive mt-0.5" />
                    <div>
                      <p className="text-xs font-semibold text-destructive">Upload failed</p>
                      <p className="text-xs text-muted-foreground break-words">{errorMsg}</p>
                    </div>
                  </div>
                </div>
                <Button variant="outline" className="w-full" onClick={reset}>
                  <Upload className="h-4 w-4 mr-2" />
                  Try Again
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </DialogContent>
    </Dialog>
  );
}
