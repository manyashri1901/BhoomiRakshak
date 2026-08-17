import { api } from "./client";

export interface UploadResult {
  documentPath: string;
  documentHash: string;
}

export function uploadDocument(file: File) {
  const formData = new FormData();
  formData.append("file", file);
  return api
    .post<UploadResult>("/documents/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    })
    .then((r) => r.data);
}

function documentFilename(documentPath: string): string {
  return documentPath.split("/").pop() ?? documentPath;
}

// Download requires the auth header, so a plain <a href> won't work —
// fetch the file as a blob (token attached by the axios interceptor) and
// trigger the browser's save flow from the resulting object URL.
export async function downloadDocument(documentPath: string): Promise<void> {
  const filename = documentFilename(documentPath);
  const response = await api.get(`/documents/${encodeURIComponent(filename)}`, {
    responseType: "blob",
  });
  const url = URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
