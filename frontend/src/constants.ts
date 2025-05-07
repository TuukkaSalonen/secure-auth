// Auth action types
export const LOGIN = "LOGIN";
export const LOGOUT = "LOGOUT";
export const SET_USER = "SET_USER";
export const SET_MFA = "SET_MFA";

// API URL for the backend
export const API_BASE_URL = "http://localhost:5000/api";

// Accepted file types for upload
export const acceptedFileTypes = {
    // Images
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "image/gif": [".gif"],
    "image/svg+xml": [".svg"],
    "image/webp": [".webp"],
    "image/bmp": [".bmp"],
    "image/tiff": [".tif", ".tiff"],

    // Audio
    "audio/mpeg": [".mp3"],
    "audio/wav": [".wav"],
    "audio/ogg": [".ogg"],
    "audio/mp4": [".m4a"],
    "audio/flac": [".flac"],
    "audio/aac": [".aac"],

    // Video
    "video/mp4": [".mp4"],
    "video/mpeg": [".mpeg"],
    "video/ogg": [".ogv"],
    "video/webm": [".webm"],
    "video/quicktime": [".mov"],
    "video/x-msvideo": [".avi"],
    "video/x-matroska": [".mkv"],

    // Documents
    "application/pdf": [".pdf"],
    "application/msword": [".doc", ".docx"],
    "application/vnd.ms-excel": [".xls", ".xlsx"],
    "application/vnd.ms-powerpoint": [".ppt", ".pptx"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": [".pptx"],
    "text/plain": [
      ".txt",
      ".py",
      ".js",
      ".html",
      ".css",
      ".ts",
      ".c",
      ".cpp",
      ".java",
      ".jsx",
      ".tsx",
      ".json",
      ".md",
      ".xml",
      ".csv",
      ".yaml",
      ".yml",
      ".sql",
      ".hs",
      ".sh",
      ".bat",
      ".ini",
      ".log",
      ".conf",
      ".hs",
    ],

    // Archives
    "application/zip": [".zip", ".tar", ".gz", ".7z", ".rar"],
    "application/x-tar": [".tar"],
    "application/gzip": [".gz"],

    // Other
    "application/json": [".json"],
    "application/xml": [".xml"],
    "application/x-yaml": [".yaml", ".yml"],
    "application/octet-stream": [".bin", ".exe", ".iso"],
    "application/x-msdownload": [".exe", ".msi"],
    "application/x-shockwave-flash": [".swf"],
    "application/x-bzip": [".bz2"],
    "application/x-bzip2": [".bz2"],
    "application/x-rar-compressed": [".rar"],
  }