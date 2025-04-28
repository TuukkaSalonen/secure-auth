import React, { useEffect, useState } from "react";
import { useDropzone } from "react-dropzone";
import { uploadFile, downloadFile, getFiles, deleteFile } from "../api/files";
import { Link } from "react-router-dom";
import styles from "./styles/Files.module.css";

// File item interface for file list
interface FileItem {
  id: string;
  filename: string;
  file_size: number;
  uploaded_at: string;
}

// Files component for file upload, download, and delete functionality
const Files: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [fileList, setFileList] = useState<FileItem[]>([]);

  // Fetch files on component mount
  useEffect(() => {
    fetchFiles();
  }, []);

  // Fetch files from the server
  const fetchFiles = async () => {
    setFileList(await getFiles());
  };

  // Handle file drop and validation with a size limit of 100MB
  const onDrop = (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;
    if (file.size > 100 * 1024 * 1024) {
      alert("File size exceeds 100MB limit.");
      return;
    }
    setFile(acceptedFiles[0]);
  };

  // Set up dropzone for file upload with accepted file types
  const { getRootProps, getInputProps } = useDropzone({
    accept: {
      "image/jpeg": [".jpg", ".jpeg"],
      "image/png": [".png"],
      "image/gif": [".gif"],
      "image/svg+xml": [".svg"],
      "audio/mpeg": [".mp3"],
      "audio/wav": [".wav"],
      "audio/ogg": [".ogg"],
      "audio/mp4": [".m4a"],
      "video/mp4": [".mp4"],
      "application/pdf": [".pdf"],
      "application/msword": [".docx"],
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
      ],
      "application/zip": [".zip", ".tar", ".gz"],
    },
    onDrop,
  });

  // Handle file download file by ID
  const handleDownload = async (fileId: string) => {
    await downloadFile(fileId);
  };

  // Handle file deletion by ID
  const handleDelete = async (fileId: string) => {
    const confirmDelete = window.confirm(
      "Are you sure you want to delete this file?"
    );
    if (confirmDelete) {
      const response = await deleteFile(fileId);
      if (response.success) {
        fetchFiles();
      } else {
        alert("Failed to delete file.");
      }
    }
  };

  // Handle file upload on form submission
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!file) {
      alert("Please select a file first!");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await uploadFile(formData);

    // Check if the file upload was successful
    if (response.success) {
      setFile(null);
      fetchFiles();
    } else {
      alert("File upload failed!");
    }
  };

  return (
    <div className={styles.filesContainer}>
      <h1>Files</h1>
      <form onSubmit={handleSubmit}>
        <div {...getRootProps()} className={styles.dropzone}>
          <input {...getInputProps()} />
          {!file ? (
            <p>Drag & drop a file here, or click to select one</p>
          ) : (
            <p>Upload or clear the file using the buttons below.</p>
          )}
          {file && (
            <div className={styles.selectedFile}>
              <strong>Selected file:</strong> {file.name}
            </div>
          )}
        </div>
        {file && (
          <div className={styles.fileActions}>
            <button className={styles.btn} type="submit">
              Upload
            </button>
            <button
              className={styles.btn}
              type="button"
              onClick={() => setFile(null)}
            >
              Clear
            </button>
          </div>
        )}
      </form>
      {fileList.length === 0 && <p>No files uploaded yet.</p>}
      <ul className={styles.fileList}>
        {fileList.map((file: FileItem) => (
          <li key={file.id} className={styles.fileItem}>
            <span>{file.filename}</span>
            <span>({file.file_size} bytes)</span>
            <span>
              Uploaded at: {new Date(file.uploaded_at).toLocaleDateString()}
            </span>
            <div>
              <button
                className={styles.btn}
                onClick={() => handleDownload(file.id)}
              >
                Download
              </button>
              <button
                className={`${styles.btn} ${styles.btnDelete}`}
                onClick={() => handleDelete(file.id)}
              >
                Delete
              </button>
            </div>
          </li>
        ))}
      </ul>
      <Link to="/" className={styles.link}>
        Back to Home
      </Link>
    </div>
  );
};

export default Files;
