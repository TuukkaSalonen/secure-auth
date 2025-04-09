import React, { useEffect, useState } from "react";
import { useDropzone } from "react-dropzone";
import { uploadFile, downloadFile, getFiles, deleteFile } from "../api/files";
import { Link } from "react-router-dom";
//import styles from "./styles/Files.module.css";

interface FileItem {
  id: string;
  filename: string;
  file_size: number;
  uploaded_at: string;
}

const Files: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [fileList, setFileList] = useState<FileItem[]>([]);

  useEffect(() => {
    fetchFiles();
  }, []);

  const fetchFiles = async () => {
    setFileList(await getFiles());
  };

  const onDrop = (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;
    if (file.size > 100 * 1024 * 1024) {
      alert("File size exceeds 100MB limit.");
      return;
    }
    setFile(acceptedFiles[0]);
  };

  const { getRootProps, getInputProps } = useDropzone({
    accept: {
      "image/jpeg": [".jpg", ".jpeg"],
      "image/png": [".png"],
      "image/gif": [".gif"],
      "audio/mpeg": [".mp3"],
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

  const handleDownload = async (fileId: string) => {
    await downloadFile(fileId);
  };

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

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!file) {
      alert("Please select a file first!");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await uploadFile(formData);
    if (response.success) {
      setFile(null);
      fetchFiles();
    } else {
      alert("File upload failed!");
    }
  };

  return (
    <div>
      <h1>Files</h1>
      {fileList.length === 0 && <p>No files uploaded yet.</p>}
      <ul>
        {fileList.map((file: FileItem) => (
          <li key={file.id}>
            <span>{file.filename}</span>
            <span> ({file.file_size} bytes)</span>
            <span> - {new Date(file.uploaded_at).toLocaleDateString()}</span>
            <button onClick={() => handleDownload(file.id)}>Download</button>
            <button
              style={{ backgroundColor: "red" }}
              onClick={() => handleDelete(file.id)}
            >
              Delete
            </button>
          </li>
        ))}
      </ul>
      <form onSubmit={handleSubmit}>
        <div
          {...getRootProps()}
          style={{
            border: "2px dashed #cccccc",
            padding: "20px",
            textAlign: "center",
            cursor: "pointer",
          }}
        >
          <input {...getInputProps()} />
          <p>Drag & drop a file here, or click to select one</p>
          {file && (
            <div style={{ marginTop: "10px", fontSize: "14px", color: "#333" }}>
              <strong>Selected file:</strong> {file.name}
            </div>
          )}
        </div>
        {file && (
          <>
            <button type="submit">Upload</button>
            <button type="button" onClick={() => setFile(null)}>
              Clear
            </button>
          </>
        )}
      </form>
      <Link to="/">Back to Home</Link>
    </div>
  );
};

export default Files;
