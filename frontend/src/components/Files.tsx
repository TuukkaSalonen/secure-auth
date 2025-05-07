import React, { useEffect, useState } from "react";
import { useDropzone } from "react-dropzone";
import {
  uploadFile,
  downloadFile,
  downloadAllFiles,
  getFiles,
  deleteFile,
  deleteAllFiles,
} from "../api/files";
import { Link } from "react-router-dom";
import styles from "./styles/Files.module.css";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { confirmAlert } from "react-confirm-alert";
import "react-confirm-alert/src/react-confirm-alert.css";
import { acceptedFileTypes } from "../constants";

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
  const [loading, setLoading] = useState(false);

  // Fetch files on component mount
  useEffect(() => {
    fetchFiles();
  }, []);

  // Fetch files from the server
  const fetchFiles = async () => {
    setLoading(true);
    try {
      const files = await getFiles();
      setFileList(files);
    } catch {
      toast.error("Failed to fetch files");
    } finally {
      setLoading(false);
    }
  };

  // Handle file drop and validation with a size limit of 100MB
  const onDrop = (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;
    if (file.size > 100 * 1024 * 1024) {
      toast.error("File size exceeds 100MB limit.");
      return;
    }
    setFile(acceptedFiles[0]);
  };

  // Set up dropzone for file upload with accepted file types
  const { getRootProps, getInputProps } = useDropzone({
    accept: acceptedFileTypes,
    onDrop,
  });

  // Handle file download file by ID
  const handleDownload = async (fileId: string) => {
    const result = await downloadFile(fileId);
    if (!result?.success) {
      if (result?.message) {
        toast.error(result.message);
      } else {
        toast.error("Failed to download file. Please try again.");
      }
    }
  };

  // Handle file download file by ID
  const handleDownloadAll = async () => {
    const result = await downloadAllFiles();
    if (!result?.success) {
      if (result?.message) {
        toast.error(result.message);
      } else {
        toast.error("Failed to download files. Please try again.");
      }
    }
  };

  // Handle file deletion by ID
  const handleDelete = (fileId: string) => {
    confirmAlert({
      title: "Confirm Deletion",
      message: "Are you sure you want to delete this file?",
      buttons: [
        {
          label: "Yes",
          onClick: async () => {
            const response = await deleteFile(fileId);
            if (response.success) {
              toast.success("File deleted");
              fetchFiles();
            } else {
              if (response.message) {
                toast.error(response.message);
              } else {
                toast.error("Failed to delete file. Please try again.");
              }
            }
          },
        },
        {
          label: "No",
        },
      ],
    });
  };

  // Handle deletion of all files
  const handleDeleteAll = () => {
    confirmAlert({
      title: "Confirm Deletion",
      message: "Are you sure you want to delete all files?",
      buttons: [
        {
          label: "Yes",
          onClick: async () => {
            const response = await deleteAllFiles();
            if (response.success) {
              toast.success("Files deleted");
              fetchFiles();
            } else {
              if (response.message) {
                toast.error(response.message);
              } else {
                toast.error("Failed to delete files. Please try again.");
              }
            }
          },
        },
        {
          label: "No",
        },
      ],
    });
  };

  // Handle file upload on form submission
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!file) {
      toast.error("Please select a file to upload.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await uploadFile(formData);

    // Check if the file upload was successful
    if (response.success) {
      toast.success("File uploaded successfully!");
      setFile(null);
      fetchFiles();
    } else {
      if (response.message) {
        toast.error(response.message);
      } else {
        toast.error("Failed to upload file. Please try again.");
      }
    }
  };

  // Format file size for display, found this function in StackOverflow
  const formatFileSize = (size: number) => {
    const i = size == 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
    return (
      +(size / Math.pow(1024, i)).toFixed(2) * 1 +
      " " +
      ["B", "kB", "MB", "GB", "TB"][i]
    );
  };

  return (
    <div className={styles.filesContainer}>
      <h1 style={{marginTop: "0px", marginBottom: "8px"}}>Files</h1>
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

      <h2 style={{margin:"8px"}}>Uploaded Files</h2>
      {loading ? (
        <div className={styles.spinnerContainer}>
          <FontAwesomeIcon icon={faSpinner} spin className={styles.spinner} />
        </div>
      ) : (
        <>
          {fileList.length > 0 ? (
            <>
              <p style={{ margin: "0px" }}>Total files: {fileList.length}</p>
              <button
                className={`${styles.btn}`}
                onClick={() => handleDownloadAll()}
              >
                Download All Files
              </button>
              <button
                className={`${styles.btn} ${styles.btnDelete}`}
                onClick={() => handleDeleteAll()}
              >
                Delete All Files
              </button>
              <div className={styles.scrollableContainer}>
                <ul className={styles.fileList}>
                  {fileList.map((file: FileItem) => (
                    <li key={file.id} className={styles.fileItem}>
                      <span>{file.filename}</span>
                      <span>{formatFileSize(file.file_size)}</span>
                      <span>
                        Uploaded at:{" "}
                        {new Date(file.uploaded_at).toLocaleDateString()}
                      </span>
                      <div style={{margin: "0px"}}>
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
              </div>
            </>
          ) : (
            <p>No files uploaded yet.</p>
          )}
        </>
      )}
      <Link to="/" className={styles.link}>
        Back to Home
      </Link>
    </div>
  );
};

export default Files;
