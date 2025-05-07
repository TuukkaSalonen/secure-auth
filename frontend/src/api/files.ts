import { getCSRFAccessToken } from "./auth";
import { API_BASE_URL } from "../constants";

// File upload, download, and delete API calls
// CSRF tokens are sent with each request

// Upload file to the server database
export const uploadFile = async (formData: FormData) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch(`${API_BASE_URL}/file/upload`, {
      method: "POST",
      body: formData,
      headers: {
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    const data = await response.json();
    if (!response.ok) {
      if (data.message) {
        return { success: false, message: data.message };
      } else {
        throw new Error("Network response was not ok");
      }
    }
    return { success: true, message: data.message };
  } catch (error) {
    console.error("Error uploading files:", error);
    return { success: false, message: "Error uploading files" };
  }
};

// Download file from the server database
export const downloadFile = async (fileId: string) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch(`${API_BASE_URL}/file/download/${fileId}`, {
      method: "GET",
      headers: {
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    if (!response.ok) {
      throw new Error("Network response was not ok");
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;

    const contentDisposition = response.headers.get("Content-Disposition");

    const filename = contentDisposition
      ? contentDisposition
          .split("filename=")[1]
          .replace(/(^"|"$)/g, "")
          .trim()
      : "downloaded_file";

    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    return { success: true, message: "File downloaded successfully" };
  } catch (error) {
    console.error("Error downloading file:", error);
    return { success: false, message: "Error downloading file" };
  }
};

// Download all files from the server database
export const downloadAllFiles = async () => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch(`${API_BASE_URL}/file/download/all`, {
      method: "GET",
      headers: {
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    if (!response.ok) {
      throw new Error("Network response was not ok");
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;

    const contentDisposition = response.headers.get("Content-Disposition");

    const filename = contentDisposition
      ? contentDisposition
          .split("filename=")[1]
          .replace(/(^"|"$)/g, "")
          .trim()
      : "downloaded_files";

    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    return { success: true, message: "Files downloaded successfully" };
  } catch (error) {
    console.error("Error downloading file:", error);
    return { success: false, message: "Error downloading files" };
  }
};

// Delete file from the server database
export const deleteFile = async (fileId: string) => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch(`${API_BASE_URL}/file/delete/${fileId}`, {
      method: "DELETE",
      headers: {
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    const data = await response.json();
    if (!response.ok) {
      if (data.message) {
        return { success: false, message: data.message };
      }
      throw new Error("Network response was not ok");
    }
    return { success: true, message: data.message };
  } catch (error) {
    console.error("Error deleting file:", error);
    return { success: false, message: "Error deleting file" };
  }
};

// Delete all users files from the server database
export const deleteAllFiles = async () => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch(`${API_BASE_URL}/file/delete/all`, {
      method: "DELETE",
      headers: {
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    const data = await response.json();
    if (!response.ok) {
      if (data.message) {
        return { success: false, message: data.message };
      }
      throw new Error("Network response was not ok");
    }
    return { success: true, message: data.message };
  } catch (error) {
    console.error("Error deleting all files:", error);
    return { success: false, message: "Error deleting all files" };
  }
};

// Get list of available files from the server database
export const getFiles = async () => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch(`${API_BASE_URL}/file/list`, {
      method: "GET",
      headers: {
        ...(csrfToken && { "X-CSRF-Token": csrfToken }),
      },
      credentials: "include",
    });
    if (!response.ok) {
      throw new Error("Network response was not ok");
    }
    const data = await response.json();
    return data.files;
  } catch (error) {
    console.error("Error fetching files:", error);
    return [];
  }
};
