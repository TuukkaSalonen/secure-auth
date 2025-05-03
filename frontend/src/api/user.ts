import { API_BASE_URL } from "../constants";
import { getCSRFAccessToken } from "./auth";

// User API calls

// Delete user account and all the related data, such as files from the server database
export const deleteUser = async () => {
  try {
    const csrfToken = await getCSRFAccessToken();
    const response = await fetch(`${API_BASE_URL}/user/delete`, {
      method: "Delete",
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
