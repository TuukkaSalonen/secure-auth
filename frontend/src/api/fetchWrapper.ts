import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

// Wrap fetch to handle rate limiting
export const fetchWrapper = async (
  url: string,
  options: RequestInit = {}
): Promise<Response> => {
  const response = await fetch(url, options);

  if (response.status === 429) {
    const message =
      "Too many requests for this action. Please try again later.";
    toast.error(message);
    throw new Error(message);
  }
  return response;
};
