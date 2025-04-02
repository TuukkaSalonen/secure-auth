// Wrap fetch to handle rate limiting
export const fetchWrapper = async (
  url: string,
  options: RequestInit = {}
): Promise<Response> => {
  const response = await fetch(url, options);

  if (response.status === 429) {
    const message = "Too many requests for this action. Please try again later.";
    alert(message);
    throw new Error(message);
  }
  return response;
};